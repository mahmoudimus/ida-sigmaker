from __future__ import annotations

import json
import os
import pathlib
import platform
import pprint
import shlex
import string
import subprocess
import sysconfig
import tempfile

# ============================
# Embedded C runtime detector
# ============================

_RUNTIME_DETECTOR_TEMPLATE = string.Template(
    r"""
#ifdef _MSC_VER
  #include <stdio.h>
  #include <string.h>
  #include <intrin.h>
#else
  #include <stdio.h>
  #include <string.h>
#endif

// Feature macros
$feature_macros

#if defined(__APPLE__)
  #include <sys/types.h>
  #include <sys/sysctl.h>
#endif

$linux_arm_includes

$cpuid_helper

int main(void) {
#if HAVE_X86
  // x86 detection
  int r1[4]   = {0,0,0,0};
  int r7_0[4] = {0,0,0,0};
  int r7_1[4] = {0,0,0,0};
  cpuid_ex(r1,   1, 0);
  cpuid_ex(r7_0, 7, 0);
  cpuid_ex(r7_1, 7, 1);

  unsigned ecx1   = (unsigned)r1[2];
  unsigned edx1   = (unsigned)r1[3];
  unsigned ebx7   = (unsigned)r7_0[1];
  unsigned ecx7   = (unsigned)r7_0[2];
  unsigned eax7_1 = (unsigned)r7_1[0];

  int sse2          = (edx1 & (1u<<26)) != 0;
  int avx           = (ecx1 & (1u<<28)) != 0;
  int f16c          = (ecx1 & (1u<<29)) != 0;
  int fma           = (ecx1 & (1u<<12)) != 0;
  int avx2          = (ebx7 & (1u<<5 )) != 0;
  int avx512f       = (ebx7 & (1u<<16)) != 0;
  int avx512_vnni   = (ecx7 & (1u<<11)) != 0;
  int avx512_bf16   = (eax7_1 & (1u<<5)) != 0;

  char label[64]; label[0] = '\0';
  if (avx2 && f16c && fma) {
    if (avx512f) {
      if (avx512_vnni && avx512_bf16) snprintf(label,sizeof(label),"x86 (AVX-512 VNNI+BF16)");
      else if (avx512_vnni)           snprintf(label,sizeof(label),"x86 (AVX-512 VNNI)");
      else                             snprintf(label,sizeof(label),"x86 (Skylake-class AVX-512F)");
    } else snprintf(label,sizeof(label),"x86 (Haswell-class AVX2)");
  } else if (avx)   snprintf(label,sizeof(label),"x86 (AVX)");
  else if (sse2)    snprintf(label,sizeof(label),"x86 (SSE2)");
  else              snprintf(label,sizeof(label),"x86 (baseline)");

  puts("arch=x86");
  printf("label=%s\n", label);
  printf("x86_sse2=%d\n", sse2);
  printf("x86_avx=%d\n", avx);
  printf("x86_avx2=%d\n", avx2);
  printf("x86_f16c=%d\n", f16c);
  printf("x86_fma=%d\n", fma);
  printf("x86_avx512f=%d\n", avx512f);
  printf("x86_avx512_vnni=%d\n", avx512_vnni);
  printf("x86_avx512_bf16=%d\n", avx512_bf16);

#elif HAVE_ARM
  // ARM/AArch64 detection
  int neon=0, fp16=0, bf16=0, i8mm=0, sve=0, sve2=0;

  #if defined(__APPLE__)
    size_t sz = sizeof(int); int v=0;
    if (sysctlbyname("hw.optional.neon", &v, &sz, NULL, 0)==0) neon=v; v=0;
    if (sysctlbyname("hw.optional.arm.FEAT_FP16", &v, &sz, NULL, 0)==0) fp16=v; v=0;
    if (sysctlbyname("hw.optional.arm.FEAT_BF16", &v, &sz, NULL, 0)==0) bf16=v; v=0;
    if (sysctlbyname("hw.optional.arm.FEAT_I8MM", &v, &sz, NULL, 0)==0) i8mm=v;
  #elif defined(__linux__) && (defined(__aarch64__) || defined(__arm__))
    unsigned long hw1 = getauxval(AT_HWCAP);
    unsigned long hw2 = getauxval(AT_HWCAP2);
    #ifdef HWCAP_ASIMD
      neon = (hw1 & HWCAP_ASIMD) != 0;
    #endif
    #ifdef HWCAP_ASIMDDP
      int asimddp = (hw1 & HWCAP_ASIMDDP) != 0;
    #else
      int asimddp = 0;
    #endif
    #ifdef HWCAP_SVE
      sve  = (hw1 & HWCAP_SVE) != 0;
    #endif
    #ifdef HWCAP2_I8MM
      i8mm = (hw2 & HWCAP2_I8MM) != 0;
    #else
      i8mm = asimddp; // heuristic if headers are old
    #endif
    #ifdef HWCAP2_BF16
      bf16 = (hw2 & HWCAP2_BF16) != 0;
    #endif
    #ifdef HWCAP2_SVE2
      sve2 = (hw2 & HWCAP2_SVE2) != 0;
    #endif
    fp16 = neon; // simplified heuristic
  #endif

  const char* label = "ARM (baseline)";
  if (sve2) label = "ARM (SVE2)";
  else if (sve) label = "ARM (SVE)";
  else if (neon) {
    if (i8mm && bf16 && fp16) label = "ARM (NEON+i8mm+bf16+fp16)";
    else if (i8mm)           label = "ARM (NEON+i8mm)";
    else if (fp16)           label = "ARM (NEON+fp16)";
    else                     label = "ARM (NEON)";
  } else label = "ARM (no NEON)";

  puts("arch=arm");
  printf("label=%s\n", label);
  printf("arm_neon=%d\n",  neon);
  printf("arm_fp16=%d\n",  fp16);
  printf("arm_bf16=%d\n",  bf16);
  printf("arm_i8mm=%d\n",  i8mm);
  printf("arm_sve=%d\n",   sve);
  printf("arm_sve2=%d\n",  sve2);

#else
  puts("arch=unknown");
  puts("label=Unknown arch");
#endif
  return 0;
}
"""
)

_feature_macros = r"""
#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
  #define HAVE_X86 1
#else
  #define HAVE_X86 0
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__)
  #define HAVE_ARM 1
#else
  #define HAVE_ARM 0
#endif
"""

_linux_arm_includes = r"""
#if defined(__linux__) && (defined(__aarch64__) || defined(__arm__))
  #include <sys/auxv.h>
  #if defined(__has_include)
    #if __has_include(<asm/hwcap.h>)
      #include <asm/hwcap.h>
    #elif __has_include(<linux/auxvec.h>)
      #include <linux/auxvec.h>
    #endif
  #else
    #include <asm/hwcap.h>
  #endif
#endif
"""

_cpuid_helper = r"""
#if HAVE_X86
  static void cpuid_ex(int regs[4], int leaf, int subleaf) {
  #ifdef _MSC_VER
    __cpuidex(regs, leaf, subleaf);
  #else
    unsigned a,b,c,d;
    __asm__ __volatile__("cpuid"
                         : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                         : "a"(leaf), "c"(subleaf));
    regs[0]=(int)a; regs[1]=(int)b; regs[2]=(int)c; regs[3]=(int)d;
  #endif
  }
#endif
"""

_RUNTIME_DETECTOR_C = _RUNTIME_DETECTOR_TEMPLATE.substitute(
    feature_macros=_feature_macros,
    linux_arm_includes=_linux_arm_includes,
    cpuid_helper=_cpuid_helper,
)


# ============================
# Build-time try-compile fallback
# ============================

_SNIPPETS = {
    "sse2": r"""
        #include <immintrin.h>
        int main(void){
            __m128i a = _mm_set1_epi32(1), b = _mm_set1_epi32(2);
            __m128i c = _mm_add_epi32(a,b); (void)c; return 0;
        }
    """,
    "avx": r"""
        #include <immintrin.h>
        int main(void){
            __m256 a = _mm256_set1_ps(1.0f), b = _mm256_set1_ps(2.0f);
            __m256 c = _mm256_add_ps(a,b); (void)c; return 0;
        }
    """,
    "avx2": r"""
        #include <immintrin.h>
        int main(void){
            __m256i a = _mm256_set1_epi32(1), b = _mm256_set1_epi32(2);
            __m256i c = _mm256_add_epi32(a,b); (void)c; return 0;
        }
    """,
    "neon": r"""
        #include <arm_neon.h>
        int main(void){
            uint32x4_t a = vdupq_n_u32(1), b = vdupq_n_u32(2);
            uint32x4_t c = vaddq_u32(a,b); (void)c; return 0;
        }
    """,
}


# ============================
# Compiler helpers
# ============================


def _split_cc(cc_str: str) -> tuple[str, list[str]]:
    parts = shlex.split(cc_str) if cc_str else []
    return (
        (parts[0], parts[1:])
        if parts
        else ("cl.exe" if platform.system() == "Windows" else "cc", [])
    )


def _driver_kind(cc_bin: str) -> str:
    base = pathlib.Path(cc_bin).name.lower()
    if base in ("cl", "cl.exe"):
        return "msvc"
    if base in ("clang-cl", "clang-cl.exe"):
        return "clang-cl"
    if "clang" in base:
        return "clang"
    if "gcc" in base or "g++" in base:
        return "gcc"
    try:
        out = subprocess.run(
            [cc_bin, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2,
        )
        t = (out.stdout + out.stderr).lower()
        if "clang" in t:
            return "clang"
        if "gcc" in t or "gnu" in t:
            return "gcc"
    except Exception:
        pass
    return "unknown"


def _target_arch(cc_bin: str, driver: str) -> str:
    if driver in ("gcc", "clang"):
        try:
            out = subprocess.run(
                [cc_bin, "-dumpmachine"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
            )
            triple = out.stdout.strip().lower()
            if any(x in triple for x in ("x86_64", "amd64", "i686", "i386")):
                return "x86"
            if any(x in triple for x in ("aarch64", "arm64", "armv7", "arm")):
                return "arm"
        except Exception:
            pass
    m = platform.machine().lower()
    if m.startswith(("x86", "i386", "i686")) or m in ("amd64", "x86_64"):
        return "x86"
    if m.startswith(("arm", "aarch64")) or "arm64" in m:
        return "arm"
    return "unknown"


def _obj_suffix() -> str:
    return ".obj" if platform.system() == "Windows" else ".o"


def _exe_name(basename: str) -> str:
    return f"{basename}.exe" if platform.system() == "Windows" else basename


def _compile_link_runtime(
    cc_bin: str,
    cc_extra: list[str],
    driver: str,
    src_path: pathlib.Path,
    exe_path: pathlib.Path,
) -> tuple[bool, str]:
    if driver in ("msvc", "clang-cl"):
        cmd = [cc_bin, "/nologo", str(src_path), "/Fe:" + str(exe_path)]
    else:
        cmd = [cc_bin] + cc_extra + [str(src_path), "-o", str(exe_path)]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ok = p.returncode == 0 and exe_path.exists()
    return ok, (p.stdout + p.stderr)


def _candidate_flags(feature: str, driver: str, arch: str):
    if arch == "x86":
        msvc_like = (
            [
                [
                    f"/arch:{'SSE2' if feature=='sse2' else 'AVX' if feature=='avx' else 'AVX2'}"
                ]
            ]
            if feature in ("sse2", "avx", "avx2")
            else []
        )
        gnu_like = (
            [[{"sse2": "-msse2", "avx": "-mavx", "avx2": "-mavx2"}[feature]]]
            if feature in ("sse2", "avx", "avx2")
            else []
        )
        if driver == "msvc":
            return msvc_like
        if driver == "clang-cl":
            return msvc_like + gnu_like
        if driver in ("gcc", "clang"):
            return gnu_like
        return msvc_like + gnu_like

    if arch == "arm":
        if feature != "neon":
            return []
        if driver in ("gcc", "clang"):
            return [[], ["-mfpu=neon"], ["-mfpu=neon", "-mfloat-abi=hard"]]
        if driver in ("clang-cl", "msvc"):
            return [[]]
        return [[]]
    return []


def _compile(
    cc_bin: str, cc_extra: list[str], code: str, flags: list[str], msvc_like: bool
) -> bool:
    with tempfile.TemporaryDirectory() as td:
        td_path = pathlib.Path(td)
        src = td_path / "t.c"
        obj = td_path / f"t{_obj_suffix()}"
        src.write_text(code)
        if msvc_like:
            cmd = [cc_bin, "/nologo", "/c", str(src), "/Fo:" + str(obj)] + flags
        else:
            cmd = [cc_bin] + cc_extra + ["-c", str(src), "-o", str(obj)] + flags
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return p.returncode == 0 and obj.exists()
        except FileNotFoundError:
            return False


# ============================
# Runtime helper parsing
# ============================


def _parse_kv_output(stdout: str) -> dict:
    flat: dict[str, int | str] = {}
    for line in stdout.splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if v.isdigit():
            flat[k] = int(v)
        else:
            flat[k] = v

    arch = str(flat.get("arch", "unknown"))
    label = str(flat.get("label", "Unknown arch"))
    out: dict = {"arch": arch, "label": label}

    if arch == "x86":
        out["x86"] = {
            "sse2": flat.get("x86_sse2", 0),
            "avx": flat.get("x86_avx", 0),
            "avx2": flat.get("x86_avx2", 0),
            "f16c": flat.get("x86_f16c", 0),
            "fma": flat.get("x86_fma", 0),
            "avx512f": flat.get("x86_avx512f", 0),
            "avx512_vnni": flat.get("x86_avx512_vnni", 0),
            "avx512_bf16": flat.get("x86_avx512_bf16", 0),
        }
    elif arch == "arm":
        out["arm"] = {
            "neon": flat.get("arm_neon", 0),
            "fp16": flat.get("arm_fp16", 0),
            "bf16": flat.get("arm_bf16", 0),
            "i8mm": flat.get("arm_i8mm", 0),
            "sve": flat.get("arm_sve", 0),
            "sve2": flat.get("arm_sve2", 0),
        }
    return out


# ============================
# Public entry point
# ============================


def probe_compiler_intrinsics() -> dict:
    # Prefer the CPython build compiler; allow CC env to override
    cc_cfg = sysconfig.get_config_var("CC") or ""
    cc_env = os.environ.get("CC")
    cc_str = cc_env or cc_cfg or ("cl.exe" if platform.system() == "Windows" else "cc")
    cc_bin, cc_extra = _split_cc(cc_str)
    driver = _driver_kind(cc_bin)
    arch_guess = _target_arch(cc_bin, driver)

    # Try runtime detector first
    with tempfile.TemporaryDirectory() as td:
        td_path = pathlib.Path(td)
        src = td_path / "cpu_features_min.c"
        exe = td_path / _exe_name("cpu_features_min")
        src.write_text(_RUNTIME_DETECTOR_C)
        ok, _log = _compile_link_runtime(cc_bin, cc_extra, driver, src, exe)
        if ok:
            try:
                run = subprocess.run(
                    [str(exe)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=5,
                )
                if run.returncode == 0 and run.stdout:
                    data = _parse_kv_output(run.stdout)
                    return {
                        "compiler": cc_bin,
                        "extra_tokens": cc_extra,
                        "driver": driver,
                        "arch": data.get("arch", arch_guess),
                        "method": "runtime",
                        "runtime": data,
                        "note": "Runtime CPU probe via compiled helper (key=value).",
                    }
            except Exception:
                pass  # fall through to build-time try-compile

    # Fallback: build-time try-compiles
    msvc_like = driver in ("msvc", "clang-cl")
    results = {}
    for feature, snippet in _SNIPPETS.items():
        if feature in ("sse2", "avx", "avx2") and arch_guess != "x86":
            results[feature] = {
                "supported": False,
                "flags": None,
                "skipped": f"arch={arch_guess}",
            }
            continue
        if feature == "neon" and arch_guess != "arm":
            results[feature] = {
                "supported": False,
                "flags": None,
                "skipped": f"arch={arch_guess}",
            }
            continue

        tried, succeeded = [], None
        for flags in _candidate_flags(feature, driver, arch_guess):
            tried.append(flags)
            if _compile(cc_bin, cc_extra, snippet, flags, msvc_like):
                succeeded = flags
                break
        results[feature] = {
            "supported": succeeded is not None,
            "flags": succeeded,
            "tried": tried,
        }

    return {
        "compiler": cc_bin,
        "extra_tokens": cc_extra,
        "driver": driver,
        "arch": arch_guess,
        "method": "build-try-compile",
        "supports": results,
        "note": "Fallback: compiler can compile intrinsics with these flags (build-time capability).",
    }


if __name__ == "__main__":
    pathlib.Path(pathlib.Path(__file__).parent / "simd_probe.json").write_text(
        json.dumps(probe_compiler_intrinsics(), indent=2)
    )
