"""Build script for the IDA Pro sigmaker Cython module.

This ``setup.py`` detects the host platform and architecture in order to
select appropriate compilation and linkage flags.
The build expects the IDA SDK to be installed and accessible via the
environment variable ``IDA_SDK``.
"""

import functools
import json
import os
import pathlib
import platform
import re
import subprocess
import sys

from Cython.Build import cythonize
from setuptools import Extension, find_packages, setup

# ---------------------------------------------------------------------------
# Platform detection
# Use the host system and architecture to adjust compiler options.
OSTYPE = platform.system()
ARCH = platform.processor() or platform.machine()
x64 = platform.architecture()[0] == "64bit"
COMPILER_OPTIMIZATION_LEVEL = re.compile(r"-O[0-3]\b")


if ARCH == "ppc64le":
    LIBRARY = "ppc64le"
elif ARCH == "aarch64":
    LIBRARY = "aarch64"
elif ARCH == "arm" or ARCH == "arm64":
    LIBRARY = "arm64"
else:  # 'AMD64', 'x86_64', 'i686', 'i386'
    LIBRARY = "amd64" if x64 else "intel32"

if OSTYPE == "Darwin":
    LIBRARY_EXT = ".dylib"
elif OSTYPE == "Linux":
    LIBRARY_EXT = ".so"
else:
    LIBRARY_EXT = ".dll"


def get_simd_info():
    simd_probe_path = pathlib.Path(__file__).parent / "simd_probe.json"
    if not simd_probe_path.exists():
        msg = f"simd_probe.json not found at {simd_probe_path}, "
        msg += "will run `python probe_compiler_intrinsics.py` to generate it"
        print(msg)
        subprocess.run([sys.executable, "probe_compiler_intrinsics.py"], check=True)
        if not simd_probe_path.exists():
            msg = f"simd_probe.json not found at {simd_probe_path}, "
            msg += "tried to run `python probe_compiler_intrinsics.py` to generate it, "
            msg += "but it did not succeed. "
            msg += "Please run it manually: python probe_compiler_intrinsics.py"
            raise FileNotFoundError(msg)
    with open(simd_probe_path, "r") as f:
        return json.load(f)


# ----------------------------
# SIMD flag selection (from probe)
# ----------------------------
def determine_simd_flags() -> list[str]:
    """
    Choose compiler flags to enable the highest supported SIMD level.

    Strategy:
    - If probe method is 'build-try-compile', use the *exact flags* that succeeded.
    - Else (runtime), map detected features to conventional flags per compiler.
    - Preference on x86: AVX2 > AVX > SSE2.
    - On AArch64, NEON is baseline; avoid adding flags. On ARMv7, add -mfpu=neon for gcc/clang if present.
    """
    info = get_simd_info()
    driver = info.get("driver", "unknown")
    arch = info.get("arch", "unknown")

    def _from_try_compile():
        sup = info.get("supports", {})
        # x86: prefer highest supported feature
        for feat in ("avx2", "avx", "sse2"):
            f = sup.get(feat)
            if isinstance(f, dict) and f.get("supported") and f.get("flags"):
                return f["flags"]
        # ARM: neon flags (primarily armv7)
        f = sup.get("neon")
        if isinstance(f, dict) and f.get("supported") and f.get("flags"):
            return f["flags"]
        return []

    def _from_runtime():
        rt = info.get("runtime", {})

        if arch == "x86":
            x86 = rt.get("x86", {})
            if not x86:
                return []
            if driver in ("msvc", "clang-cl"):
                if x86.get("avx2"):
                    return ["/arch:AVX2"]
                if x86.get("avx"):
                    return ["/arch:AVX"]
                if x86.get("sse2"):
                    return ["/arch:SSE2"]
                return []
            else:  # gcc/clang posix
                if x86.get("avx2"):
                    return ["-mavx2"]
                if x86.get("avx"):
                    return ["-mavx"]
                if x86.get("sse2"):
                    return ["-msse2"]
                return []

        if arch == "arm":
            arm = rt.get("arm", {})
            if not arm:
                return []
            # AArch64: NEON baseline → no flags. For 32-bit ARM, -mfpu=neon may be needed.
            mach = platform.machine().lower()
            is_armv7 = mach.startswith("arm") and not (
                "aarch64" in mach or "arm64" in mach
            )
            if is_armv7 and driver in ("gcc", "clang") and arm.get("neon"):
                return ["-mfpu=neon"]
            return []

        return []

    if info.get("method") == "build-try-compile":
        return _from_try_compile()

    flags = _from_runtime()
    return flags if flags else _from_try_compile()


def compile_args(debug_mode=False):
    """Return platform-specific compilation arguments."""
    debug_flags = []
    simd_flags = determine_simd_flags()
    match OSTYPE:
        case "Windows":
            if debug_mode:
                debug_flags = ["/Z7", "/Od"]
            # For MSVC: `/TP` tells the compiler to treat sources as C++
            # files and `/EHa` enables asynchronous exception handling.
            return ["/TP", "/EHa"] + debug_flags + simd_flags
        case "Linux":
            # Suppress a few warnings that are often triggered by IDA
            # headers.
            if debug_mode:
                debug_flags = ["-g", "-O0", "-Wall", "-Wextra", "-Wpedantic"]
            return (
                [
                    "-Wno-stringop-truncation",
                    "-Wno-catch-value",
                    "-Wno-unused-variable",
                ]
                + debug_flags
                + simd_flags
            )
        case "Darwin":
            # On macOS specify the minimum supported version and optionally
            # enable debug symbols when the DEBUG environment variable is set.
            ignore_warnings = [
                "-Wno-unused-variable",
                "-Wno-nullability-completeness",
                "-Wno-sign-compare",
                "-Wno-logical-op-parentheses",
                "-Wno-varargs",
                "-Wno-unused-private-field",
                "-Wno-c99-extensions",
                "-Wno-nested-anon-types",
                "-Wno-gnu-anonymous-struct",
                "-Wno-nullability-extension",
                "-Wno-extra-semi",
            ]
            if debug_mode:
                debug_flags = [
                    "-g",
                    "-fno-omit-frame-pointer",
                    "-O0",
                    "-ggdb",
                    "-UNDEBUG",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    # Cython is not deprecation-proof
                    "-Wno-deprecated-declarations",
                ]
                # If DEBUG is set, ensure CFLAGS has -O0 (override any -O[0-3])
                cflags = os.environ.get("CFLAGS", "")
                # Remove any -O[0-3] flags
                cflags = COMPILER_OPTIMIZATION_LEVEL.sub("", cflags)
                # Add -O0 at the beginning (or just set if empty)
                cflags = "-O0 " + cflags.strip()
                os.environ["CFLAGS"] = cflags.strip()
            return (
                ["-mmacosx-version-min=10.9"]
                + debug_flags
                + ignore_warnings
                + simd_flags
            )
        case _:
            # Default: no extra flags
            return simd_flags


def link_args(debug_mode=False):
    """Return platform-specific linker arguments."""
    debug_flags = []
    match OSTYPE:
        case "Darwin":
            # Use @loader_path to encode a relative rpath.  The placeholder
            # ``{rpath}`` will be substituted at runtime below.
            rpath = os.path.join("lib")
            if debug_mode:
                debug_flags = ["-g"]
            return [
                "-Wl,-headerpad_max_install_names,-rpath,@loader_path/" + rpath
            ] + debug_flags
        case "Linux":
            rpath = os.path.join("lib")
            if debug_mode:
                debug_flags = ["-g"]
            return ["-Wl,-rpath,$ORIGIN/" + rpath] + debug_flags
        case "Windows":
            if debug_mode:
                return ["/DEBUG"]
            return []
        case _:
            return []


def using_ida_sdk(include_dirs, library_dirs):
    IDA_SDK = pathlib.Path(os.environ.get("IDA_SDK", "/opt/ida/9/sdk"))
    if not IDA_SDK.exists():
        raise FileNotFoundError(f"IDA SDK not found at {IDA_SDK}")
    include_dirs.append(IDA_SDK / "include")
    library_dirs.append(IDA_SDK / "lib")

    match OSTYPE:
        case "Windows":
            library_dirs.append(IDA_SDK / "lib" / "x64_win_vc_64")
            library_dirs.append(IDA_SDK / "lib" / "x64_win_qt")
        case "Darwin":
            if LIBRARY == "arm64" or LIBRARY == "aarch64":
                library_dirs.append(IDA_SDK / "lib" / "arm64_mac_clang_64")
            else:
                library_dirs.append(IDA_SDK / "lib" / "x64_mac_clang_64")
        case "Linux":
            library_dirs.append(IDA_SDK / "lib" / "x64_linux_gcc_64")
        case _:
            pass


def ext_modules(with_ida_sdk=False, debug_mode=False):
    include_dirs = [
        pathlib.Path(__file__).parent / "include",
    ]
    library_dirs = []
    libraries = []
    if with_ida_sdk:
        using_ida_sdk(include_dirs, library_dirs)

    include_paths = [str(path) for path in include_dirs]
    library_paths = [str(path) for path in library_dirs]

    modules = []
    macros: list[tuple[str, str | None]] = [("__EA64__", "1")] if x64 else []

    if debug_mode:
        # Profiling and coverage require special macro directives
        macros.append(("CYTHON_TRACE", "1"))
        macros.append(("CYTHON_CLINE_IN_TRACEBACK", "1"))
        macros.append(("CYTHON_CLINE_IN_TRACEBACK_RUNTIME", "1"))
        if sys.version_info >= (3, 13):
            macros.append(("CYTHON_USE_SYS_MONITORING", "1"))
        if sys.version_info < (3, 12):
            macros.append(("CYTHON_PROFILE", "1"))

    partialed_cythonize = functools.partial(
        cythonize,
        compiler_directives={
            "language_level": "3",
            "binding": True,
            "embedsignature": True,
            "boundscheck": False,
            "wraparound": False,
            # these are enabled for debugging only
            "profile": debug_mode,
            "linetrace": debug_mode,
        },
        annotate=debug_mode,
        gdb_debug=debug_mode,
    )
    modules += partialed_cythonize(
        Extension(
            "*",
            ["src/**/*.pyx"],
            language="c++",
            include_dirs=include_paths,
            library_dirs=library_paths,
            libraries=libraries,
            extra_compile_args=compile_args(debug_mode),
            extra_link_args=link_args(debug_mode),
            define_macros=macros,
        )
    )
    # modules += partialed_cythonize(["src/**/*.py"])
    return modules


DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"
setup(
    name="ida-sigmaker",
    version="1.3.0",
    description="IDA Pro plugin to generate signatures for code",
    ext_modules=ext_modules(with_ida_sdk=False, debug_mode=DEBUG_MODE),
    packages=find_packages(include=("sigmaker*",)),
    package_dir={"": "src"},
    python_requires=">=3.10",
    zip_safe=False,
)
