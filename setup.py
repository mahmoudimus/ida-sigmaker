"""Build script for the IDA Pro sigmaker Cython module.

This ``setup.py`` detects the host platform and architecture in order to
select appropriate compilation and linkage flags.
The build expects the IDA SDK to be installed and accessible via the
environment variable ``IDA_SDK``.
"""

import functools
import os
import pathlib
import platform
import re
import sys

from Cython.Build import cythonize
from setuptools import Extension, setup

# ---------------------------------------------------------------------------
# Platform detection
# Use the host system and architecture to adjust compiler options.
OSTYPE = platform.system()
ARCH = (platform.processor() or platform.machine()).lower()
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


def determine_simd_flags() -> list[str]:
    # SIMD selection occurs at runtime inside the extension; keep compile flags baseline.
    return []


def compile_args(debug_mode=False, sdk_version: int = 0):
    """Return platform-specific compilation arguments."""
    debug_flags = []
    simd_flags = determine_simd_flags()
    match OSTYPE:
        case "Windows":
            standard_flags = ["/std:c++17"] if int(sdk_version) >= 940 else []
            if debug_mode:
                debug_flags = ["/Z7", "/Od"]
            # For MSVC: `/TP` tells the compiler to treat sources as C++
            # files and `/EHa` enables asynchronous exception handling.
            #
            # Qt 6 headers additionally require conformance mode. Without
            # `/Zc:__cplusplus` MSVC reports __cplusplus as 199711L whatever
            # `/std:` says and qcompilerdetection.h raises C1189; without
            # `/permissive-` ADL resolves Qt's comparesEqual/compareThreeWay
            # ambiguously (C2666) and an incomplete QString trips C2139.
            qt_flags = ["/Zc:__cplusplus", "/permissive-"]
            return (
                ["/TP", "/EHa"]
                + standard_flags
                + qt_flags
                + debug_flags
                + simd_flags
            )
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


def _sdk_include_dir(sdk_path: pathlib.Path) -> pathlib.Path:
    """Return the include directory for legacy and GitHub SDK layouts."""
    if (sdk_path / "src" / "include").exists():
        return sdk_path / "src" / "include"
    return sdk_path / "include"


def _sdk_lib_dir(sdk_path: pathlib.Path, *subdirectories: str) -> pathlib.Path:
    """Return a library directory for legacy and GitHub SDK layouts."""
    root = (
        sdk_path / "src" / "lib"
        if (sdk_path / "src" / "lib").exists()
        else sdk_path / "lib"
    )
    return root.joinpath(*subdirectories)


def _windows_sdk_lib_subdir(
    sdk_version: int,
    library: str = LIBRARY,
    is_64bit: bool = x64,
) -> str:
    """Return the Windows import-library directory for an IDA SDK version.

    IDA 9.4 introduced native Windows ARM64 support and renamed the x64
    import-library directory. Older SDKs use ``x64_win_vc_64``; IDA 9.4+
    uses ``x64_win_64`` or ``arm64_win_64`` according to the build ABI.
    """
    normalized_library = str(library).lower()
    is_arm64 = normalized_library in {"arm64", "aarch64"}

    if is_arm64 and int(sdk_version) < 940:
        raise ValueError("ARM64 Windows SDK libraries require IDA 9.4 or newer")

    if int(sdk_version) >= 940:
        if is_arm64:
            return "arm64_win_64"
        return "x64_win_64" if is_64bit else "x64_win_32"

    return "x64_win_vc_64" if is_64bit else "x64_win_32"


def get_ida_sdk_version(sdk_path: pathlib.Path) -> int:
    """Read ``IDA_SDK_VERSION`` from the SDK's ``pro.h`` when available."""
    pro_h = _sdk_include_dir(sdk_path) / "pro.h"
    if pro_h.exists():
        for line in pro_h.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("#define IDA_SDK_VERSION"):
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2].isdigit():
                    return int(parts[2])
    return 0


# IDA SDK 9.4 stopped shipping lib/x64_win_qt, the prebuilt namespaced Qt6
# import libraries. ida-qt-libs republishes them, built with QT_NAMESPACE=QT
# and symbol-for-symbol identical to the last set Hex-Rays shipped.
IDA_QT_REPO = "mahmoudimus/ida-qt-libs"

# IDA SDK version -> matching release. Each IDA release pins a specific Qt
# version, so the artifact is chosen by SDK rather than hardcoded. 9.3 and 9.4
# both ship Qt 6.8.2 and their import libraries are currently byte-identical,
# but that is a coincidence of those two releases, not a rule.
IDA_QT_TAGS = {
    930: "ida-9.3-qt-6.8.2-win64",
    940: "ida-9.4.0-qt-6.8.2-win64",
}


def _ida_qt_tag(sdk_version: int) -> str:
    """Return the ida-qt-libs release matching *sdk_version*."""
    known = IDA_QT_TAGS.get(int(sdk_version))
    if known:
        return known

    newest = IDA_QT_TAGS[max(IDA_QT_TAGS)]
    print(
        f"warning: no ida-qt-libs release recorded for SDK {sdk_version}; "
        f"falling back to {newest}. If that IDA ships a different Qt version "
        "the ABI will not match - set IDA_QT explicitly, or see "
        f"https://github.com/{IDA_QT_REPO}/releases",
        file=sys.stderr,
    )
    return newest


def _download_ida_qt(dest: pathlib.Path, tag: str) -> pathlib.Path:
    """Download and checksum-verify an ida-qt-libs release into *dest*."""
    import hashlib
    import urllib.request
    import zipfile

    base = f"https://github.com/{IDA_QT_REPO}/releases/download/{tag}"
    dest.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(f"{base}/SHA256SUMS") as response:
        checksums = {
            parts[1]: parts[0]
            for parts in (line.split() for line in response.read().decode().splitlines())
            if len(parts) == 2
        }

    archive = dest / f"{tag}.zip"
    if not archive.is_file():
        print(f"downloading {tag}...", file=sys.stderr)
        urllib.request.urlretrieve(f"{base}/{tag}.zip", archive)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    expected = checksums.get(archive.name)
    if digest != expected:
        archive.unlink(missing_ok=True)
        raise RuntimeError(
            f"checksum mismatch for {archive.name}: expected {expected}, got {digest}"
        )

    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(dest)
    return dest / tag


def _ida_qt_dir(sdk_path: pathlib.Path, sdk_version: int) -> pathlib.Path | None:
    """Return a directory containing Qt6*.lib, or None if Qt is unavailable.

    Resolution order:
      1. ``IDA_QT`` - an extracted ida-qt-libs release, or any directory with
         namespaced Qt import libraries.
      2. The SDK's own ``lib/x64_win_qt``, which exists through SDK 9.3.
      3. A downloaded ida-qt-libs release, unless ``IDA_QT_NO_DOWNLOAD`` is set.
    """
    override = os.environ.get("IDA_QT")
    if override:
        candidate = pathlib.Path(override)
        # Accept either the release root or its lib/ directory.
        for path in (candidate / "lib", candidate):
            if path.is_dir() and any(path.glob("Qt6*.lib")):
                return path
        raise FileNotFoundError(f"IDA_QT={override} contains no Qt6*.lib")

    bundled = _sdk_lib_dir(sdk_path, "x64_win_qt")
    if bundled.is_dir() and any(bundled.glob("Qt*.lib")):
        return bundled

    if os.environ.get("IDA_QT_NO_DOWNLOAD"):
        return None

    tag = _ida_qt_tag(sdk_version)
    cache = pathlib.Path(__file__).parent / ".ida-qt"
    extracted = cache / tag
    if not (extracted / "lib").is_dir():
        extracted = _download_ida_qt(cache, tag)
    return extracted / "lib"


def using_ida_sdk(include_dirs, library_dirs):
    IDA_SDK = pathlib.Path(os.environ.get("IDA_SDK", "/opt/ida/9/sdk"))
    if not IDA_SDK.exists():
        raise FileNotFoundError(f"IDA SDK not found at {IDA_SDK}")
    sdk_version = get_ida_sdk_version(IDA_SDK)
    include_dirs.append(_sdk_include_dir(IDA_SDK))
    library_dirs.append(_sdk_lib_dir(IDA_SDK))

    match OSTYPE:
        case "Windows":
            library_dirs.append(
                _sdk_lib_dir(
                    IDA_SDK,
                    _windows_sdk_lib_subdir(
                        sdk_version, library=LIBRARY, is_64bit=x64
                    ),
                )
            )
            qt_dir = _ida_qt_dir(IDA_SDK, sdk_version)
            if qt_dir is not None:
                library_dirs.append(qt_dir)
                # An ida-qt-libs release carries headers alongside lib/; the
                # SDK's own x64_win_qt does not.
                qt_include = qt_dir.parent / "include"
                if qt_include.is_dir():
                    include_dirs.append(qt_include)
        case "Darwin":
            if LIBRARY == "arm64" or LIBRARY == "aarch64":
                library_dirs.append(_sdk_lib_dir(IDA_SDK, "arm64_mac_clang_64"))
            else:
                library_dirs.append(_sdk_lib_dir(IDA_SDK, "x64_mac_clang_64"))
        case "Linux":
            library_dirs.append(_sdk_lib_dir(IDA_SDK, "x64_linux_gcc_64"))
        case _:
            pass
    return sdk_version


def ext_modules(with_ida_sdk=False, debug_mode=False):
    include_dirs = [
        pathlib.Path(__file__).parent / "src" / "include",
    ]
    library_dirs = []
    libraries = []
    sdk_version = 0
    if with_ida_sdk:
        sdk_version = using_ida_sdk(include_dirs, library_dirs)

    include_paths = [str(path) for path in include_dirs]
    library_paths = [str(path) for path in library_dirs]
    print(include_paths)
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
            "sigmaker._speedups.simd_scan",
            ["src/**/*.pyx"],
            language="c++",
            include_dirs=include_paths,
            library_dirs=library_paths,
            libraries=libraries,
            extra_compile_args=compile_args(debug_mode, sdk_version),
            extra_link_args=link_args(debug_mode),
            define_macros=macros,
        )
    )
    # modules += partialed_cythonize(["src/**/*.py"])
    return modules


DEBUG_MODE = os.environ.get("DEBUG", "0") == "1"
setup(
    name="ida-sigmaker",
    description="IDA Pro plugin to generate signatures for code",
    ext_modules=ext_modules(with_ida_sdk=False, debug_mode=DEBUG_MODE),
)
