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

from Cython.Build import cythonize
from setuptools import Extension, find_packages, setup

# ---------------------------------------------------------------------------
# Platform detection
# Use the host system and architecture to adjust compiler options.
OSTYPE = platform.system()
ARCH = platform.processor() or platform.machine()
x64 = platform.architecture()[0] == "64bit"
COMPILER_OPTIMIZATION_LEVEL = re.compile(r"-O[0-3]\b")
DEBUG_MODE = os.environ.get("DEBUG") == "1"

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


def compile_args():
    """Return platform-specific compilation arguments."""
    match OSTYPE:
        case "Windows":
            if DEBUG_MODE:
                debug_flags = ["/Z7", "/Od"]
            # For MSVC: `/TP` tells the compiler to treat sources as C++
            # files and `/EHa` enables asynchronous exception handling.
            return ["/TP", "/EHa"] + debug_flags
        case "Linux":
            # Suppress a few warnings that are often triggered by IDA
            # headers.  These are the same warnings ignored in amplpy's
            # build script【561865107149785†L125-L153】.
            if DEBUG_MODE:
                debug_flags = ["-g", "-O0", "-Wall", "-Wextra", "-Wpedantic"]
            return [
                "-Wno-stringop-truncation",
                "-Wno-catch-value",
                "-Wno-unused-variable",
            ] + debug_flags
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
            debug_flags = []
            if DEBUG_MODE:
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
            return ["-mmacosx-version-min=10.9"] + debug_flags + ignore_warnings
        case _:
            # Default: no extra flags
            return []


def link_args():
    """Return platform-specific linker arguments."""
    match OSTYPE:
        case "Darwin":
            # Use @loader_path to encode a relative rpath.  The placeholder
            # ``{rpath}`` will be substituted at runtime below.
            rpath = os.path.join("lib")
            if DEBUG_MODE:
                debug_flags = ["-g"]
            return [
                "-Wl,-headerpad_max_install_names,-rpath,@loader_path/" + rpath
            ] + debug_flags
        case "Linux":
            rpath = os.path.join("lib")
            if DEBUG_MODE:
                debug_flags = ["-g"]
            return ["-Wl,-rpath,$ORIGIN/" + rpath] + debug_flags
        case "Windows":
            if DEBUG_MODE:
                return ["/DEBUG"]
            return []
        case _:
            return []


IDA_SDK = pathlib.Path(os.environ.get("IDA_SDK", "/opt/ida/9/sdk"))
if not IDA_SDK.exists():
    raise FileNotFoundError(f"IDA SDK not found at {IDA_SDK}")

include_dirs = [
    IDA_SDK / "include",
    pathlib.Path(__file__).parent / "include",
]
library_dirs = [
    IDA_SDK / "lib",
]

libraries = []
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


def ext_modules():
    include_paths = [str(path) for path in include_dirs]
    library_paths = [str(path) for path in library_dirs]

    modules = []
    macros: list[tuple[str, str | None]] = [("__EA64__", "1")] if x64 else []
    if DEBUG_MODE:
        # Profiling requires special macro directives
        macros.append(("CYTHON_TRACE", "1"))
        macros.append(("CYTHON_CLINE_IN_TRACEBACK", "1"))
        macros.append(("CYTHON_CLINE_IN_TRACEBACK_RUNTIME", "1"))
        macros.append(("CYTHON_USE_SYS_MONITORING", "1"))

    partialed_cythonize = functools.partial(
        cythonize,
        compiler_directives={
            "language_level": "3",
            "binding": True,
            "embedsignature": True,
            "boundscheck": False,
            "wraparound": False,
            # these are enabled for debugging only
            "profile": DEBUG_MODE,
            "linetrace": DEBUG_MODE,
        },
        annotate=DEBUG_MODE,
        gdb_debug=DEBUG_MODE,
    )
    modules += partialed_cythonize(
        Extension(
            "*",
            ["src/sigmaker/**/*.pyx"],
            language="c++",
            include_dirs=include_paths,
            library_dirs=library_paths,
            libraries=libraries,
            extra_compile_args=compile_args(),
            extra_link_args=link_args(),
            define_macros=macros,
        )
    )

    return modules


setup(
    name="ida-sigmaker",
    version="0.1.0",
    description="IDA Pro plugin to generate signatures for code",
    ext_modules=ext_modules(),
    packages=find_packages(include=("sigmaker*",)),
    package_dir={"": "src"},
    python_requires=">=3.10",
    zip_safe=False,
)
