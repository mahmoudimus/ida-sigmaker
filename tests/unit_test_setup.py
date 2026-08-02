import os
import pathlib
import runpy
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load_setup_namespace():
    """Load setup.py without running Cython or the real setuptools setup."""
    with mock.patch("Cython.Build.cythonize", return_value=[]), mock.patch(
        "setuptools.setup", return_value=None
    ):
        return runpy.run_path(str(ROOT / "setup.py"), run_name="sigmaker_setup_test")


class TestIDASDKLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup_namespace = _load_setup_namespace()

    def test_windows_sdk_subdir_before_94_uses_legacy_x64_name(self):
        select = self.setup_namespace["_windows_sdk_lib_subdir"]

        self.assertEqual(
            select(930, library="amd64", is_64bit=True), "x64_win_vc_64"
        )

    def test_windows_sdk_subdir_94_uses_new_x64_name(self):
        select = self.setup_namespace["_windows_sdk_lib_subdir"]

        self.assertEqual(select(940, library="amd64", is_64bit=True), "x64_win_64")

    def test_windows_sdk_subdir_94_uses_arm64_name_case_insensitively(self):
        select = self.setup_namespace["_windows_sdk_lib_subdir"]

        self.assertEqual(
            select(940, library="ARM64", is_64bit=True), "arm64_win_64"
        )

    def test_windows_sdk_subdir_rejects_arm64_before_94(self):
        select = self.setup_namespace["_windows_sdk_lib_subdir"]

        with self.assertRaisesRegex(ValueError, "IDA 9.4 or newer"):
            select(930, library="arm64", is_64bit=True)

    def test_sdk_helpers_support_src_layout_and_parse_version(self):
        sdk_include_dir = self.setup_namespace["_sdk_include_dir"]
        sdk_lib_dir = self.setup_namespace["_sdk_lib_dir"]
        get_version = self.setup_namespace["get_ida_sdk_version"]

        with tempfile.TemporaryDirectory() as directory:
            sdk = pathlib.Path(directory)
            include = sdk / "src" / "include"
            include.mkdir(parents=True)
            (sdk / "src" / "lib").mkdir()
            (include / "pro.h").write_text(
                "#define IDA_SDK_VERSION 940\n", encoding="utf-8"
            )

            self.assertEqual(sdk_include_dir(sdk), include)
            self.assertEqual(sdk_lib_dir(sdk), sdk / "src" / "lib")
            self.assertEqual(
                sdk_lib_dir(sdk, "x64_win_64"), sdk / "src" / "lib" / "x64_win_64"
            )
            self.assertEqual(get_version(sdk), 940)

    def test_using_ida_sdk_selects_94_windows_directory(self):
        using_ida_sdk = self.setup_namespace["using_ida_sdk"]

        with tempfile.TemporaryDirectory() as directory:
            sdk = pathlib.Path(directory)
            include = sdk / "src" / "include"
            lib = sdk / "src" / "lib"
            include.mkdir(parents=True)
            lib.mkdir()
            (include / "pro.h").write_text(
                "#define IDA_SDK_VERSION 940\n", encoding="utf-8"
            )

            setup_globals = using_ida_sdk.__globals__
            original_globals = {
                name: setup_globals[name] for name in ("OSTYPE", "LIBRARY", "x64")
            }
            setup_globals.update(OSTYPE="Windows", LIBRARY="amd64", x64=True)
            include_dirs = []
            library_dirs = []
            try:
                with mock.patch.dict(os.environ, {"IDA_SDK": str(sdk)}, clear=False):
                    sdk_version = using_ida_sdk(include_dirs, library_dirs)
            finally:
                setup_globals.update(original_globals)

            self.assertEqual(sdk_version, 940)
            self.assertIn(include, include_dirs)
            self.assertIn(lib / "x64_win_64", library_dirs)
            self.assertIn(lib / "x64_win_qt", library_dirs)

    def test_windows_sdk_version_enables_cxx17_compile_flag(self):
        compile_args = self.setup_namespace["compile_args"]
        setup_globals = compile_args.__globals__
        original_ostype = setup_globals["OSTYPE"]
        setup_globals["OSTYPE"] = "Windows"
        try:
            self.assertIn("/std:c++17", compile_args(sdk_version=940))
        finally:
            setup_globals["OSTYPE"] = original_ostype


if __name__ == "__main__":
    unittest.main()
