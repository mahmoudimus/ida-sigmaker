import pathlib
import re
import unittest

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestWheelBuildConfiguration(unittest.TestCase):
    def test_release_workflow_builds_supported_cpython_wheels(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy.yml").read_text()
        self.assertIn("pypa/cibuildwheel@v3.4.1", workflow)
        selection = re.search(r'CIBW_BUILD: "([^"]+)"', workflow)
        self.assertIsNotNone(selection)
        self.assertEqual(
            selection.group(1).split(),
            ["cp310-*", "cp311-*", "cp312-*", "cp313-*", "cp314-*"],
        )

    def test_project_advertises_python_314(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        self.assertIn("Programming Language :: Python :: 3.14", project["classifiers"])
