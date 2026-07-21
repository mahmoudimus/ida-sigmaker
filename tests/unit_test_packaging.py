import importlib.util
import json
import pathlib
import re
import unittest

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
HCLI_SCHEMA = "https://hcli.docs.hex-rays.com/schemas/ida-plugin.json"
HCLI_VERSION = "0.18.5"
REPOSITORY_URL = "https://github.com/mahmoudimus/ida-sigmaker"
SUPPORTED_IDA_VERSIONS = [
    "9.0",
    "9.0sp1",
    "9.1",
    "9.2",
    "9.3",
    "9.4",
    "10.0",
]


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


class TestHCLIPackaging(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((ROOT / "ida-plugin.json").read_text())
        self.plugin = self.manifest["plugin"]

    def test_manifest_has_hcli_metadata(self):
        self.assertEqual(self.manifest["$schema"], HCLI_SCHEMA)
        self.assertEqual(
            self.plugin["entryPoint"], "src/sigmaker/__init__.py"
        )
        self.assertTrue((ROOT / self.plugin["entryPoint"]).is_file())
        self.assertEqual(self.plugin["urls"]["repository"], REPOSITORY_URL)
        self.assertTrue(self.plugin["authors"])
        self.assertTrue(self.plugin["authors"][0]["email"])
        self.assertEqual(self.plugin["license"], "MIT")
        self.assertTrue(self.plugin["keywords"])
        self.assertEqual(self.plugin["idaVersions"], SUPPORTED_IDA_VERSIONS)

    def test_hcli_installs_the_matching_speedup_wheel(self):
        self.assertEqual(
            self.plugin["pythonDependencies"],
            [f"sigmaker=={self.plugin['version']}"],
        )

    def test_direct_install_remains_dependency_free(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        self.assertEqual(project["dependencies"], [])

    def test_release_calls_the_pypi_workflow_directly(self):
        release_workflow = (ROOT / ".github/workflows/release.yml").read_text()
        deploy_workflow = (ROOT / ".github/workflows/deploy.yml").read_text()

        self.assertNotIn("workflow_run:", release_workflow)
        self.assertNotIn("workflow_run:", deploy_workflow)
        self.assertIn("workflow_call:", deploy_workflow)
        self.assertRegex(deploy_workflow, r"release:\s+types:\s+- published")
        self.assertRegex(
            release_workflow,
            r"publish-to-pypi:\s+needs: release\s+uses: "
            r"\./\.github/workflows/deploy\.yml\s+with:\s+publish: true",
        )

    def test_manual_pypi_publish_requires_explicit_confirmation(self):
        deploy_workflow = (ROOT / ".github/workflows/deploy.yml").read_text()

        self.assertRegex(
            deploy_workflow,
            r"workflow_dispatch:\s+inputs:\s+publish:\s+"
            r"description:.*\s+required: true\s+type: boolean\s+default: false",
        )
        self.assertIn("inputs.publish == true", deploy_workflow)

    def test_ci_lints_the_plugin_with_pinned_hcli_inputs(self):
        workflow = (ROOT / ".github/workflows/python.yml").read_text()
        self.assertIn(
            f"HexRaysSA/ida-hcli/releases/download/v{HCLI_VERSION}/"
            f"hcli-linux-x86_64-{HCLI_VERSION}",
            workflow,
        )
        self.assertIn(
            "b35eb351ce9e706709212604f937118643eee861bf4411bc4cac94217245b277",
            workflow,
        )
        self.assertIn(
            "3cee9691f72459c5ac75b028c827016e93e58923/plugin-repository.json",
            workflow,
        )
        self.assertIn(
            "plugin --repo /tmp/plugin-repository-v1.json lint .", workflow
        )

    def test_version_sync_updates_the_hcli_dependency(self):
        script = ROOT / "tools" / "sync_plugin_version.py"
        spec = importlib.util.spec_from_file_location("sync_plugin_version", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        sync_plugin_version = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sync_plugin_version)

        manifest = json.dumps(
            {
                "plugin": {
                    "version": "1.0.0",
                    "pythonDependencies": ["sigmaker==1.0.0"],
                }
            }
        )
        updated = json.loads(sync_plugin_version.sync_manifest(manifest, "2.0.0"))

        self.assertEqual(updated["plugin"]["version"], "2.0.0")
        self.assertEqual(
            updated["plugin"]["pythonDependencies"], ["sigmaker==2.0.0"]
        )


class TestCoverageConfiguration(unittest.TestCase):
    def test_unit_tests_use_one_process_level_collector(self):
        unit_tests = (ROOT / "tests" / "unit_test_sigmaker.py").read_text()

        self.assertIn("class CoveredUnitTest(unittest.TestCase):", unit_tests)
        self.assertNotIn("class CoveredUnitTest(CoverageTestCase):", unit_tests)

    def test_integration_collectors_write_unique_data_files(self):
        coverage_base = (ROOT / "tests" / "coveredtestcase.py").read_text()

        self.assertIn("data_suffix=True", coverage_base)

    def test_ci_combines_unit_and_integration_coverage(self):
        workflow = (ROOT / ".github" / "workflows" / "python.yml").read_text()

        self.assertIn(
            "coverage run --branch --source=src --data-file=.coverage.unit",
            workflow,
        )
        self.assertIn(
            "-m unittest tests.unit_test_sigmaker tests.unit_test_packaging -v",
            workflow,
        )
        self.assertIn(
            "python -m unittest tests.integration_test_sigmaker -v",
            workflow,
        )
        self.assertIn(
            "coverage combine .coverage.unit .coverage.integration.*",
            workflow,
        )
        self.assertIn("coverage report -m --fail-under=90", workflow)

    def test_ci_collects_pure_python_coverage_without_building_speedups(self):
        workflow = (ROOT / ".github" / "workflows" / "python.yml").read_text()
        coverage_config = (ROOT / ".coveragerc").read_text()
        compose = (ROOT / "docker-compose.yml").read_text()

        self.assertIn("pip install coverage tomli", workflow)
        self.assertNotIn("pip install -e .[ci]", workflow)
        self.assertNotIn("plugins = Cython.Coverage", coverage_config)
        self.assertIn(
            "PYTHONPATH=/work/src:/app/ida/python:/work",
            compose,
        )
