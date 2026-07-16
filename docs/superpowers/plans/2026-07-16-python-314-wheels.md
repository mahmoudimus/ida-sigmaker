# Python 3.14 Wheels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish SigMaker's native speedup wheels for CPython 3.14 on every existing release platform.

**Architecture:** Keep the explicit cibuildwheel version selector and extend it through CPython 3.14. Upgrade cibuildwheel to a release that uses final Python 3.14, then guard the workflow and PyPI metadata with an IDA-independent packaging test.

**Tech Stack:** GitHub Actions, cibuildwheel 3.4.1, setuptools project metadata, Python 3.14, unittest.

## Global Constraints

- Do not modify SigMaker runtime or SIMD implementation code.
- Do not change the IDA test matrix or supported IDA versions.
- Keep the wheel selector explicit through `cp314-*`.
- Keep HCLI manifest and release-pipeline restructuring out of this branch.

---

### Task 1: Guard the Python 3.14 packaging contract

**Files:**
- Create: `tests/unit_test_packaging.py`
- Modify: `.github/workflows/deploy.yml:42-45`
- Modify: `pyproject.toml:24-30`

**Interfaces:**
- Consumes: the `CIBW_BUILD` environment value and `[project].classifiers` metadata.
- Produces: CPython 3.10 through 3.14 wheel selection using cibuildwheel 3.4.1 and a Python 3.14 PyPI classifier.

- [ ] **Step 1: Write the failing packaging tests**

```python
import pathlib
import re
import tomllib
import unittest


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
```

- [ ] **Step 2: Run the tests and verify they fail for the missing contract**

Run: `python3 -m unittest tests.unit_test_packaging -v`

Expected: both tests fail because the workflow uses cibuildwheel 3.1.4, omits `cp314-*`, and the classifier is absent.

- [ ] **Step 3: Update the release workflow and package metadata**

Change the action and selector to:

```yaml
- name: Build wheels
  uses: pypa/cibuildwheel@v3.4.1
  env:
      CIBW_BUILD: "cp310-* cp311-* cp312-* cp313-* cp314-*"
```

Add this classifier to `[project].classifiers`:

```toml
"Programming Language :: Python :: 3.14",
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `python3 -m unittest tests.unit_test_packaging -v`

Expected: `Ran 2 tests` and `OK`.

- [ ] **Step 5: Verify cibuildwheel selects CPython 3.10 through 3.14**

Run:

```bash
CIBW_BUILD="cp310-* cp311-* cp312-* cp313-* cp314-*" \
  uvx --from cibuildwheel==3.4.1 cibuildwheel \
  --platform macos --print-build-identifiers
```

Expected: the selected identifiers include `cp310`, `cp311`, `cp312`, `cp313`, and `cp314` for the current macOS architecture.

- [ ] **Step 6: Build and inspect the native CPython 3.14 wheel**

Run:

```bash
WHEELHOUSE=$(mktemp -d)
uv run --python 3.14 --with build python -m build --wheel --outdir "$WHEELHOUSE"
python3 -m zipfile -l "$WHEELHOUSE"/sigmaker-1.12.0-cp314-*.whl
```

Expected: the build exits zero, the filename contains `cp314`, and the archive contains `sigmaker/_speedups/simd_scan` with a native extension suffix.

- [ ] **Step 7: Run final static verification**

Run:

```bash
python3 -m unittest tests.unit_test_packaging -v
python3 -m compileall -q tests
git diff --check
```

Expected: tests report `OK`; compileall and diff checks exit zero.

- [ ] **Step 8: Commit the implementation**

```bash
git add .github/workflows/deploy.yml pyproject.toml tests/unit_test_packaging.py
git commit -m "build: publish Python 3.14 wheels"
```
