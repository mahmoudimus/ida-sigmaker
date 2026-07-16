# HCLI Publishing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish SigMaker through Hex-Rays' HCLI plugin manager using each GitHub release's source archive.

**Architecture:** Keep the root `ida-plugin.json` and existing source-tree entry point, then add the metadata HCLI requires. Treat GitHub release publication as the single deployment boundary: it triggers PyPI builds, while normal `main` test runs cannot start release work.

**Tech Stack:** HCLI 0.18.5, GitHub Actions, JSON, Python `unittest`.

## Global Constraints

- Keep `src/sigmaker/__init__.py` as the plugin entry point.
- Do not add an entry-point shim or modify SigMaker runtime code.
- Keep `[project].dependencies` empty.
- Pin HCLI's `pythonDependencies` entry to the manifest version.
- Do not bump the version or publish a release in this pull request.

---

### Task 1: Guard the HCLI manifest contract

**Files:**
- Modify: `tests/unit_test_packaging.py`
- Modify: `ida-plugin.json`

**Interfaces:**
- Consumes: `src/sigmaker/__init__.py::__version__` and the root manifest.
- Produces: HCLI-compatible metadata with a matching `sigmaker==VERSION` dependency.

- [ ] **Step 1: Add failing tests for the required metadata**

Add tests that load `ida-plugin.json` and assert:

```python
self.assertEqual(manifest["$schema"], HCLI_SCHEMA)
self.assertEqual(plugin["entryPoint"], "src/sigmaker/__init__.py")
self.assertTrue((ROOT / plugin["entryPoint"]).is_file())
self.assertEqual(plugin["urls"]["repository"], REPOSITORY_URL)
self.assertEqual(plugin["pythonDependencies"], [f"sigmaker=={plugin['version']}"])
self.assertEqual(project["dependencies"], [])
```

Also require author metadata, the MIT license, keywords, and explicit IDA 9.0+
versions accepted by the current HCLI schema.

- [ ] **Step 2: Run the focused test and verify the new assertions fail**

Run: `python3 -m unittest tests.unit_test_packaging -v`

Expected: failures for the missing HCLI schema, repository URL, author,
dependency, and array-form IDA versions.

- [ ] **Step 3: Update `ida-plugin.json`**

Add the HCLI schema URL and required metadata while retaining:

```json
"entryPoint": "src/sigmaker/__init__.py"
```

Set:

```json
"pythonDependencies": ["sigmaker==1.12.0"]
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `python3 -m unittest tests.unit_test_packaging -v`

Expected: all packaging tests report `OK`.

### Task 2: Make release publication the only automatic deployment boundary

**Files:**
- Modify: `tests/unit_test_packaging.py`
- Modify: `.github/workflows/release.yml`
- Modify: `.github/workflows/deploy.yml`

**Interfaces:**
- Consumes: tag pushes, manual workflow dispatches, and GitHub `release.published` events.
- Produces: GitHub releases from tags and PyPI builds only from published releases or manual dispatch.

- [ ] **Step 1: Add failing workflow-boundary tests**

Assert that `release.yml` has no `workflow_run` trigger, `deploy.yml` has no
`workflow_run` trigger, and the deploy workflow retains `release: types:
[published]` plus `workflow_dispatch`.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python3 -m unittest tests.unit_test_packaging -v`

Expected: the workflow-boundary tests fail because both workflows currently
contain `workflow_run`.

- [ ] **Step 3: Simplify the workflows**

Remove `release-from-workflow-run` and the `workflow_run` trigger from
`release.yml`. Keep one tag/manual release job. Remove the `workflow_run`
trigger and condition branch from `deploy.yml`, retaining release publication
and manual dispatch.

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `python3 -m unittest tests.unit_test_packaging -v`

Expected: all packaging tests report `OK`.

### Task 3: Document and validate HCLI installation

**Files:**
- Modify: `README.md`
- Modify: `.github/workflows/python.yml`
- Test: `tests/unit_test_packaging.py`

**Interfaces:**
- Consumes: HCLI 0.18.5 and GitHub-style source archives.
- Produces: repeatable HCLI linting and accurate installation guidance.

- [ ] **Step 1: Add a CI HCLI lint step**

Download the pinned HCLI 0.18.5 Linux executable in the test workflow, verify
its SHA-256 digest, mark it executable, and run:

```bash
/tmp/hcli plugin lint .
```

- [ ] **Step 2: Update the README**

State that HCLI installs the matching `sigmaker` wheel and SIMD extension
automatically. Correct `$IDAUSR` examples to the documented Windows, macOS,
and Linux paths.

- [ ] **Step 3: Validate the checkout and source archive locally**

Run:

```bash
/tmp/hcli plugin lint .
git archive --format=zip --prefix=ida-sigmaker-1.12.0/ -o /tmp/ida-sigmaker-1.12.0.zip HEAD
/tmp/hcli plugin lint /tmp/ida-sigmaker-1.12.0.zip
```

Expected: both lint commands succeed and identify `SigMaker` version `1.12.0`.

- [ ] **Step 4: Run final verification**

Run:

```bash
python3 -m unittest tests.unit_test_packaging -v
python3 -m compileall -q tests
git diff --check
```

Expected: tests report `OK`; compileall and diff checks exit zero.

- [ ] **Step 5: Commit and publish the pull request**

Stage only the design, plan, manifest, workflows, README, and packaging tests;
commit them, push `diff/hcli-publishing`, and open a ready pull request against
`main`.
