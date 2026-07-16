# HCLI Publishing Design

## Goal

Make SigMaker discoverable and installable through Hex-Rays' HCLI plugin
manager using the repository's normal GitHub releases.

## Packaging

- Keep `ida-plugin.json` at the repository root so GitHub's generated source
  archive is a valid HCLI plugin archive.
- Keep `src/sigmaker/__init__.py` as the IDAPython entry point. Do not add an
  entry-point shim or change the module.
- Add the HCLI-required repository URL and author metadata, plus license,
  keywords, supported IDA versions, and the published JSON Schema URL.
- Declare `sigmaker==1.12.0` in `pythonDependencies`. HCLI will install the
  matching PyPI wheel into IDA's Python environment, providing the optional
  SIMD extension while the source-tree entry point remains the plugin code.
- Keep `[project].dependencies` empty. HCLI metadata is deployment metadata,
  not a new runtime dependency for direct source installs.

## Release Flow

- Git tag pushes and explicit manual dispatches create GitHub releases.
- Publishing a GitHub release triggers the wheel/sdist workflow and its PyPI
  trusted-publishing step.
- Ordinary successful `main` test runs must not trigger release or PyPI work.
  Remove the `workflow_run` chain that currently reports success even when no
  version tag exists and consequently starts an untagged deployment.
- HCLI's daily indexer discovers the release source archive after publication.
  No separate repository submission or custom HCLI ZIP is required.

## Validation

- Add dependency-free unit tests that enforce the manifest fields, entry-point
  existence, version lockstep, and release-event boundaries.
- Run `hcli plugin lint` against both the checkout and a GitHub-style source
  archive before opening the pull request.
- Keep the HCLI binary outside the package and project dependencies. CI may
  download a pinned HCLI executable for validation without changing SigMaker's
  installation contract.

## Documentation

- Explain that `hcli plugin install SigMaker` installs the matching PyPI wheel
  automatically, so no follow-up `pip install` is needed for SIMD speedups.
- Document the correct platform-specific `$IDAUSR` locations from Hex-Rays'
  HCLI documentation.

## Non-Goals

- No SigMaker runtime or UI changes.
- No new `sigmaker_entry.py` file.
- No version bump or release in this pull request.
- No custom plugin bundle for offline multi-plugin distribution.
