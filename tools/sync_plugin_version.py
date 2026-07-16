#!/usr/bin/env python3
"""Keep HCLI's manifest version fields in sync with ``sigmaker.__version__``.

The single source of truth for the version is ``__version__`` in
``src/sigmaker/__init__.py`` (``pyproject.toml`` already derives the package
version from it). The IDA Plugin Repository and ``hcli`` read the version and
the exact PyPI dependency out of ``ida-plugin.json``, so both must agree. This
script updates them together.

It reads ``__version__`` by parsing the source with ``ast`` rather than
importing the module, because importing ``sigmaker`` pulls in ``idaapi``,
which only exists inside IDA. The manifest is parsed and written as JSON so
the two related fields cannot drift independently.

Usage:
    python tools/sync_plugin_version.py            # write the manifest in place
    python tools/sync_plugin_version.py --check     # exit 1 if out of sync, no write

The pre-commit hook in ``.githooks/`` runs the writing form; the unit test
``TestPluginManifestVersion`` and CI act as the backstop.
"""
import argparse
import ast
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
INIT = ROOT / "src" / "sigmaker" / "__init__.py"
MANIFEST = ROOT / "ida-plugin.json"


def package_version() -> str:
    """Return ``__version__`` from the package source without importing it."""
    tree = ast.parse(INIT.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise SystemExit(f"could not find __version__ in {INIT}")


def manifest_version(text: str) -> str:
    return json.loads(text)["plugin"]["version"]


def sync_manifest(text: str, version: str) -> str:
    """Return manifest JSON with all package-version references updated."""
    manifest = json.loads(text)
    plugin = manifest["plugin"]
    plugin["version"] = version
    plugin["pythonDependencies"] = [f"sigmaker=={version}"]
    return json.dumps(manifest, indent=4) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the manifest matches the package version; do not write",
    )
    args = parser.parse_args(argv)

    version = package_version()
    text = MANIFEST.read_text(encoding="utf-8")
    manifest = json.loads(text)
    current = manifest["plugin"]["version"]
    dependencies = manifest["plugin"].get("pythonDependencies")
    expected_dependencies = [f"sigmaker=={version}"]

    if current == version and dependencies == expected_dependencies:
        return 0

    if args.check:
        print(
            "ida-plugin.json package references are out of sync: "
            f"version={current!r}, pythonDependencies={dependencies!r}, "
            f"expected version={version!r} and dependencies="
            f"{expected_dependencies!r}; run: python "
            "tools/sync_plugin_version.py",
            file=sys.stderr,
        )
        return 1

    MANIFEST.write_text(sync_manifest(text, version), encoding="utf-8")
    print(
        "synced ida-plugin.json package references "
        f"from version {current} to {version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
