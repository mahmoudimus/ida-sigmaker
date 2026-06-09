#!/usr/bin/env python3
"""Keep ``ida-plugin.json``'s version in sync with ``sigmaker.__version__``.

The single source of truth for the version is ``__version__`` in
``src/sigmaker/__init__.py`` (``pyproject.toml`` already derives the package
version from it). The IDA Plugin Repository and ``hcli`` read the version out
of ``ida-plugin.json``, so the two must agree. This script copies the package
version into the manifest.

It reads ``__version__`` by parsing the source with ``ast`` rather than
importing the module, because importing ``sigmaker`` pulls in ``idaapi``,
which only exists inside IDA. The manifest is rewritten with a targeted
substitution so the rest of its formatting is left untouched.

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
import re
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
    current = manifest_version(text)

    if current == version:
        return 0

    if args.check:
        print(
            f"ida-plugin.json version {current!r} != sigmaker.__version__ "
            f"{version!r}; run: python tools/sync_plugin_version.py",
            file=sys.stderr,
        )
        return 1

    # Replace only the version string, so the manifest's formatting is preserved.
    new_text, n = re.subn(
        r'("version"\s*:\s*")[^"]*(")', r"\g<1>" + version + r"\g<2>", text, count=1
    )
    if n != 1:
        raise SystemExit("could not locate the version field in ida-plugin.json")
    MANIFEST.write_text(new_text, encoding="utf-8")
    print(f"synced ida-plugin.json version {current} -> {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
