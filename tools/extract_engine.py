#!/usr/bin/env python3
"""Generate the GUI-free signature engine from the single-file plugin source.

The plugin lives in one file (``src/sigmaker/__init__.py``) by design. Everything
above the ``ENGINE / PLUGIN SEAM`` marker is the self-contained signature engine;
everything below is the IDA plugin shell (config Forms, action/menu registration,
``plugin_t``) that subclasses idaapi GUI types and cannot import under idalib.

This tool slices the source at the seam and writes ``sigmaker_engine.py``, a
drop-in engine that embedders can vendor instead of hand-stripping the GUI (which
drifts on every release). It is pure stdlib so it can run anywhere.

Usage:
    python tools/extract_engine.py [OUT_PATH]    # default: ./sigmaker_engine.py
"""
from __future__ import annotations

import pathlib
import sys

# The unique sentinel inside the seam comment block (see src/sigmaker/__init__.py).
SEAM_SENTINEL = "ENGINE / PLUGIN SEAM"

_GENERATED_HEADER = (
    "# GENERATED from src/sigmaker/__init__.py (engine slice at the ENGINE / PLUGIN\n"
    "# SEAM). Do not edit by hand: regenerate with tools/extract_engine.py. This is\n"
    "# the GUI-free signature engine (no config Forms, no action/menu registration,\n"
    "# no plugin_t), so it imports under idalib without IDA's GUI base classes.\n"
    "\n"
)


def _default_source() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent / "src" / "sigmaker" / "__init__.py"


def extract_engine(
    src_path: "pathlib.Path | str | None" = None,
    out_path: "pathlib.Path | str | None" = None,
) -> str:
    """Return the engine slice of ``src_path``; write it to ``out_path`` if given.

    Raises ValueError if the seam marker is missing or appears more than once.
    """
    src = pathlib.Path(src_path) if src_path is not None else _default_source()
    lines = src.read_text(encoding="utf-8").splitlines(keepends=True)

    seam_idxs = [i for i, ln in enumerate(lines) if SEAM_SENTINEL in ln]
    if len(seam_idxs) == 0:
        raise ValueError(f"seam marker {SEAM_SENTINEL!r} not found in {src}")
    if len(seam_idxs) > 1:
        raise ValueError(
            f"seam marker {SEAM_SENTINEL!r} appears {len(seam_idxs)} times in {src}; "
            "it must be unique"
        )

    # Walk back over the contiguous comment block that contains the sentinel so the
    # marker itself is excluded from the engine.
    block_start = seam_idxs[0]
    while block_start > 0 and lines[block_start - 1].lstrip().startswith("#"):
        block_start -= 1

    engine = _GENERATED_HEADER + "".join(lines[:block_start]).rstrip("\n") + "\n"

    if out_path is not None:
        pathlib.Path(out_path).write_text(engine, encoding="utf-8")
    return engine


def main(argv: "list[str]") -> int:
    out = argv[1] if len(argv) > 1 else "sigmaker_engine.py"
    text = extract_engine(out_path=out)
    print(f"wrote {out} ({text.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
