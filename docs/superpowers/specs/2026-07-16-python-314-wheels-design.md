# Python 3.14 Wheels Design

## Goal

Publish SigMaker's compiled speedup wheel for CPython 3.14 on the same platform
matrix already used for CPython 3.10 through 3.13.

## Design

- Update the cibuildwheel GitHub Action from 3.1.4 to 3.4.1. Version 3.1.4
  carried a Python 3.14 release candidate; 3.4.1 uses the final Python 3.14
  toolchain and supports the existing Linux, Windows, and macOS runners.
- Add `cp314-*` to the explicit `CIBW_BUILD` selection. Keep the explicit list
  so new Python versions do not enter the release matrix without review.
- Add the `Programming Language :: Python :: 3.14` PyPI classifier.

## Verification

- Parse the edited workflow and project metadata.
- Ask cibuildwheel 3.4.1 to enumerate the selected macOS build identifiers and
  confirm that CPython 3.10 through 3.14 are present.
- Build the native wheel with CPython 3.14 locally and inspect its wheel tag.
- Run the focused packaging checks and repository diff checks.

## Non-Goals

- No changes to SigMaker runtime code or its SIMD implementation.
- No changes to the IDA test matrix or supported IDA versions.
- No HCLI manifest or release-pipeline restructuring in this branch.
