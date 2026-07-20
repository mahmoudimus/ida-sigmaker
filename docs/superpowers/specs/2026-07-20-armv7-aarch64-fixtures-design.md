# ARMv7 and AArch64 Fixture Design

## Goal

Add deterministic ARMv7 A32 and AArch64 ELF fixtures that prove SigMaker's
processor-aware operand wildcarding against IDA's real decoded instructions.

## Fixture Design

Each fixture is a small relocatable ELF assembled from source checked into the
repository. The adjacent notice records the exact Clang command, tool version,
target triple, and SHA-256. Generated objects are checked in because CI's IDA
containers should not require a cross-compilation toolchain.

The ARMv7 fixture uses A32 instructions with relocations that exercise an
address split across `MOVW` and `MOVT`, plus a direct `BL`. The AArch64 fixture
uses an `ADRP`/`ADD :lo12:` address materialization pair plus a direct `BL`.
Small literal instructions are included where useful to prove that stable
constants remain exact.

## Behavioral Oracle

The integration tests open disposable copies through the existing
`OpenedFixtureIntegrationTest` harness. For every selected instruction they
verify:

- IDA selected the expected processor family and byte order.
- IDA decoded the expected bytes, instruction type, and relocation-bearing
  operand metadata.
- Default ARM wildcard policy masks the address-bearing encoding bytes.
- Stable opcode, register, and literal bytes remain exact where the encoding
  permits partial coverage.

The expected formatted signature is the behavioral oracle. Merely opening the
ELF or recognizing its mnemonic is not sufficient.

## Documentation Boundary

The README may claim architecture-specific wildcard coverage for ARMv7 A32 and
AArch64 only after both real IDALIB fixture tests pass. Existing Cortex-M0
ARMv6-M Thumb coverage remains listed separately. These fixtures do not imply
coverage of every ARM profile, endianness, ABI, or instruction extension.

## Verification

Run the two new integration test classes under the same bounded Docker/IDALIB
commands used by the repository's existing fixture tests. Also run the focused
unit tests for operand wildcard selection, packaging tests, fixture hash checks,
`compileall`, and `git diff --check`. Do not run an unbounded broad test group.
