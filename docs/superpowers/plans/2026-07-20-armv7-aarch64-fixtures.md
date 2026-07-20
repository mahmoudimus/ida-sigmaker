# ARMv7 and AArch64 Fixtures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add deterministic ARMv7 A32 and AArch64 ELF fixtures that prove SigMaker's architecture-specific operand wildcard behavior through real IDALIB decoding.

**Architecture:** Check in minimal assembly sources and their reproducible relocatable objects under architecture-specific resource directories. Extend the existing disposable `OpenedFixtureIntegrationTest` harness with one class per architecture; each class treats the generated signature, not successful loading, as its behavioral oracle.

**Tech Stack:** GNU-style assembly accepted by Clang 21, ELF relocatable objects, IDA 9.x IDALIB, Python `unittest`, SigMaker's `InstructionProcessor` and `OperandProcessor`.

## Global Constraints

- Keep SigMaker dependency-free; fixture generation is a maintainer-only operation.
- Open only disposable fixture copies and never save IDA databases.
- Run every Docker test with `--memory=2g --pids-limit=256` and a hard host timeout.
- Do not run an unbounded broad unittest group.
- Do not claim every ARM version, profile, endianness, ABI, or extension is covered.

---

### Task 1: Deterministic Cross-Architecture Objects

**Files:**
- Create: `tests/_resources/arm/armv7/armv7_relocations.s`
- Create: `tests/_resources/arm/armv7/armv7_relocations.o`
- Create: `tests/_resources/arm/armv7/NOTICE.md`
- Create: `tests/_resources/arm/aarch64/aarch64_relocations.s`
- Create: `tests/_resources/arm/aarch64/aarch64_relocations.o`
- Create: `tests/_resources/arm/aarch64/NOTICE.md`

**Interfaces:**
- Produces an ARMv7 A32 ELF with `R_ARM_MOVW_ABS_NC`, `R_ARM_MOVT_ABS`, and `R_ARM_CALL` relocations.
- Produces an AArch64 ELF with `R_AARCH64_ADR_PREL_PG_HI21`, `R_AARCH64_ADD_ABS_LO12_NC`, and `R_AARCH64_CALL26` relocations.

- [ ] **Step 1: Add the ARMv7 source**

Use `.arch armv7-a` and `.arm`. The function must contain `movw r0, #:lower16:target`, `movt r0, #:upper16:target`, `bl target_fn`, `mov r1, #7`, and `bx lr`; place the target function in a separate executable section so the call relocation remains in the object.

- [ ] **Step 2: Add the AArch64 source**

The function must contain `adrp x0, target`, `add x0, x0, :lo12:target`, `bl target_fn`, `mov w1, #7`, and `ret`; place the target function in a separate executable section so `R_AARCH64_CALL26` remains present.

- [ ] **Step 3: Build both objects**

```bash
clang -target armv7-none-eabi -march=armv7-a -c \
  tests/_resources/arm/armv7/armv7_relocations.s \
  -o tests/_resources/arm/armv7/armv7_relocations.o
clang -target aarch64-none-elf -c \
  tests/_resources/arm/aarch64/aarch64_relocations.s \
  -o tests/_resources/arm/aarch64/aarch64_relocations.o
```

- [ ] **Step 4: Verify ELF identity and relocation tables**

```bash
file tests/_resources/arm/{armv7/armv7_relocations.o,aarch64/aarch64_relocations.o}
objdump -r -d tests/_resources/arm/armv7/armv7_relocations.o
objdump -r -d tests/_resources/arm/aarch64/aarch64_relocations.o
shasum -a 256 tests/_resources/arm/{armv7/armv7_relocations.o,aarch64/aarch64_relocations.o}
```

Expected architecture identities are `ELF 32-bit LSB relocatable, ARM, EABI5`
and `ELF 64-bit LSB relocatable, ARM aarch64`. Record the exact build commands,
Clang version, relocation names, and hashes in each notice.

### Task 2: IDALIB Behavioral Characterization

**Files:**
- Modify: `tests/integration_test_sigmaker.py`

**Interfaces:**
- Consumes the two checked-in objects from Task 1.
- Produces `TestArmv7RelocationFixture` and `TestAArch64RelocationFixture`.

- [ ] **Step 1: Add a shared instruction-to-signature helper**

Extract the existing fixture-local helper into a module-level function that
constructs `Signature`, applies `InstructionProcessor(OperandProcessor())`, and
returns the result. Reuse it from MIPS and both new ARM classes.

- [ ] **Step 2: Add the ARMv7 integration test**

Open `arm/armv7/armv7_relocations.o`; assert `PLFM_ARM`, little-endian mode,
IDA's 8-byte combined `MOV` at `0x0`, and the 4-byte `BL` and literal `MOV` at
`0x8` and `0xC`. Assert IDA marks the combined address operand as offset-derived
and represents the call as `o_near`. Expect eight wildcard bytes for the
combined `MOV`, four for `BL`, and `07 10 A0 E3` for stable `MOV R1,#7`.

- [ ] **Step 3: Run ARMv7 characterization under IDALIB**

```bash
timeout 180s docker compose run --rm --memory=2g --pids-limit=256 \
  idapro-tests -m unittest \
  tests.integration_test_sigmaker.TestArmv7RelocationFixture -v
```

If IDA represents a relocation operand differently from the ISA-level
expectation, inspect `op.type`, `op.n`, `op.offb`, `is_off`, and the generated
signature before changing the assertion. The signature must still encode the
intended varying-address coverage.

- [ ] **Step 4: Add the AArch64 integration test**

Open `arm/aarch64/aarch64_relocations.o`; assert `PLFM_ARM`, little-endian
mode, IDA's 8-byte combined `ADRL` at `0x0`, and the 4-byte `BL` and literal
`MOV` at `0x8` and `0xC`. Assert IDA marks the combined address operand as
offset-derived and represents the call as `o_near`. Expect eight wildcard
bytes for `ADRL`, four for `BL`, and `E1 00 80 52` for stable `MOV W1,#7`.

- [ ] **Step 5: Run AArch64 characterization under IDALIB**

```bash
timeout 180s docker compose run --rm --memory=2g --pids-limit=256 \
  idapro-tests -m unittest \
  tests.integration_test_sigmaker.TestAArch64RelocationFixture -v
```

- [ ] **Step 6: Run all checked-in architecture fixtures together**

```bash
timeout 240s docker compose run --rm --memory=2g --pids-limit=256 \
  idapro-tests -m unittest \
  tests.integration_test_sigmaker.TestThumbCombinedImmediateFixture \
  tests.integration_test_sigmaker.TestArmv7RelocationFixture \
  tests.integration_test_sigmaker.TestAArch64RelocationFixture \
  tests.integration_test_sigmaker.TestMipsHi16Lo16Fixture -v
```

### Task 3: Architecture Claims and Regression Gates

**Files:**
- Modify: `README.md`

**Interfaces:**
- Documents only the architecture variants proven by checked-in fixtures.

- [ ] **Step 1: Tighten README architecture wording**

List `ARMv6-M Thumb (Cortex-M0)`, `ARMv7 A32`, and `AArch64` as integration-tested variants. Preserve the statement that unlisted IDA processor modules use generic wildcard behavior.

- [ ] **Step 2: Verify the HCLI summary remains accurate**

Confirm that `ida-plugin.json` continues to use the concise `ARM` description
and keyword. Do not modify it to contain the detailed fixture matrix.

- [ ] **Step 3: Run bounded regression checks**

```bash
PYTHONPATH=src timeout 120s python3 -m unittest \
  tests.unit_test_sigmaker.TestWildcardPolicyDefaults \
  tests.unit_test_sigmaker.TestOperandWildcardSelection -v
timeout 120s python3 -m unittest tests.unit_test_packaging -v
python3 -m compileall -q src/sigmaker tests/integration_test_sigmaker.py
python3 tools/sync_plugin_version.py --check
git diff --check
```

- [ ] **Step 4: Commit and push PR #87**

Commit fixture/test work separately from final documentation where practical,
push `fix/architecture-operand-wildcards`, and verify the PR head and checks.
