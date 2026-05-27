# Changelog

All notable user-visible changes to this plugin are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.7.1] - 2026-05-27

### Added

- **New `Find shortest unique signature for current function` action** on the main form. Iterates every instruction in the containing function as a possible start point, growing a signature from each (bounded by function end and by the current best candidate's size), and returns the smallest unique result with the fewest wildcards. Output annotates the address with an offset into the function so you can see exactly where the unique sequence sits. ([#17](https://github.com/mahmoudimus/ida-sigmaker/issues/17), [#26](https://github.com/mahmoudimus/ida-sigmaker/pull/26))
- **Automatic xref fallback for the new action.** If no unique signature exists anywhere in the function body (e.g., the function is a small thunk identical to many others), the action falls back to generating signatures rooted at each code xref into the function and picks the best. Output reads `Xref signature into 0x... (from 0x...):`. ([#17](https://github.com/mahmoudimus/ida-sigmaker/issues/17), [#26](https://github.com/mahmoudimus/ida-sigmaker/pull/26))

### Changed

- **`WildcardPolicy.for_x86()` no longer wildcards `o_imm` immediates.** An immediate like the `0x13371338` in `mov rcx, 0x13371338` is a literal value baked into the instruction encoding; it does not shift between binary builds, so wildcarding it only removed bytes that would have made the signature unique. Memory addresses (`o_mem`), jump/call targets (`o_far`, `o_near`), and architecture-specific register operands still get wildcarded. This is a strict improvement to every action with `wildcard_operands=True`, including the existing `Create unique signature` and `Find shortest XREF signature` actions. ([#26](https://github.com/mahmoudimus/ida-sigmaker/pull/26))
- **`GeneratedSignature.__lt__` now ranks by `(size, wildcards)` ascending** instead of just size. Same-length signatures with fewer wildcards rank first. The existing `Find shortest XREF signature` action picks this up for free, picking more specific candidates as the "best" result. ([#26](https://github.com/mahmoudimus/ida-sigmaker/pull/26))
- **README acknowledgements** clarified to better reflect the historical relationship between this plugin and the broader SigMaker ecosystem.

### Internal

- New `MinimalFunctionSignatureGenerator` class implements the function-wide search with monotonic best-size pruning and an ideal-candidate early exit (size <= 5 bytes and zero wildcards stops the outer loop).
- New `Action.FIND_FUNCTION_SIG = 4` enum value for the new form action.
- Integration test coverage exercises both the function-search end to end and the x86 immediate preservation against the compiled test binary.

[1.7.1]: https://github.com/mahmoudimus/ida-sigmaker/compare/v1.7.0...v1.7.1

## [1.7.0] - 2026-05-27

### Added

- **Wait-box cancel for long signature generation.** A non-blocking wait box now appears while sigmaker is searching, with a Cancel button you can click at any time to stop the search cleanly. Replaces the previous default of recurring "Continue?" modal popups. Canceling produces a clean `Operation canceled by user` message in the output log, with no traceback. ([#18](https://github.com/mahmoudimus/ida-sigmaker/issues/18), [#24](https://github.com/mahmoudimus/ida-sigmaker/pull/24))
- **Opt-in `Enable continue prompt` checkbox** on the main form. Ticking it restores the previous periodic prompt behavior for anyone who prefers it. Off by default. ([#24](https://github.com/mahmoudimus/ida-sigmaker/pull/24))
- **Opt-in `Prompt interval` field** in the "Other options..." dialog. Sets how many seconds to wait before the first periodic prompt fires; `-1` disables the prompt entirely. Default `-1`. ([#24](https://github.com/mahmoudimus/ida-sigmaker/pull/24))
- **Opt-in `Output partial signature on cancel` checkbox** on the main form. When ticked, canceling a unique-signature search emits the partial signature with a match count instead of nothing. Off by default; output goes to the console only (no clipboard write) so an accidental cancel cannot clobber the clipboard. ([#22](https://github.com/mahmoudimus/ida-sigmaker/issues/22), [#25](https://github.com/mahmoudimus/ida-sigmaker/pull/25))

### Changed

- **Default cancel UX.** Out of the box, a sigmaker search now shows a wait box with a Cancel button instead of firing periodic "Continue?" popups. The popup behavior is preserved as the new opt-in described above. ([#18](https://github.com/mahmoudimus/ida-sigmaker/issues/18), [#24](https://github.com/mahmoudimus/ida-sigmaker/pull/24))

### Fixed

- **Canceling a unique-signature search no longer misreports as "Signature not unique".** `InstructionWalker` now raises a proper `UserCanceledError` on cancel rather than swallowing it as `StopIteration`, which the generators were treating as "ran out of instructions". The user now sees `Operation canceled by user`, not a confusing error. ([#18](https://github.com/mahmoudimus/ida-sigmaker/issues/18), [#24](https://github.com/mahmoudimus/ida-sigmaker/pull/24))
- **Wait-box Cancel button now actually cancels.** `CheckContinuePrompt.should_cancel` now polls `idaapi_user_canceled()` so the wait-box Cancel propagates through the progress reporter regardless of whether the periodic prompts are enabled. Previously the button was effectively a no-op unless the modal popup was the one being dismissed. ([#18](https://github.com/mahmoudimus/ida-sigmaker/issues/18), [#24](https://github.com/mahmoudimus/ida-sigmaker/pull/24))
- **User-facing cancel message now matches the rest of the codebase.** The output line on cancel is `Operation canceled by user` (US English), aligning with the spelling used everywhere else in the plugin.
- **Partial-on-cancel match count no longer reports `0`.** When the user clicks Cancel mid-search, the internal match-counting also bails (it polls the same cancel flag), and would return a partial count of `0`. The generator now preserves the most recently completed iteration's count instead, so users see e.g. `Partial signature (NOT unique, 3 matches)` rather than `0 matches` or `match count unavailable`. ([#22](https://github.com/mahmoudimus/ida-sigmaker/issues/22), [#25](https://github.com/mahmoudimus/ida-sigmaker/pull/25))

### Internal

- New `Action` IntEnum replaces the bare `0/1/2/3` magic numbers in `SigMakerPlugin.run`'s dispatch.
- New `GenerationStatus` enum and `GenerationPolicy` dataclass formalize the opt-in vocabulary for partial-on-cancel.
- `GeneratedSignature` now carries `status` and `match_count` fields.
- `SignatureSearcher.count_matches` exposes the per-iteration database scan count that `is_unique` was already computing and discarding.
- `InstructionWalker.end_ea` default is resolved lazily via `default_factory` so runtime patches of `idaapi.BADADDR` take effect (testability fix).

[1.7.0]: https://github.com/mahmoudimus/ida-sigmaker/compare/v1.6.0...v1.7.0
