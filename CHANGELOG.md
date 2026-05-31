# Changelog

All notable user-visible changes to this plugin are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.9.1] - 2026-05-30

### Added

- **Signature output now labels addresses with the containing function name.** `GeneratedSignature.display`, `XrefGeneratedSignature.display`, and the function-signature action append ` (funcname)` to printed addresses when the address lies in a named function, falling back to the bare address otherwise. The address is always kept, so distinct anchors in the same function stay distinguishable. ([#47](https://github.com/mahmoudimus/ida-sigmaker/pull/47))

[1.9.1]: https://github.com/mahmoudimus/ida-sigmaker/compare/v1.9.0...v1.9.1

## [1.9.0] - 2026-05-30

### Changed

- **`Find shortest unique signature for current function` worst case drops from ~12 s to ~1 s on large databases.** Profiling on 200 MB+ modules found the remaining cost was not the index or the refinement kernel but two leftovers, both now fixed: the seed-candidate map ran in a pure-Python loop over the whole seed bucket, and patterns whose seedable prefix was all wildcards fell back to a full-buffer scan. ([#45](https://github.com/mahmoudimus/ida-sigmaker/pull/45))

### Internal

- New `seed_offsets` Cython kernel maps a seed bucket to the candidate start array (the `p - s` shift, the fit guard, the n-1 boundary) under `nogil`, the same pattern as `refine_offsets`. This was the last `O(C0)` loop left in Python; moving it to C cut the worst observed function search from ~12 s to ~1 s. ([#45](https://github.com/mahmoudimus/ida-sigmaker/pull/45))
- Seeding is deferred for all-wildcard prefixes instead of running an `O(N)` masked scan when no exact byte is available to key the index. ([#45](https://github.com/mahmoudimus/ida-sigmaker/pull/45))
- Adversarial refinement microbenchmark (`tests/perf/adversarial_refine.py`, with a `--check` regression guard) plus cross-check tests pinning the Cython kernels to their Python fallbacks. Block refinement and sorted-bucket spaced-seed intersection were measured and shelved. ([#45](https://github.com/mahmoudimus/ida-sigmaker/pull/45))
- Signatures produced are byte-identical to 1.8.0; only the speed of finding them changed. ([#45](https://github.com/mahmoudimus/ida-sigmaker/pull/45))

### Documentation

- `ALGORITHM.md` gains a table of contents, a "Rejected optimizations" section explaining why the two upgrades above were shelved, and notes on the `seed_offsets` kernel and deferred seeding. ([#45](https://github.com/mahmoudimus/ida-sigmaker/pull/45))

[1.9.0]: https://github.com/mahmoudimus/ida-sigmaker/compare/v1.8.0...v1.9.0

## [1.8.0] - 2026-05-29

### Changed

- **`Find shortest unique signature for current function` is faster again on large databases, and the gap widens as the database grows.** The per-starting-point seed scan is replaced by a two-byte position index built once per search, so each starting point is seeded from the rarest byte run in its pattern in time proportional to that run's frequency, not the database size. About 2.48x over 1.7.3 on a 16 MB module. ([#35](https://github.com/mahmoudimus/ida-sigmaker/pull/35))
- **The seed is now chosen from the most selective run, one byte or two.** A single rare byte can be more selective than a common two-byte pair, so the search picks whichever run has the smallest index bucket. ([#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36))

### Internal

- Two-byte bucket position index built in the Cython `_speedups` extension as a `nogil` counting sort; one-byte buckets telescope from it for free (a range view, no second index). ([#35](https://github.com/mahmoudimus/ida-sigmaker/pull/35), [#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36))
- Per-byte candidate refinement moved into the Cython extension (`refine_offsets`): in-place `nogil` compaction over a typed uint32 buffer with zero per-call allocation. Refinement on the largest function of a 16 MB module dropped from ~14 s to ~0.28 s; that function's total search fell from ~24 s to ~15.6 s. ([#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36))
- `_ByteIndex` is a frozen slots dataclass; the runtime array module is aliased as `py_stdlib_arr_mod` to keep it distinct from the cimported C-level API. ([#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36))
- Signatures produced are byte-identical to 1.7.3; only the speed of finding them changed. ([#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36))

### Documentation

- New [`ALGORITHM.md`](./ALGORITHM.md) deriving the match-set math, the counting-sort index, the selectivity proof, and what is novel about the approach. README gains a table of contents, a Performance section with benchmarks, and a library stability contract for downstream embedders. ([#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36))

[1.8.0]: https://github.com/mahmoudimus/ida-sigmaker/compare/v1.7.3...v1.8.0

## [1.7.3] - 2026-05-28

### Changed

- **`Find shortest unique signature for current function` is dramatically faster on large databases.** The search now scans the database once per starting point to seed a set of candidate match offsets, then refines that set in memory as the signature grows, instead of re-scanning the whole database on every byte. A function that previously took minutes now finishes in seconds. ([#33](https://github.com/mahmoudimus/ida-sigmaker/pull/33))
- **The live `Matches:` count is back, and exact.** Candidate refinement tracks the surviving match count for free at every step, so the `Create unique signature` wait box shows the real count again and the function-search wait box shows an exact inner count instead of the temporary `2+` placeholder. ([#27](https://github.com/mahmoudimus/ida-sigmaker/issues/27), [#33](https://github.com/mahmoudimus/ida-sigmaker/pull/33))

### Fixed

- **The `Start Profiling` / `Stop Profiling` menu items now appear.** They were attached at plugin init, before IDA builds its menus, so they silently never showed. They are now attached through the disassembly right-click popup, grouped with the main action under a `SigMaker` submenu. ([#33](https://github.com/mahmoudimus/ida-sigmaker/pull/33))

### Internal

- New `SignatureSearcher.find_all_offsets` (seed scan returning raw buffer offsets) and `_refine_offsets` (in-memory candidate refinement). Uniqueness checks below `MIN_USEFUL_SIG_BYTES` use a cheap early-bail probe so the enumerating seed scan is deferred until the pattern is long enough to be selective. ([#33](https://github.com/mahmoudimus/ida-sigmaker/pull/33))
- Cancellation polling in the scan loops is throttled (every 65536 matches) so `idaapi.user_cancelled()`, which pumps the UI event loop, does not dominate a scan over a common pattern. ([#33](https://github.com/mahmoudimus/ida-sigmaker/pull/33))
- Signatures produced are byte-identical to 1.7.2; the change is purely how quickly they are found and that exact match counts are restored. ([#33](https://github.com/mahmoudimus/ida-sigmaker/pull/33))

[1.7.3]: https://github.com/mahmoudimus/ida-sigmaker/compare/v1.7.2...v1.7.3

## [1.7.2] - 2026-05-28

### Added

- **Live wait-box progress** for the `Create unique signature` and `Find shortest unique signature for current function` actions. The wait box updates as the search runs: current signature length and elapsed time for both, plus function bounds, current anchor, inner-search bounds, best size, and candidate count for the function search. ([#27](https://github.com/mahmoudimus/ida-sigmaker/issues/27), [#30](https://github.com/mahmoudimus/ida-sigmaker/pull/30))
- **Self-describing wait boxes.** Every action's wait box now leads with the action name and a one-line explanation of what it is doing, so a screenshot always identifies which action produced it. ([#30](https://github.com/mahmoudimus/ida-sigmaker/pull/30))
- **`start_profiling` / `stop_profiling` helpers**, exposed as `Edit/Plugins` menu actions, for capturing a cProfile dump of a slow run from inside IDA. ([#30](https://github.com/mahmoudimus/ida-sigmaker/pull/30))

### Changed

- **`Find shortest unique signature for current function` is dramatically faster.** Uniqueness checks now stop at the second match instead of enumerating every match in the database, and the segment buffer is loaded once per search instead of once per growth step. A function search that previously took minutes on a large database now completes in seconds. ([#31](https://github.com/mahmoudimus/ida-sigmaker/pull/31))
- **Wait-box refresh throttle default is now 1 second** (previously 100 ms), so the box does not repaint faster than it can be read. ([#27](https://github.com/mahmoudimus/ida-sigmaker/issues/27), [#30](https://github.com/mahmoudimus/ida-sigmaker/pull/30))

### Removed

- **The live `Matches:` count is temporarily removed from the `Create unique signature` wait box.** Counting every match on every growth step was the search's bottleneck; the wait box still shows the growing length and elapsed time. A future release restores an exact count cheaply via incremental candidate refinement. ([#27](https://github.com/mahmoudimus/ida-sigmaker/issues/27), [#30](https://github.com/mahmoudimus/ida-sigmaker/pull/30))

### Internal

- `MinimalFunctionSignatureGenerator` decodes each function instruction once up front and grows anchors over the cached data, instead of re-decoding per anchor. ([#31](https://github.com/mahmoudimus/ida-sigmaker/pull/31))
- `SignatureSearcher.is_unique` stops at the second match; `count_matches` still enumerates fully for callers that need the exact count (such as partial-on-cancel). ([#31](https://github.com/mahmoudimus/ida-sigmaker/pull/31))
- The compiled `_speedups` SIMD extension now loads from a sibling directory when the package-level import resolves to a namespace package without a matching compiled build (dev and symlink layouts). ([#31](https://github.com/mahmoudimus/ida-sigmaker/pull/31))

[1.7.2]: https://github.com/mahmoudimus/ida-sigmaker/compare/v1.7.1...v1.7.2

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
