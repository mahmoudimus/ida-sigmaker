# PR 57 regression hardening

Status: approved design, 2026-07-14. Applies to `codex/batch-signature-search`
(PR #57).

## Problem

PR #57 adds batch signature searching, richer match metadata, and extensible
result formatters. A regression review found that the current implementation
also changes ordinary single-search parsing, performs expensive metadata work
before output requests it, duplicates metadata ownership, omits segment-scope
support from batch search, and reports canceled partial scans as successful.

The existing SIMD and refinement benchmarks pass because they measure the scan
kernels, not the new work performed after a scan. A 100,000-hit batch currently
performs 100,000 file-offset lookups and rebuilds every `Match` object before a
formatter is selected.

The PR also claims automatic SIMD buffer reuse, but the current batch path only
reuses a buffer when its caller supplies one.

## Goals

- Keep `SearchResults(matches, signature_str)` and existing single-search
  embedders compatible.
- Use a strict, documented signature grammar instead of guessing arbitrary
  input.
- Preserve explicit full-byte and nibble wildcards, including trailing
  wildcards.
- Keep batch entry splitting unambiguous.
- Keep expensive file-offset lookup out of the search path.
- Create each `Match` once while still attaching cheap RVA metadata.
- Give batch search the same segment-scope policy as single search.
- Propagate batch cancellation instead of exporting partial results as complete.
- Load and reuse one SIMD buffer automatically for a batch.
- Add regression and performance tests for the complete batch workflow.

## Non-goals

- Redesign the complete signature-search API around new request objects.
- Change ordinary `find_all()` cancellation behavior for existing callers.
- Add the IDA dialog or export prompt from stacked PR #60.
- Add fuzzy C declaration extraction or multiline signature reconstruction.
- Make C output a built-in formatter.

## Strict signature grammar

`SignatureParser.parse(raw)` continues returning the display-oriented SigMaker
search pattern string. It accepts only explicit forms:

- exact byte tokens: `48`, `8B`, `00`
- full-byte wildcards: `?` and `??`
- nibble wildcards: `4?` and `?F`
- individually prefixed bytes: `0x48 0x8B`
- escaped bytes, including existing bytes-plus-mask input
- existing `x`/`?` masks and binary masks
- whitespace, commas, and semicolons as byte separators
- one optional balanced pair of surrounding parentheses or brackets

It rejects:

- single hex nibbles such as `E 8 4`
- glued runs such as `488B9090` or `0x488B9090`
- colon, pipe, underscore, hyphen, and dot separators
- malformed or unknown tokens such as `GG`
- prose or declaration fragments that are not valid signatures

Invalid input returns the existing empty parse result, and
`SignatureSearcher.search()` converts that into its structured
`SearchResults.error`. The changelog and README explicitly state that parsing is
stricter: malformed input is rejected rather than converted to wildcards or
otherwise guessed.

Trailing wildcards remain part of the parsed pattern. Full-byte wildcards use
`?` in `signature_str` / `search_pattern` and `??` in
`normalized_signature`.

## Batch entry boundaries

`SignatureSearcher.from_many(text)` creates one searcher per non-empty input
line. Newlines are the only batch entry boundary.

Each line may be:

- an unnamed signature
- `name = pattern`
- `name := pattern`

Comments and Markdown fence lines retain their current behavior. A semicolon is
not a batch separator; it remains a byte separator inside one signature. The
batch parser does not join lines or infer source declarations.

## Shared search policy

Single and batch search share a private helper that resolves `scope_ea` to an
optional `(start_ea, end_ea)` segment range. This keeps fallback behavior the
same when the address is not in a segment.

`BatchSignatureSearcher.search()` becomes keyword-only:

```python
def search(
    self,
    *,
    buf: typing.Optional[InMemoryBuffer] = None,
    scope_ea: typing.Optional[int] = None,
) -> BatchSearchResults:
    ...
```

Providing both `buf` and `scope_ea` raises `ValueError`. A caller-provided
buffer does not expose enough information to prove that it represents the
requested segment, so silently combining them could search the wrong corpus.

Without SIMD, batch search passes the resolved scope directly to `find_all()`.
With SIMD, batch search lazily loads one `InMemoryBuffer` when the first valid,
uncached pattern needs a scan. It loads the requested segment when `scope_ea`
resolves and all segments otherwise, then passes that same buffer to every
remaining unique normalized pattern. Empty or entirely invalid batches do not
load a buffer.

Duplicate normalized patterns continue sharing one scan result. Each
`SearchResults.matches` value gets its own list but may share immutable `Match`
objects with duplicate entries.

## Match and result metadata

`Match` remains a frozen, slotted dataclass with one metadata authority:

```python
Match(
    address: int,
    *,
    rva: typing.Optional[int] = None,
    file_offset: typing.Optional[int] = None,
)
```

Equality and hashing continue depending only on `address`. Existing `str`,
`repr`, integer conversion, and format behavior remain compatible.

`find_all()` gains an optional keyword-only imagebase used only by callers that
request enriched matches. The IDA and SIMD scan paths construct
`Match(address, rva=address - imagebase)` directly, avoiding the second
full-list allocation currently performed by `SearchResults.__post_init__()`.
Count and uniqueness callers keep the default and pay no metadata cost.

`SearchResults` no longer exposes the new `imagebase` and `file_offsets` fields
introduced only on this unmerged branch. It keeps the legacy positional fields
and the additive pattern/name/error fields. It also owns a private lazy
file-offset cache used by output code. The cache stores successful offsets and
unavailable results so repeated format operations do not repeat failed IDA
lookups.

`Match.file_offset` remains optional. If a caller explicitly constructs an
enriched `Match`, `f"{hit:fileoffset}"` formats that value. Otherwise the Match
formatter retains the documented unavailable fallback. Built-in exporters call
`SearchResults.file_offset_for_match(hit)`, which resolves and caches only the
hits they actually output.

Consequences by formatter:

| operation | file-offset lookups |
|---|---:|
| batch search only | 0 |
| text output | at most previewed hits |
| CSV output | every exported hit |
| JSON output | every exported hit |
| custom C example | each emitted unique hit |

RVA formatters read `hit.rva` directly. `BatchSearchResults.imagebase` remains
for aggregate headers and output metadata.

## Cancellation

`find_all()` and the SIMD helper gain a keyword-only `raise_on_cancel=False`
option. Existing callers retain their current partial-list behavior.

Batch search passes `raise_on_cancel=True`. Both scan implementations raise
`UserCanceledError` when IDA reports cancellation. Batch search does not cache,
format, or return the partial match list.

The cancellation regression test drives the real `find_all()` cancellation
branch. It does not mock `find_all()` to raise an exception that production
never raises.

## Formatter changes

- Text output resolves file offsets only for previewed matches.
- CSV and JSON resolve offsets lazily while serializing all matches.
- The C formatter example uses `entry.file_offset_for_match(hit)` rather than
  assuming batch search pre-populated `hit.file_offset`.
- RVA output uses `hit.rva` directly.
- Formatter registration and `f"{results:csv}"` behavior remain unchanged.

## Tests

Unit regressions cover:

1. Every accepted strict token form.
2. Rejection of single nibbles, glued hex, colon separators, and invalid tokens.
3. Preservation of trailing full-byte and nibble wildcards.
4. Newline-only batch splitting and semicolon byte separation.
5. Batch `scope_ea` propagation on IDA and SIMD paths.
6. Rejection of `buf` plus `scope_ea`.
7. One automatic SIMD buffer load per batch.
8. No SIMD buffer load for an empty or entirely invalid batch.
9. No file-offset lookups during batch search.
10. No second `Match` allocation for enriched results.
11. Lazy positive and negative offset caching during formatter output.
12. Real IDA-path and SIMD-path cancellation propagation.
13. Existing non-batch cancellation behavior remains unchanged.

A high-match-count regression test uses 100,000 synthetic hits and asserts zero
file-offset calls during `BatchSignatureSearcher.search()`. Timing remains a
benchmark observation rather than a brittle wall-clock assertion.

The real-IDA integration suite adds one batch test covering named entries,
duplicate normalized patterns, a no-match entry, match metadata, and output
serialization against the existing fixture binary.

## Documentation and PR updates

- README documents the strict grammar and newline-only batch entries.
- README explains that file offsets are lazy and exporters request them.
- CHANGELOG adds a `Changed` note for stricter malformed-input handling.
- The C formatter example follows the lazy file-offset API.
- PR #57 removes semicolon entry examples, corrects automatic buffer-reuse
  wording, records the final test count, and uses `PYTHONPATH=src` for local
  checkout validation.

## Risks

- Scripts that depended on malformed input becoming wildcards will now receive
  a structured parse error. This is intentional and documented.
- Scripts using semicolons to put several batch entries on one line must switch
  to newlines. Semicolon-separated bytes remain valid.
- Adding optional metadata and cancellation keywords to `find_all()` must remain
  additive so existing positional callers are unaffected.
- Real IDA file-offset lookup can still be expensive when exporting every hit;
  the cost is explicit and proportional to requested output rather than hidden
  in search.
