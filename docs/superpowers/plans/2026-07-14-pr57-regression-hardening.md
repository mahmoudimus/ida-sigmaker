# PR 57 Regression Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the parsing, performance, scope, cancellation, and metadata regressions found in PR #57 without changing existing single-search compatibility or scan-kernel speed.

**Architecture:** Keep the existing `src/sigmaker/__init__.py` module layout. Make `SignatureParser` the strict input boundary while leaving `SigText` as the permissive internal normalizer, construct enriched immutable `Match` values directly in the scan paths, keep file offsets behind a private lazy result cache, and make single and batch search share scope and cancellation policy helpers.

**Tech Stack:** Python 3.10+, `dataclasses`, `unittest`, IDAPython/idalib, optional Cython SIMD scanner, Markdown documentation.

## Global Constraints

- Preserve `SearchResults(matches, signature_str)` positional construction.
- Preserve ordinary `find_all()` partial-result cancellation unless `raise_on_cancel=True` is explicitly passed.
- Reject malformed arbitrary input instead of guessing wildcards.
- Preserve exact-byte, full-wildcard, nibble-wildcard, escaped-byte, mask, and explicit `0xHH` input forms.
- Treat newlines as the only batch entry boundary; semicolons remain byte separators.
- Perform zero file-offset lookups during batch search.
- Automatically load at most one SIMD buffer for a batch, and no buffer for an empty or entirely invalid batch.
- Keep PR #60 UI/export-dialog work out of this branch.

---

### Task 1: Strict Signature Input and Newline Batch Boundaries

**Files:**
- Modify: `tests/unit_test_sigmaker.py:1490-1733`
- Modify: `src/sigmaker/__init__.py:2935-3095`

**Interfaces:**
- Consumes: existing `SignatureParser.parse(raw: str) -> str` and `SignatureSearcher.from_many(text: str) -> list[SignatureSearcher]`.
- Produces: strict `SignatureParser._normalize_explicit_pattern(raw: str) -> str`; newline-only `SignatureSearcher._split_statements(text: str) -> list[tuple[int, str]]`.

- [ ] **Step 1: Add strict parser and batch-boundary regression tests**

Add table-driven tests under `TestSignatureSearcherInput` and replace the semicolon-as-entry expectation under `TestSignatureSearcherFromMany`:

```python
def test_parser_accepts_only_explicit_signature_tokens(self):
    cases = {
        "48 8B 00": "48 8B 00",
        "48,8B;00": "48 8B 00",
        "(48 8B ? ?? 4? ?F)": "48 8B ? ? 4? ?F",
        r"\x48\x8B\x00": "48 8B 00",
        "0x48 0x8B 0x00": "48 8B 00",
        "48 8B ? ?? 4? ?F ??": "48 8B ? ? 4? ?F ?",
    }
    for raw, expected in cases.items():
        with self.subTest(raw=raw):
            self.assertEqual(sigmaker.SignatureParser.parse(raw), expected)

def test_parser_rejects_ambiguous_or_random_input(self):
    for raw in (
        "E 8 4 ? C",
        "488B9090",
        "0x488B9090",
        "48:8B:90",
        "48 GG 90",
        "hello world",
        r"prefix \x48\x8B xx",
    ):
        with self.subTest(raw=raw):
            self.assertEqual(sigmaker.SignatureParser.parse(raw), "")

def test_semicolon_separates_bytes_not_batch_entries(self):
    searchers = sigmaker.SignatureSearcher.from_many("first := 48;8B;90\nsecond = CC")
    self.assertEqual(
        [(item.name, item.input_signature, item.source_line) for item in searchers],
        [("first", "48;8B;90", 1), ("second", "CC", 2)],
    )
```

- [ ] **Step 2: Run the focused tests and verify the expected failures**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestSignatureSearcherInput \
  tests.unit_test_sigmaker.TestSignatureSearcherFromMany
```

Expected: failures show single nibbles/glued hex/colon input are still normalized and semicolons still create multiple batch entries.

- [ ] **Step 3: Implement strict token parsing and newline-only splitting**

Replace `_normalize_loose_hex()` with an explicit chunk parser. Strip at most one balanced outer `()` or `[]`, split only on whitespace/comma/semicolon, accept exact tokens or complete repeated escaped/prefixed-byte chunks, and return `""` for any unknown chunk:

```python
_EXPLICIT_TOKEN = re.compile(r"(?:[0-9A-Fa-f]{2}|[0-9A-Fa-f]\?|\?[0-9A-Fa-f]|\?\??)")
_ESCAPED_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
_PREFIXED_RUN = re.compile(r"(?:0x[0-9A-Fa-f]{2})+")

@classmethod
def _normalize_explicit_pattern(cls, input_str: str) -> str:
    text = input_str.strip()
    if len(text) >= 2 and (text[0], text[-1]) in {("(", ")"), ("[", "]")}:
        text = text[1:-1].strip()
    elif any(ch in text for ch in "()[]"):
        return ""

    tokens: list[str] = []
    for chunk in re.split(r"[\s,;]+", text):
        if not chunk:
            continue
        if cls._ESCAPED_RUN.fullmatch(chunk):
            tokens.extend(match[2:].upper() for match in cls._ESCAPED_HEX.findall(chunk))
        elif cls._PREFIXED_RUN.fullmatch(chunk):
            tokens.extend(match[2:].upper() for match in re.findall(r"0x[0-9A-Fa-f]{2}", chunk))
        elif cls._EXPLICIT_TOKEN.fullmatch(chunk):
            tokens.append("?" if chunk in {"?", "??"} else chunk.upper())
        else:
            return ""
    return " ".join(tokens)
```

Keep mask parsing, but accept it only when a recognized mask occupies the end
of the stripped input and everything before it is a complete escaped-byte or
`0xHH` expression. Use full matches so declaration/prose prefixes cannot be
ignored:

```python
escaped_expression = re.compile(r"(?:\\x[0-9A-Fa-f]{2}|[\s,;])+")
prefixed_expression = re.compile(r"(?:0x[0-9A-Fa-f]{2}|[\s,;])+")

mask_match = cls._MASK_REGEX.search(text) or cls._BINARY_MASK_REGEX.search(text)
if mask_match is not None:
    if text[mask_match.end():].strip():
        return ""
    byte_expression = text[:mask_match.start()].strip()
    if escaped_expression.fullmatch(byte_expression):
        byte_tokens = cls._ESCAPED_HEX.findall(byte_expression)
    elif prefixed_expression.fullmatch(byte_expression):
        byte_tokens = re.findall(r"0x[0-9A-Fa-f]{2}", byte_expression)
    else:
        return ""
    mask_text = mask_match.group(0)
    mask = (
        "".join("x" if bit == "1" else "?" for bit in mask_text[2:][::-1])
        if mask_text.startswith("0b")
        else mask_text
    )
    if len(byte_tokens) != len(mask):
        return ""
    return cls._masked_bytes_to_ida(byte_tokens, mask, slice_from=2)
```

Change `_split_statements()` to append at most one stripped, comment-free
statement per source line.

- [ ] **Step 4: Run focused and parser-adjacent tests**

Run the Step 2 command plus:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestSigTextAndSignatureParsing
```

Expected: all selected tests pass; `SigText.normalize()` remains permissive internally while `SignatureParser.parse()` is strict.

- [ ] **Step 5: Commit the parser boundary**

```bash
git add src/sigmaker/__init__.py tests/unit_test_sigmaker.py
git commit -m "fix: make signature input parsing explicit"
```

---

### Task 2: Single-Authority Match Metadata and Lazy File Offsets

**Files:**
- Modify: `tests/unit_test_sigmaker.py:1490-1661`
- Modify: `tests/unit_test_sigmaker.py:1734-2080`
- Modify: `src/sigmaker/__init__.py:655-722`
- Modify: `src/sigmaker/__init__.py:2461-2965`
- Modify: `src/sigmaker/__init__.py:3160-3355`

**Interfaces:**
- Consumes: frozen `Match(address, *, rva=None, file_offset=None)`.
- Produces: `SearchResults.file_offset_for_match(hit) -> Optional[int]` backed by private `_file_offset_cache`; `find_all(..., *, imagebase=None)` constructs enriched `Match` objects directly.

- [ ] **Step 1: Add tests for immutable match reuse and lazy positive/negative offset caching**

Replace tests that mutate `SearchResults.imagebase` or pass `file_offsets=` with enriched `Match` values. Add:

```python
def test_search_constructs_enriched_match_once(self):
    with patch.object(sigmaker.idaapi, "get_imagebase", return_value=0x1000), patch.object(
        sigmaker.SignatureSearcher, "find_all", return_value=[sigmaker.Match(0x1100, rva=0x100)]
    ) as find_all:
        result = sigmaker.SignatureSearcher.from_signature("90").search()
    find_all.assert_called_once_with("90", scope=None, imagebase=0x1000)
    self.assertEqual(result.matches, [sigmaker.Match(0x1100)])
    self.assertEqual(result.matches[0].rva, 0x100)

def test_file_offset_lookup_caches_available_and_unavailable_results(self):
    result = sigmaker.SearchResults([sigmaker.Match(0x1000), sigmaker.Match(0x2000)], "90")
    with patch.object(sigmaker.SearchResults, "_file_offset_for_ea", side_effect=[0x400, None]) as lookup:
        self.assertEqual(result.file_offset_for_match(result.matches[0]), 0x400)
        self.assertEqual(result.file_offset_for_match(result.matches[0]), 0x400)
        self.assertIsNone(result.file_offset_for_match(result.matches[1]))
        self.assertIsNone(result.file_offset_for_match(result.matches[1]))
    self.assertEqual(lookup.call_count, 2)
```

Update formatter fixtures to construct `Match(..., rva=..., file_offset=...)` rather than populate result-level metadata.

- [ ] **Step 2: Run metadata and formatter tests and verify failures**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestSignatureSearcherInput \
  tests.unit_test_sigmaker.TestBatchSignatureSearcher \
  tests.unit_test_sigmaker.TestBatchSearchFormatters
```

Expected: failures show `SearchResults` still owns public `imagebase/file_offsets`, rebuilds matches, and does not cache unavailable offsets.

- [ ] **Step 3: Remove duplicate result metadata and construct enriched matches in scan paths**

Keep the first two `SearchResults` fields unchanged, remove public `imagebase` and `file_offsets`, remove `_apply_match_metadata()`, and add:

```python
#: Lazily resolved file offsets, including cached unavailable values.
_file_offset_cache: dict[int, typing.Optional[int]] = dataclasses.field(
    default_factory=dict, init=False, repr=False
)

def rva_for_match(self, hit: Match) -> typing.Optional[int]:
    return hit.rva

def file_offset_for_match(self, hit: Match) -> typing.Optional[int]:
    if hit.file_offset is not None:
        return hit.file_offset
    ea = int(hit)
    if ea not in self._file_offset_cache:
        self._file_offset_cache[ea] = self._file_offset_for_ea(ea)
    return self._file_offset_cache[ea]
```

Add keyword-only `imagebase: Optional[int] = None` to `find_all()` and `_find_all_simd()`. Construct each hit once:

```python
def make_match(address: int) -> Match:
    rva = None if imagebase is None else address - imagebase
    return Match(address, rva=rva)
```

Use the same construction for IDA and SIMD hits. In `SignatureSearcher.search()`, resolve imagebase once and pass it to `find_all()`.
Remove the per-entry `imagebase` key from `SearchResults.to_record()`; the
batch-level `BatchSearchResults.imagebase` remains the single serialized
imagebase authority.

- [ ] **Step 4: Run focused tests and confirm no eager file-offset calls**

Run the Step 2 command. Expected: all selected tests pass, and batch-search mocks assert `idaapi.get_fileregion_offset` was not called before formatting.

- [ ] **Step 5: Commit metadata simplification**

```bash
git add src/sigmaker/__init__.py tests/unit_test_sigmaker.py
git commit -m "perf: resolve batch file offsets lazily"
```

---

### Task 3: Shared Scope Resolution and One Reused Batch Buffer

**Files:**
- Modify: `tests/unit_test_sigmaker.py:1734-1896`
- Modify: `tests/unit_test_sigmaker.py:5249-5395`
- Modify: `src/sigmaker/__init__.py:3140-3460`

**Interfaces:**
- Consumes: `InMemoryBuffer.load(mode=SEGMENTS, scope_ea=None)` and `SignatureSearcher.find_all(..., scope=..., imagebase=...)`.
- Produces: `SignatureSearcher._scope_for_ea(scope_ea) -> Optional[tuple[int, int]]`; keyword-only `BatchSignatureSearcher.search(*, buf=None, scope_ea=None)`.

- [ ] **Step 1: Add scope, buffer-conflict, and one-load tests**

Add tests that assert:

```python
def test_batch_rejects_buffer_and_scope_together(self):
    with self.assertRaisesRegex(ValueError, "buf.*scope_ea"):
        sigmaker.BatchSignatureSearcher.from_text("90").search(buf=MagicMock(), scope_ea=0x1010)

def test_batch_reuses_one_automatic_simd_buffer(self):
    loaded = MagicMock()
    loaded.imagebase = 0x1000
    with patch.object(sigmaker, "SIMD_SPEEDUP_AVAILABLE", True), patch.object(
        sigmaker.InMemoryBuffer, "load", return_value=loaded
    ) as load, patch.object(sigmaker.SignatureSearcher, "find_all", return_value=[] ) as find_all:
        sigmaker.BatchSignatureSearcher.from_text("first = 90\nsecond = CC").search()
    load.assert_called_once_with(mode=sigmaker.InMemoryBuffer.LoadMode.SEGMENTS)
    self.assertEqual(find_all.call_count, 2)
    self.assertTrue(all(call.kwargs["buf"] is loaded for call in find_all.call_args_list))

def test_invalid_batch_does_not_load_simd_buffer(self):
    with patch.object(sigmaker, "SIMD_SPEEDUP_AVAILABLE", True), patch.object(
        sigmaker.InMemoryBuffer, "load"
    ) as load:
        result = sigmaker.BatchSignatureSearcher.from_text("bad = random prose").search()
    load.assert_not_called()
    self.assertEqual(result[0].status, "error")
```

Add IDA and SIMD cases proving a valid `scope_ea` resolves to one segment and an address outside any segment falls back to whole-database behavior.

- [ ] **Step 2: Run focused scope and batch tests and verify failures**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestBatchSignatureSearcher \
  tests.unit_test_sigmaker.TestSearchScope
```

Expected: batch rejects `scope_ea` as an unexpected keyword and does not automatically load/reuse a buffer.

- [ ] **Step 3: Implement shared scope and lazy buffer reuse**

Extract the existing segment lookup into:

```python
@staticmethod
def _scope_for_ea(scope_ea: typing.Optional[int]) -> typing.Optional[tuple[int, int]]:
    if scope_ea is None:
        return None
    seg = idaapi.getseg(scope_ea)
    if seg is None:
        return None
    return int(seg.start_ea), int(seg.end_ea)
```

Make batch `search()` keyword-only. Reject `buf` plus `scope_ea`, resolve scope once, and lazily load `active_buf` only when the first valid uncached signature needs a SIMD scan. Pass `scope` to IDA search; for SIMD, load the scoped/all-segment buffer once and pass it to every unique scan. Derive batch imagebase from the active buffer when one is loaded.

- [ ] **Step 4: Run scope, batch, and existing address-mapping tests**

Run the Step 2 command plus:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestSearchAddressMapping \
  tests.unit_test_sigmaker.TestSegmentScope
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit scope and buffer behavior**

```bash
git add src/sigmaker/__init__.py tests/unit_test_sigmaker.py
git commit -m "perf: reuse one scoped buffer for batch search"
```

---

### Task 4: Real Cancellation Propagation for Batch Scans

**Files:**
- Modify: `tests/unit_test_sigmaker.py:1734-1896`
- Modify: `tests/unit_test_sigmaker.py:2559-2717`
- Modify: `src/sigmaker/__init__.py:3209-3355`

**Interfaces:**
- Consumes: existing `UserCanceledError` and partial-result behavior.
- Produces: keyword-only `raise_on_cancel: bool = False` on `find_all()` and `_find_all_simd()`; batch always passes `True`.

- [ ] **Step 1: Replace the mock-only batch cancellation test with real IDA/SIMD branch tests**

Drive `find_all()` itself. For IDA, return one hit and then make `idaapi_user_canceled()` true; for SIMD, set `_CANCEL_POLL_STRIDE = 1`, return a match from `_simd_scan_bytes`, and then report cancellation. Assert batch raises `UserCanceledError` and ordinary direct `find_all()` still returns the partial list.

```python
with patch.object(sigmaker, "SIMD_SPEEDUP_AVAILABLE", False), patch.object(
    sigmaker, "idaapi_user_canceled", side_effect=[False, True]
), patch.object(sigmaker.idaapi, "bin_search", return_value=(0x1000, 0)):
    with self.assertRaises(sigmaker.UserCanceledError):
        sigmaker.BatchSignatureSearcher.from_text("90").search()
```

- [ ] **Step 2: Run cancellation tests and verify batch currently returns partial success**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestBatchSignatureSearcher \
  tests.unit_test_sigmaker.TestSearchCancellation
```

Expected: new batch cancellation cases fail because the production scan loops break and return partial matches.

- [ ] **Step 3: Add opt-in cancellation raising to both scan paths**

At each cancellation check:

```python
if idaapi_user_canceled():
    LOGGER.info("Search canceled by user")
    if raise_on_cancel:
        raise UserCanceledError("Search canceled by user")
    break
```

Thread the keyword through `find_all()` to `_find_all_simd()`. Batch passes `raise_on_cancel=True`; existing callers omit it.

- [ ] **Step 4: Run cancellation, batch, and uniqueness tests**

Run the Step 2 command plus:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestSignatureSearcherCountMatches
```

Expected: all selected tests pass and direct legacy cancellation still returns partial results.

- [ ] **Step 5: Commit cancellation behavior**

```bash
git add src/sigmaker/__init__.py tests/unit_test_sigmaker.py
git commit -m "fix: propagate canceled batch searches"
```

---

### Task 5: Formatter Laziness and Complete-Path Performance Regression

**Files:**
- Modify: `tests/unit_test_sigmaker.py:1897-2080`
- Modify: `tests/performance_test.py`
- Modify: `examples/batch_search_c_formatter.py`
- Modify: `src/sigmaker/__init__.py:2780-2965`

**Interfaces:**
- Consumes: `SearchResults.file_offset_for_match(hit)` lazy cache and `Match.rva`.
- Produces: text preview resolves only previewed offsets; CSV/JSON resolve all emitted offsets; custom C example uses the lazy result helper.

- [ ] **Step 1: Add formatter lookup-count and 100,000-hit search tests**

Add tests proving text resolves only `max_preview_matches`, CSV/JSON resolve each unique emitted address, repeated formatting reuses positive and negative cache entries, and search itself resolves none:

```python
def test_batch_search_does_not_resolve_file_offsets_for_many_hits(self):
    hits = [sigmaker.Match(0x1000 + index, rva=index) for index in range(100_000)]
    with patch.object(sigmaker.SignatureSearcher, "find_all", return_value=hits), patch.object(
        sigmaker.SearchResults, "_file_offset_for_ea"
    ) as lookup:
        results = sigmaker.BatchSignatureSearcher.from_text("90").search(buf=MagicMock(imagebase=0x1000))
    lookup.assert_not_called()
    self.assertEqual(results[0].match_count, 100_000)
    self.assertIs(results[0].matches[0], hits[0])
```

- [ ] **Step 2: Run formatter and performance tests and verify failures**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.unit_test_sigmaker.TestBatchSearchFormatters \
  tests.performance_test
```

Expected: lookup-count assertions expose eager search-time offset work until Tasks 2-3 are complete; after those tasks, only any stale formatter assumptions fail.

- [ ] **Step 3: Update built-in and example formatters**

Use `hit.rva` for RVA output and `entry.file_offset_for_match(hit)` only at serialization time. Remove assumptions that `hit.file_offset` is populated by batch search. Keep `f"{results:csv}"`, registry decorators, suffix selection, and output schemas unchanged.

- [ ] **Step 4: Run formatter, full performance, and standalone perf guards**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest tests.performance_test --buffer
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python tests/perf/adversarial_refine.py --check
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python tests/perf/working_set_sweep.py --check
```

Expected: all tests and guards pass with no regression report.

- [ ] **Step 5: Commit formatter/performance coverage**

```bash
git add src/sigmaker/__init__.py tests/unit_test_sigmaker.py tests/performance_test.py examples/batch_search_c_formatter.py
git commit -m "test: guard batch search metadata costs"
```

---

### Task 6: Real-IDA Integration, Documentation, and PR Accuracy

**Files:**
- Modify: `tests/integration_test_sigmaker.py:253-312`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `examples/batch_search_c_formatter.py`
- Modify: GitHub PR #57 body

**Interfaces:**
- Consumes: final strict parser, scoped batch search, lazy metadata, and registered formatter APIs.
- Produces: a real-binary batch integration witness and accurate user-facing behavior documentation.

- [ ] **Step 1: Add one real-IDA batch integration test**

Use the existing fixture binary and a known matching signature. Search named duplicate patterns plus one valid no-match pattern, then assert duplicate cache behavior indirectly through equal matches, RVA metadata, JSON/CSV serialization, and no parse errors:

```python
def test_batch_signature_search_against_real_binary(self):
    results = sigmaker.BatchSignatureSearcher.from_text(
        "first := 48 8B ? 48 89\nsecond = 48 8B ?? 48 89\nmissing = DE AD BE EF"
    ).search()
    self.assertEqual(len(results), 3)
    self.assertEqual(results[0].matches, results[1].matches)
    self.assertTrue(all(hit.rva is not None for hit in results[0].matches))
    self.assertEqual(results[2].status, "no_matches")
    self.assertEqual(json.loads(f"{results:json}")["entry_count"], 3)
```

- [ ] **Step 2: Run the real-IDA test when the local idapro runtime is available**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest \
  tests.integration_test_sigmaker.TestIntegrationWithRealBinary.test_batch_signature_search_against_real_binary
```

Expected: PASS under idalib; if local licensing/runtime blocks it, record that exact limitation and rely on the existing Docker CI matrix before merge.

- [ ] **Step 3: Update README, changelog, and C formatter guidance**

Document accepted strict forms and rejected examples, state that arbitrary malformed input is no longer guessed, show newline-only batch input with semicolon byte separators, explain lazy file-offset cost, and preserve the `idapythonrc.py` copy-in registration example. Remove any wording that says semicolons separate batch entries or offsets are populated eagerly.

- [ ] **Step 4: Run complete local verification**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest tests.unit_test_sigmaker
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m unittest tests.performance_test --buffer
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pyenv exec python -m py_compile src/sigmaker/__init__.py examples/batch_search_c_formatter.py tests/unit_test_sigmaker.py tests/integration_test_sigmaker.py
git diff --check
rg -n "sigmogger|RBLX|semicolon-separated entries" README.md CHANGELOG.md examples src tests
```

Expected: unit and performance suites pass, compilation and whitespace checks are clean, and the forbidden/stale wording scan has no matches.

- [ ] **Step 5: Commit integration and documentation**

```bash
git add README.md CHANGELOG.md examples/batch_search_c_formatter.py tests/integration_test_sigmaker.py
git commit -m "docs: describe strict batch signature search"
```

- [ ] **Step 6: Update PR #57 and push the verified branch**

Update the PR body to describe newline-only batch entries, strict input rejection, automatic one-buffer reuse, lazy file-offset resolution, cancellation propagation, exact local test commands with `PYTHONPATH=src`, and the final test count. Push `codex/batch-signature-search`, then inspect the live checks and Copilot review state.
