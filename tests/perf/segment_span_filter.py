#!/usr/bin/env python
"""Compare Python and Cython segment-span candidate filtering.

This is a reporting benchmark, not a wall-clock CI assertion. It fails only
when the implementations disagree. Build the extension before running:

    pyenv exec pip install -e .
    PYTHONPATH=src pyenv exec python tests/perf/segment_span_filter.py
"""

import array
import pathlib
import sys
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

with patch.dict("sys.modules", {"idaapi": MagicMock(), "idc": MagicMock()}):
    import sigmaker


SEGMENT_SIZE = 4096
SEGMENT_COUNT = 1024
PATTERN_SIZE = 16


def _best(function, iterations=5):
    best_elapsed = None
    result = None
    for _ in range(iterations):
        start = time.perf_counter()
        result = function()
        elapsed = time.perf_counter() - start
        best_elapsed = elapsed if best_elapsed is None else min(best_elapsed, elapsed)
    return best_elapsed, result


def _benchmark_direct_single_span() -> None:
    data = memoryview((b"\x90" + b"\x00" * 15) * (1 << 18))
    signature = sigmaker._SimdSignature("90")
    size = len(data)

    def original_loop():
        count = 0
        offset = 0
        while offset < size:
            index = sigmaker._simd_scan_bytes(data[offset:], signature)
            if index < 0:
                break
            count += 1
            offset += index + 1
        return count

    def segmented_loop():
        count = 0
        segment_start = 0
        for segment_end in (size,):
            offset = segment_start
            while offset < segment_end:
                index = sigmaker._simd_scan_bytes(
                    data[offset:segment_end], signature
                )
                if index < 0:
                    break
                count += 1
                offset += index + 1
            segment_start = segment_end
        return count

    original_elapsed, original_count = _best(original_loop)
    segmented_elapsed, segmented_count = _best(segmented_loop)
    if segmented_count != original_count:
        raise AssertionError("Segmented direct scan changed the match count")

    delta = segmented_elapsed / original_elapsed - 1
    print("\ndirect single-span scan:")
    print(f"hits:        {original_count:,}")
    print(f"original:    {original_elapsed * 1000:.3f} ms")
    print(f"segmented:   {segmented_elapsed * 1000:.3f} ms")
    print(f"delta:       {delta:+.1%}")


def main() -> None:
    if not sigmaker.SIMD_SPEEDUP_AVAILABLE:
        raise RuntimeError("SIMD extension is not built; run: pip install -e .")

    total_size = SEGMENT_SIZE * SEGMENT_COUNT
    candidate_list = list(range(0, total_size, 4))
    segment_ends = array.array(
        "Q", range(SEGMENT_SIZE, total_size + 1, SEGMENT_SIZE)
    )

    start = time.perf_counter()
    python_candidates = sigmaker._filter_offsets_by_segment_ends(
        candidate_list,
        PATTERN_SIZE,
        segment_ends,
    )
    python_elapsed = time.perf_counter() - start

    cython_candidates = array.array("I", candidate_list)
    start = time.perf_counter()
    cython_count = sigmaker.simd_scan.filter_offsets_by_segment_ends(
        cython_candidates,
        len(cython_candidates),
        PATTERN_SIZE,
        segment_ends,
    )
    cython_elapsed = time.perf_counter() - start

    actual = list(cython_candidates[:cython_count])
    if actual != python_candidates:
        raise AssertionError("Python and Cython segment-span filters disagree")

    ratio = python_elapsed / cython_elapsed if cython_elapsed else float("inf")
    print(f"candidates: {len(candidate_list):,}")
    print(f"survivors:  {cython_count:,}")
    print(f"python:     {python_elapsed * 1000:.3f} ms")
    print(f"cython:     {cython_elapsed * 1000:.3f} ms")
    print(f"ratio:      {ratio:.2f}x")
    _benchmark_direct_single_span()


if __name__ == "__main__":
    main()
