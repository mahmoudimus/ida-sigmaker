#!/usr/bin/env python
"""Report segment-safe scan and candidate-filter overhead.

This benchmark has no wall-clock assertions. It fails only when the compared
implementations produce different results. Build the extension before running:

    pip install -e .
    PYTHONPATH=src python tests/perf/segment_span_filter.py
"""

import array
import pathlib
import statistics
import sys
import time
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

with patch.dict("sys.modules", {"idaapi": MagicMock(), "idc": MagicMock()}):
    import sigmaker


SEGMENT_SIZE = 4096
SEGMENT_COUNT = 1024
PATTERN_SIZE = 16


def _speedups_module():
    module = sigmaker._Speedups.current().module
    if module is None:
        raise RuntimeError("SIMD extension is not built; run: pip install -e .")
    return module


def _interleaved_medians(left, right, iterations=7):
    left()
    right()
    left_elapsed = []
    right_elapsed = []
    left_result = None
    right_result = None
    for iteration in range(iterations):
        functions = ((left, left_elapsed), (right, right_elapsed))
        if iteration % 2:
            functions = reversed(functions)
        for function, elapsed_samples in functions:
            start = time.perf_counter()
            result = function()
            elapsed_samples.append(time.perf_counter() - start)
            if function is left:
                left_result = result
            else:
                right_result = result
    return (
        statistics.median(left_elapsed),
        left_result,
        statistics.median(right_elapsed),
        right_result,
    )


def _python_filter(candidates, pattern_size, range_starts, range_ends):
    range_index = 0
    survivors = []
    for start in candidates:
        while (
            range_index < len(range_ends)
            and start >= range_ends[range_index]
        ):
            range_index += 1
        if range_index == len(range_ends):
            break
        if (
            start >= range_starts[range_index]
            and start + pattern_size <= range_ends[range_index]
        ):
            survivors.append(start)
    return survivors


def _benchmark_direct_single_range():
    payload = bytearray((b"\x90" + b"\x00" * 15) * (1 << 18))
    data = memoryview(payload)
    speedups = _speedups_module()
    signature = speedups.Signature("90")
    size = len(data)

    def original_loop():
        offsets = []
        offset = 0
        since_poll = 0
        cancel_requested = sigmaker.UIServices.current().cancel_requested
        while offset < size:
            since_poll += 1
            if since_poll >= sigmaker._CANCEL_POLL_STRIDE:
                since_poll = 0
                if cancel_requested():
                    break
            index = speedups.scan_bytes(data[offset:], signature)
            if index < 0:
                break
            offsets.append(offset + index)
            offset += index + 1
        return offsets

    buf = sigmaker.InMemoryBuffer(file_path=pathlib.Path("/x"))
    buf._buffer = payload
    buf._segments.append((0, 0x1000, size))

    def range_loop():
        return sigmaker.SignatureSearcher._scan_simd_ranges(
            signature,
            buf,
            offsets_only=True,
        )

    (
        original_elapsed,
        original_offsets,
        range_elapsed,
        range_offsets,
    ) = _interleaved_medians(original_loop, range_loop)
    if range_offsets != original_offsets:
        raise AssertionError("Range iteration changed the direct match count")

    delta = range_elapsed / original_elapsed - 1
    print("\ndirect single-range scan:")
    print(f"hits:       {len(original_offsets):,}")
    print(f"original:   {original_elapsed * 1000:.3f} ms")
    print(f"range:      {range_elapsed * 1000:.3f} ms")
    print(f"delta:      {delta:+.1%}")


def _benchmark_candidate_refinement(
    candidate_list,
    total_size,
    range_starts,
    range_ends,
):
    data = memoryview(bytearray(b"\x90" * total_size))
    signature = sigmaker.Signature(
        [
            sigmaker.SignatureByte(0x90, False),
            sigmaker.SignatureByte(0x90, False),
        ]
    )
    search_ranges = (range_starts, range_ends)

    def temporary_copy_path():
        refined = [
            candidate
            for candidate in candidate_list
            if candidate + 1 < len(data) and data[candidate + 1] == 0x90
        ]
        candidates = array.array("Q", refined)
        count = sigmaker._filter_offsets_into_search_ranges(
            candidates,
            len(candidates),
            len(signature),
            *search_ranges,
        )
        return candidates, count

    def persistent_array_path():
        candidates = array.array("Q", candidate_list)
        count = sigmaker._refine_candidate_offsets(
            data,
            candidates,
            len(candidates),
            signature,
            1,
            search_ranges,
        )
        return candidates, count

    (
        temporary_elapsed,
        temporary_result,
        persistent_elapsed,
        persistent_result,
    ) = _interleaved_medians(
        temporary_copy_path,
        persistent_array_path,
    )
    temporary_candidates, temporary_count = temporary_result
    persistent_candidates, persistent_count = persistent_result
    if (
        list(temporary_candidates[:temporary_count])
        != list(persistent_candidates[:persistent_count])
    ):
        raise AssertionError("Candidate refinement paths disagree")

    print("\ncandidate refinement and range compaction:")
    print(f"candidates: {len(candidate_list):,}")
    print(f"temporary:  {temporary_elapsed * 1000:.3f} ms")
    print(f"persistent: {persistent_elapsed * 1000:.3f} ms")
    print(f"speedup:    {temporary_elapsed / persistent_elapsed:.2f}x")


def main():
    speedups = _speedups_module()

    total_size = SEGMENT_SIZE * SEGMENT_COUNT
    candidate_list = list(range(0, total_size, 4))
    range_starts = array.array(
        "Q", range(0, total_size, SEGMENT_SIZE)
    )
    range_ends = array.array(
        "Q", range(SEGMENT_SIZE, total_size + 1, SEGMENT_SIZE)
    )

    def python_filter():
        return _python_filter(
            candidate_list,
            PATTERN_SIZE,
            range_starts,
            range_ends,
        )

    def converted_cython_filter():
        candidates = array.array("I", candidate_list)
        count = speedups.filter_offsets_by_search_ranges(
            candidates,
            len(candidates),
            PATTERN_SIZE,
            range_starts,
            range_ends,
        )
        return candidates, count

    (
        python_elapsed,
        expected,
        converted_elapsed,
        converted_result,
    ) = _interleaved_medians(python_filter, converted_cython_filter)
    converted_candidates, converted_count = converted_result

    inplace_samples = []
    for _ in range(7):
        candidates = array.array("I", candidate_list)
        start = time.perf_counter()
        speedups.filter_offsets_by_search_ranges(
            candidates,
            len(candidates),
            PATTERN_SIZE,
            range_starts,
            range_ends,
        )
        inplace_samples.append(time.perf_counter() - start)
    inplace_elapsed = statistics.median(inplace_samples)

    if list(converted_candidates[:converted_count]) != expected:
        raise AssertionError("Python and Cython range filters disagree")

    converted_ratio = python_elapsed / converted_elapsed
    inplace_ratio = python_elapsed / inplace_elapsed
    print(f"candidates: {len(candidate_list):,}")
    print(f"survivors:  {converted_count:,}")
    print(
        "array bytes: "
        f"{len(candidates) * candidates.itemsize:,} candidates + "
        f"{(len(range_starts) + len(range_ends)) * range_starts.itemsize:,} ranges"
    )
    print(f"python:     {python_elapsed * 1000:.3f} ms")
    print(f"converted:  {converted_elapsed * 1000:.3f} ms")
    print(f"in-place:   {inplace_elapsed * 1000:.3f} ms")
    print(f"ratios:     {converted_ratio:.2f}x / {inplace_ratio:.2f}x")
    _benchmark_candidate_refinement(
        candidate_list,
        total_size,
        range_starts,
        range_ends,
    )
    _benchmark_direct_single_range()


if __name__ == "__main__":
    main()
