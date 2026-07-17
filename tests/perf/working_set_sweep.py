#!/usr/bin/env python
"""Working-set sweep for the refine kernel.

Answers a different question than adversarial_refine.py. That harness shows
refine is *sequential/bandwidth-bound* when the candidate set is dense (sorted
positions a few bytes apart, so mv[p+j] streams). This one isolates the other
axis: what happens to the *same* kernel, doing the *same* number of probes,
when the bytes it touches no longer fit in cache.

Method: hold the candidate count N fixed, and spread those N candidates evenly
across a buffer of growing size S. The refine kernel reads mv[p+j] once per
candidate, so the instruction count is identical at every S. Only the stride
between probes grows (stride = S / N), which walks the access pattern from
"contiguous, prefetchable" at small S to "one cache line, then one page, per
probe" at large S. If the cost per candidate were compute-bound it would stay
flat. It does not: it tracks the cache hierarchy. That is the proof that the
lever for this kernel is memory traffic, not arithmetic, so vectorizing the
byte compare cannot help.

Pure buffer: no idalib, no .i64, deterministic, sweepable. Run native (the
docker image emulates amd64 and has no real cache to measure):
    ~/.pyenv/versions/sig310/bin/python tests/perf/working_set_sweep.py
Build the extension first: python setup.py build_ext --inplace
"""
import array
import pathlib
import random
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))
from unittest.mock import MagicMock, patch  # noqa: E402

with patch.dict("sys.modules", {"idaapi": MagicMock(), "idc": MagicMock()}):
    import sigmaker  # noqa: E402

assert sigmaker._Speedups.current().available, (
    "extension not built; run: python setup.py build_ext --inplace"
)

# Fixed across the whole sweep: same probe count at every footprint.
N = 2_000_000
J = 1            # refine offset; mv[p+J] is the probed byte
SEED = 0x5EED


def _make_buffer(size, chunk=1 << 22):
    """A real (non-dedupable) random buffer of `size` bytes. randbytes is
    chunked because Random.randbytes builds an int of n*8 bits and overflows a
    C int for large n; all-zero buffers are skipped so page dedup can't make
    the access pattern look artificially cache-friendly."""
    rng = random.Random(SEED)
    parts = []
    remaining = size
    while remaining > 0:
        c = min(chunk, remaining)
        parts.append(rng.randbytes(c))
        remaining -= c
    return b"".join(parts)


def _best(fn, iters):
    best = None
    for _ in range(iters):
        dt = fn()
        best = dt if best is None else min(best, dt)
    return best


def bench(footprint, iters=5):
    """Spread N candidates evenly over `footprint` bytes and time one refine
    step. stride = footprint / N grows with the footprint while N (the probe
    count) stays fixed, so any change in ns/cand is the memory system, not the
    work."""
    size = max(footprint, N + J + 1)
    stride = max(1, (size - J - 1) // N)
    size = stride * N + J + 1            # tighten footprint to N*stride
    buf = _make_buffer(size)
    mv = memoryview(buf)
    positions = array.array("I", range(0, stride * N, stride))
    assert len(positions) == N

    def one_step():
        arr = array.array("I", positions)    # fresh copy (refine compacts)
        t0 = time.perf_counter()
        sigmaker._refine_offsets_into(mv, arr, N, J, 0x00, 0x00)
        return time.perf_counter() - t0

    # value=0x00, mask=0x00 => (byte & 0) == 0 is always true: every probe is
    # read and kept, so the timed work is exactly "N probes of mv[p+J]".
    t = _best(one_step, iters)
    return {
        "footprint_mb": size / (1 << 20),
        "stride": stride,
        "t_ms": t * 1e3,
        "ns_per_cand": t / N * 1e9,
    }


def main(check=False):
    print("=" * 70)
    print("WORKING-SET SWEEP -- refine kernel, fixed N=%d probes, J=%d" % (N, J))
    print("=" * 70)
    print(f"{'footprint(MB)':>14} {'stride(B)':>10} {'t_step(ms)':>11} "
          f"{'ns/cand':>9}")
    rows = []
    for mb in (2, 8, 32, 64, 128, 256, 512):
        r = bench(mb << 20)
        rows.append(r)
        print(f"{r['footprint_mb']:>14.1f} {r['stride']:>10} "
              f"{r['t_ms']:>11.2f} {r['ns_per_cand']:>9.3f}")
    print("\nReading: ns/cand is the per-candidate refine cost. Same N probes "
          "at every row, only the footprint (stride) changes. Flat ns/cand "
          "would mean compute-bound; ns/cand that climbs with footprint means "
          "the kernel is memory-bound (each probe increasingly misses cache), "
          "so the byte compare is never the bottleneck and vectorizing it "
          "cannot help. The lever is fewer/closer memory touches.")

    if check:
        ns = [r["ns_per_cand"] for r in rows]
        ratio = max(ns) / min(ns)
        print(f"\n[check] ns/cand spread small..large footprint: "
              f"{ratio:.2f}x  (want > 3.0: a real cache cliff)")
        assert ratio > 3.0, (
            "ns/cand stayed flat across the cache hierarchy: refine no longer "
            "looks memory-bound on this machine (smarter prefetch? buffer fits "
            "a larger cache?) -- re-examine the memory-bound claim"
        )
        print("[check] PASS: refine cost tracks the cache hierarchy "
              "(memory-bound, not compute-bound).")


if __name__ == "__main__":
    main(check="--check" in sys.argv)
