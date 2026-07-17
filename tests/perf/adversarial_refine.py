#!/usr/bin/env python
"""Adversarial refine microbenchmark.

Settles "is the block-refine (Upgrade 1) or spaced-intersection (Upgrade 2)
upgrade ever worth building?" by constructing the synthetic input that forces
each upgrade's regime and timing the buffer-level kernels in isolation:

  - _ByteIndex.build         (index build)
  - simd_scan.seed_offsets   (seed map; Phase 5)
  - _refine_offsets_into     (refine)

Both upgrades only matter when refine is the dominant line. This harness
manufactures exactly that, in each upgrade's sub-shape:

  Upgrade 1 wants long contiguous exact runs (word compare replaces N scalar
            steps): make_u1 -> a single long 0x00 run with alpha ~ 1.
  Upgrade 2 wants a large candidate set probed across a cache-busting buffer
            (sequential bucket-gallop vs random D-probes): make_u2 -> a big
            small-alphabet buffer with a huge single-byte seed bucket.

Key thing it measures for Upgrade 2: our candidate array is ALWAYS sorted
ascending (the index bucket is sorted; seed_offsets and refine preserve order),
so refine's D-probes are at monotonically increasing addresses, not random.
The throughput sweep below shows whether refine is latency-bound (random, which
Upgrade 2 could beat) or already bandwidth-bound/sequential (which it cannot).

Pure buffer: no idalib, no .i64, deterministic, sweepable. Run:
    pyenv exec python tests/perf/adversarial_refine.py
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


def _speedups_module():
    module = sigmaker._Speedups.current().module
    if module is None:
        raise RuntimeError("extension not built; run: python setup.py build_ext --inplace")
    return module


def _best(fn, iters):
    best = None
    for _ in range(iters):
        dt = fn()
        best = dt if best is None else min(best, dt)
    return best


# --------------------------------------------------------------------------
# Upgrade 1: long contiguous exact run, alpha ~ 1 (candidate set barely shrinks)
# --------------------------------------------------------------------------
def make_u1(L, tail=b"\xDE\xAD\xBE\xEF\xCA\xFE\x13\x37"):
    """A long 0x00 run on both sides of a unique tail: the seed on '00 00'
    matches ~everywhere and stays matching across K contiguous exact 0x00
    bytes, so sum|M_r| ~= K * C0 (the worst-case R*C0 made real)."""
    return b"\x00" * L + tail + b"\x00" * L


def bench_u1(L, K, iters=3):
    D = make_u1(L)
    mv = memoryview(D)
    n = len(mv)
    speedups = _speedups_module()
    t_idx = _best(lambda: _time(lambda: sigmaker._ByteIndex.build(mv)), 1)
    idx = sigmaker._ByteIndex.build(mv)
    base = idx.candidates(0x0000)          # ascending absolute positions, key 00 00
    C0 = len(base)

    def one_refine_chain():
        arr = array.array("I", base)       # fresh mutable copy
        count = len(arr)
        t0 = time.perf_counter()
        for j in range(1, K):
            count = sigmaker._refine_offsets_into(mv, arr, count, j, 0x00, 0xFF)
        return time.perf_counter() - t0

    # seed-map cost over the same bucket, for "is refine the dominant line?"
    t_seed = _best(lambda: _time(
        lambda: speedups.seed_offsets(base, 0, K, n)), iters)
    t_refine = _best(one_refine_chain, iters)
    steps = max(1, K - 1)
    touched = steps * C0
    return {
        "scenario": "u1", "L": L, "K": K, "C0": C0,
        "t_index": t_idx, "t_seedmap": t_seed, "t_refine": t_refine,
        "byte_steps": steps, "block_steps": -(-steps // 8),
        "ns_per_cand_step": (t_refine / touched * 1e9) if touched else 0.0,
    }


# --------------------------------------------------------------------------
# Upgrade 2: huge sorted candidate set probed across a cache-busting buffer
# --------------------------------------------------------------------------
_ALPHABET = b"\x00\x01\x8B\x45"
_TRANS = bytes(_ALPHABET[i & 3] for i in range(256))


def make_u2(size, seed=1234, chunk=1 << 22):
    """A big buffer over a 4-symbol alphabet: every single-byte bucket holds
    ~size/4 positions, so there is no rare seed and C0 is huge. translate() is
    C-speed so setup stays cheap. randbytes is chunked because Random.randbytes
    builds an int of n*8 bits and overflows a C int for large n."""
    rng = random.Random(seed)
    parts = []
    remaining = size
    while remaining > 0:
        c = min(chunk, remaining)
        parts.append(rng.randbytes(c))
        remaining -= c
    return b"".join(parts).translate(_TRANS)


def bench_u2(size, j=64, iters=3):
    """One refine step over the full ~size/4 candidate set at offset j, swept
    over DB size. Because the candidate array is sorted ascending, mv[p+j] is
    read at monotonically increasing addresses. If GB/s stays flat as size
    crosses the LLC, refine is bandwidth-bound/sequential and Upgrade 2's
    cache-advantage premise does not hold; if GB/s collapses, there is a
    latency component Upgrade 2 could attack."""
    D = make_u2(size)
    mv = memoryview(D)
    idx = sigmaker._ByteIndex.build(mv)
    base = idx.candidates1(0x00)           # ascending, ~size/4
    C0 = len(base)

    def one_step():
        arr = array.array("I", base)       # 4*C0 sequential bytes
        t0 = time.perf_counter()
        sigmaker._refine_offsets_into(mv, arr, len(arr), j, 0x00, 0xFF)
        return time.perf_counter() - t0

    t_refine = _best(one_step, iters)
    bytes_moved = C0 * 5                    # 4*C0 candidates + C0 data probes
    return {
        "scenario": "u2", "size": size, "j": j, "C0": C0,
        "t_refine": t_refine, "GBps": bytes_moved / t_refine / 1e9,
    }


def _time(fn):
    t0 = time.perf_counter()
    fn()
    return time.perf_counter() - t0


def main(check=False):
    print("=" * 78)
    print("UPGRADE 1 -- block/word refine (long contiguous exact runs, alpha~1)")
    print("=" * 78)
    print(f"{'L':>10} {'K':>6} {'C0':>12} {'t_seedmap':>10} {'t_refine':>10} "
          f"{'ns/cand/step':>13} {'steps->block':>14}")
    u1 = []
    for L in (8_000_000,):
        for K in (8, 16, 64, 256):
            r = bench_u1(L, K)
            u1.append(r)
            print(f"{r['L']:>10} {r['K']:>6} {r['C0']:>12} "
                  f"{r['t_seedmap']*1e3:>9.2f}m {r['t_refine']*1e3:>9.2f}m "
                  f"{r['ns_per_cand_step']:>13.3f} "
                  f"{r['byte_steps']:>5}->{r['block_steps']:<6}")
    print("\nReading: 'ns/cand/step' is the per-candidate-per-byte refine cost. "
          "Block refine would cut 'steps' to 'block' (ceil/8). On THIS input "
          "(16M-hit seed on a long identical run) that ~8x is real, but the "
          "regime is padding: production seeds on the rarest run, never a "
          "16M-hit '00 00', so refine never enters with this shape.")

    print("\n" + "=" * 78)
    print("UPGRADE 2 -- spaced intersection (huge sorted C0 across LLC boundary)")
    print("=" * 78)
    print(f"{'size(MB)':>10} {'C0':>12} {'t_refine':>10} {'GB/s':>8}")
    u2 = []
    for size in (16 << 20, 64 << 20, 256 << 20, 512 << 20):
        r = bench_u2(size)
        u2.append(r)
        print(f"{size >> 20:>10} {r['C0']:>12} {r['t_refine']*1e3:>9.2f}m "
              f"{r['GBps']:>8.2f}")
    print("\nReading: candidates are sorted ascending, so mv[p+j] is read at "
          "monotonic addresses (sequential, not random). Flat GB/s across the "
          "LLC boundary => refine is bandwidth-bound/sequential => Upgrade 2's "
          "'beat the random D-probes' premise does not hold for our refine.")

    if check:
        # Hardware-tolerant invariants that encode the findings. They fail if a
        # future change makes refine superlinear (U1) or latency-bound (U2).
        ns = [r["ns_per_cand_step"] for r in u1]
        ratio_u1 = max(ns) / min(ns)
        gbps = [r["GBps"] for r in u2]
        ratio_u2 = max(gbps) / min(gbps)
        print(f"\n[check] U1 ns/cand/step spread (refine linear in K): "
              f"{ratio_u1:.2f}x  (want < 1.5)")
        print(f"[check] U2 GB/s spread 16MB..512MB (no cache cliff): "
              f"{ratio_u2:.2f}x  (want < 2.0)")
        assert ratio_u1 < 1.5, "refine cost is no longer ~linear in step count"
        assert ratio_u2 < 2.0, "refine GB/s collapsed past LLC: now latency-bound"
        print("[check] PASS: refine is linear and sequential; both upgrades stay shelved.")


if __name__ == "__main__":
    main(check="--check" in sys.argv)
