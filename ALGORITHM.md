# The shortest-unique-signature algorithm

This document explains the math behind the "find shortest unique signature for
the current function" search, where the approach fits relative to known string
algorithms, and how the Cython `_speedups` extension is what makes it practical.
It is written for someone who wants to understand *why* the search is fast, not
just *what* the code does.

GitHub renders LaTeX in Markdown, so the math below is in `$...$` (inline) and
`$$...$$` (block) form.

---

## Contents

- [1. The problem](#1-the-problem)
- [2. The naive cost, and where 462 seconds went](#2-the-naive-cost-and-where-462-seconds-went)
- [3. Monotonic shrinkage: seed once, then refine](#3-monotonic-shrinkage-seed-once-then-refine)
- [4. The 2-byte position index (counting sort)](#4-the-2-byte-position-index-counting-sort)
- [5. Dynamic Seed Selection (1-byte or 2-byte) from one index](#5-dynamic-seed-selection-1-byte-or-2-byte-from-one-index)
- [6. In-place refinement on a typed buffer](#6-in-place-refinement-on-a-typed-buffer)
- [7. Complexity summary](#7-complexity-summary)
- [8. Relationship to known string algorithms](#8-relationship-to-known-string-algorithms)
- [9. What is novel here](#9-what-is-novel-here)
- [10. Future algorithmic directions](#10-future-algorithmic-directions)
- [11. Rejected optimizations](#11-rejected-optimizations)
- [12. How Cython makes it work](#12-how-cython-makes-it-work)
- [13. References](#13-references)

## 1. The problem

A database $D$ is the concatenation of the analyzed program's segment bytes,
of total length $N$ (tens of MB, so $N \sim 10^7$). A **pattern**
$P = (t_0, t_1, \dots, t_{\ell-1})$ is a sequence of tokens; each token $t_j$ is
either an exact byte (value $v_j$, mask $m_j = \text{0xFF}$) or a wildcard
(mask $m_j = \text{0x00}$, matches anything). $P$ **matches** $D$ at position
$p$ when

$$
\forall j \in [0, \ell): \quad (D[p + j] \wedge m_j) = (v_j \wedge m_j).
$$

(Here $\wedge$ denotes bitwise AND.) Let the match set be

$$
M(P) = \lbrace p \in [0, N - \ell] : P \text{ matches } D \text{ at } p \rbrace.
$$

This algorithm operates on full exact bytes and full-byte wildcards only: every
token mask $m_j$ is either `0xFF` or `0x00`. The lower-level SIMD scanner can
represent partial nibble masks for the separate signature *search* feature, but
the signature *generator* and the index-backed search described here neither
produce nor rely on them, and the seed selector anchors only on fully exact bytes.

For a function at address $a$, we decode its instructions, turn operands into
wildcards according to the wildcard policy, and obtain a growing pattern
$P_\ell$ (the first $\ell$ tokens). We want the **shortest** $\ell$ such that
$P_\ell$ is unique:

$$
\ell^\ast = \min \lbrace \ell : |M(P_\ell)| = 1 \rbrace.
$$

**Scope.** This document is about one problem: finding the shortest signature
that is *unique* in the current database under a *fixed* wildcard policy. A
separate and harder question, which bytes should be left exact so a signature
survives a recompile (cross-build robustness), is a different optimization and is
deliberately out of scope. The wildcard policy is an input to this algorithm, not
something it chooses.

## 2. The naive cost, and where 462 seconds went

The obvious method: for $\ell = \ell_{\min}, \ell_{\min}+1, \dots$, scan all of
$D$ and count matches of $P_\ell$, stop when the count reaches 1. Even with a
SIMD-accelerated scan that costs $O(N)$ per length, this performs
$L = \ell^\ast - \ell_{\min} + 1$ **independent full scans**:

$$
T_{\text{naive}} = O(L \cdot N).
$$

When the search has to consider several anchors (growing outside the function
boundary, or comparing several candidate start points), it becomes
$O(A \cdot L \cdot N)$ for $A$ anchors. On a real 16 MB module a single function
took **462 s**. The whole optimization is about removing the two multiplicative
factors $L$ and $A$ from the $N$ term.

## 3. Monotonic shrinkage: seed once, then refine

The match set is **monotonically non-increasing** in $\ell$. Appending a token
adds a constraint, which can only remove positions, never add them:

$$
M(P_{\ell+1}) \subseteq M(P_\ell).
$$

So there is no reason to recompute $M(P_{\ell+1})$ from scratch. Given $M(P_\ell)$,
the next set is just a **filter** of the previous one:

$$
M(P_{\ell+1}) = \lbrace p \in M(P_\ell) : (D[p + \ell] \wedge m_\ell) = (v_\ell \wedge m_\ell) \rbrace.
$$

This is the *seed-then-refine* recurrence. We pay for **one** initial match set
(the "seed"), then each subsequent length is

$$
O(|M(P_\ell)|)
$$

work, proportional to the *current candidate count*, not $N$.

That monotonicity is the reason the algorithm is fast in practice, but it does
not by itself give an unconditional telescoping bound. If the seed set has size
$C_0$ and there are $R$ refinement steps after the seed, monotonicity only gives

$$
\sum_{r=0}^{R-1} |M_r| \le R \cdot C_0.
$$

The stronger "almost $O(C_0)$" behavior is an empirical or average-case claim.
For example, if each informative exact byte keeps at most an $\alpha < 1$
fraction of candidates in expectation, then the expected refinement sum is
geometric:

$$
\mathbb{E}\!\left[\sum_{r=0}^{R-1} |M_r|\right]
    \le C_0 \sum_{r=0}^{R-1} \alpha^r
    < \frac{C_0}{1-\alpha}.
$$

Wildcard bytes have $\alpha = 1$ for selectivity: they never shrink the set,
except for dropping candidates that no longer fit at the right edge of the
database. So only exact bytes are *informative* refinement steps, and the
expensive post-seed filtering skips wildcards entirely. The incremental growth
loop does still pass a newly appended wildcard through the same in-place kernel,
but only to maintain the right-edge boundary after the candidate set has already
collapsed; those calls are cheap and not worth optimizing away. Wildcard-heavy
patterns simply have fewer informative steps $R$.

With that qualification, the total per-anchor cost is
$O(\text{seed} + \sum_r |M_r|)$, worst-case $O(\text{seed} + R C_0)$ and usually
much smaller on real code bytes. The remaining question is: **how cheaply can we
build the seed?**

## 4. The 2-byte position index (counting sort)

Building the seed by scanning $D$ is still $O(N)$, and doing it per anchor brings
back the $A \cdot N$ blowup. We precompute, **once per search**, an index that
answers "where does this 2-byte run occur?" in time proportional to the answer
size.

For each 2-byte key $k \in [0, 2^{16})$ define its bucket

$$
B_k = \lbrace p \in [0, N-1) : D[p] = \lfloor k / 256 \rfloor \ \text{ and } \ D[p+1] = k \bmod 256 \rbrace.
$$

We store every window start grouped by key in one flat array `positions`, with a
`heads` offset array (a CSR / counting-sort layout):

- `heads[k]` is the start of bucket $k$ inside `positions`;
- bucket $k$ is the slice `positions[heads[k] : heads[k+1]]`;
- the bucket size $|B_k|$ is `heads[k+1] - heads[k]`, available in $O(1)$ time.

Construction is a textbook **counting sort** over the $N-1$ adjacent-byte windows,
two passes over $D$:

1. **Count.** For each window key $k$, increment `heads[k+1]`.
2. **Prefix-sum** `heads` so `heads[k]` becomes bucket $k$'s start, then
   **scatter**: place each window offset $i$ at `positions[w[k]++]` using a copy
   $w$ of the bucket starts.

$$
T_{\text{build}} = O(N), \qquad S_{\text{build}} = O(N + 2^{16}).
$$

Built once, amortized across **all** anchors. With the index in hand, seeding a
pattern that contains an exact 2-byte run at offset $s$ with key $k$ costs only

$$
O(|B_k|): \quad M_{\text{seed}} = \lbrace p - s : p \in B_k, \ \text{pattern fits} \rbrace,
$$

and then we refine against the remaining tokens (Section 3). The full $O(N)$ seed
scan is gone, replaced by a bucket read.

## 5. Dynamic Seed Selection (1-byte *or* 2-byte) from one index

The seed cost is $O(|B_k|)$, so we want the **rarest** run. Two refinements:

**(a) Choose the smallest bucket.** A pattern usually has several exact 2-byte
runs. Pick the one minimizing bucket size.

**(b) A single rare byte can beat a common pair.** `e8` (a `call` opcode) is
everywhere; a lone `0f` followed by a common byte may be more selective as just
the rare byte alone. We therefore also consider **1-byte** runs, and we get them
*for free* from the same index. Because keys are ordered $k = (b \ll 8) \mid c$
and the counting sort lays buckets out in key order, all 256 two-byte keys whose
high byte is $b$ occupy a **contiguous** block of `positions`. Hence the 1-byte
bucket is a telescoping sum that collapses to a single subtraction:

$$
\bigl|B^{(1)}_b\bigr| = \sum_{c=0}^{255} \bigl|B_{(b \ll 8)\mid c}\bigr|
= \texttt{heads}[(b{+}1)\ll 8] - \texttt{heads}[b \ll 8],
$$

and the 1-byte candidate list is the single slice
`positions[heads[b<<8] : heads[(b+1)<<8]]`. No second index, no extra memory, no
rescan. (One boundary fix: position $N-1$ is never a 2-byte window *start*, so a
1-byte hit on the final database byte is added explicitly when it can yield a
valid pattern start.)

Seed selection then minimizes selectivity over the union of both widths:

$$
(s^\ast, w^\ast) = \arg\min_{(s, w) \in \text{exact runs}} \bigl|B^{(w)}_{\text{key}(s,w)}\bigr|.
$$

This is a deliberately small contiguous-seed family: fully exact 1-byte and
2-byte anchors. Since the 1-byte options are a *superset* of the candidate seeds,
the chosen seed bucket is never worse than a 2-byte-only choice:

$$
C_0 = \bigl|B^{(w^\ast)}\bigr| \le \min_{\text{2-byte runs}} |B_k|.
$$

A smaller seed means fewer candidates entering the refine chain, which improves
both the worst-case $R C_0$ bound and the expected-case candidate decay described
in Section 3.

The selector deliberately uses only contiguous, fully exact 1-byte and 2-byte
anchors. Richer seed families (longer runs, spaced or gapped seeds, multi-context
seeds) are intentionally *not* used: those techniques pay off in read mapping
because the mismatch positions are unknown at search time, whereas here the
wildcard positions are fixed by the policy before the search begins. The seed is
only an anchor; every other exact byte is already exploited by refinement, so a
richer seed family would add index complexity without new selectivity. It is
worth revisiting only if profiling ever shows seed enumeration, not refinement,
to be the bottleneck (see Section 10).

**Deferred seeding.** Two cases skip the index seed and wait. First, for a pattern
shorter than `MIN_USEFUL_SIG_BYTES` $= 5$, even the rarest run is too common (the
seed would enumerate a large fraction of $D$), so seeding waits until the pattern
is long enough to be selective. Second, when the seedable prefix is all wildcards
there is no exact byte to key the index on at all; rather than fall back to a full
$O(N)$ masked scan, seeding is deferred until an exact byte appears. Both avoid
materializing, or scanning for, a seed that cannot be selective yet.

## 6. In-place refinement on a typed buffer

Each refine step (Section 3) is a filter over the candidate array. We represent
candidates as a typed `uint32` buffer and compact survivors **in place** with a
two-pointer scan. With read index $r$, write index $w \le r$, target
$\tau = v \wedge m$:

```
for r in 0 .. count-1:
    c = cands[r]
    if c + j < N and (D[c + j] & m) == τ:
        cands[w] = cands[r]   # keep
        w += 1
return w                      # new count
```

Because $w \le r$ at all times, a survivor is never overwritten before it is read.
The buffer is allocated **once** at seed time and only shrinks; the ~165k refine
calls of a large function perform **zero allocation**.

## 7. Complexity summary

| Stage | Cost | Frequency |
|------|------|-----------|
| Index build (counting sort) | $O(N)$ | once per search |
| Seed selection | $O(\ell)$ over tokens | per anchor |
| Seed enumeration | $O(C_0)$ | per anchor |
| Refine, all informative steps | $O(\sum_r |M_r|) \subseteq O(RC_0)$ | per anchor |

Per search:

$$
T = \underbrace{O(N)}_{\text{one index build}} +
    \sum_{\text{anchors}} O\bigl(\ell + C_0 + \sum_r |M_r|\bigr)
$$

versus the naive $O(A \cdot L \cdot N)$. The $N$ term is paid **once** and shared;
all per-anchor database-wide work is replaced by work over the chosen seed bucket
and its surviving candidates. In the worst case refinement can still be
$O(RC_0)$, but real runs are expected to be close to geometric decay when exact
bytes are selective.

## 8. Relationship to known string algorithms

The space is not empty; this design sits near several well-studied ones.

The exact, unmasked version of the problem is essentially **left-bounded shortest
unique substring** (LSUS): for a fixed start position, find the shortest substring
beginning there that occurs once. Recent LSUS work gives linear-time
suffix-array/LCP baselines, and shortest-unique/absent-substring (SUS/SAS)
algorithms remain active, especially on packed small-alphabet strings. Those are
the right reference points for the wildcard-free case and for an answer-length
sanity check.

The masked case connects to **wildcard pattern matching** and **longest common
extensions with wildcards**, whose recurring lesson is exactly ours: anchor on
informative non-wildcard positions instead of treating all positions uniformly.
**Internal pattern matching** queries are the natural primitive if one ever wants
sublinear repeated-substring queries inside a fixed text rather than a per-search
rebuilt index.

The closest practical neighbor is in the same domain. **YARA**'s atom-based
scanning picks a short, rare, non-wildcard substring of a rule, finds its
occurrences (classically via **Aho-Corasick** multi-pattern matching), and then
verifies the full masked pattern at each hit. That is seed-then-refine for binary
signatures. The algorithm here is the inverse-direction relative: instead of
matching a known pattern, it *grows* the shortest pattern that is unique, using a
byte-window index as the atom oracle and monotone in-place refinement as the
verifier.

The bioinformatics seed-design literature (spaced, gapped, sampled, and
multi-context seeds) does **not** transfer cleanly, for the reason in Section 5:
it hedges against *unknown* mismatch positions, while here the wildcard positions
are known before the search.

## 9. What is novel here

This is a **novel application**. The literature has the individual primitives, but
the composition that solves *this* problem, growing the shortest masked byte
signature that is unique in a live database, does not come pre-packaged anywhere
we found. The **key use case** is concrete and load-bearing for reverse engineers:
relocating a specific function or routine across rebuilds of a binary,
interactively, inside the disassembler. That is what turns a 7.7-minute search
into seconds (Section 2) and is what makes the feature usable at all.

What we do **not** claim is a new general theory of shortest unique substrings or
wildcard matching; the primitives (inverted byte buckets, seed/filter/verify,
monotone candidate filtering) are individually standard. The contribution is the
specialization, and how cheaply the pieces combine for masked function signatures:

1. **The 1-byte index is free.** This is the one genuinely non-obvious trick. A
   single counting-sort layout over adjacent byte *pairs* yields the exact 2-byte
   buckets, and because the buckets are stored in key order, every 1-byte bucket
   is just a contiguous *marginal* of that same `heads` array: a range view, with
   no second index and no extra memory.

2. **Mixed-width seed selection from that one structure.** Dynamic Seed Selection
   compares fully exact 1-byte and 2-byte anchors by bucket size and picks the
   most selective seed currently available, so the candidate set entering
   refinement is as small as the pattern allows.

3. **Monotone in-place refinement.** Once seeded, candidate offsets live in one
   `uint32` buffer that only shrinks; refinement touches surviving candidates
   instead of rescanning the database for every length.

4. **A reverse-engineering-specific fit.** The index is far cheaper to build and
   discard per search than a suffix-family structure, and far faster than repeated
   full rescans, which is what an interactive IDA workflow actually needs.

## 10. Future algorithmic directions

The current implementation is intentionally conservative. The instrumentation this
section used to call for has since been done: seed bucket size $C_0$, informative
refinement steps $R$, wildcard density, and the candidate-decay curve. It
redirected the effort. The real costs were a Python seed-enumeration loop (now in
C, Section 12) and a needless full scan on all-wildcard prefixes (now deferred,
Section 5), not a fancier seed. Richer seed families (longer contiguous, spaced,
or multi-context seeds) were measured and shelved; see Section 11. The one open
direction that remains:

1. **Exact LSUS baseline.** When wildcarding is disabled, or a long exact region
   dominates the signature, a suffix-array/LCP LSUS baseline is a useful reference
   for both answer length and runtime.

## 11. Rejected optimizations

A couple of ideas looked good on paper, and the reasoning for skipping them is more
useful than the verdict, so it is worth writing down.

Both got the same treatment: profile the worst functions, then build a small
adversarial benchmark that deliberately constructs each idea's best case and check
whether it actually wins. Neither did, because the profile kept pointing somewhere
else. Not the index build (~0.05 s), and after the seed map was moved into C, not
the refine kernel either (~0.1 s), but two boring things we had left on the table:
an $O(C_0)$ loop still mapping seed candidates in pure Python one boxed integer at
a time, and a full $O(N)$ scan that fired whenever a pattern began with nothing but
wildcards. Fixing those is what moved the numbers. Everything below is what we
talked ourselves out of along the way.

**Block refinement.** The obvious next idea is to group the exact bytes into runs
and compare a whole run at once with a wide `uint64` or SIMD load, skipping the
wildcard gaps, on the theory that fewer instructions means less time. The benchmark
says otherwise: refinement is bound by memory bandwidth, not instruction count. It
is already a tight, linear, stride-1 sweep, which is the access pattern a CPU
streams fastest, so wider-but-fewer compares do nothing for a loop that is waiting
on memory rather than on the ALU. The premise was also weaker than it looked, since
the expensive filtering pass already skips wildcards (Section 3). With refinement
sitting around 0.1 s, there was simply nothing here worth chasing.

**Spaced-seed intersection.** The index has a tempting property: each bucket's
positions come out already sorted, because we fill them in one left-to-right pass
over the database. So for a spaced pattern like `8B ?? ?? 45` you could grab both
byte buckets and intersect them with a two-pointer merge. The problem is that we
already do exactly this, just more cheaply: seeding from the rarest byte and
refining against the rest *is* that intersection, and it only ever touches the
smaller bucket. An explicit merge has to read both buckets end to end, which is
strictly more work the moment one of them is a common byte with millions of
entries. And once deferred seeding keeps the starting set small, the merge is pure
overhead; no input in the benchmark ever reached the point where it paid off.

The honest summary is that the wins were never algorithmic. They were "stop running
this loop in Python" and "don't scan the whole database for a prefix that can't
anchor anything", the kind of thing you only find by measuring, not by reaching for
a cleverer data structure. The microbenchmark stays in the tree with a `--check`
mode, so if some later change pushes the bottleneck back onto refinement, it will
fail loudly and these two ideas get a fresh hearing.

## 12. How Cython makes it work

The math above is correct in pure Python too, but it would not be *fast* in pure
Python. The hot kernels, the index build, the seed-candidate map, and the per-step
refine, are memory-bound, branchy loops over millions of bytes. That is precisely
the workload where CPython's per-element overhead (boxed integers, attribute
lookups, interpreter dispatch, dynamic bounds checks) costs 50-100x. The
`_speedups` extension compiles them to tight C:

- **`build_byte_index`** is the counting sort of Section 4, written as C loops
  over a `const unsigned char[:]` typed memoryview, running under `nogil` so the
  IDA UI stays responsive during the $O(N)$ build.

- **`refine_offsets`** is the in-place compaction of Section 6: a `nogil`
  two-pointer loop over a `unsigned int[:]` candidate view and the
  `const unsigned char[:]` data view, with no allocation. Moving this one
  function into Cython dropped the refinement time on the largest test module
  from **~14 s** (a Python list comprehension called ~165k times) to **~0.28 s**,
  roughly **50x**.

- **`seed_offsets`** is the candidate-mapping kernel of Section 5: a `nogil` loop
  that turns a seed bucket into the `array.array('I')` of pattern starts (the
  `p - s` shift, the fit guard, the $N-1$ boundary case) in C. This was the last
  `O(C_0)` loop left in Python, a generator expression that boxed and walked the
  entire bucket; moving it into Cython cut the worst observed function search from
  **~12 s** to **~1 s**, the same playbook as `refine_offsets`, cross-checked
  against the Python version for byte-identical output.

- **`array.array('I')` is the bridge.** A candidate set is simultaneously a
  first-class Python object the orchestration layer can slice and return, *and*
  a zero-copy `unsigned int[:]` typed memoryview inside Cython. The same buffer
  is the Python-visible candidate list and the C-level `uint32*` that
  `refine_offsets` compacts in place, so candidates cross the Python/C boundary
  with no marshalling and no per-call allocation. This is the crux that makes
  Section 6's "allocate once, only shrink" actually hold across the whole search.

- **`nogil`** on both kernels means the heavy work runs without holding the
  interpreter lock, which keeps the UI live and leaves headroom for the
  SIMD scan path used when the index is unavailable.

When the extension is absent, `SIMD_SPEEDUP_AVAILABLE` is `False` and pure-Python
fallbacks produce **identical** results (cross-checked in the test suite); the
plugin still works, just without the speedups.

### A note on `cimport array` vs `import array`

In `simd_scan.pyx` you will see both, sharing the name `array`:

```cython
from cpython cimport array       # compile-time: C-level array.array type + array.clone
import array as py_stdlib_arr_mod        # run-time: the Python array module (constructor)
```

This is **not** a collision or a bug; it is the documented Cython idiom for
working with `array.array` efficiently, and the two lines do different jobs. We
give the run-time module the alias `py_stdlib_arr_mod` to make the split obvious at
every call site:

- `from cpython cimport array` is **compile-time only**. It pulls in the C-level
  declarations from Cython's bundled `cpython/array.pxd`: the `array.array`
  extension type (so `cdef array.array x` is a statically typed C variable) and
  inline C functions such as `array.clone` (allocate a sibling buffer without
  going through the Python constructor). A `cimport` creates **no runtime name
  binding**.

- `import array as py_stdlib_arr_mod` is the ordinary **run-time** import of the Python
  `array` module. It is what makes the *constructor call* `py_stdlib_arr_mod.array('I')`
  resolve at run time (for example, the template argument to `array.clone`).

So every use is unambiguous by name: `array.*` (`cdef array.array`,
`array.clone(...)`) is the cimported C-level API, and `py_stdlib_arr_mod.array(...)` is
the run-time Python constructor. They no longer share a name, so there is nothing
to "override". (The canonical Cython array tutorial shows both lines sharing the
name `array`; aliasing one side is the same idiom, just spelled out.)

## 13. References

- Larissa L. M. Aguiar and Felipe A. Louza, ["Faster computation of
  left-bounded shortest unique substrings"](https://doi.org/10.1186/s13015-025-00287-5),
  *Algorithms for Molecular Biology*, 2025.
- Panagiotis Charalampopoulos, Manal Mohamed, Solon P. Pissis, Hilde Verbeek,
  and Wiktor Zuba, ["Faster Algorithms for Shortest Unique or Absent
  Substrings"](https://arxiv.org/abs/2605.04826), arXiv, 2026.
- Gabriel Bathie, Panagiotis Charalampopoulos, and Tatiana Starikovskaya,
  ["Pattern Matching with Mismatches and
  Wildcards"](https://doi.org/10.4230/LIPIcs.ESA.2024.20), ESA 2024.
- Gabriel Bathie, Panagiotis Charalampopoulos, and Tatiana Starikovskaya,
  ["Longest Common Extensions with Wildcards: Trade-Off and
  Applications"](https://doi.org/10.4230/LIPIcs.ESA.2024.19), ESA 2024.
- Tomasz Kociumaka, Jakub Radoszewski, Wojciech Rytter, and Tomasz Waleń,
  ["Internal Pattern Matching Queries in a Text and
  Applications"](https://doi.org/10.1137/1.9781611973730.36), SODA 2015.
- Alfred V. Aho and Margaret J. Corasick, ["Efficient string matching: an aid to
  bibliographic search"](https://doi.org/10.1145/360825.360855),
  *Communications of the ACM*, 1975.
- VirusTotal, [YARA: The pattern matching swiss
  knife](https://github.com/VirusTotal/yara).
