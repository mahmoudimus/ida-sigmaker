# The shortest-unique-signature algorithm

This document explains the math behind the "find shortest unique signature for
the current function" search, why the approach is novel, and how the Cython
`_speedups` extension is what makes it practical. It is written for someone who
wants to understand *why* the search is fast, not just *what* the code does.

GitHub renders LaTeX in Markdown, so the math below is in `$...$` (inline) and
`$$...$$` (block) form.

---

## 1. The problem

A database $D$ is the concatenation of the analyzed program's segment bytes,
of total length $N$ (tens of MB, so $N \sim 10^7$). A **pattern**
$P = (t_0, t_1, \dots, t_{\ell-1})$ is a sequence of tokens; each token $t_j$ is
either an exact byte (value $v_j$, mask $m_j = \text{0xFF}$) or a wildcard
(mask $m_j = \text{0x00}$, matches anything). $P$ **matches** $D$ at position
$p$ when

$$
\forall j \in [0, \ell): \quad (D[p + j] \mathbin{\&} m_j) = (v_j \mathbin{\&} m_j).
$$

Let the match set be

$$
M(P) = \{\, p \in [0,\, N - \ell] : P \text{ matches } D \text{ at } p \,\}.
$$

For a function at address $a$, we decode its instructions, turn operands into
wildcards according to the wildcard policy, and obtain a growing pattern
$P_\ell$ (the first $\ell$ tokens). We want the **shortest** $\ell$ such that
$P_\ell$ is unique:

$$
\ell^* = \min \{\, \ell : |M(P_\ell)| = 1 \,\}.
$$

## 2. The naive cost, and where 462 seconds went

The obvious method: for $\ell = \ell_{\min}, \ell_{\min}+1, \dots$, scan all of
$D$ and count matches of $P_\ell$, stop when the count reaches 1. Even with a
SIMD-accelerated scan that costs $O(N)$ per length, this performs $L = \ell^* -
\ell_{\min} + 1$ **independent full scans**:

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
M(P_{\ell+1}) = \{\, p \in M(P_\ell) : (D[p + \ell] \mathbin{\&} m_\ell) = (v_\ell \mathbin{\&} m_\ell) \,\}.
$$

This is the *seed-then-refine* recurrence. We pay for **one** initial match set
(the "seed"), then each subsequent length is

$$
O(|M(P_\ell)|)
$$

work, proportional to the *current candidate count*, not $N$. Candidate counts
collapse fast (each added exact byte divides the set by roughly $256$ for random
data), so the entire refine chain telescopes:

$$
\sum_{\ell} |M(P_\ell)| = O(|M(P_{\ell_{\min}})|) = O(C_0),
$$

where $C_0$ is the seed size. The total per-anchor cost is now
$O(\text{seed} + C_0)$. The remaining question is: **how cheaply can we build the
seed?**

## 4. The 2-byte position index (counting sort)

Building the seed by scanning $D$ is still $O(N)$, and doing it per anchor brings
back the $A \cdot N$ blowup. We precompute, **once per search**, an index that
answers "where does this 2-byte run occur?" in time proportional to the answer
size.

For each 2-byte key $k \in [0, 2^{16})$ define its bucket

$$
B_k = \{\, p \in [0,\, N-1) : D[p] = (k \gg 8) \ \wedge\ D[p+1] = (k \mathbin{\&} \text{0xFF}) \,\}.
$$

We store every window start grouped by key in one flat array `positions`, with a
`heads` offset array (a CSR / counting-sort layout):

- `heads[k]` is the start of bucket $k$ inside `positions`;
- bucket $k$ is the slice `positions[heads[k] : heads[k+1]]`;
- $|B_k| = $ `heads[k+1] - heads[k]`, available in $O(1)$.

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
O(|B_k|): \quad M_{\text{seed}} = \{\, p - s : p \in B_k,\ \text{pattern fits} \,\},
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
\bigl|B^{(1)}_b\bigr| = \sum_{c=0}^{255} \bigl|B_{(b \ll 8)\,\mid\, c}\bigr|
= \texttt{heads}[(b{+}1)\ll 8] - \texttt{heads}[b \ll 8],
$$

and the 1-byte candidate list is the single slice
`positions[heads[b<<8] : heads[(b+1)<<8]]`. No second index, no extra memory, no
rescan. (One boundary fix: position $N-1$ is never a 2-byte window *start*, so a
1-byte hit on the final database byte is added explicitly when it can yield a
valid pattern start.)

Seed selection then minimizes selectivity over the union of both widths:

$$
(s^*, w^*) = \arg\min_{(s,\, w) \in \text{exact runs}} \bigl|B^{(w)}_{\text{key}(s,w)}\bigr|.
$$

Since the 1-byte options are a *superset* of the candidate seeds, the chosen seed
bucket is never worse than a 2-byte-only choice:

$$
C_0 = \bigl|B^{(w^*)}\bigr| \le \min_{\text{2-byte runs}} |B_k|.
$$

A smaller seed means fewer candidates entering the refine chain, which (Section 3)
bounds the whole per-anchor cost.

**Deferred seeding.** For a pattern shorter than `MIN_USEFUL_SIG_BYTES` $= 5$, even
the rarest run is too common (the seed would enumerate a large fraction of $D$),
so seeding is deferred and a direct scan is used until the pattern is long enough
to be selective. This avoids materializing a multi-million-entry seed for a 2-byte
pattern.

## 6. In-place refinement on a typed buffer

Each refine step (Section 3) is a filter over the candidate array. We represent
candidates as a typed `uint32` buffer and compact survivors **in place** with a
two-pointer scan. With read index $r$, write index $w \le r$, target
$\tau = v \mathbin{\&} m$:

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
| Refine, all lengths | $O(C_0)$ (telescoping) | per anchor |

Per search:

$$
T = \underbrace{O(N)}_{\text{one index build}} + \sum_{\text{anchors}} O\bigl(\ell + C_0\bigr)
$$

versus the naive $O(A \cdot L \cdot N)$. The $N$ term is paid **once** and shared;
all per-anchor work is proportional to the chosen seed bucket $C_0$, which the
selection step drives toward the rarest run in the pattern.

## 8. What is novel here

Signature scanners typically do one of two things: rescan the whole database for
each candidate length, or build a heavy general-purpose substring index (suffix
automaton / suffix array / large $q$-gram table). This algorithm instead exploits
the *specific* structure of the masked-signature problem:

1. **Wildcards mean we never need general substring search.** We only need to
   anchor on the rarest *exact* run and then verify the rest token-by-token. That
   turns "find the shortest unique pattern" into "pick the most selective seed,
   then refine."

2. **One counting-sort index serves both 1-byte and 2-byte selectivity.** The
   key-ordered bucket layout makes the 1-byte index a *range view* of the 2-byte
   index (a single subtraction for size, a single slice for contents). Dynamic
   Seed Selection compares mixed-width runs with a closed-form selectivity
   measure from one structure, with no extra memory.

3. **Monotone shrinkage turns length growth into in-place filtering.** Because
   $M(P_{\ell+1}) \subseteq M(P_\ell)$, the candidate set is a single buffer that
   only ever shrinks; after the seed we never touch the database again, only the
   handful of bytes at the growing frontier of the surviving candidates.

The combination, a rarest-run seed chosen from a dual-width counting-sort index,
feeding a monotone in-place refine, is what collapses $O(L \cdot N)$ per anchor
into $O(C_0)$ per anchor on top of a single shared $O(N)$ build.

## 9. How Cython makes it work

The math above is correct in pure Python too, but it would not be *fast* in pure
Python. The two hot kernels, the index build and the per-step refine, are
memory-bound, branchy loops over millions of bytes. That is precisely the
workload where CPython's per-element overhead (boxed integers, attribute lookups,
interpreter dispatch, dynamic bounds checks) costs 50-100x. The `_speedups`
extension compiles them to tight C:

- **`build_byte_index`** is the counting sort of Section 4, written as C loops
  over a `const unsigned char[:]` typed memoryview, running under `nogil` so the
  IDA UI stays responsive during the $O(N)$ build.

- **`refine_offsets`** is the in-place compaction of Section 6: a `nogil`
  two-pointer loop over a `unsigned int[:]` candidate view and the
  `const unsigned char[:]` data view, with no allocation. Moving this one
  function into Cython dropped the refinement time on the largest test module
  from **~14 s** (a Python list comprehension called ~165k times) to **~0.28 s**,
  roughly **50x**.

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
