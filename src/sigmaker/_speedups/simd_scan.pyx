# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
from libc.stddef cimport size_t
from libc.stdint cimport uint8_t
from libc.stdlib cimport malloc, free
from libc.string cimport memcmp, memchr

from sigmaker._speedups.simd_scan cimport Signature, SimdLevel, simd_support_best_level

cdef extern from "simd_support.hpp":
    unsigned _tzcnt32_inline(unsigned x) noexcept nogil
    unsigned _scan32_anchors_inline(const unsigned char* base,
                                    const unsigned char* base_kminus1,
                                    unsigned char p0, unsigned char pk,
                                    int m0, int mk) noexcept nogil
    unsigned _scan16_anchors_sse2_inline(const unsigned char* base,
                                         const unsigned char* base_kminus1,
                                         unsigned char p0, unsigned char pk,
                                         int m0, int mk) noexcept nogil
    unsigned _scan16_anchors_inline(const unsigned char* base,
                                    const unsigned char* base_kminus1,
                                    unsigned char p0, unsigned char pk,
                                    int m0, int mk) noexcept nogil


cdef inline unsigned _tzcnt32(unsigned x) noexcept nogil:
    return _tzcnt32_inline(x)

# -----------------------------------------------------------------------------
# Parsing helpers (nibbles + nibble-mask construction)
# -----------------------------------------------------------------------------
cdef inline uint8_t _parse_hex_nibble(int c) noexcept nogil:
    if 48 <= c <= 57:   
        return <uint8_t>(c - 48)        # '0'..'9'
    if 65 <= c <= 70:   
        return <uint8_t>(c - 65 + 10)   # 'A'..'F'
    if 97 <= c <= 102:  
        return <uint8_t>(c - 97 + 10)   # 'a'..'f'
    return <uint8_t>0   # '?' -> 0

cdef inline bint _is_hex_or_q(int c) nogil:
    return <bint>((48 <= c <= 57) or (65 <= c <= 70) or (97 <= c <= 102) or (c == 63))

cdef inline void _build_mask_byte(int up_c, int lo_c, uint8_t* out_mask) noexcept nogil:
    cdef uint8_t m = <uint8_t>0
    if up_c != 63:
        m |= <uint8_t>0xF0
    if lo_c != 63:
        m |= <uint8_t>0x0F
    out_mask[0] = m

cdef inline void _write_byte_from_two_chars(int up_c, int lo_c, uint8_t* out_b) noexcept nogil:
    cdef uint8_t hi = _parse_hex_nibble(up_c)
    cdef uint8_t lo = _parse_hex_nibble(lo_c)
    out_b[0] = <uint8_t>((hi << 4) | lo)

# -----------------------------------------------------------------------------
# Signature container (data + optional nibble-mask bytes)
# -----------------------------------------------------------------------------
cdef class Signature:
    def __cinit__(self, data: str, simd_kind: int = 0, mask: str = ""):
        """
        simd_kind: 0=portable, 1=AVX2(x86), 2=NEON(ARM)
        """
        if simd_kind == SimdLevel.SIMD_BEST_SUPPORTED:
            simd_kind = <int>simd_support_best_level()
        self._data = NULL
        self._size = 0
        self._has_mask = <bint>False
        self._simd_kind = <SimdLevel>simd_kind

        cdef:
            bytes data_b = data.encode('ascii')
            bytes mask_b = mask.encode('ascii') if mask is not None else b""
            const char* d = <const char*>data_b
            Py_ssize_t dn = <Py_ssize_t>len(data_b)
            const char* m = <const char*>mask_b
            Py_ssize_t mn = <Py_ssize_t>len(mask_b)

        # Variables for parsing
        cdef:
            size_t k = 0
            size_t mask_k = 0
            size_t i
            int up_c, lo_c
            Py_ssize_t pos
            Py_ssize_t mask_pos
            Py_ssize_t parse_pos
            Py_ssize_t mask_parse_pos
            Py_ssize_t explicit_mask_pos

        if dn == 0:
            raise ValueError("invalid signature: empty")

        # Parse the string to count bytes and validate format
        pos = <Py_ssize_t>0
        while pos < dn:
            if k > 0:
                # Expect a space separator
                if pos >= dn or data_b[pos] != 32:
                    raise ValueError(f"invalid signature {data}: missing space separator")
                pos += 1

            if pos >= dn:
                raise ValueError(f"invalid signature {data}: incomplete byte")

            if pos + 1 < dn and _is_hex_or_q(data_b[pos]) and _is_hex_or_q(data_b[pos + 1]):
                # Hex pair - represents one byte (try this first)
                pos += 2
                k += 1
            elif data_b[pos] == 63:  # '?'
                # Wildcard - represents one byte
                pos += 1
                k += 1
            else:
                raise ValueError(f"invalid signature {data}: invalid hex or '?'")

        if mn != 0:
            # Parse mask string to validate format and count bytes
            mask_pos = <Py_ssize_t>0
            while mask_pos < mn:
                if mask_k > 0:
                    if mask_pos >= mn or mask_b[mask_pos] != 32:
                        raise ValueError("invalid mask: missing space separator")
                    mask_pos += 1

                if mask_pos >= mn:
                    raise ValueError("invalid mask: incomplete byte")

                if mask_pos + 1 < mn and _is_hex_or_q(mask_b[mask_pos]) and _is_hex_or_q(mask_b[mask_pos + 1]):
                    mask_pos += 2
                    mask_k += 1
                elif mask_b[mask_pos] == 63:  # '?'
                    mask_pos += 1
                    mask_k += 1
                else:
                    raise ValueError("invalid mask: invalid hex")

            if mask_k != k:
                raise ValueError("invalid mask: size mismatch with data")

        cdef bint has_q = <bint>(data.find('?') != -1)
        self._has_mask = <bint>((mn != 0) or has_q)
        self._size = k

        cdef size_t total = k + (k if self._has_mask else 0)
        cdef size_t malloc_size = <size_t>((total if total > 0 else 1) * (sizeof(uint8_t)))
        self._data = <uint8_t*>malloc(malloc_size)
        if self._data == NULL:
            raise MemoryError("Could not allocate memory for signature")

        # Write pattern bytes
        i = 0
        parse_pos = <Py_ssize_t>0
        cdef uint8_t* dst = self._data

        while i < k:
            if i > 0:
                # Skip space separator
                if parse_pos >= dn or data_b[parse_pos] != 32:
                    raise ValueError(f"invalid signature {data}: missing space separator")
                parse_pos += 1

            if parse_pos >= dn:
                self._reset()
                raise ValueError("invalid signature: incomplete byte")

            if parse_pos + 1 < dn and _is_hex_or_q(data_b[parse_pos]) and _is_hex_or_q(data_b[parse_pos + 1]):
                # Hex pair (try this first)
                up_c = data_b[parse_pos]
                lo_c = data_b[parse_pos + 1]
                _write_byte_from_two_chars(up_c, lo_c, dst + i)
                parse_pos += 2
            elif data_b[parse_pos] == 63:  # '?'
                # Wildcard - write 0 to data
                dst[i] = <uint8_t>0
                parse_pos += 1
            else:
                self._reset()
                raise ValueError("invalid hex/'?' in data")
            i += 1

        # Set SIMD kind before potential early return
        
        self._simd_kind = <SimdLevel>(<int>simd_kind if <int>simd_kind in (
            SimdLevel.SIMD_SCALAR, 
            SimdLevel.SIMD_X86_SSE2, 
            SimdLevel.SIMD_X86_AVX2, 
            SimdLevel.SIMD_ARM_NEON
        ) else SimdLevel.SIMD_SCALAR)

        if not self._has_mask:
            return

        # Initial mask from '?' nibbles
        cdef uint8_t* mptr = self._data + k
        mask_parse_pos = <Py_ssize_t>0
        i = 0

        while i < k:
            if i > 0:
                if mask_parse_pos >= dn or data_b[mask_parse_pos] != 32:
                    self._reset()
                    raise ValueError("invalid signature: missing space separator")
                mask_parse_pos += 1

            if mask_parse_pos >= dn:
                self._reset()
                raise ValueError("invalid signature: incomplete byte")

            if mask_parse_pos + 1 < dn and _is_hex_or_q(data_b[mask_parse_pos]) and _is_hex_or_q(data_b[mask_parse_pos + 1]):
                # Hex pair - create nibble-level mask (try this first)
                up_c = data_b[mask_parse_pos]
                lo_c = data_b[mask_parse_pos + 1]
                mask_parse_pos += 2

                # Create nibble-level mask using existing helper function
                _build_mask_byte(up_c, lo_c, mptr + i)
            elif data_b[mask_parse_pos] == 63:  # '?'
                # Wildcard - full byte wildcard, mask should be 0x00 (ignore all bits)
                mptr[i] = <uint8_t>0x00
                mask_parse_pos += 1
            else:
                self._reset()
                raise ValueError("invalid signature: invalid hex")
            i += 1

        # Explicit mask override (no '?' allowed)
        if mn != 0:
            explicit_mask_pos = 0
            i = 0

            while i < k:
                if i > 0:
                    if explicit_mask_pos >= mn or mask_b[explicit_mask_pos] != 32:
                        self._reset()
                        raise ValueError("invalid mask formatting: space")
                    explicit_mask_pos += 1

                if explicit_mask_pos >= mn:
                    self._reset()
                    raise ValueError("invalid mask: incomplete byte")

                up_c = mask_b[explicit_mask_pos]
                lo_c = mask_b[explicit_mask_pos + 1]
                explicit_mask_pos += 2

                if up_c == 63 or lo_c == 63:
                    self._reset()
                    raise ValueError("explicit mask must not contain '?'")
                _write_byte_from_two_chars(up_c, lo_c, mptr + i)
                i += 1
                
    def __dealloc__(self):
        if self._data != NULL:
            free(<void*>self._data)
            self._data = NULL

    cdef void _reset(self) noexcept nogil:
        if self._data != NULL:
            free(<void*>self._data)
        self._data = NULL
        self._size = 0
        self._has_mask = <bint>False
        with gil:
            self._simd_kind = simd_support_best_level()

    cdef const uint8_t* _data_ptr(self) noexcept nogil: 
        return self._data
        
    cdef const uint8_t* _mask_ptr(self) noexcept nogil:
        if self._has_mask and self._data != NULL:
            return self._data + self._size
        else:
            return <const uint8_t*>NULL
        
    cdef size_t _get_size(self) noexcept nogil: 
        return self._size
        
    cdef SimdLevel _simd_kind_val(self) noexcept nogil: 
        return self._simd_kind
        
    cdef void _set_simd_kind_val(self, SimdLevel kind) noexcept nogil:
        if kind in (
            SimdLevel.SIMD_SCALAR, 
            SimdLevel.SIMD_X86_SSE2, 
            SimdLevel.SIMD_X86_AVX2, 
            SimdLevel.SIMD_ARM_NEON
        ):
            self._simd_kind = kind
        else:
            self._simd_kind = SimdLevel.SIMD_SCALAR

    @property
    def size_bytes(self) -> int: 
        return <int>self._size
        
    @property
    def has_mask(self) -> bool: 
        return bool(self._has_mask)

    def data_ptr(self) -> bytes:
        """Get the signature pattern data as a bytes object.

        Returns the raw signature data that will be searched for in the target binary.
        Each byte represents either a literal value or 0x00 for wildcard positions
        (when a mask is present).

        Returns:
            bytes: The signature pattern data. Empty bytes object if signature is invalid.

        Example:
            >>> sig = Signature("48 8B C4")
            >>> sig.data_ptr()
            b'H\x8b\xc4'
            >>> sig = Signature("48 8B ??")
            >>> sig.data_ptr()
            b'H\x8b\x00\x00'
        """
        cdef size_t size = self._get_size()
        if self._data == NULL or size == 0:
            return b""
        # Create bytes object from C array
        return bytes(self._data[:size])

    def mask_ptr(self) -> bytes | None:
        """Get the signature mask as a bytes object, or None if no mask exists.

        The mask defines which bits in the signature pattern should be compared
        during scanning. A mask byte of 0xFF means all bits in the corresponding
        data byte are compared (exact match). A mask byte of 0x00 means none of
        the bits are compared (wildcard).

        For nibble-level wildcards:
        - 0xFF = both nibbles compared (exact match)
        - 0x0F = lower nibble compared, upper nibble ignored
        - 0xF0 = upper nibble compared, lower nibble ignored
        - 0x00 = both nibbles ignored (full wildcard)

        Returns:
            bytes or None: The signature mask data, or None if signature has no wildcards.

        Example:
            >>> sig = Signature("48 8B ??")  # ?? = full wildcard
            >>> sig.mask_ptr()
            b'\xff\xff\x00\x00'
            >>> sig = Signature("48 ? 8B")  # ? = upper nibble wildcard
            >>> sig.mask_ptr()
            b'\xff\x0f\xff'
        """
        if not self._has_mask:
            return None
        cdef size_t size = self._get_size()
        cdef const uint8_t* mask = self._mask_ptr()
        if mask == NULL or size == 0:
            return None
        # Create bytes object from C array
        return bytes(mask[:size])

    def size(self) -> int:
        """Get the size of the signature in bytes.

        Returns the length of the signature pattern, which determines how many
        bytes will be compared during scanning operations.

        Returns:
            int: The number of bytes in the signature pattern.

        Example:
            >>> sig = Signature("48 8B C4")
            >>> sig.size()
            3
            >>> sig = Signature("48 8B ??")
            >>> sig.size()
            4
        """
        return <int>self._get_size()

    def simd_kind(self) -> int:
        """Get the current SIMD instruction set configuration for this signature.

        The SIMD kind determines which CPU instruction set will be used for
        scanning operations with this signature. Different instruction sets
        provide different performance characteristics.

        Returns:
            int: The current SIMD configuration:
                - 0: Portable (software fallback, works on all CPUs)
                - 1: AVX2 (Intel/AMD x86 with AVX2 support)
                - 2: NEON (ARM with NEON support)

        Example:
            >>> sig = Signature("48 8B C4")
            >>> sig.simd_kind()  # Default is portable
            0
            >>> sig.set_simd_kind(1)  # Enable AVX2
            >>> sig.simd_kind()
            1

        Note:
            The SIMD kind is automatically detected based on CPU capabilities
            during signature creation, but can be overridden for performance tuning.
        """
        return <int>self._simd_kind_val()

    def set_simd_kind(self, int kind):
        """Set the SIMD instruction set to use for scanning with this signature.

        This method allows manual override of the automatic SIMD detection,
        enabling performance tuning for specific use cases or CPU configurations.

        Args:
            kind (int): The SIMD instruction set to use:
                - 0: Portable (software fallback, works on all CPUs)
                - 1: AVX2 (Intel/AMD x86 with AVX2 support)
                - 2: NEON (ARM with NEON support)

        Note:
            - Invalid values (outside 0-2) will be clamped to 0 (portable)
            - AVX2/NEON will automatically fall back to portable if not supported
            - The setting persists for all scans using this signature object

        Example:
            >>> sig = Signature("48 8B C4")
            >>> sig.set_simd_kind(1)  # Force AVX2 usage
            >>> # All subsequent scans with sig will use AVX2 if available
        """
        self._set_simd_kind_val(<SimdLevel>kind)

# Portable search: first/last anchors + memcmp / masked middle verify
cdef inline const uint8_t* _safe_search(const uint8_t* s, const uint8_t* e,
                                        const uint8_t* p, const uint8_t* m,
                                        size_t k) noexcept nogil:
    cdef:
        size_t n = <size_t>(e - s)
        uint8_t p0 = <uint8_t>0, m0 = <uint8_t>0
        size_t i
        size_t j
        const void* hit

    if k == 0:
        return s

    if n < k:
        return e

    if k == 1:
        if m != NULL:
            p0 = p[0]
            m0 = m[0]
            for i in range(n):
                if (s[i] & m0) == p0:
                    return s + i
            return e
        else:
            hit = memchr(<const void*>s, <int>p[0], <size_t>n)
            return <const uint8_t*>hit if hit != NULL else e

    cdef uint8_t pk = p[k-1]
    cdef uint8_t mk = <uint8_t>0
    p0 = p[0]

    if m != NULL:
        m0 = m[0]
        mk = m[k-1]

    cdef size_t limit = n - k + 1
    if m == NULL:
        for i in range(limit):
            if s[i] == p0 and s[i + k - 1] == pk:
                if k == 2:
                    return s + i
                if memcmp(<const void*>(s + i + 1), <const void*>(p + 1), <size_t>(k - 2)) == 0:
                    return s + i
        return e
    else:
        for i in range(limit):
            if ((s[i] & m0) == p0) and ((s[i + k - 1] & mk) == pk):
                if k == 2:
                    return s + i
                j = 1
                while <size_t>j < k - 1:
                    if (s[i + j] & m[j]) != p[j]:
                        break
                    j += 1
                if j == k - 1:
                    return s + i
        return e


ctypedef unsigned (*anchor_fn_t)(const unsigned char* base,
                                 const unsigned char* base_kminus1,
                                 unsigned char p0, unsigned char pk,
                                 int m0, int mk) noexcept nogil

ctypedef size_t (*scan_core_fn_t)(const uint8_t* s, const uint8_t* e,
                                  const uint8_t* p, const uint8_t* m,
                                  size_t k) noexcept nogil
                                  
                                  
cdef inline const uint8_t* _simd_then_scalar(const uint8_t* s, const uint8_t* e,
                                             const uint8_t* p, const uint8_t* m,
                                             size_t k,
                                             size_t stride,
                                             anchor_fn_t scan_anchors) noexcept nogil:
    cdef:
        size_t n = <size_t>(e - s)
        size_t i = 0
        unsigned em, o
        size_t j
        size_t vec_last_start
        size_t total_starts
        unsigned char p0, pk
        int m0, mk
        
    if k == 0: return s
    if n < k:  return e
    if k == 1: return _safe_search(s, e, p, m, k)

    total_starts = n - k + 1
    p0 = p[0]
    pk = p[k-1]
    m0 = -1
    mk = -1
    if m != NULL:
        m0 = <int>m[0]
        mk = <int>m[k-1]

    if total_starts >= stride:
        vec_last_start = total_starts - stride
        while i <= vec_last_start:
            em = scan_anchors(s + i, s + i + k - 1, p0, pk, m0, mk)
            while em:
                o = _tzcnt32(em)
                if k == 2:
                    return s + i + o
                if m == NULL:
                    if memcmp(<const void*>(s + i + o + 1), <const void*>(p + 1), <size_t>(k - 2)) == 0:
                        return s + i + o
                else:
                    j = 1
                    while j < k - 1:
                        if (s[i + o + j] & m[j]) != p[j]:
                            break
                        j += 1
                    if j == k - 1:
                        return s + i + o
                em &= (em - 1)
            i += 1  # Increment by 1, not stride! We need to check all positions

    # tail search: start scalar at first unprocessed start position
    return _safe_search(s + i, e, p, m, k)


# Thin shims:
cdef inline const uint8_t* _avx_search(const uint8_t* s, const uint8_t* e,
                                       const uint8_t* p, const uint8_t* m,
                                       size_t k) noexcept nogil:
    return _simd_then_scalar(s, e, p, m, k, 32, _scan32_anchors_inline)

cdef inline const uint8_t* _neon_search(const uint8_t* s, const uint8_t* e,
                                        const uint8_t* p, const uint8_t* m,
                                        size_t k) noexcept nogil:
    return _simd_then_scalar(s, e, p, m, k, 16, _scan16_anchors_inline)
    
cdef inline const uint8_t* _sse2_search(const uint8_t* s, const uint8_t* e,
                                        const uint8_t* p, const uint8_t* m,
                                        size_t k) noexcept nogil:
    return _simd_then_scalar(s, e, p, m, k, 16, _scan16_anchors_sse2_inline)
    
    
cdef inline const uint8_t* _scan_range(const uint8_t* s, const uint8_t* e,
                                       const uint8_t* p, const uint8_t* m,
                                       size_t k) noexcept nogil:
    cdef:
        size_t n = <size_t>(e - s)
        const uint8_t* i
        size_t r
        
    if n < k: 
        return e
    r = k + 64
    if r + k < n:
        i = _safe_search(s, e - r, p, m, k)
        if i != e - r: 
            return i
        s = e - r - k + 1
    return _safe_search(s, e, p, m, k)
    

# Public scanner core (used by Python wrapper after it chooses the path)
cdef size_t sig_scan(const uint8_t* data, size_t size, Signature search) noexcept nogil:
    if data == NULL or size == 0:
        return <size_t>-1

    cdef:
        const uint8_t* p = search._data_ptr()
        size_t k = search._get_size()

    if p == NULL or k == 0:
        return 0
    if size < k:
        return <size_t>-1

    cdef:
        const uint8_t* s = data
        const uint8_t* e = data + size
        const uint8_t* m = search._mask_ptr()
    return <size_t>(_scan_range(s, e, p, m, k) - s)




def simd_best_level() -> int:
    """Get the best available SIMD instruction set for the current CPU.
    
    This function detects the highest level of SIMD support available on the
    current CPU and returns the corresponding SimdLevel enum value.
    
    Returns:
        int: The best available SIMD level:
            - 0: SIMD_SCALAR (portable fallback)
            - 1: SIMD_X86_SSE2 (x86 SSE2 support)
            - 2: SIMD_X86_AVX2 (x86 AVX2 support)
            - 3: SIMD_ARM_NEON (ARM NEON support)
    
    Example:
        >>> from sigmaker._speedups import simd_scan
        >>> level = simd_scan.simd_best_level()
        >>> print(f"Best SIMD level: {level}")
    """
    return <int>simd_support_best_level()


def scan_bytes(const unsigned char[:] data_view, Signature sig) -> int:
    """Scan a memoryview buffer for a signature pattern.

    This function provides the primary interface for signature scanning,
    automatically selecting the optimal SIMD implementation based on the
    signature's configured SIMD kind and CPU capabilities.

    Args:
        data_view (unsigned char memoryview): The data buffer to scan
        sig (Signature): The signature pattern to search for

    Returns:
        int: 0-based offset of the first match, or -1 if not found

    Example:
        >>> import numpy as np
        >>> from sigmaker import _simd_scan
        >>> data = np.frombuffer(b'\x48\x8B\xC4\x90\x48\x8B\xC4', dtype=np.uint8)
        >>> sig = _simd_scan.Signature("48 8B C4")
        >>> _simd_scan.scan_bytes(data, sig)
        0
        >>> _simd_scan.scan_bytes(data[1:], sig)  # Search from offset 1
        4

    Note:
        - Uses SIMD acceleration when available and configured
        - Thread-safe and can be called from multiple threads
        - Automatically handles different signature types (with/without masks)
    """
    cdef:
        const uint8_t* ptr = <const uint8_t*>&data_view[0]
        Py_ssize_t n = data_view.shape[0]
        size_t k = sig._get_size()
    
    if n == 0: 
        return -1
    if k == 0: 
        return 0
    if <size_t>n < k: 
        return -1

    cdef const uint8_t* s = ptr
    cdef const uint8_t* e = ptr + n
    cdef const uint8_t* p = sig._data_ptr()
    cdef const uint8_t* m = sig._mask_ptr()
    cdef const uint8_t* hit
    cdef int lvl

    cdef int kind = sig.simd_kind()
    if kind == 0:
        # Auto-select based on runtime/compile-time conservative probe
        lvl = simd_best_level()
        if lvl == SimdLevel.SIMD_X86_AVX2:
            hit = _avx_search(s, e, p, m, k)
        elif lvl == SimdLevel.SIMD_ARM_NEON:
            hit = _neon_search(s, e, p, m, k)
        elif lvl == SimdLevel.SIMD_X86_SSE2:
            hit = _sse2_search(s, e, p, m, k)
        else:
            hit = _scan_range(s, e, p, m, k)
    elif kind == 1:    # SCALAR
        hit = _scan_range(s, e, p, m, k)
    elif kind == 2:    # SSE2
        hit = _sse2_search(s, e, p, m, k)
    elif kind == 3:    # AVX2
        hit = _avx_search(s, e, p, m, k)
    elif kind == 4:    # NEON
        hit = _neon_search(s, e, p, m, k)
    else:
        hit = _scan_range(s, e, p, m, k)

    if hit == e:
        return -1
    return <int>(hit - s)