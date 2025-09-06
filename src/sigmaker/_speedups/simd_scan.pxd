# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
from libc.stddef cimport size_t
from libc.stdint cimport uint8_t

cdef class Signature:
    """Cython implementation of signature scanning with SIMD support.

    This class provides high-performance binary signature scanning capabilities
    with support for wildcards, nibbles, and multiple SIMD instruction sets.
    """
    cdef:
        uint8_t* _data        # [size_] data bytes [+ size_ mask bytes if _has_mask]
        size_t   _size
        bint     _has_mask
        int      _simd_kind   # 0=portable, 1=AVX2(x86), 2=NEON(ARM)

    cdef void _reset(self) noexcept nogil
    """Reset the signature object to clean state."""

    cdef const uint8_t* _data_ptr(self) noexcept nogil
    """Get internal pointer to signature data bytes (for internal use)."""

    cdef const uint8_t* _mask_ptr(self) noexcept nogil
    """Get internal pointer to signature mask bytes (for internal use)."""

    cdef size_t _get_size(self) noexcept nogil
    """Get the size of the signature in bytes (for internal use)."""

    cdef int _simd_kind_val(self) noexcept nogil
    """Get the current SIMD configuration value (for internal use)."""

    cdef void _set_simd_kind_val(self, int kind) noexcept nogil
    """Set the SIMD configuration value (for internal use)."""

cdef size_t npos_value() noexcept nogil
"""Get the sentinel value indicating 'not found' for scan operations."""

cdef size_t sig_scan(const uint8_t* data, size_t size, Signature search) noexcept nogil
"""Scan a data buffer for a signature pattern using SIMD acceleration.

Args:
    data: Pointer to the data buffer to scan
    size: Size of the data buffer in bytes
    search: Signature object containing the pattern to search for

Returns:
    Offset of the first match, or npos_value() if not found
"""