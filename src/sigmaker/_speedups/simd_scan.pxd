# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
from libc.stddef cimport size_t
from libc.stdint cimport uint8_t

cdef extern from "simd_support.hpp":
    cdef enum SimdLevel:
        SIMD_BEST_SUPPORTED # 0
        SIMD_SCALAR # 1
        SIMD_X86_SSE2 # 2
        SIMD_X86_AVX2 # 3
        SIMD_ARM_NEON # 4
    SimdLevel simd_support_best_level() noexcept

cdef class Signature:
    """Cython implementation of signature scanning with SIMD support.

    This class provides high-performance binary signature scanning capabilities
    with support for wildcards, nibbles, and multiple SIMD instruction sets.
    """
    cdef:
        uint8_t* _data        # [size_] data bytes [+ size_ mask bytes if _has_mask]
        size_t   _size
        bint     _has_mask
        SimdLevel      _simd_kind 

    cdef void _reset(self) noexcept nogil
    """Reset the signature object to clean state."""

    cdef const uint8_t* _data_ptr(self) noexcept nogil
    """Get internal pointer to signature data bytes (for internal use)."""

    cdef const uint8_t* _mask_ptr(self) noexcept nogil
    """Get internal pointer to signature mask bytes (for internal use)."""

    cdef size_t _get_size(self) noexcept nogil
    """Get the size of the signature in bytes (for internal use)."""

    cdef SimdLevel _simd_kind_val(self) noexcept nogil
    """Get the current SIMD configuration value (for internal use)."""

    cdef void _set_simd_kind_val(self, SimdLevel kind) noexcept nogil
    """Set the SIMD configuration value (for internal use)."""

cdef size_t sig_scan(const uint8_t* data, size_t size, Signature search) noexcept nogil
"""Scan a data buffer for a signature pattern using SIMD acceleration.

Args:
    data: Pointer to the data buffer to scan
    size: Size of the data buffer in bytes
    search: Signature object containing the pattern to search for

Returns:
    Offset of the first match, or npos_value() if not found
"""