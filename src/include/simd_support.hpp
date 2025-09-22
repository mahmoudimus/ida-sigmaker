#ifndef SIMD_SUPPORT_HPP
#define SIMD_SUPPORT_HPP

#include <cstddef>
#include <cstdint>

// SIMD headers inclusion strategy:
// 1. Only include headers when the compiler target supports them
// 2. Let setup.py handle compiler flags - don't try to detect SIMD support here
// 3. The "target specific option mismatch" error means setup.py added wrong flags
// SSE2 support for x86 (always available on x86_64, fallback for older x86)

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <emmintrin.h>
#endif

// AVX2 support for x86_64
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(__AVX2__) || defined(__AVX__)
#include <immintrin.h>
#endif
#endif

// NEON support for ARM64
#if defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    enum SimdLevel
    {
        SIMD_BEST_SUPPORTED = 0,
        SIMD_SCALAR = 1,
        SIMD_X86_SSE2 = 2,
        SIMD_X86_AVX2 = 3,
        SIMD_ARM_NEON = 4
    };

    // Best-effort probe. Avoids ISA usage at global scope.
    static inline SimdLevel simd_support_best_level(void)
    {
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
        return SIMD_ARM_NEON;
#elif defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    // x86: detect AVX2 safely at runtime using CPUID + XGETBV
#if defined(_MSC_VER)
    int r1[4] = {0, 0, 0, 0};
    int r7[4] = {0, 0, 0, 0};
    __cpuidex(r1, 1, 0);
    __cpuidex(r7, 7, 0);
    unsigned ecx1 = (unsigned)r1[2];
    unsigned ebx7 = (unsigned)r7[1];
    int has_avx = (ecx1 & (1u << 28)) != 0;
    int has_osxsave = (ecx1 & (1u << 27)) != 0;
    if (has_avx && has_osxsave)
    {
        unsigned __int64 x = _xgetbv(0);
        int xmm = (x & (1ull << 1)) != 0;
        int ymm = (x & (1ull << 2)) != 0;
        int avx2 = (ebx7 & (1u << 5)) != 0;
        if (xmm && ymm && avx2)
            return SIMD_X86_AVX2;
    }
#else
    unsigned a = 0, b = 0, c = 0, d = 0;
    // CPUID leaf 1
    __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    unsigned ecx1 = c;
    int has_avx = (ecx1 & (1u << 28)) != 0;
    int has_osxsave = (ecx1 & (1u << 27)) != 0;
    if (has_avx && has_osxsave)
    {
        unsigned eax_xcr0 = 0, edx_xcr0 = 0;
        unsigned ecx_in = 0;
        __asm__ __volatile__("xgetbv" : "=a"(eax_xcr0), "=d"(edx_xcr0) : "c"(ecx_in));
        unsigned long long x = ((unsigned long long)edx_xcr0 << 32) | (unsigned long long)eax_xcr0;
        int xmm = (x & (1ull << 1)) != 0;
        int ymm = (x & (1ull << 2)) != 0;
        // CPUID leaf 7 subleaf 0
        __asm__ __volatile__("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(7), "c"(0));
        unsigned ebx7 = b;
        int avx2 = (ebx7 & (1u << 5)) != 0;
        if (xmm && ymm && avx2)
            return SIMD_X86_AVX2;
    }
#endif
    return SIMD_X86_SSE2;
#else
    return SIMD_SCALAR;
#endif
    }

    static inline int _compiled_arch_kind(void)
    {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
        return 1; // x86/AVX2 helpers compiled in
#elif defined(__ARM_NEON) || defined(__aarch64__)
    return 2; // ARM/NEON helpers compiled in
#else
    return 0; // portable only
#endif // defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    }

    // -----------------------------------------------------------------------------
    // Inline C helpers: SSE2/AVX2 (x86) and NEON (ARM) anchor comparators + tzcnt/ctz
    // -----------------------------------------------------------------------------

    // ----- tzcnt/ctz fallback -----
    static inline unsigned _tzcnt32_inline(unsigned x)
    {
#if defined(__has_builtin)
#if __has_builtin(__builtin_ctz)
        if (x == 0u)
            return 32u;
        return (unsigned)__builtin_ctz(x);
#endif // __has_builtin(__builtin_ctz)
#endif // defined(__has_builtin)
        if (x == 0u)
            return 32u;
        unsigned c = 0u;
        while ((x & 1u) == 0u)
        {
            x >>= 1u;
            ++c;
        }
        return c;
    }

    // ----- SSE2 16B anchor mask (primary implementation for x86) -----
    static inline unsigned _scan16_anchors_sse2_inline(const unsigned char *base,
                                                       const unsigned char *base_kminus1,
                                                       unsigned char p0, unsigned char pk,
                                                       int m0, int mk)
    {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)

        const __m128i v_s0 = _mm_loadu_si128((const __m128i *)base);
        const __m128i v_s1 = _mm_loadu_si128((const __m128i *)base_kminus1);

        const __m128i v_p0 = _mm_set1_epi8((char)p0);
        const __m128i v_pk = _mm_set1_epi8((char)pk);

        __m128i e0, e1;
        if (m0 >= 0)
        {
            const __m128i v_m0 = _mm_set1_epi8((char)m0);
            e0 = _mm_cmpeq_epi8(_mm_and_si128(v_s0, v_m0),
                                _mm_and_si128(v_p0, v_m0));
        }
        else
        {
            e0 = _mm_cmpeq_epi8(v_s0, v_p0);
        }

        if (mk >= 0)
        {
            const __m128i v_mk = _mm_set1_epi8((char)mk);
            e1 = _mm_cmpeq_epi8(_mm_and_si128(v_s1, v_mk),
                                _mm_and_si128(v_pk, v_mk));
        }
        else
        {
            e1 = _mm_cmpeq_epi8(v_s1, v_pk);
        }

        const __m128i both = _mm_and_si128(e0, e1);
        return (unsigned)_mm_movemask_epi8(both);
#else
    (void)base;
    (void)base_kminus1;
    (void)p0;
    (void)pk;
    (void)m0;
    (void)mk;
    return 0u;
#endif // defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    }

    // ----- AVX2 32B anchor mask -----
    static inline unsigned _scan32_anchors_inline(const unsigned char *base,
                                                  const unsigned char *base_kminus1,
                                                  unsigned char p0, unsigned char pk,
                                                  int m0, int mk)
    {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#if defined(__AVX2__) || defined(__AVX__)
        const __m256i v_s0 = _mm256_loadu_si256((const __m256i *)base);
        const __m256i v_s1 = _mm256_loadu_si256((const __m256i *)base_kminus1);

        const __m256i v_p0 = _mm256_set1_epi8((char)p0);
        const __m256i v_pk = _mm256_set1_epi8((char)pk);

        __m256i e0, e1;
        if (m0 >= 0)
        {
            const __m256i v_m0 = _mm256_set1_epi8((char)m0);
            e0 = _mm256_cmpeq_epi8(_mm256_and_si256(v_s0, v_m0),
                                   _mm256_and_si256(v_p0, v_m0));
        }
        else
        {
            e0 = _mm256_cmpeq_epi8(v_s0, v_p0);
        }

        if (mk >= 0)
        {
            const __m256i v_mk = _mm256_set1_epi8((char)mk);
            e1 = _mm256_cmpeq_epi8(_mm256_and_si256(v_s1, v_mk),
                                   _mm256_and_si256(v_pk, v_mk));
        }
        else
        {
            e1 = _mm256_cmpeq_epi8(v_s1, v_pk);
        }

        const __m256i both = _mm256_and_si256(e0, e1);
        return (unsigned)_mm256_movemask_epi8(both);
#else
        // Fallback to SSE2 when AVX2 not available
        return _scan16_anchors_sse2_inline(base, base_kminus1, p0, pk, m0, mk);
#endif // defined(__AVX2__) || defined(__AVX__)
#else
    (void)base;
    (void)base_kminus1;
    (void)p0;
    (void)pk;
    (void)m0;
    (void)mk;
    return 0u;
#endif // defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    }

#if defined(__ARM_NEON) || defined(__aarch64__)
    // ----- NEON 16B movemask -----
    static inline unsigned _neon_movemask_u8(uint8x16_t in)
    {
        static const uint8_t __attribute__((aligned(16))) bit_tbl[16] =
            {1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128};
        // Keep only MSBs of each lane
        uint8x16_t msb = vshrq_n_u8(in, 7);
        // Multiply by distinct bit-weights
        uint8x16_t weighted = vandq_u8(msb, vld1q_u8(bit_tbl));
        // Horizontal pairwise adds to two bytes: [lo8_bits_sum, hi8_bits_sum]
        uint8x8_t sum = vpadd_u8(vget_low_u8(weighted), vget_high_u8(weighted));
        sum = vpadd_u8(sum, sum);
        sum = vpadd_u8(sum, sum);
        return (unsigned)vget_lane_u8(sum, 0) | ((unsigned)vget_lane_u8(sum, 1) << 8);
    }

    // ----- NEON 16B anchor mask -----
    static inline unsigned _scan16_anchors_inline(const unsigned char *base,
                                                  const unsigned char *base_kminus1,
                                                  unsigned char p0, unsigned char pk,
                                                  int m0, int mk)
    {
        const uint8x16_t v_s0 = vld1q_u8(base);
        const uint8x16_t v_s1 = vld1q_u8(base_kminus1);

        const uint8x16_t v_p0 = vdupq_n_u8(p0);
        const uint8x16_t v_pk = vdupq_n_u8(pk);

        uint8x16_t e0, e1;
        if (m0 >= 0)
        {
            const uint8x16_t v_m0 = vdupq_n_u8((uint8_t)m0);
            e0 = vceqq_u8(vandq_u8(v_s0, v_m0), vandq_u8(v_p0, v_m0));
        }
        else
        {
            e0 = vceqq_u8(v_s0, v_p0);
        }

        if (mk >= 0)
        {
            const uint8x16_t v_mk = vdupq_n_u8((uint8_t)mk);
            e1 = vceqq_u8(vandq_u8(v_s1, v_mk), vandq_u8(v_pk, v_mk));
        }
        else
        {
            e1 = vceqq_u8(v_s1, v_pk);
        }

        return _neon_movemask_u8(vandq_u8(e0, e1));
    }
#else
// Fallback for non-ARM platforms
static inline unsigned _neon_movemask_u8(uint8_t *in)
{
    (void)in;
    return 0u;
}

static inline unsigned _scan16_anchors_inline(const unsigned char *base,
                                              const unsigned char *base_kminus1,
                                              unsigned char p0, unsigned char pk,
                                              int m0, int mk)
{
    (void)base;
    (void)base_kminus1;
    (void)p0;
    (void)pk;
    (void)m0;
    (void)mk;
    return 0u;
}
#endif // defined(__ARM_NEON) || defined(__aarch64__)

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SIMD_SUPPORT_HPP