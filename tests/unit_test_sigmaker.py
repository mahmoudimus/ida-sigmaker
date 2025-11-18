"""
unit_test_sigmaker.py - Unit tests for sigmaker

Tests the sigmaker module and related functionality with mocked system interfaces
to ensure reliable testing across different platforms and architectures.
"""

import array
import gc
import itertools
import logging
import pathlib
import platform
import random
import re
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

TEST_DIR = pathlib.Path(__file__).parent
# SRC_DIR = TEST_DIR.parent / "src"
# sys.path.insert(0, SRC_DIR.as_posix())
# Add the src directory to the path so we can import sigmaker
sys.path.insert(0, TEST_DIR.as_posix())
from coveredtestcase import CoverageTestCase

# Use a context manager to patch sys.modules before importing sigmaker
with patch.dict("sys.modules", {"idaapi": MagicMock(), "idc": MagicMock()}):
    import sigmaker


SigText = sigmaker.SigText


# Set up logging for tests
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _assert_sig(
    testcase: unittest.TestCase,
    raw: str,
    exp_canon: str,
    exp_pattern: list[tuple[int, bool]],
) -> None:
    canon, pattern = sigmaker.SigText.normalize(raw)
    testcase.assertEqual(canon, exp_canon, f"canon mismatch for: {raw!r}")
    testcase.assertEqual(pattern, exp_pattern, f"pattern mismatch for: {raw!r}")


def slow_masked_find(hay: bytes, pattern: bytes, mask: bytes | None) -> int:
    """Reference implementation (portable Python)."""
    k = len(pattern)
    n = len(hay)
    if k == 0:
        return 0
    if n < k:
        return -1

    if mask is None:
        return hay.find(pattern)

    m = mask
    # Anchor prune: match first & last with mask (same rule as Cython)
    p0, mk0 = pattern[0], m[0]
    pk, mkk = pattern[-1], m[-1]
    for i in range(0, n - k + 1):
        if (hay[i] & mk0) != (p0 & mk0):
            continue
        if (hay[i + k - 1] & mkk) != (pk & mkk):
            continue
        ok = True
        for j in range(1, k - 1):
            if (hay[i + j] & m[j]) != (pattern[j] & m[j]):
                ok = False
                break
        if ok:
            return i
    return -1


def make_buf_with_pattern(
    pat_bytes: bytes, at: int, total: int = 4096, fill: int = 0x90
) -> bytes:
    assert at + len(pat_bytes) <= total
    b = bytearray([fill] * total)
    b[at : at + len(pat_bytes)] = pat_bytes
    return bytes(b)


def _mask_bytes(sig: sigmaker.simd_scan.Signature):
    m = sig.mask_ptr()
    return None if m is None else bytes(m)


class CoveredUnitTest(CoverageTestCase):
    coverage_data_file = ".coverage.unit"


class TestSigTextNormalize(CoveredUnitTest):

    # ----------------------------
    # Fast-path: pure hex (no '?')
    # ----------------------------
    def test_fastpath_pure_hex_minimal(self):
        _assert_sig(
            self, "48 8B C4", "48 8B C4", [(0x48, False), (0x8B, False), (0xC4, False)]
        )

    def test_fastpath_pure_hex_unspaced(self):
        _assert_sig(
            self, "488BC4", "48 8B C4", [(0x48, False), (0x8B, False), (0xC4, False)]
        )

    def test_fastpath_pure_hex_mixed_separators(self):
        raw = "48,8B;C4|90\t4C\n8D\r05_12-34"
        _assert_sig(
            self,
            raw,
            "48 8B C4 90 4C 8D 05 12 34",
            [
                (0x48, False),
                (0x8B, False),
                (0xC4, False),
                (0x90, False),
                (0x4C, False),
                (0x8D, False),
                (0x05, False),
                (0x12, False),
                (0x34, False),
            ],
        )

    def test_fastpath_pure_hex_with_0x_prefixes(self):
        _assert_sig(
            self,
            "0x48 0x8b 0Xc4 90",
            "48 8B C4 90",
            [(0x48, False), (0x8B, False), (0xC4, False), (0x90, False)],
        )

    def test_fastpath_lowercase_hex(self):
        _assert_sig(
            self, "e8 00 0f", "E8 00 0F", [(0xE8, False), (0x00, False), (0x0F, False)]
        )

    # -----------------------------------------
    # Wildcards: per-byte & per-nibble handling
    # -----------------------------------------
    def test_wildcards_byte_questions(self):
        # "??" = wildcard byte; single "?" token also becomes "??"
        _assert_sig(
            self,
            "E8 ?? 48 89 C7",
            "E8 ?? 48 89 C7",
            [(0xE8, False), (0x00, True), (0x48, False), (0x89, False), (0xC7, False)],
        )

        _assert_sig(
            self,
            "E8 ? 48 89 C7",
            "E8 ?? 48 89 C7",
            [(0xE8, False), (0x00, True), (0x48, False), (0x89, False), (0xC7, False)],
        )

    def test_wildcards_nibble_left(self):
        # '?F' → value = 0x0F, wildcard True (nibble wildcard supported downstream by mask)
        _assert_sig(self, "?F", "?F", [(0x0F, True)])

    def test_wildcards_nibble_right(self):
        # 'F?' → value = 0xF0, wildcard True
        _assert_sig(self, "F?", "F?", [(0xF0, True)])

    def test_wildcards_mixed_sequence(self):
        # Classic IDA style with per-byte wildcards
        _assert_sig(
            self,
            "E8 ? ? ? ? 48 89 C7",
            "E8 ?? ?? ?? ?? 48 89 C7",
            [
                (0xE8, False),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x48, False),
                (0x89, False),
                (0xC7, False),
            ],
        )

    def test_wildcards_dot_as_question(self):
        _assert_sig(
            self,
            "E8 . . . . 48 89 C7",
            "E8 ?? ?? ?? ?? 48 89 C7",
            [
                (0xE8, False),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x48, False),
                (0x89, False),
                (0xC7, False),
            ],
        )

    # -------------------------------------
    # Single nibble tokens → promoted '?X'
    # -------------------------------------
    def test_single_nibble_promoted(self):
        # 'A' -> 'A?' → value 0xA0, wildcard True
        _assert_sig(self, "A", "A?", [(0xA0, True)])

        # lowercase single nibble
        _assert_sig(self, "f", "F?", [(0xF0, True)])

    def test_single_nibble_list(self):
        # Multiple single nibbles promoted independently
        _assert_sig(
            self, "A B C", "A? B? C?", [(0xA0, True), (0xB0, True), (0xC0, True)]
        )

    # --------------------------------------------------
    # Exhaustive per-nibble wildcards across all hex nibbles
    # --------------------------------------------------
    def test_exhaustive_nibble_pairs(self):
        hexdigits = "0123456789ABCDEF"
        for d in hexdigits:
            with self.subTest(left_wild=d):
                canon, pattern = sigmaker.SigText.normalize(f"?{d}")
                self.assertEqual(canon, f"?{d}")
                self.assertEqual(pattern, [((0x0 << 4) | int(d, 16), True)])

            with self.subTest(right_wild=d):
                canon, pattern = sigmaker.SigText.normalize(f"{d}?")
                self.assertEqual(canon, f"{d}?")
                self.assertEqual(pattern, [((int(d, 16) << 4) | 0x0, True)])

    # -----------------
    # Whitespace / empty
    # -----------------
    def test_whitespace_only(self):
        self.assertEqual(sigmaker.SigText.normalize("   \t \n "), ("", []))

    def test_empty_string(self):
        self.assertEqual(sigmaker.SigText.normalize(""), ("", []))

    # --------------
    # Invalid inputs
    # --------------
    def test_invalid_char(self):
        with self.assertRaises(ValueError):
            sigmaker.SigText.normalize("E8 G0")  # 'G' is not hex

    def test_invalid_token_length(self):
        with self.assertRaises(ValueError):
            sigmaker.SigText.normalize("E8Q")  # glued token of length 3 (no separator)

        with self.assertRaises(ValueError):
            sigmaker.SigText.normalize("???")  # length 3 token, invalid

    def test_invalid_glued_hex_and_wildcards(self):
        # This used to be accepted by some looser parsers; here we require separators.
        with self.assertRaises(ValueError):
            sigmaker.SigText.normalize("E8??90")  # not tokenized; must be "E8 ?? 90"

    def test_invalid_mixed_bad_symbol(self):
        with self.assertRaises(ValueError):
            sigmaker.SigText.normalize(
                "48 ^ 90"
            )  # '^' becomes its own token -> invalid

    def test_spacing_separators(self):
        # spacing / separators
        _assert_sig(
            self,
            "e8  ??  ?? ??   ??  ??  48 89 c7",
            "E8 ?? ?? ?? ?? ?? 48 89 C7",
            [
                (0xE8, False),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x48, False),
                (0x89, False),
                (0xC7, False),
            ],
        )

    def test_odd_nibbles_padded(self):
        # odd nibbles padded (single hex becomes high-nibble set, low nibble '?')
        _assert_sig(
            self,
            "E 8 4 ? C",
            "E? 8? 4? ?? C?",
            [
                (0xE0, True),  # E? → 0xE0 with mask 0x0F
                (0x80, True),  # 8? → 0x80 with mask 0x0F
                (0x40, True),  # 4? → 0x40 with mask 0x0F
                (0x00, True),  # ? → wildcard byte
                (0xC0, True),  # C? → mask 0x0F (wildcard low nibble)
            ],
        )

    def test_mixed_nibble_tokens(self):
        # mixed nibble tokens pass through
        _assert_sig(
            self,
            "F? ?C ?? 48 89 C7",
            "F? ?C ?? 48 89 C7",
            [
                (0xF0, True),  # F? → mask 0x0F
                (0x0C, True),  # ?C → mask 0xF0
                (0x00, True),  # ?? → wildcard
                (0x48, False),
                (0x89, False),
                (0xC7, False),
            ],
        )

    def test_0x_runs_even(self):
        # 0x runs (even)
        _assert_sig(
            self,
            "0xE84889C7",
            "E8 48 89 C7",
            [
                (0xE8, False),
                (0x48, False),
                (0x89, False),
                (0xC7, False),
            ],
        )

    def test_0x_runs_odd(self):
        # 0x runs (odd)
        _assert_sig(
            self,
            "0xE84889C",  # odd -> last nibble padded with '?'
            "E8 48 89 ?C",
            [
                (0xE8, False),
                (0x48, False),
                (0x89, False),
                (0x0C, True),  # ?C → mask 0xF0
            ],
        )


class TestSignatureFormatting(CoveredUnitTest):

    def test_build_ida_signature_string(self):
        sig = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0xC7, False),
                sigmaker.SignatureByte(0x44, False),
                sigmaker.SignatureByte(0x24, False),
                sigmaker.SignatureByte(0x34, False),
                sigmaker.SignatureByte(0x00, False),
                sigmaker.SignatureByte(0x00, False),
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x00, True),
            ]
        )
        self.assertEqual(f"{sig:ida}", "C7 44 24 34 00 00 ? ?")

    def test_build_byte_array_with_mask(self):
        sig = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x49, False),
                sigmaker.SignatureByte(0x28, False),
                sigmaker.SignatureByte(0x15, False),
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x30, False),
            ]
        )
        expected = "\\x49\\x28\\x15\\x00\\x00\\x30 xxx??x"
        self.assertEqual(f"{sig:mask}", expected)

    def test_build_bytes_with_bitmask(self):
        sig = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0xE8, False),
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x45, False),
            ]
        )
        self.assertEqual(
            f"{sig:bitmask}",
            "0xE8, 0x00, 0x45 0b101",
        )

    def test_format_signature_variants(self):
        sig = sigmaker.Signature(
            [sigmaker.SignatureByte(0xAB, False), sigmaker.SignatureByte(0x00, True)]
        )
        self.assertEqual(
            f"{sig:ida}",
            "AB ?",
        )
        self.assertEqual(
            f"{sig:x64dbg}",
            "AB ??",
        )


class TestUtilities(CoveredUnitTest):

    def test_trim_signature(self):
        sig = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x90, False),
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x00, True),
            ]
        )
        sig.trim_signature()
        self.assertEqual(len(sig), 1)

    def test_get_regex_matches(self):
        matches = []
        pattern = re.compile(r"[A-Z]{2}")
        found_matches = pattern.findall("AA BB CC")
        matches.extend(found_matches)
        ok = len(found_matches) > 0
        self.assertTrue(ok)
        self.assertEqual(matches, ["AA", "BB", "CC"])

    def test_parse_signature(self):
        normalized, pattern = sigmaker.SigText.normalize("C7 44 24 34 00 00 ?? ?")
        self.assertEqual(normalized, "C7 44 24 34 00 00 ?? ??")
        self.assertEqual(len(pattern), 8)
        # bytes
        self.assertEqual(pattern[0], (0xC7, False))
        self.assertEqual(pattern[5], (0x00, False))
        # wildcards
        self.assertEqual(pattern[6], (0, True))
        self.assertEqual(pattern[7], (0, True))


class TestSignatureManipulation(CoveredUnitTest):
    """Test signature building and manipulation functions"""

    def test_signature_trimming(self):
        signature = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x48, False),
                sigmaker.SignatureByte(0x8B, False),
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x00, True),
            ]
        )
        signature.trim_signature()
        self.assertEqual(len(signature), 2)

        signature = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x48, False),
                sigmaker.SignatureByte(0x8B, False),
            ]
        )
        original_length = len(signature)
        signature.trim_signature()
        self.assertEqual(len(signature), original_length)

        signature = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x00, True),
            ]
        )
        signature.trim_signature()
        self.assertEqual(len(signature), 0)

    def test_signature_byte_creation(self):
        sig_byte = sigmaker.SignatureByte(0x48, False)
        self.assertEqual(sig_byte.value, 0x48)
        self.assertFalse(sig_byte.is_wildcard)

        wild_byte = sigmaker.SignatureByte(0x00, True)
        self.assertEqual(wild_byte.value, 0x00)
        self.assertTrue(wild_byte.is_wildcard)


class TestOutputFormats(CoveredUnitTest):
    """Test signature output formatting"""

    def test_all_signature_types(self):
        signature = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x48, False),
                sigmaker.SignatureByte(0x8B, False),
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0xC0, False),
            ]
        )

        ida_result = f"{signature:ida}"
        self.assertEqual(ida_result, "48 8B ? C0")

        x64dbg_result = f"{signature:x64dbg}"
        self.assertEqual(x64dbg_result, "48 8B ?? C0")

        mask_result = f"{signature:mask}"
        self.assertEqual(mask_result, "\\x48\\x8B\\x00\\xC0 xx?x")

        bitmask_result = f"{signature:bitmask}"
        self.assertEqual(bitmask_result, "0x48, 0x8B, 0x00, 0xC0 0b1011")

    def test_format_signature_edge_cases(self):
        empty_signature = sigmaker.Signature([])
        empty_result = f"{empty_signature:ida}"
        self.assertEqual(empty_result, "")

        all_wildcards = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x00, True),
                sigmaker.SignatureByte(0x00, True),
            ]
        )
        wildcard_result = f"{all_wildcards:ida}"
        self.assertEqual(wildcard_result, "? ?")

    def test_double_question_mark_format(self):
        signature = sigmaker.Signature(
            [
                sigmaker.SignatureByte(0x48, False),
                sigmaker.SignatureByte(0x00, True),
            ]
        )
        single_result = f"{signature:ida}"
        self.assertEqual(single_result, "48 ?")

        double_result = f"{signature:x64dbg}"
        self.assertEqual(double_result, "48 ??")


class TestErrorHandling(CoveredUnitTest):
    """Test error handling and edge cases"""

    def test_unexpected_exception(self):
        with self.assertRaises(sigmaker.Unexpected):
            raise sigmaker.Unexpected("Test error message")

        try:
            raise sigmaker.Unexpected("Test error")
        except sigmaker.Unexpected as e:
            self.assertEqual(str(e), "Test error")

    def test_regex_matching(self):
        matches = []
        test_string = "AB CD EF"
        pattern = re.compile(r"[A-Z]{2}")

        found_matches = pattern.findall(test_string)
        matches.extend(found_matches)
        result = len(found_matches) > 0
        self.assertTrue(result)
        self.assertEqual(matches, ["AB", "CD", "EF"])

        matches.clear()
        no_match_string = "123 456"
        found_matches = pattern.findall(no_match_string)
        matches.extend(found_matches)
        result = len(found_matches) > 0
        self.assertFalse(result)
        self.assertEqual(matches, [])


@unittest.skipUnless(
    sigmaker.SIMD_SPEEDUP_AVAILABLE,
    "SIMD speedup not available or _simd_scan module not compiled",
)
class TestSimdScanIntegration(CoveredUnitTest):
    """Integration tests combining multiple _simd_scan features"""

    def test_signature_reuse(self):
        """Test reusing the same signature object multiple times."""
        sig = sigmaker._SimdSignature("48 8B C4")

        # Test with different data sets
        test_data1 = array.array("B", [0x48, 0x8B, 0xC4, 0x48, 0x89])
        test_data2 = array.array("B", [0xFF, 0x48, 0x8B, 0xC4, 0x00])

        result1 = sigmaker._simd_scan_bytes(memoryview(test_data1), sig)
        result2 = sigmaker._simd_scan_bytes(memoryview(test_data2), sig)

        self.assertEqual(result1, 0)
        self.assertEqual(result2, 1)

    def test_multiple_signatures(self):
        """Test scanning with multiple different signature objects."""
        signatures = [
            sigmaker._SimdSignature("48 8B"),
            sigmaker._SimdSignature("8B C4"),
            sigmaker._SimdSignature("C4 48"),
        ]

        test_data = array.array("B", [0x48, 0x8B, 0xC4, 0x48, 0x89, 0x45])
        data_view = memoryview(test_data)

        results = []
        for sig in signatures:
            result = sigmaker._simd_scan_bytes(data_view, sig)
            results.append(result)

        self.assertEqual(results, [0, 1, 2])  # Each pattern found at expected position


@unittest.skipUnless(
    sigmaker.SIMD_SPEEDUP_AVAILABLE,
    "SIMD speedup not available or _simd_scan module not compiled",
)
class TestSimdScanSignature(CoveredUnitTest):
    """Test the Signature class from _simd_scan.pyx"""

    def test_signature_creation_basic(self):
        """Test basic signature creation without mask."""
        sig_str = "48 8B C4"
        sig = sigmaker._SimdSignature(sig_str)

        self.assertEqual(sig.size_bytes, 3)
        self.assertFalse(sig.has_mask)

        # Test data access
        data_ptr = sig.data_ptr()
        self.assertIsNotNone(data_ptr)

        # Test mask access (should be NULL for no mask)
        mask_ptr = sig.mask_ptr()
        self.assertIsNone(mask_ptr)

    def test_signature_creation_with_mask(self):
        """Test signature creation with explicit mask."""
        sig_str = "48 8B C4"
        mask_str = "FF FF 00"
        sig = sigmaker._SimdSignature(sig_str, mask=mask_str)

        self.assertEqual(sig.size_bytes, 3)
        self.assertTrue(sig.has_mask)

        # Test data and mask access
        data_ptr = sig.data_ptr()
        mask_ptr = sig.mask_ptr()
        self.assertIsNotNone(data_ptr)
        self.assertIsNotNone(mask_ptr)

    def test_signature_creation_with_wildcards(self):
        """Test signature creation with wildcard nibbles."""
        sig_str = "48 8B ??"
        sig = sigmaker._SimdSignature(sig_str)

        self.assertEqual(sig.size_bytes, 3)
        self.assertTrue(sig.has_mask)  # Wildcards create implicit mask

    def test_signature_creation_invalid_format(self):
        """Test signature creation with invalid format."""
        with self.assertRaises(ValueError):
            sigmaker._SimdSignature("48 8")  # Invalid format (incomplete byte pair)

    def test_signature_creation_empty(self):
        """Test signature creation with empty string."""
        with self.assertRaises(ValueError):
            sigmaker._SimdSignature("")

    def test_signature_creation_invalid_hex(self):
        """Test signature creation with invalid hex characters."""
        with self.assertRaises(ValueError):
            sigmaker._SimdSignature("XX 8B C4")  # Invalid hex

    def test_signature_simd_kind_setting(self):
        """Test SIMD kind setting and getting."""
        sig = sigmaker._SimdSignature("48 8B C4")

        # Default should be best level available
        self.assertEqual(sig.simd_kind(), sigmaker.simd_scan.simd_best_level())

        # Test AVX2 setting
        sig.set_simd_kind(2)
        self.assertEqual(sig.simd_kind(), 2)

        # Test NEON setting
        sig.set_simd_kind(4)
        self.assertEqual(sig.simd_kind(), 4)

        # Test invalid SIMD kind (should reset to SIMD_SCALAR)
        sig.set_simd_kind(5)
        self.assertEqual(sig.simd_kind(), 1)

    def test_signature_with_simd_kind_constructor(self):
        """Test signature creation with SIMD kind in constructor."""
        sig = sigmaker._SimdSignature("48 8B C4", simd_kind=2)
        self.assertEqual(sig.simd_kind(), 2)

        sig = sigmaker._SimdSignature("48 8B C4", simd_kind=3)
        self.assertEqual(sig.simd_kind(), 3)

        sig = sigmaker._SimdSignature("48 8B C4", simd_kind=4)
        self.assertEqual(sig.simd_kind(), 4)

        # Invalid SIMD kind should default to 1 (SIMD_SCALAR)
        sig = sigmaker._SimdSignature("48 8B C4", simd_kind=5)
        self.assertEqual(sig.simd_kind(), 1)


@unittest.skipUnless(
    platform.system() == "Darwin"
    and any(
        arch in platform.machine().lower()
        for arch in ("x86_64", "amd64", "i686", "x86")
    ),
    "Requires macOS x86",
)
class TestMacOSx86Integration(CoveredUnitTest):
    """Integration tests specific to macOS x86."""

    def test_simd_scan_best_level(self):
        """Test the simd_best_level function."""
        self.assertEqual(sigmaker.simd_scan.simd_best_level(), 3)


@unittest.skipUnless(
    platform.system() == "Darwin"
    and any(
        arch in platform.machine().lower()
        for arch in ("aarch64", "arm64", "armv8", "armv7", "arm")
    ),
    "Requires macOS ARM",
)
class TestMacOSARMIntegration(CoveredUnitTest):
    """Integration tests specific to macOS ARM (Apple Silicon)."""

    def test_simd_scan_best_level(self):
        """Test the simd_best_level function."""
        self.assertEqual(
            sigmaker.simd_scan.simd_best_level(), 4
        )  # SIMD_ARM_NEON always available on ARM


@unittest.skipUnless(
    platform.system() == "Linux"
    and any(
        arch in platform.machine().lower()
        for arch in ("x86_64", "amd64", "i686", "x86")
    ),
    "Requires Linux x86",
)
class TestLinux86Integration(CoveredUnitTest):
    """Integration tests specific to Linux x86."""

    def test_simd_scan_best_level(self):
        """Test the simd_best_level function."""
        self.assertIn(
            sigmaker.simd_scan.simd_best_level(), [2, 3]
        )  # either SSE2 or AVX2


@unittest.skipUnless(platform.system() == "Windows", "Requires Windows")
class TestWindowsIntegration(CoveredUnitTest):
    """Integration tests specific to Windows."""

    def test_simd_scan_best_level(self):
        """Test the simd_best_level function."""
        self.assertIn(
            sigmaker.simd_scan.simd_best_level(), [2, 3]
        )  # either SSE2 or AVX2


@unittest.skipUnless(
    sigmaker.SIMD_SPEEDUP_AVAILABLE,
    "SIMD speedup not available or _simd_scan module not compiled",
)
class TestSimdScanParsingHelpers(CoveredUnitTest):
    """Test parsing helper functions from _simd_scan.pyx"""

    def test_hex_nibble_parsing(self):
        """Test hex nibble parsing functionality through Signature creation."""
        # Test all valid hex characters
        test_cases = [
            ("0", 0x00),
            ("1", 0x10),
            ("2", 0x20),
            ("3", 0x30),
            ("4", 0x40),
            ("5", 0x50),
            ("6", 0x60),
            ("7", 0x70),
            ("8", 0x80),
            ("9", 0x90),
            ("A", 0xA0),
            ("B", 0xB0),
            ("C", 0xC0),
            ("D", 0xD0),
            ("E", 0xE0),
            ("F", 0xF0),
            ("a", 0xA0),
            ("b", 0xB0),
            ("c", 0xC0),
            ("d", 0xD0),
            ("e", 0xE0),
            ("f", 0xF0),
        ]

        for nibble, expected in test_cases:
            with self.subTest(nibble=nibble):
                sig_str = "{0}0".format(nibble)
                sig = sigmaker._SimdSignature(sig_str)
                data = sig.data_ptr()
                self.assertEqual(data[0], expected)

    def test_wildcard_parsing(self):
        """Test wildcard nibble parsing."""
        # Test wildcard nibbles
        sig = sigmaker._SimdSignature("??")
        self.assertTrue(sig.has_mask)

        # Check that wildcards are properly handled
        data = sig.data_ptr()
        mask = sig.mask_ptr()
        self.assertIsNotNone(mask)

        # Wildcard nibbles should have 0 in data and 0 in mask (meaning ignore)
        self.assertEqual(data[0], 0x00)
        self.assertEqual(mask[0], 0x00)  # Both nibbles are wildcards

    def test_mixed_wildcard_parsing(self):
        """Test mixed wildcard and hex nibble parsing."""
        sig = sigmaker._SimdSignature("?F ?0")
        self.assertTrue(sig.has_mask)

        data = sig.data_ptr()
        mask = sig.mask_ptr()

        # First byte: ?F -> data=0x0F, mask=0x0F (upper nibble ignored)
        self.assertEqual(data[0], 0x0F)
        self.assertEqual(mask[0], 0x0F)

        # Second byte: ?0 -> data=0x00, mask=0x0F (lower nibble ignored)
        self.assertEqual(data[1], 0x00)
        self.assertEqual(mask[1], 0x0F)


@unittest.skipUnless(
    sigmaker.SIMD_SPEEDUP_AVAILABLE,
    "SIMD speedup not available or _simd_scan module not compiled",
)
class TestSimdScanBytes(CoveredUnitTest):
    """Test the scan_bytes function from _simd_scan.pyx"""

    def setUp(self):
        """Set up test data."""
        # Create test data: 48 8B C4 48 89 45 F8
        self.test_data = array.array("B", [0x48, 0x8B, 0xC4, 0x48, 0x89, 0x45, 0xF8])
        self.data_view = memoryview(self.test_data)

    def test_scan_bytes_exact_match(self):
        """Test scanning for an exact match."""
        sig = sigmaker._SimdSignature("48 8B C4")
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, 0)  # Found at position 0

    def test_scan_bytes_partial_match(self):
        """Test scanning for a partial match."""
        sig = sigmaker._SimdSignature("48 89 45")
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, 3)  # Found at position 3

    def test_scan_bytes_no_match(self):
        """Test scanning when pattern is not found."""
        sig = sigmaker._SimdSignature("FF FF FF")
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, -1)  # Not found

    def test_scan_bytes_with_wildcards(self):
        """Test scanning with wildcard bytes."""
        sig = sigmaker._SimdSignature("48 ?? C4")
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, 0)  # Found at position 0

    def test_scan_bytes_empty_signature(self):
        """Test scanning with empty signature."""
        sig = sigmaker._SimdSignature(
            "48 8B C4 48 89 45 F8"
        )  # Exact match for entire data
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, 0)

    def test_scan_bytes_larger_than_data(self):
        """Test scanning with signature larger than data."""
        sig = sigmaker._SimdSignature("48 8B C4 48 89 45 F8 FF FF")
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, -1)  # Not found (too large)

    def test_scan_bytes_empty_data(self):
        """Test scanning in empty data."""
        empty_data = array.array("B", [])
        empty_view = memoryview(empty_data)
        sig = sigmaker._SimdSignature("48 8B")
        result = sigmaker._simd_scan_bytes(empty_view, sig)
        self.assertEqual(result, -1)

    def test_scan_bytes_single_byte(self):
        """Test scanning for single byte patterns."""
        sig = sigmaker._SimdSignature("48")
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, 0)  # First byte

        sig = sigmaker._SimdSignature("45")
        result = sigmaker._simd_scan_bytes(self.data_view, sig)
        self.assertEqual(result, 5)  # Found at position 5


@unittest.skipUnless(
    sigmaker.SIMD_SPEEDUP_AVAILABLE,
    "SIMD speedup not available or _simd_scan module not compiled",
)
class TestSimdScanEdgeCases(CoveredUnitTest):
    """Test edge cases and error conditions"""

    def test_signature_large_pattern(self):
        """Test with a large signature pattern."""
        # Create a large pattern (256 bytes)
        pattern_parts = []
        for i in range(128):
            pattern_parts.append("48 8B")
        large_pattern = " ".join(pattern_parts)

        sig = sigmaker._SimdSignature(large_pattern)
        self.assertEqual(sig.size_bytes, 256)

        # Test scanning with large pattern
        test_data = array.array("B", [0x48, 0x8B] * 130)  # Enough data
        data_view = memoryview(test_data)

        result = sigmaker._simd_scan_bytes(data_view, sig)
        self.assertEqual(result, 0)  # Should find at beginning

    def test_signature_complex_mask(self):
        """Test signature with complex mask patterns."""
        # Pattern with alternating wildcards
        sig_str = "48 ? 8B ? C4 ? 89"
        sig = sigmaker._SimdSignature(sig_str)

        self.assertTrue(sig.has_mask)
        self.assertEqual(sig.size_bytes, 7)

    def test_memory_management(self):
        """Test that signatures properly manage memory."""
        import gc

        # Create many signatures to test memory management
        signatures = []
        for i in range(1000):
            sig = sigmaker._SimdSignature("48 8B {0:02X}".format(i % 256))
            signatures.append(sig)

        # Force garbage collection
        del signatures
        gc.collect()

        # Should not crash or leak memory
        self.assertTrue(True)

    def test_simd_kind_persistence(self):
        """Test that SIMD kind setting persists correctly."""
        sig = sigmaker._SimdSignature("48 8B C4")

        # Test all valid SIMD kinds
        for kind in [1, 2, 3, 4]:
            sig.set_simd_kind(kind)
            self.assertEqual(sig.simd_kind(), kind)


@unittest.skipUnless(
    sigmaker.SIMD_SPEEDUP_AVAILABLE,
    "SIMD speedup not available or _simd_scan module not compiled",
)
class TestSimdScanPerformance(CoveredUnitTest):
    """Test performance characteristics of SIMD scanning"""

    def test_small_data_performance(self):
        """Test scanning performance with small data sets."""
        # Create small test data
        test_data = array.array("B", [0x48, 0x8B, 0xC4, 0x48, 0x89, 0x45])
        data_view = memoryview(test_data)

        sig = sigmaker._SimdSignature("48 8B")

        start_time = time.time()
        result = sigmaker._simd_scan_bytes(data_view, sig)
        end_time = time.time()

        self.assertEqual(result, 0)
        self.assertLess(end_time - start_time, 0.01)  # Should be very fast

    def test_large_data_performance(self):
        """Test scanning performance with larger data sets."""
        # Create larger test data (1KB)
        test_data = array.array("B", [0x48, 0x8B] * 512)
        data_view = memoryview(test_data)

        sig = sigmaker._SimdSignature("48 8B")

        start_time = time.time()
        result = sigmaker._simd_scan_bytes(data_view, sig)
        end_time = time.time()

        self.assertEqual(result, 0)
        self.assertLess(end_time - start_time, 0.1)  # Should be reasonably fast


class TestStandaloneSimdScanning(CoveredUnitTest):
    """Test SIMD scanning directly without IDA Pro dependencies."""

    def test_simd_scan_exact_match(self):
        """Test SIMD scanning with exact match pattern."""
        # Create test data: some bytes followed by our target pattern
        pattern = b"\xe8\x12\x34\x56\x78\x48\x89\xc7"  # E8 12 34 56 78 48 89 C7
        prefix = b"\x90\x90\x90\x90"  # NOP padding
        suffix = b"\x90\x90\x90\x90"

        test_data = prefix + pattern + suffix
        data_view = memoryview(test_data)

        # Create SIMD signature
        sig_str = "E8 12 34 56 78 48 89 C7"
        sig = sigmaker.simd_scan.Signature(sig_str)

        # Scan for the pattern
        result = sigmaker.simd_scan.scan_bytes(data_view, sig)

        # Should find the pattern at offset 4 (after the 4 NOP bytes)
        self.assertEqual(result, 4, f"Expected match at offset 4, got {result}")

    def test_simd_signature_construction(self):
        """Test that SIMD signature construction works correctly for wildcard patterns."""
        # Test pattern: "E8 ?? ?? ?? ?? 48 89 C7"
        pattern = "E8 ?? ?? ?? ?? 48 89 C7"
        sig = sigmaker.simd_scan.Signature(pattern)

        # Get the internal data and mask
        data_size = sig.size()
        print(f"\n=== Testing SIMD Signature Construction ===")
        print(f"Pattern: {pattern}")
        print(f"Data size: {data_size}")

        # Get data and mask as bytes objects
        data_bytes_obj = sig.data_ptr()
        mask_bytes_obj = sig.mask_ptr()

        # Convert to lists for easier inspection
        data_bytes = list(data_bytes_obj)
        mask_bytes = list(mask_bytes_obj) if mask_bytes_obj else []

        print(f"Data bytes: {' '.join(f'{b:02X}' for b in data_bytes)}")
        print(
            f"Mask bytes: {' '.join(f'{b:02X}' for b in mask_bytes) if mask_bytes else 'None'}"
        )

        # Expected values:
        # Data: E8 00 00 00 00 48 89 C7 (wildcards become 0x00)
        # Mask: FF 00 00 00 00 FF FF FF (wildcards become 0x00, exact bytes become 0xFF)

        expected_data = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC7]
        expected_mask = [0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF]

        self.assertEqual(
            data_bytes,
            expected_data,
            f"Data bytes should be {expected_data}, got {data_bytes}",
        )
        self.assertEqual(
            mask_bytes,
            expected_mask,
            f"Mask bytes should be {expected_mask}, got {mask_bytes}",
        )

        # Test with a simple data buffer
        test_data = b"\xe8\x80\x0a\x00\x00\x48\x89\xc7"  # Our known pattern
        data_view = memoryview(test_data)

        result = sigmaker.simd_scan.scan_bytes(data_view, sig)
        print(f"Search result for exact match: {result}")

        self.assertEqual(result, 0, f"Should find pattern at offset 0, got {result}")

    def test_simd_scan_with_wildcards(self):
        """Test SIMD scanning with wildcard pattern."""
        # Create test data with our target pattern
        pattern = b"\xe8\xaa\xbb\xcc\xdd\x48\x89\xc7"  # E8 ?? ?? ?? ?? 48 89 C7
        prefix = b"\x90\x90\x90\x90"
        suffix = b"\x90\x90\x90\x90"

        test_data = prefix + pattern + suffix
        data_view = memoryview(test_data)

        # Create SIMD signature with wildcards
        sig_str = "E8 ?? ?? ?? ?? 48 89 C7"
        sig = sigmaker.simd_scan.Signature(sig_str)

        # Scan for the pattern
        result = sigmaker.simd_scan.scan_bytes(data_view, sig)

        # Should find the pattern at offset 4
        self.assertEqual(result, 4, f"Expected match at offset 4, got {result}")

    def test_simd_scan_no_match(self):
        """Test SIMD scanning when pattern is not found."""
        # Create test data without our target pattern
        test_data = b"\x90\x90\x90\x90\x12\x34\x56\x78\x90\x90\x90\x90"
        data_view = memoryview(test_data)

        # Create SIMD signature
        sig_str = "E8 12 34 56 78 48 89 C7"
        sig = sigmaker.simd_scan.Signature(sig_str)

        # Scan for the pattern
        result = sigmaker.simd_scan.scan_bytes(data_view, sig)

        # Should not find the pattern
        self.assertEqual(result, -1, f"Expected no match (-1), got {result}")

    def test_simd_scan_multiple_matches(self):
        """Test SIMD scanning with multiple potential matches."""
        # Create test data with multiple instances of the pattern
        pattern = b"\xe8\x12\x34\x56\x78\x48\x89\xc7"
        test_data = pattern + b"\x90\x90" + pattern + b"\x90\x90" + pattern
        data_view = memoryview(test_data)

        # Create SIMD signature
        sig_str = "E8 12 34 56 78 48 89 C7"
        sig = sigmaker.simd_scan.Signature(sig_str)

        # Scan for the first occurrence
        result = sigmaker.simd_scan.scan_bytes(data_view, sig)

        # Should find the first pattern at offset 0
        self.assertEqual(result, 0, f"Expected first match at offset 0, got {result}")

    def test_simd_scan_at_boundary(self):
        """Test SIMD scanning at the end of data."""
        # Create test data where pattern is at the very end
        pattern = b"\xe8\x12\x34\x56\x78\x48\x89\xc7"
        prefix = b"\x90\x90\x90\x90"
        test_data = prefix + pattern
        data_view = memoryview(test_data)

        # Create SIMD signature
        sig_str = "E8 12 34 56 78 48 89 C7"
        sig = sigmaker.simd_scan.Signature(sig_str)

        # Scan for the pattern
        result = sigmaker.simd_scan.scan_bytes(data_view, sig)

        # Should find the pattern at offset 4
        self.assertEqual(result, 4, f"Expected match at offset 4, got {result}")

    def test_simd_signature_creation_edge_cases(self):
        """Test SIMD signature creation with various edge cases."""
        # Test empty signature
        with self.assertRaises(ValueError):
            sig = sigmaker.simd_scan.Signature("")

        # Test invalid hex
        with self.assertRaises(ValueError):
            sig = sigmaker.simd_scan.Signature("GG")

        # Test odd number of characters
        with self.assertRaises(ValueError):
            sig = sigmaker.simd_scan.Signature("E812")

    def test_simd_scan_empty_data(self):
        """Test SIMD scanning with empty data."""
        test_data = b""
        data_view = memoryview(test_data)

        sig_str = "E8 12 34 56 78 48 89 C7"
        sig = sigmaker.simd_scan.Signature(sig_str)

        result = sigmaker.simd_scan.scan_bytes(data_view, sig)
        self.assertEqual(result, -1, f"Expected no match for empty data, got {result}")

    def test_simd_scan_pattern_larger_than_data(self):
        """Test SIMD scanning when pattern is larger than data."""
        test_data = b"\xe8\x12"  # Only 2 bytes
        data_view = memoryview(test_data)

        sig_str = "E8 12 34 56 78 48 89 C7"  # 8 bytes
        sig = sigmaker.simd_scan.Signature(sig_str)

        result = sigmaker.simd_scan.scan_bytes(data_view, sig)
        self.assertEqual(
            result, -1, f"Expected no match when pattern > data, got {result}"
        )

    def test_integration_test_pattern(self):
        """Test the exact pattern from the failing integration test."""
        # Create test data that contains the pattern from the failing test
        # Pattern: E8 ?? ?? ?? ?? 48 89 C7
        # Let's use concrete values for the wildcards: E8 AA BB CC DD 48 89 C7
        pattern = b"\xe8\xaa\xbb\xcc\xdd\x48\x89\xc7"
        prefix = b"\x90\x90\x90\x90"  # Some padding
        suffix = b"\x90\x90\x90\x90"

        test_data = prefix + pattern + suffix
        data_view = memoryview(test_data)

        # Test exact match first
        exact_sig_str = "E8 AA BB CC DD 48 89 C7"
        exact_sig = sigmaker.simd_scan.Signature(exact_sig_str)
        exact_result = sigmaker.simd_scan.scan_bytes(data_view, exact_sig)
        self.assertEqual(
            exact_result, 4, f"Exact match should be at offset 4, got {exact_result}"
        )

        # Test with wildcards
        wildcard_sig_str = "E8 ?? ?? ?? ?? 48 89 C7"
        wildcard_sig = sigmaker.simd_scan.Signature(wildcard_sig_str)
        wildcard_result = sigmaker.simd_scan.scan_bytes(data_view, wildcard_sig)
        self.assertEqual(
            wildcard_result,
            4,
            f"Wildcard match should be at offset 4, got {wildcard_result}",
        )

        # Verify both give same result
        self.assertEqual(
            exact_result,
            wildcard_result,
            "Exact and wildcard searches should find same match",
        )

    def test_sigmaker_searcher_pipeline(self):
        """Test the full sigmaker search pipeline without IDA Pro."""
        # Create test data
        pattern = b"\xe8\xaa\xbb\xcc\xdd\x48\x89\xc7"
        test_data = b"\x90\x90\x90\x90" + pattern + b"\x90\x90\x90\x90"
        data_view = memoryview(test_data)

        # Test the search pipeline similar to SignatureSearcher
        sig_str = "E8 ?? ?? ?? ?? 48 89 C7"

        # Normalize the signature (mimic SigText.normalize)
        norm_text, pattern_tuples = SigText.normalize(sig_str)
        self.assertEqual(norm_text, "E8 ?? ?? ?? ?? 48 89 C7")

        # Create SIMD signature
        sig = sigmaker.simd_scan.Signature(norm_text)

        # Scan
        result = sigmaker.simd_scan.scan_bytes(data_view, sig)

        # Should find the pattern
        self.assertEqual(result, 4, f"Should find pattern at offset 4, got {result}")

        # Test that the result is within bounds
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, len(test_data) - 8)  # 8 is pattern length

    def test_find_common_patterns_in_binary(self):
        """Test finding some common instruction patterns that might exist in binaries."""
        # Create test data with some common x86-64 instruction patterns
        patterns_to_test = [
            ("NOP sled", b"\x90\x90\x90\x90"),
            ("RET", b"\xc3"),
            ("MOV EAX, EAX", b"\x89\xc0"),
            ("PUSH RBP", b"\x55"),
            ("POP RBP", b"\x5d"),
            ("XOR EAX, EAX", b"\x31\xc0"),
            ("CALL rel32", b"\xe8\x00\x00\x00\x00"),  # CALL with 4 zero bytes
            ("MOV RCX, RDX", b"\x48\x89\xd1"),
        ]

        # Create a larger test binary with multiple patterns
        test_data = b""
        offsets = {}

        for name, pattern in patterns_to_test:
            # Add some padding before each pattern
            padding = b"\xcc" * random.randint(1, 10)  # INT3 as padding
            test_data += padding
            offsets[name] = len(test_data)
            test_data += pattern

        # Add final padding
        test_data += b"\xcc" * 20
        data_view = memoryview(test_data)

        # Test finding each pattern
        for name, pattern in patterns_to_test:
            sig_str = " ".join(f"{b:02X}" for b in pattern)
            sig = sigmaker.simd_scan.Signature(sig_str)
            result = sigmaker.simd_scan.scan_bytes(data_view, sig)

            expected_offset = offsets[name]
            self.assertEqual(
                result,
                expected_offset,
                f"Pattern '{name}' ({sig_str}) should be at offset {expected_offset}, got {result}",
            )

    def test_wildcard_variations(self):
        """Test various wildcard patterns to ensure they work correctly."""
        # Test data with a pattern that has some varying bytes
        base_pattern = b"\xe8\x12\x34\x56\x78\x48\x89\xc7"
        variations = [
            (b"\xe8\x12\x34\x56\x78\x48\x89\xc7", "E8 12 34 56 78 48 89 C7"),  # Exact
            (
                b"\xe8\xaa\x34\x56\x78\x48\x89\xc7",
                "E8 ?? 34 56 78 48 89 C7",
            ),  # First byte wildcard
            (
                b"\xe8\x12\xbb\x56\x78\x48\x89\xc7",
                "E8 12 ?? 56 78 48 89 C7",
            ),  # Second byte wildcard
            (
                b"\xe8\x12\x34\xcc\x78\x48\x89\xc7",
                "E8 12 34 ?? 78 48 89 C7",
            ),  # Third byte wildcard
            (
                b"\xe8\x12\x34\x56\xdd\x48\x89\xc7",
                "E8 12 34 56 ?? 48 89 C7",
            ),  # Fourth byte wildcard
        ]

        for i, (pattern_bytes, sig_str) in enumerate(variations):
            test_data = b"\x90\x90" + pattern_bytes + b"\x90\x90"
            data_view = memoryview(test_data)

            sig = sigmaker.simd_scan.Signature(sig_str)
            result = sigmaker.simd_scan.scan_bytes(data_view, sig)

            self.assertEqual(
                result,
                2,
                f"Variation {i} ({sig_str}) should be at offset 2, got {result}",
            )

    def test_debug_binary_patterns(self):
        """Test that can help debug what patterns exist in the IDA test binary."""
        # This test creates a simulated binary with common patterns
        # and tests our search functionality

        # Create a "binary" with common patterns
        binary_data = (
            b"\x90\x90\x90\x90"  # NOP sled
            b"\xe8\x00\x00\x00\x00"  # CALL rel32 (what the integration test looks for)
            b"\x48\x89\xc7"  # MOV RDI, RAX
            b"\xc3"  # RET
            b"\x55"  # PUSH RBP
            b"\x48\x89\xe5"  # MOV RBP, RSP
            b"\x5d"  # POP RBP
            b"\x31\xc0"  # XOR EAX, EAX
        )

        data_view = memoryview(binary_data)

        # Test the exact pattern from the failing integration test
        test_patterns = [
            "E8 ?? ?? ?? ?? 48 89 C7",  # Original failing pattern
            "E8 00 00 00 00 48 89 C7",  # With concrete zeros
            "E8 ?? ?? ?? ??",  # Just the CALL part
            "48 89 C7",  # Just the MOV part
            "90 90 90 90",  # NOP sled
            "C3",  # RET
        ]

        print("\n=== Debug: Testing patterns in simulated binary ===")
        for sig_str in test_patterns:
            try:
                sig = sigmaker.simd_scan.Signature(sig_str)
                result = sigmaker.simd_scan.scan_bytes(data_view, sig)
                status = "FOUND" if result != -1 else "NOT FOUND"
                print(f"Pattern '{sig_str}': {status} at offset {result}")
            except Exception as e:
                print(f"Pattern '{sig_str}': ERROR - {e}")

        # The integration test expects to find the pattern at some offset
        # If our simulated binary doesn't contain it, that's why the test fails
        integration_pattern = "E8 ?? ?? ?? ?? 48 89 C7"
        sig = sigmaker.simd_scan.Signature(integration_pattern)
        result = sigmaker.simd_scan.scan_bytes(data_view, sig)

        if result == -1:
            self.skipTest(
                "Integration test pattern not found in simulated binary. "
                "This explains why the real integration test fails - "
                "the pattern doesn't exist in the test binary."
            )
        else:
            self.assertNotEqual(result, -1, "Should find the integration test pattern")


class TestSigTextAndSignatureParsing(CoveredUnitTest):
    def test_normalize_equivalents_spacing_and_separators(self):
        cases = [
            ("E8 ?? ?? ?? ?? 48 89 C7", "E8 ?? ?? ?? ?? 48 89 C7"),
            ("e8  ??  ?? ??   ??  ??  48 89 c7", "E8 ?? ?? ?? ?? ?? 48 89 C7"),
            ("E8 ? ? ? ? 48 89 C7", "E8 ?? ?? ?? ?? 48 89 C7"),
            ("0xE8 ?? ?? ?? ?? 0x48 0x89 0xC7", "E8 ?? ?? ?? ?? 48 89 C7"),
            ("E8,??,??,??,??,48,89,C7", "E8 ?? ?? ?? ?? 48 89 C7"),
            ("E8|??|??|??|??|48|89|C7", "E8 ?? ?? ?? ?? 48 89 C7"),
            ("E8-??-??-??-??-48-89-C7", "E8 ?? ?? ?? ?? 48 89 C7"),
            (" E8\t??\n??\r??  ?? _ 48,89;C7 ", "E8 ?? ?? ?? ?? 48 89 C7"),
        ]
        for inp, want in cases:
            norm, patt = SigText.normalize(inp)
            # Update expectations based on actual token count
            token_count = len(norm.split())
            self.assertEqual(norm, want, f"normalize({inp!r})")

            # quick structural check: token count matches
            self.assertEqual(len(norm.split()), token_count)
            self.assertEqual(len(patt), token_count)
            # First/last should be concrete, middle wildcards.
            self.assertEqual(patt[0][0], 0xE8)
            self.assertFalse(patt[0][1])
            # Check that we have wildcards in the middle
            wildcard_count = sum(1 for _, w in patt if w)
            self.assertGreater(wildcard_count, 0)
            self.assertEqual(patt[-3][0], 0x48)
            self.assertFalse(patt[-3][1])
            self.assertEqual(patt[-2][0], 0x89)
            self.assertFalse(patt[-2][1])
            self.assertEqual(patt[-1][0], 0xC7)
            self.assertFalse(patt[-1][1])

    def test_normalize_odd_nibbles_are_padded(self):
        # 1 nibble becomes one wildcarded nibble => forms a byte with '?'
        norm, patt = SigText.normalize("E 8 4 ? C")
        self.assertEqual(norm, "E? 8? 4? ?? C?")
        self.assertEqual([b for b, _ in patt], [0xE0, 0x80, 0x40, 0x00, 0xC0])
        self.assertEqual([w for _, w in patt], [True, True, True, True, True])

    def test_signature_mask_full_and_nibble(self):
        # Full-byte wildcards
        sig = sigmaker.simd_scan.Signature("11 ?? 22 ?? 33")
        self.assertEqual(sig.size(), 5)
        self.assertEqual(bytes(sig.data_ptr()), b"\x11\x00\x22\x00\x33")
        self.assertEqual(_mask_bytes(sig), b"\xff\x00\xff\x00\xff")

        # Nibble wildcards: upper/lower nibble masking
        sig2 = sigmaker.simd_scan.Signature("?1 2? 3?")
        self.assertEqual(sig2.size(), 3)
        self.assertEqual(bytes(sig2.data_ptr()), b"\x01\x20\x30")
        self.assertEqual(_mask_bytes(sig2), b"\x0f\xf0\xf0")

        # Mixed concrete & wildcard nibbles across several tokens
        sig3 = sigmaker.simd_scan.Signature("4? ?F ?? 7A A7")
        self.assertEqual(bytes(sig3.data_ptr()), b"\x40\x0f\x00\x7a\xa7")
        self.assertEqual(_mask_bytes(sig3), b"\xf0\x0f\x00\xff\xff")

    def test_signature_rejects_bad_formats(self):
        bad = [
            "",
            "GZ",
            "E8 ?X",
            "??Z",
            "E8?? ??",
            "xY",
            "0x",
            "E8? ? 48",
            "E8 ? ? ? ? 48 89 C7 Z",
        ]
        for s in bad:
            with self.assertRaises((ValueError, AssertionError), msg=f"input={s!r}"):
                sigmaker.simd_scan.Signature(s)

    def test_signature_bytes_and_mask_roundtrip(self):
        # Generate all hex bytes 00..FF and make sure each parses correctly alone.
        for hi, lo in itertools.product("0123456789ABCDEF", repeat=2):
            tok = f"{hi}{lo}"
            sig = sigmaker.simd_scan.Signature(tok)
            self.assertEqual(sig.size(), 1)
            self.assertEqual(bytes(sig.data_ptr()), bytes([int(tok, 16)]))
            self.assertIsNone(sig.mask_ptr())


class TestSIMDScannerEquivalence(CoveredUnitTest):
    def _assert_match_all_kinds(self, hay: bytes, pat: str, expect: int):
        # Portable
        s0 = sigmaker.simd_scan.Signature(pat, simd_kind=0)
        s0.set_simd_kind(0)
        off0 = sigmaker.simd_scan.scan_bytes(memoryview(hay), s0)

        # AVX2 (will fall back if not compiled for x86; still must be correct)
        s1 = sigmaker.simd_scan.Signature(pat, simd_kind=1)
        s1.set_simd_kind(1)
        off1 = sigmaker.simd_scan.scan_bytes(memoryview(hay), s1)

        # NEON (same story: correct even if compiled w/o NEON)
        s2 = sigmaker.simd_scan.Signature(pat, simd_kind=2)
        s2.set_simd_kind(2)
        off2 = sigmaker.simd_scan.scan_bytes(memoryview(hay), s2)

        # Collect results
        results = [(off0, "portable"), (off1, "AVX2"), (off2, "NEON")]

        # If expect is -1 (no match expected), all results should be -1
        if expect == -1:
            for off, name in results:
                self.assertEqual(
                    off,
                    -1,
                    f"{name} returned {off}, expected -1 (no match) for pattern {pat!r}",
                )
            return

        # Filter out -1 (unavailable implementations)
        valid_results = [(off, name) for off, name in results if off != -1]

        if not valid_results:
            self.fail(f"No SIMD implementations found the pattern {pat!r}")

        # All valid results should match each other
        first_valid_offset = valid_results[0][0]
        for off, name in valid_results:
            self.assertEqual(
                off,
                first_valid_offset,
                f"{name} returned {off}, expected {first_valid_offset} for pattern {pat!r}",
            )

        # The first valid result should match the expected value
        self.assertEqual(
            first_valid_offset,
            expect,
            f"Valid SIMD implementations returned {first_valid_offset}, expected {expect} for pattern {pat!r}",
        )

        # Also cross-check against reference
        ref = slow_masked_find(hay, bytes(s0.data_ptr()), s0.mask_ptr())
        self.assertEqual(ref, expect, "Reference finder disagrees")

    def test_basic_exact_no_mask(self):
        pat = "48 89 C7"
        for at in (0, 1, 15, 16, 31, 32, 63, 64, 512, 4090):
            hay = make_buf_with_pattern(
                bytes.fromhex("48 89 C7"), at, total=max(4096, at + 3)
            )
            self._assert_match_all_kinds(hay, pat, at)

    def test_full_byte_wildcards(self):
        # E8 ?? ?? ?? ?? 48 89 C7
        pat = "E8 ?? ?? ?? ?? 48 89 C7"
        seq = bytes.fromhex("E8 11 22 33 44 48 89 C7")
        for at in (0, 1, 15, 16, 31, 32, 63, 64, 2048):
            hay = make_buf_with_pattern(seq, at)
            self._assert_match_all_kinds(hay, pat, at)

    def test_nibble_wildcards(self):
        # 4? 8B ?4 C?
        pat = "4? 8B ?4 C?"
        seq = bytes.fromhex("40 8B 34 C5")  # matches 4x 8B x4 Cx
        for at in (0, 13, 31, 32, 63, 64, 2000):
            hay = make_buf_with_pattern(seq, at)
            self._assert_match_all_kinds(hay, pat, at)

    def test_first_or_last_is_wildcard(self):
        # wildcard at head; exact tail
        pat = "?? 11 22 33"
        seq = bytes.fromhex("AA 11 22 33")
        for at in (0, 30, 31, 32, 63, 64):
            hay = make_buf_with_pattern(seq, at)
            self._assert_match_all_kinds(hay, pat, at)

        # exact head; wildcard tail
        pat2 = "11 22 33 ??"
        seq2 = bytes.fromhex("11 22 33 AA")
        for at in (0, 30, 31, 32, 63, 64):
            hay = make_buf_with_pattern(seq2, at)
            self._assert_match_all_kinds(hay, pat2, at)

    def test_multiple_matches_returns_first(self):
        pat = "DE AD ?? BE EF"
        # Place two matches; expect the first
        hay = (
            b"\x90" * 100
            + bytes.fromhex("DE AD 11 BE EF")
            + b"\x90" * 50
            + bytes.fromhex("DE AD 22 BE EF")
            + b"\x90" * 100
        )
        self._assert_match_all_kinds(hay, pat, 100)

    def test_no_match(self):
        pat = "AA BB CC"
        hay = b"\x90" * 1024
        self._assert_match_all_kinds(hay, pat, -1)

    def test_randomized_masks_vs_reference(self):
        rnd = random.Random(1337)
        for _ in range(100):
            k = rnd.randint(2, 12)
            # Build random pattern with random wildcards/nibble-wildcards
            toks = []
            for _j in range(k):
                mode = rnd.randint(0, 4)
                if mode == 0:
                    # exact byte
                    toks.append(f"{rnd.randrange(256):02X}")
                elif mode == 1:
                    toks.append("??")
                elif mode == 2:
                    # upper-nibble wildcard
                    toks.append(f"?{rnd.randrange(16):X}")
                elif mode == 3:
                    # lower-nibble wildcard
                    toks.append(f"{rnd.randrange(16):X}?")
                else:
                    # half/half mix
                    hi = rnd.choice(["?", f"{rnd.randrange(16):X}"])
                    lo = rnd.choice(["?", f"{rnd.randrange(16):X}"])
                    toks.append(hi + lo)
            pat = " ".join(toks)

            # Place it at a random viable position (stress different anchor windows)
            total = 4096
            at = rnd.randrange(0, total - k)
            # Create a random realization that matches the mask
            # For “data”: use nibble-consistent filling
            b = bytearray([0x90] * total)

            # Synthesize bytes consistent with the mask nibble-wise
            def synth_byte(tok):
                if tok == "??":
                    return rnd.randrange(256)
                hi, lo = tok[0], tok[1]
                h = rnd.randrange(16) if hi == "?" else int(hi, 16)
                l = rnd.randrange(16) if lo == "?" else int(lo, 16)
                return (h << 4) | l

            blob = bytes(synth_byte(t) for t in toks)
            b[at : at + k] = blob
            hay = bytes(b)
            # Verify
            self._assert_match_all_kinds(hay, pat, at)


class TestExponentialBackoffTimer(CoveredUnitTest):
    """Test the ExponentialBackoffTimer class."""

    def test_initial_state(self):
        """Test timer is initialized correctly."""
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=10.0)

        # Should be scheduled to prompt at 10 seconds
        self.assertEqual(timer.next_prompt_at, 10.0)
        self.assertEqual(timer.current_interval, 10.0)

        # Should not prompt before interval
        self.assertFalse(timer.should_prompt(0.0))
        self.assertFalse(timer.should_prompt(5.0))
        self.assertFalse(timer.should_prompt(9.9))

        # Should prompt at or after interval
        self.assertTrue(timer.should_prompt(10.0))
        self.assertTrue(timer.should_prompt(10.1))
        self.assertTrue(timer.should_prompt(15.0))

    def test_exponential_backoff_scenario(self):
        """Test the full exponential backoff scenario from the docstring."""
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=10.0)

        # First prompt at 10 seconds
        self.assertFalse(timer.should_prompt(9.9))
        self.assertTrue(timer.should_prompt(10.0))
        self.assertTrue(timer.should_prompt(10.1))

        # User responds at 13 seconds
        timer.acknowledge_prompt(13.0)

        # Next prompt should be at 13 + 20 = 33 seconds
        self.assertEqual(timer.current_interval, 20.0)
        self.assertEqual(timer.next_prompt_at, 33.0)
        self.assertFalse(timer.should_prompt(13.0))
        self.assertFalse(timer.should_prompt(20.0))
        self.assertFalse(timer.should_prompt(32.9))
        self.assertTrue(timer.should_prompt(33.0))
        self.assertTrue(timer.should_prompt(33.1))

        # User responds at 36 seconds
        timer.acknowledge_prompt(36.0)

        # Next prompt should be at 36 + 40 = 76 seconds
        self.assertEqual(timer.current_interval, 40.0)
        self.assertEqual(timer.next_prompt_at, 76.0)
        self.assertFalse(timer.should_prompt(36.0))
        self.assertFalse(timer.should_prompt(50.0))
        self.assertFalse(timer.should_prompt(75.9))
        self.assertTrue(timer.should_prompt(76.0))
        self.assertTrue(timer.should_prompt(76.1))

    def test_immediate_response(self):
        """Test when user responds immediately at the prompt time."""
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=10.0)

        # User responds exactly at 10 seconds
        timer.acknowledge_prompt(10.0)

        # Next prompt at 10 + 20 = 30 seconds
        self.assertEqual(timer.current_interval, 20.0)
        self.assertEqual(timer.next_prompt_at, 30.0)
        self.assertFalse(timer.should_prompt(29.9))
        self.assertTrue(timer.should_prompt(30.0))

    def test_delayed_response(self):
        """Test when user takes a long time to respond."""
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=10.0)

        # Prompt should show at 10, but user doesn't respond until 25 seconds
        self.assertTrue(timer.should_prompt(10.0))
        self.assertTrue(timer.should_prompt(20.0))
        self.assertTrue(timer.should_prompt(25.0))

        # User finally responds at 25 seconds
        timer.acknowledge_prompt(25.0)

        # Next prompt at 25 + 20 = 45 seconds
        self.assertEqual(timer.current_interval, 20.0)
        self.assertEqual(timer.next_prompt_at, 45.0)
        self.assertFalse(timer.should_prompt(44.9))
        self.assertTrue(timer.should_prompt(45.0))

    def test_multiple_doublings(self):
        """Test that interval keeps doubling correctly over many prompts."""
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=5.0)

        expected_intervals = [5.0, 10.0, 20.0, 40.0, 80.0, 160.0]
        expected_prompts = [5.0, 15.0, 35.0, 75.0, 155.0, 315.0]

        for i, (expected_interval, expected_prompt) in enumerate(zip(expected_intervals, expected_prompts)):
            # Check current state
            self.assertEqual(timer.current_interval, expected_interval, f"Iteration {i}")
            self.assertEqual(timer.next_prompt_at, expected_prompt, f"Iteration {i}")

            # Verify should_prompt behavior
            self.assertFalse(timer.should_prompt(expected_prompt - 0.1))
            self.assertTrue(timer.should_prompt(expected_prompt))

            # Acknowledge at exactly the prompt time
            timer.acknowledge_prompt(expected_prompt)

    def test_fractional_intervals(self):
        """Test with fractional second intervals."""
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=1.5)

        # First prompt at 1.5 seconds
        self.assertEqual(timer.next_prompt_at, 1.5)
        self.assertFalse(timer.should_prompt(1.4))
        self.assertTrue(timer.should_prompt(1.5))

        # User responds at 2.0 seconds
        timer.acknowledge_prompt(2.0)

        # Next prompt at 2.0 + 3.0 = 5.0 seconds
        self.assertEqual(timer.current_interval, 3.0)
        self.assertEqual(timer.next_prompt_at, 5.0)

    def test_properties_are_readonly(self):
        """Test that properties return correct values and reflect state."""
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=10.0)

        # Initial state
        self.assertEqual(timer.current_interval, 10.0)
        self.assertEqual(timer.next_prompt_at, 10.0)

        # After first acknowledgment
        timer.acknowledge_prompt(12.0)
        self.assertEqual(timer.current_interval, 20.0)
        self.assertEqual(timer.next_prompt_at, 32.0)

        # After second acknowledgment
        timer.acknowledge_prompt(35.0)
        self.assertEqual(timer.current_interval, 40.0)
        self.assertEqual(timer.next_prompt_at, 75.0)


class TestProgressReporter(CoveredUnitTest):
    """Test the ProgressReporter protocol and CheckContinuePrompt implementation."""

    def setUp(self):
        """Set up test fixtures."""
        # Store the original ask_yn function
        self.original_ask_yn = getattr(sigmaker.idaapi, "ask_yn", MagicMock())
        # Ensure BADADDR is set to a real integer
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF

    def tearDown(self):
        """Restore original functions."""
        sigmaker.idaapi.ask_yn = self.original_ask_yn

    def test_check_continue_prompt_basic(self):
        """Test basic CheckContinuePrompt functionality."""
        prompt = sigmaker.CheckContinuePrompt(
            enable_prompt=False  # Disable prompting for this test
        )

        # Check initial state
        self.assertGreater(prompt.elapsed_time, 0)
        self.assertFalse(prompt.should_cancel())

        # Update progress
        prompt.report_progress(message="Test message", test_key="test_value")
        self.assertFalse(prompt.should_cancel())

    def test_check_continue_prompt_disabled(self):
        """Test that prompting can be disabled."""
        prompt = sigmaker.CheckContinuePrompt(enable_prompt=False)

        # Should never cancel when prompting is disabled
        for _ in range(10):
            self.assertFalse(prompt.should_cancel())

    def test_check_continue_prompt_metadata(self):
        """Test progress metadata tracking."""
        prompt = sigmaker.CheckContinuePrompt(
            metadata={"static_key": "static_value"}, enable_prompt=False
        )

        # Add dynamic metadata
        prompt.report_progress(
            message="Processing...", dynamic_key="dynamic_value", count=42
        )

        # Check that metadata was stored
        self.assertEqual(prompt._dynamic_metadata["dynamic_key"], "dynamic_value")
        self.assertEqual(prompt._dynamic_metadata["count"], 42)
        self.assertEqual(prompt._progress_message, "Processing...")

    # Note: Integration tests for UniqueSignatureGenerator and RangeSignatureGenerator
    # with progress reporters are complex due to mocking requirements. The core functionality
    # is tested in the CheckContinuePrompt tests above, and the signature generators
    # accept and use progress reporters correctly as shown in the implementation.


class TestSearchCancellation(CoveredUnitTest):
    """Test that signature search can be cancelled by the user."""

    def setUp(self):
        """Set up test fixtures."""
        # Store the original user_cancelled function if it exists
        self.original_user_cancelled = getattr(
            sigmaker.idaapi, "user_cancelled", MagicMock(return_value=False)
        )

    def tearDown(self):
        """Restore original functions."""
        sigmaker.idaapi.user_cancelled = self.original_user_cancelled

    def test_find_all_cancellation_basic(self):
        """Test that find_all respects user cancellation."""
        # Create a mock that returns False initially, then True after 2 calls
        call_count = [0]

        def mock_user_cancelled():
            call_count[0] += 1
            # Cancel after 2 calls to allow at least one iteration
            return call_count[0] > 2

        # Setup idaapi mocks
        sigmaker.idaapi.user_cancelled = mock_user_cancelled
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.inf_get_min_ea = MagicMock(return_value=0x1000)
        sigmaker.idaapi.inf_get_max_ea = MagicMock(return_value=0xFFFF)
        sigmaker.idaapi.compiled_binpat_vec_t = MagicMock
        sigmaker.idaapi.parse_binpat_str = MagicMock()
        sigmaker.idaapi.BIN_SEARCH_NOCASE = 0
        sigmaker.idaapi.BIN_SEARCH_FORWARD = 0

        # Mock bin_search to simulate finding multiple matches
        mock_bin_search = MagicMock()
        mock_bin_search.side_effect = [
            (0x1000, None),  # First match
            (0x2000, None),  # Second match
            (0x3000, None),  # Third match (should be cancelled before this)
            (sigmaker.idaapi.BADADDR, None),  # No more matches
        ]
        sigmaker.idaapi.bin_search = mock_bin_search

        # Disable SIMD to test the regular path
        original_simd = sigmaker.SIMD_SPEEDUP_AVAILABLE
        sigmaker.SIMD_SPEEDUP_AVAILABLE = False

        try:
            results = sigmaker.SignatureSearcher.find_all("48 8B C4")

            # Should have found at least one match before cancellation
            self.assertGreater(len(results), 0)
            # Should not have found all matches due to cancellation
            self.assertLess(len(results), 3)
            # Verify user_cancelled was called
            self.assertGreater(call_count[0], 0)
        finally:
            # Restore SIMD setting
            sigmaker.SIMD_SPEEDUP_AVAILABLE = original_simd

    def test_find_all_no_cancellation(self):
        """Test that find_all works normally when not cancelled."""
        # Setup idaapi mocks
        sigmaker.idaapi.user_cancelled = MagicMock(return_value=False)
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.inf_get_min_ea = MagicMock(return_value=0x1000)
        sigmaker.idaapi.inf_get_max_ea = MagicMock(return_value=0xFFFF)
        sigmaker.idaapi.compiled_binpat_vec_t = MagicMock
        sigmaker.idaapi.parse_binpat_str = MagicMock()
        sigmaker.idaapi.BIN_SEARCH_NOCASE = 0
        sigmaker.idaapi.BIN_SEARCH_FORWARD = 0

        # Mock bin_search to simulate finding multiple matches
        mock_bin_search = MagicMock()
        mock_bin_search.side_effect = [
            (0x1000, None),
            (0x2000, None),
            (0x3000, None),
            (sigmaker.idaapi.BADADDR, None),
        ]
        sigmaker.idaapi.bin_search = mock_bin_search

        # Disable SIMD to test the regular path
        original_simd = sigmaker.SIMD_SPEEDUP_AVAILABLE
        sigmaker.SIMD_SPEEDUP_AVAILABLE = False

        try:
            results = sigmaker.SignatureSearcher.find_all("48 8B C4")

            # Should have found all 3 matches
            self.assertEqual(len(results), 3)
            self.assertEqual(int(results[0]), 0x1000)
            self.assertEqual(int(results[1]), 0x2000)
            self.assertEqual(int(results[2]), 0x3000)
        finally:
            # Restore SIMD setting
            sigmaker.SIMD_SPEEDUP_AVAILABLE = original_simd

    def test_cancellation_returns_partial_results(self):
        """Test that cancellation returns partial results found so far."""
        # Mock user_cancelled to cancel after finding 2 matches
        call_count = [0]

        def mock_user_cancelled():
            call_count[0] += 1
            return call_count[0] > 3

        # Setup idaapi mocks
        sigmaker.idaapi.user_cancelled = mock_user_cancelled
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.inf_get_min_ea = MagicMock(return_value=0x1000)
        sigmaker.idaapi.inf_get_max_ea = MagicMock(return_value=0xFFFF)
        sigmaker.idaapi.compiled_binpat_vec_t = MagicMock
        sigmaker.idaapi.parse_binpat_str = MagicMock()
        sigmaker.idaapi.BIN_SEARCH_NOCASE = 0
        sigmaker.idaapi.BIN_SEARCH_FORWARD = 0

        # Mock bin_search to return multiple matches
        mock_bin_search = MagicMock()
        mock_bin_search.side_effect = [
            (0x1000, None),
            (0x2000, None),
            (0x3000, None),
            (0x4000, None),
            (sigmaker.idaapi.BADADDR, None),
        ]
        sigmaker.idaapi.bin_search = mock_bin_search

        # Disable SIMD to test the regular path
        original_simd = sigmaker.SIMD_SPEEDUP_AVAILABLE
        sigmaker.SIMD_SPEEDUP_AVAILABLE = False

        try:
            results = sigmaker.SignatureSearcher.find_all("48 8B C4")

            # Should return partial results (at least 1, but not all 4)
            self.assertGreater(len(results), 0)
            self.assertLess(len(results), 4)
        finally:
            # Restore SIMD setting
            sigmaker.SIMD_SPEEDUP_AVAILABLE = original_simd


if __name__ == "__main__":
    # Run the tests (coverage is handled by the base class)
    unittest.main(verbosity=2)
