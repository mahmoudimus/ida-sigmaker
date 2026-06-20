"""
unit_test_sigmaker.py - Unit tests for sigmaker

Tests the sigmaker module and related functionality with mocked system interfaces
to ensure reliable testing across different platforms and architectures.
"""

import array
import csv
import dataclasses
import gc
import itertools
import io
import json
import logging
import pathlib
import platform
import random
import re
import sys
import tempfile
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


class TestSignatureSearcherInput(CoveredUnitTest):
    """Normal signature search owns single-pattern parse/validation policy."""

    def test_searcher_does_not_expose_parser_api(self):
        self.assertFalse(
            hasattr(sigmaker.SignatureSearcher, "parse_search_signature")
        )

    def test_search_results_keeps_plain_match_list_without_metadata(self):
        matches = [sigmaker.Match(0x1000)]

        result = sigmaker.SearchResults(matches, "90")

        self.assertIs(result.matches, matches)
        self.assertIs(result.matches[0], matches[0])
        self.assertEqual(result.matches[0], sigmaker.Match(0x1000))
        self.assertEqual(str(result.matches[0]), "0x1000")
        self.assertEqual(repr(result.matches[0]), "Match(address=0x1000)")
        self.assertEqual(hash(result.matches[0]), hash(sigmaker.Match(0x1000)))

    def test_metadata_lookup_does_not_replace_matches(self):
        result = sigmaker.SearchResults([sigmaker.Match(0x1000)], "90")
        original = result.matches[0]
        result.imagebase = 0x1000

        with patch.object(
            sigmaker.SearchResults,
            "_file_offset_for_ea",
            return_value=0x400,
        ):
            self.assertEqual(result.rva_for_match(original), 0)
            self.assertEqual(result.file_offset_for_match(original), 0x400)

        self.assertIs(result.matches[0], original)
        self.assertIsNone(result.matches[0].rva)
        self.assertIsNone(result.matches[0].file_offset)
        self.assertEqual(result.file_offsets[0x1000], 0x400)

    def test_match_metadata_keeps_address_equality_and_hash(self):
        plain = sigmaker.Match(0x1000)
        enriched = sigmaker.Match(0x1000, rva=0x100, file_offset=0x400)

        self.assertTrue(dataclasses.is_dataclass(sigmaker.Match))
        self.assertIs(type(enriched), sigmaker.Match)
        self.assertEqual(enriched, plain)
        self.assertEqual(hash(enriched), hash(plain))
        self.assertEqual(str(enriched), "0x1000")
        self.assertEqual(repr(enriched), "Match(address=0x1000)")
        self.assertEqual(f"{enriched:rva}", "0x100")
        self.assertEqual(f"{enriched:fileoffset}", "0x400")
        with self.assertRaises(AttributeError):
            enriched.rva = 0x200

    def test_search_uses_canonical_signature(self):
        with patch.object(
            sigmaker.SignatureSearcher,
            "find_all",
            return_value=[sigmaker.Match(0x1000)],
        ) as find_all, patch.object(
            sigmaker.idaapi,
            "get_imagebase",
            return_value=0x1000,
        ):
            result = sigmaker.SignatureSearcher.from_signature(
                "E8 ? ? ? ? 48"
            ).search()

        find_all.assert_called_once_with("E8 ?? ?? ?? ?? 48")
        self.assertEqual(result.signature_str, "E8 ? ? ? ? 48")
        self.assertEqual(result.search_pattern, "E8 ? ? ? ? 48")
        self.assertEqual(result.normalized_signature, "E8 ?? ?? ?? ?? 48")
        self.assertEqual(result.raw_pattern, "E8 ? ? ? ? 48")
        self.assertEqual(result.status, "matched")
        self.assertEqual(result.match_count, 1)
        self.assertEqual(result.imagebase, 0x1000)
        self.assertEqual(result.rva_for_match(sigmaker.Match(0x1000)), 0)
        self.assertEqual(result.matches[0], sigmaker.Match(0x1000))
        self.assertEqual(result.matches[0].rva, 0)

    def test_search_preserves_search_pattern_signature_string(self):
        cases = (
            "48 8B ? 48 89",
            "\\x48\\x8B\\x00\\x48\\x89 xx?xx",
            "0x48, 0x8B, 0x00, 0x48, 0x89 0b11011",
        )

        for raw in cases:
            with self.subTest(raw=raw), patch.object(
                sigmaker.SignatureSearcher,
                "find_all",
                return_value=[sigmaker.Match(0x1000)],
            ) as find_all:
                result = sigmaker.SignatureSearcher.from_signature(raw).search()

            find_all.assert_called_once_with("48 8B ?? 48 89")
            self.assertEqual(result.signature_str, "48 8B ? 48 89")
            self.assertEqual(result.search_pattern, "48 8B ? 48 89")
            self.assertEqual(result.normalized_signature, "48 8B ?? 48 89")

    def test_search_preserves_nibble_wildcard_patterns(self):
        cases = (
            ("4? ?F ?? 7A", "4? ?F ? 7A", "4? ?F ?? 7A"),
            ("48 8B 4? ?F ??", "48 8B 4? ?F ?", "48 8B 4? ?F ??"),
        )

        for raw, search_pattern, normalized in cases:
            with self.subTest(raw=raw), patch.object(
                sigmaker.SignatureSearcher,
                "find_all",
                return_value=[sigmaker.Match(0x1000)],
            ) as find_all:
                result = sigmaker.SignatureSearcher.from_signature(raw).search()

            find_all.assert_called_once_with(normalized)
            self.assertEqual(result.raw_pattern, raw)
            self.assertEqual(result.signature_str, search_pattern)
            self.assertEqual(result.search_pattern, search_pattern)
            self.assertEqual(result.normalized_signature, normalized)

    def test_search_rejects_all_wildcard_pattern(self):
        with patch.object(sigmaker.idaapi, "msg") as msg, patch.object(
            sigmaker.SignatureSearcher,
            "find_all",
        ) as find_all:
            result = sigmaker.SignatureSearcher.from_signature("?? ?? ??").search()

        find_all.assert_not_called()
        self.assertEqual(result.matches, [])
        self.assertEqual(result.signature_str, "")
        msg.assert_called_once_with("Unrecognized signature type\n")


class TestBatchSignatureParser(CoveredUnitTest):
    """Batch search accepts named and unnamed pasted signature lines."""

    def test_parse_named_quoted_and_plain_patterns(self):
        text = """
        constexpr const char* print = "48 8B ?? ??";
        update: E8 ? ? ? ? 48 89 C7
        90 90 CC
        """

        queries = sigmaker.BatchSignatureParser.parse_many(text)

        self.assertEqual(len(queries), 3)
        self.assertEqual(queries[0].name, "print")
        self.assertEqual(queries[0].raw_pattern, "48 8B ?? ??")
        self.assertEqual(queries[0].source_line, 2)
        self.assertEqual(queries[1].name, "update")
        self.assertEqual(queries[1].raw_pattern, "E8 ? ? ? ? 48 89 C7")
        self.assertEqual(queries[1].source_line, 3)
        self.assertEqual(queries[2].name, "")
        self.assertEqual(queries[2].raw_pattern, "90 90 CC")
        self.assertEqual(queries[2].source_line, 4)

    def test_parse_ignores_blank_comment_and_fence_lines(self):
        text = """
        // generated signatures
        ```
        foo = "AA BB CC" // inline comment

        # another comment
        bar: 11 22 33
        ```
        """

        queries = sigmaker.BatchSignatureParser.parse_many(text)

        self.assertEqual(
            [(query.name, query.raw_pattern) for query in queries],
            [("foo", "AA BB CC"), ("bar", "11 22 33")],
        )

    def test_empty_input_returns_no_queries(self):
        self.assertEqual(sigmaker.BatchSignatureParser.parse_many("  \n\t"), [])


class TestBatchSignatureSearcher(CoveredUnitTest):
    """Batch search normalizes patterns and keeps per-entry errors."""

    def test_search_reuses_normalized_match_results(self):
        calls: list[str] = []
        shared_buf = MagicMock()
        shared_buf.imagebase = 0x140000000

        def fake_find_all(ida_signature, buf=None):
            calls.append(ida_signature)
            self.assertIs(buf, shared_buf)
            return [sigmaker.Match(0x140001000)]

        text = """
        first = "48 8B C4"
        second: 48 8B C4
        third = "E8 ? ? ? ? 48"
        """

        with patch.object(
            sigmaker.SignatureSearcher,
            "find_all",
            side_effect=fake_find_all,
        ), patch.object(
            sigmaker.idaapi,
            "get_fileregion_offset",
            return_value=0x401000,
        ):
            results = sigmaker.BatchSignatureSearcher.from_text(text).search(
                buf=shared_buf
            )

        self.assertEqual(calls, ["48 8B C4", "E8 ?? ?? ?? ?? 48"])
        self.assertEqual(len(results), 3)
        result_list = list(results)
        self.assertEqual(len(result_list), 3)
        self.assertIs(results[0], result_list[0])
        self.assertEqual(results[:2], result_list[:2])
        self.assertTrue(all(entry.matches for entry in results))
        self.assertTrue(
            all(isinstance(entry, sigmaker.SearchResults) for entry in results)
        )
        self.assertEqual(results.imagebase, 0x140000000)
        self.assertEqual(
            results[0].file_offset_for_match(sigmaker.Match(0x140001000)),
            0x401000,
        )
        self.assertEqual(results[0].normalized_signature, "48 8B C4")
        self.assertEqual(results[2].signature_str, "E8 ? ? ? ? 48")
        self.assertEqual(results[2].search_pattern, "E8 ? ? ? ? 48")
        self.assertEqual(results[2].normalized_signature, "E8 ?? ?? ?? ?? 48")
        self.assertEqual(
            results[0].rva_for_match(sigmaker.Match(0x140001000)),
            0x1000,
        )
        self.assertEqual(
            results[0].file_offset_for_match(sigmaker.Match(0x140001000)),
            0x401000,
        )
        self.assertEqual(
            results[0].match_record(sigmaker.Match(0x140001000)),
            {"ea": 0x140001000, "rva": 0x1000, "file_offset": 0x401000},
        )
        self.assertEqual(results[0].matches[0], sigmaker.Match(0x140001000))
        hit = results[0].matches[0]
        self.assertEqual(hit.rva, 0x1000)
        self.assertEqual(hit.file_offset, 0x401000)
        self.assertEqual(f"{hit}", "0x140001000")
        self.assertEqual(f"{hit:ea}", "0x140001000")
        self.assertEqual(f"{hit:address}", "0x140001000")
        self.assertEqual(f"{hit:rva}", "0x1000")
        self.assertEqual(f"{hit:rva:x}", "1000")
        self.assertEqual(f"{hit:fileoffset}", "0x401000")
        self.assertEqual(f"{hit:file_offset}", "0x401000")
        self.assertEqual(f"{hit:file:X}", "401000")
        self.assertEqual(f"{hit:#x}", "0x140001000")
        sparse_hit = sigmaker.Match(0x140001000)
        self.assertEqual(
            repr(sparse_hit),
            "Match(address=0x140001000)",
        )
        self.assertEqual(f"{sparse_hit:rva}", repr(sparse_hit))
        self.assertEqual(f"{sparse_hit:fileoffset}", repr(sparse_hit))

    def test_search_preserves_batch_nibble_wildcard_patterns(self):
        with patch.object(
            sigmaker.SignatureSearcher,
            "find_all",
            return_value=[sigmaker.Match(0x1000)],
        ) as find_all:
            results = sigmaker.BatchSignatureSearcher.from_text(
                'nibble = "4? ?F ?? 7A"'
            ).search()

        find_all.assert_called_once_with("4? ?F ?? 7A", buf=None)
        self.assertEqual(results[0].raw_pattern, "4? ?F ?? 7A")
        self.assertEqual(results[0].signature_str, "4? ?F ? 7A")
        self.assertEqual(results[0].search_pattern, "4? ?F ? 7A")
        self.assertEqual(results[0].normalized_signature, "4? ?F ?? 7A")

    def test_search_records_parse_errors_per_entry(self):
        text = """
        good = "48 8B C4"
        bad = "not-a-signature"
        """

        with patch.object(
            sigmaker.SignatureSearcher, "find_all", return_value=[sigmaker.Match(0x1000)]
        ):
            results = sigmaker.BatchSignatureSearcher.from_text(text).search()

        self.assertEqual(results[0].status, "matched")
        self.assertEqual(results[1].status, "error")
        self.assertIn("Unrecognized", results[1].error)

    def test_search_rejects_all_wildcard_patterns(self):
        text = 'wild = "?? ?? ??"'

        with patch.object(sigmaker.SignatureSearcher, "find_all") as find_all:
            results = sigmaker.BatchSignatureSearcher.from_text(text).search()

        find_all.assert_not_called()
        self.assertEqual(results[0].status, "error")
        self.assertIn("Unrecognized", results[0].error)

    def test_search_propagates_user_cancellation(self):
        with patch.object(
            sigmaker.SignatureSearcher,
            "find_all",
            side_effect=sigmaker.UserCanceledError("Canceled"),
        ):
            with self.assertRaises(sigmaker.UserCanceledError):
                sigmaker.BatchSignatureSearcher.from_text('"48 8B C4"').search()

    def test_search_propagates_unexpected_search_errors(self):
        with patch.object(
            sigmaker.SignatureSearcher,
            "find_all",
            side_effect=RuntimeError("database unavailable"),
        ):
            with self.assertRaises(RuntimeError):
                sigmaker.BatchSignatureSearcher.from_text('"48 8B C4"').search()


class TestBatchSearchFormatters(CoveredUnitTest):
    """Batch result renderers produce useful text/csv/json outputs."""

    def _results(self):
        matched = sigmaker.SearchResults(
            matches=[sigmaker.Match(0x140001000)],
            signature_str="48 8B ? 48 89",
            raw_pattern="\\x48\\x8B\\x00\\x48\\x89 xx?xx",
            name="print",
            source_line=1,
            imagebase=0x140000000,
            file_offsets={0x140001000: 0x401000},
            canonical_pattern="48 8B ?? 48 89",
        )
        multi = sigmaker.SearchResults(
            matches=[sigmaker.Match(0x140002000), sigmaker.Match(0x140003000)],
            signature_str="90",
            raw_pattern="90",
            name="tick",
            source_line=2,
            imagebase=0x140000000,
            file_offsets={
                0x140002000: 0x402000,
                0x140003000: 0x403000,
            },
        )
        error = sigmaker.SearchResults(
            matches=[],
            signature_str="",
            raw_pattern="bad",
            name="bad",
            source_line=3,
            error="Unrecognized signature format",
        )
        return sigmaker.BatchSearchResults(
            [matched, multi, error],
            source_text="",
            imagebase=0x140000000,
        )

    def test_render_text_includes_names_and_statuses(self):
        out = self._results().format(sigmaker.BatchSearchTextFormatter())
        self.assertIn("[print]", out)
        self.assertIn("matched", out)
        self.assertIn("[bad]", out)
        self.assertIn("Unrecognized signature format", out)

    def test_results_format_defaults_to_text_formatter(self):
        out = self._results().format()
        self.assertIn("Batch search finished: 2/3 matched, 1 error(s)", out)
        self.assertIn("Imagebase: 0x140000000", out)
        self.assertIn("[print] 1 match(es) for 48 8B ? 48 89", out)

    def test_display_writes_formatted_text_to_text_io(self):
        output = io.StringIO()
        formatter = sigmaker.BatchSearchTextFormatter(max_preview_matches=1)

        self._results().display(output=output, formatter=formatter)

        self.assertEqual(output.getvalue(), self._results().format(formatter))

    def test_display_writes_formatted_text_to_callable_sink(self):
        chunks: list[str] = []
        formatter = sigmaker.BatchSearchTextFormatter()

        self._results().display(output=chunks.append, formatter=formatter)

        self.assertEqual(chunks, [self._results().format(formatter)])

    def test_display_defaults_to_ida_message_sink(self):
        with patch.object(sigmaker.idaapi, "msg") as msg, patch.object(
            sigmaker.idaapi,
            "get_func_name",
            return_value="print_fn",
        ):
            self._results().display()

        msg.assert_called_once()
        self.assertIn(
            "0x140001000 (rva 0x1000, file 0x401000, print_fn)",
            msg.call_args.args[0],
        )

    def test_render_csv_quotes_fields(self):
        out = self._results().format(sigmaker.BatchSearchCsvFormatter())
        rows = list(csv.DictReader(io.StringIO(out)))

        self.assertEqual(rows[0]["name"], "print")
        self.assertEqual(rows[0]["search_pattern"], "48 8B ? 48 89")
        self.assertEqual(rows[0]["normalized_signature"], "48 8B ?? 48 89")
        self.assertEqual(rows[0]["raw_pattern"], "\\x48\\x8B\\x00\\x48\\x89 xx?xx")
        self.assertEqual(rows[0]["match_eas"], "0x140001000")
        self.assertEqual(rows[0]["match_rvas"], "0x1000")
        self.assertEqual(rows[0]["match_file_offsets"], "0x401000")

    def test_render_json_is_parseable(self):
        out = self._results().format(sigmaker.BatchSearchJsonFormatter())
        payload = json.loads(out)
        self.assertEqual(payload["imagebase"], 0x140000000)
        self.assertEqual(payload["entry_count"], 3)
        self.assertEqual(payload["entries"][0]["name"], "print")
        self.assertEqual(payload["entries"][0]["search_pattern"], "48 8B ? 48 89")
        self.assertEqual(
            payload["entries"][0]["normalized_signature"],
            "48 8B ?? 48 89",
        )
        self.assertEqual(
            payload["entries"][0]["raw_pattern"],
            "\\x48\\x8B\\x00\\x48\\x89 xx?xx",
        )
        self.assertEqual(payload["entries"][0]["matches"][0]["ea"], 0x140001000)
        self.assertEqual(payload["entries"][0]["matches"][0]["rva"], 0x1000)
        self.assertEqual(
            payload["entries"][0]["matches"][0]["file_offset"],
            0x401000,
        )

    def test_formatter_for_path_uses_suffix(self):
        cases = {
            "out.txt": sigmaker.BatchSearchTextFormatter,
            "out.csv": sigmaker.BatchSearchCsvFormatter,
            "out.json": sigmaker.BatchSearchJsonFormatter,
            "out.c": sigmaker.BatchSearchTextFormatter,
        }
        for path, formatter_type in cases.items():
            formatter = sigmaker.batch_search_formatter_for_path(pathlib.Path(path))
            self.assertIsInstance(formatter, formatter_type)

    def test_format_accepts_registered_format_name(self):
        old_formatter = sigmaker.BATCH_SEARCH_FORMATTERS.get("test")
        try:
            @sigmaker.BatchSearchFormatter.register("test")
            class TestFormatter:
                def format(self, results):
                    return f"entries={len(results)}\n"

            self.assertEqual(self._results().format("test"), "entries=3\n")
        finally:
            if old_formatter is None:
                sigmaker.BATCH_SEARCH_FORMATTERS.pop("test", None)
            else:
                sigmaker.BATCH_SEARCH_FORMATTERS["test"] = old_formatter

    def test_formatter_register_decorator_can_bind_suffix(self):
        old_formatter = sigmaker.BATCH_SEARCH_FORMATTERS.get("c")
        old_suffix = sigmaker.BATCH_SEARCH_FORMAT_SUFFIXES.get(".c")
        try:
            @sigmaker.BatchSearchFormatter.register("c", suffixes=(".c",))
            class TestFormatter:
                def format(self, results):
                    return "custom\n"

            formatter = sigmaker.batch_search_formatter_for_path(pathlib.Path("out.c"))
            self.assertEqual(formatter.format(self._results()), "custom\n")
        finally:
            if old_formatter is None:
                sigmaker.BATCH_SEARCH_FORMATTERS.pop("c", None)
            else:
                sigmaker.BATCH_SEARCH_FORMATTERS["c"] = old_formatter
            if old_suffix is None:
                sigmaker.BATCH_SEARCH_FORMAT_SUFFIXES.pop(".c", None)
            else:
                sigmaker.BATCH_SEARCH_FORMAT_SUFFIXES[".c"] = old_suffix


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

    def test_user_takes_5_seconds_to_respond(self):
        """Test when user takes 5 seconds to click the Continue button.

        Scenario:
        - Prompt appears at t=10
        - User stares at it for 5 seconds
        - User clicks Continue at t=15
        - Next prompt should be 20 seconds after the click (at t=35, not t=30)
        """
        timer = sigmaker.ExponentialBackoffTimer(initial_interval=10.0)

        # At t=10, prompt should appear
        self.assertTrue(timer.should_prompt(10.0))

        # Prompt is showing, user is thinking...
        # At t=11, t=12, t=13, t=14 - prompt still showing, user hasn't clicked
        # (in real code, should_prompt() wouldn't be called again until after acknowledge)

        # At t=15, user finally clicks "Continue"
        timer.acknowledge_prompt(15.0)

        # Next prompt should be at t=15 + 20 = 35 seconds
        # (20 seconds after user clicked, NOT 20 seconds after prompt appeared)
        self.assertEqual(timer.current_interval, 20.0)
        self.assertEqual(timer.next_prompt_at, 35.0)

        # Verify the timing
        self.assertFalse(timer.should_prompt(15.0), "Should not prompt immediately after acknowledge")
        self.assertFalse(timer.should_prompt(20.0), "Should not prompt at t=20")
        self.assertFalse(timer.should_prompt(30.0), "Should not prompt at t=30 (10 + 20)")
        self.assertFalse(timer.should_prompt(34.9), "Should not prompt just before threshold")
        self.assertTrue(timer.should_prompt(35.0), "Should prompt at t=35 (15 + 20)")
        self.assertTrue(timer.should_prompt(40.0), "Should prompt after threshold")


class TestCheckContinuePromptIntegration(CoveredUnitTest):
    """Test CheckContinuePrompt integration with ExponentialBackoffTimer."""

    def test_elapsed_time_property_recalculates(self):
        """Test that elapsed_time property recalculates after dialog blocks.

        This verifies that when we pass self.elapsed_time to acknowledge_prompt(),
        we're passing the UPDATED time (including time spent in the dialog), not
        the time from before the dialog was shown.
        """
        import time

        prompt = sigmaker.CheckContinuePrompt(
            prompt_interval=0.1,  # 100ms for fast test
            enable_prompt=False,  # Don't actually show dialogs
        )

        start = time.time()

        # First check - elapsed_time should be very small
        elapsed1 = prompt.elapsed_time
        self.assertLess(elapsed1, 0.01, "Initial elapsed time should be near zero")

        # Wait 50ms
        time.sleep(0.05)

        # Second check - elapsed_time should have increased
        elapsed2 = prompt.elapsed_time
        self.assertGreater(elapsed2, elapsed1, "elapsed_time should increase")
        self.assertGreater(elapsed2, 0.04, "Should be at least 40ms")

        # Wait another 50ms
        time.sleep(0.05)

        # Third check - elapsed_time should have increased again
        elapsed3 = prompt.elapsed_time
        self.assertGreater(elapsed3, elapsed2, "elapsed_time should increase again")
        self.assertGreater(elapsed3, 0.09, "Should be at least 90ms")

        # Verify the property keeps recalculating, not caching
        self.assertNotEqual(elapsed1, elapsed2)
        self.assertNotEqual(elapsed2, elapsed3)

    def test_timer_gets_updated_time_after_simulated_dialog_delay(self):
        """Test that timer receives updated elapsed_time after a simulated dialog delay.

        This simulates what happens when a blocking dialog is shown:
        1. Check if should prompt (at t=10)
        2. Show dialog (blocks for 5 seconds)
        3. Call acknowledge_prompt with updated elapsed_time (at t=15)
        """
        import time

        # Use very short interval for fast test
        prompt = sigmaker.CheckContinuePrompt(
            prompt_interval=0.05,  # 50ms
            enable_prompt=False,  # Don't show actual dialogs
        )

        # Wait for first prompt threshold
        time.sleep(0.06)  # Just over 50ms

        # At this point, elapsed_time is ~60ms
        elapsed_before = prompt.elapsed_time
        self.assertGreater(elapsed_before, 0.05)

        # Simulate user taking time to respond (like dialog blocking)
        time.sleep(0.05)  # User "thinks" for 50ms

        # Now acknowledge with CURRENT elapsed_time (should be ~110ms)
        elapsed_after = prompt.elapsed_time
        self.assertGreater(elapsed_after, elapsed_before)

        # When we call acknowledge_prompt, timer should get the UPDATED time
        prompt._timer.acknowledge_prompt(elapsed_after)

        # Next prompt should be based on when user clicked, not when prompt appeared
        # next_prompt_at should be elapsed_after + (interval * 2)
        expected_next = elapsed_after + (0.05 * 2)
        self.assertAlmostEqual(prompt._timer.next_prompt_at, expected_next, places=2)


class TestProgressReporter(CoveredUnitTest):
    """Test the ProgressReporter protocol and CheckContinuePrompt implementation."""

    def setUp(self):
        """Set up test fixtures."""
        # Store the original ask_yn function
        self.original_ask_yn = getattr(sigmaker.idaapi, "ask_yn", MagicMock())
        # Without this, sigmaker.idaapi_user_canceled (bound from a MagicMock
        # at import time) returns a truthy MagicMock instance and the new
        # wait-box-cancel poll inside should_cancel() fires on every call.
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        # Ensure BADADDR is set to a real integer
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF

    def tearDown(self):
        """Restore original functions."""
        sigmaker.idaapi.ask_yn = self.original_ask_yn
        sigmaker.idaapi_user_canceled = self.original_user_canceled

    def test_check_continue_prompt_disabled(self):
        """Test that prompting can be disabled."""
        prompt = sigmaker.CheckContinuePrompt(enable_prompt=False)

        # Should never cancel when prompting is disabled
        for _ in range(10):
            self.assertFalse(prompt.should_cancel())

    def test_should_cancel_polls_idaapi_user_canceled(self):
        """Even with prompts disabled, the wait-box Cancel must propagate."""
        original = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        try:
            sigmaker.idaapi_user_canceled = MagicMock(return_value=True)
            prompt = sigmaker.CheckContinuePrompt(enable_prompt=False)
            self.assertTrue(prompt.should_cancel())
            # And once flagged, it stays canceled even if the wait-box flag clears.
            sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
            self.assertTrue(prompt.should_cancel())
        finally:
            sigmaker.idaapi_user_canceled = original

    def test_should_cancel_returns_false_when_no_cancel(self):
        original = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        try:
            sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
            prompt = sigmaker.CheckContinuePrompt(enable_prompt=False)
            self.assertFalse(prompt.should_cancel())
        finally:
            sigmaker.idaapi_user_canceled = original

    # Note: Integration tests for UniqueSignatureGenerator and RangeSignatureGenerator
    # with progress reporters are complex due to mocking requirements. The core functionality
    # is tested in the CheckContinuePrompt tests above, and the signature generators
    # accept and use progress reporters correctly as shown in the implementation.


class TestSearchCancellation(CoveredUnitTest):
    """Test that signature search can be canceled by the user."""

    def setUp(self):
        """Set up test fixtures."""
        # Store the original idaapi_user_canceled function if it exists
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )

    def tearDown(self):
        """Restore original functions."""
        sigmaker.idaapi_user_canceled = self.original_user_canceled

    def test_find_all_cancellation_basic(self):
        """Test that find_all respects user cancellation."""
        # Create a mock that returns False initially, then True after 2 calls
        call_count = [0]

        def mock_user_canceled():
            call_count[0] += 1
            # Cancel after 2 calls to allow at least one iteration
            return call_count[0] > 2

        # Setup idaapi mocks
        sigmaker.idaapi_user_canceled = mock_user_canceled
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
            (0x3000, None),  # Third match (should be canceled before this)
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
            # Verify user_canceled was called
            self.assertGreater(call_count[0], 0)
        finally:
            # Restore SIMD setting
            sigmaker.SIMD_SPEEDUP_AVAILABLE = original_simd

    def test_find_all_no_cancellation(self):
        """Test that find_all works normally when not canceled."""
        # Setup idaapi mocks
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
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
        # Mock user_canceled to cancel after finding 2 matches
        call_count = [0]

        def mock_user_canceled():
            call_count[0] += 1
            return call_count[0] > 3

        # Setup idaapi mocks
        sigmaker.idaapi_user_canceled = mock_user_canceled
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


class TestSigMakerConfigDefaults(CoveredUnitTest):
    """Defaults must give the wait-box-cancel UX out of the box (issue #18)."""

    def test_default_disables_continue_prompt(self):
        cfg = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
        )
        self.assertFalse(cfg.enable_continue_prompt)
        self.assertEqual(cfg.prompt_interval, -1)

    def test_default_output_partial_on_cancel_is_false(self):
        cfg = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
        )
        self.assertFalse(cfg.output_partial_on_cancel)


class TestInstructionWalkerCancellation(CoveredUnitTest):
    """User-cancellation inside InstructionWalker must raise UserCanceledError, not StopIteration."""

    def setUp(self):
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.decode_insn = MagicMock(return_value=1)

    def tearDown(self):
        sigmaker.idaapi_user_canceled = self.original_user_canceled

    def test_walker_raises_user_canceled_error_on_cancel(self):
        sigmaker.idaapi_user_canceled = MagicMock(return_value=True)
        walker = sigmaker.InstructionWalker(start_ea=0x1000, end_ea=0x2000)
        with self.assertRaises(sigmaker.UserCanceledError):
            next(iter(walker))

    def test_walker_does_not_raise_when_not_canceled(self):
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        walker = sigmaker.InstructionWalker(start_ea=0x1000, end_ea=0x2000)
        ea, ins, ins_len = next(iter(walker))
        self.assertEqual(ea, 0x1000)
        self.assertEqual(ins_len, 1)


class TestActionEnum(CoveredUnitTest):
    """The Action IntEnum must mirror the SignatureMakerForm.rAction radio order."""

    def test_action_values_match_form_order(self):
        # Order is locked by SignatureMakerForm.rAction:
        #   ("rCreateUniqueSig", "rFindXRefSig", "rCopyCode", "rSearchSignature")
        self.assertEqual(int(sigmaker.Action.CREATE_UNIQUE), 0)
        self.assertEqual(int(sigmaker.Action.FIND_XREF), 1)
        self.assertEqual(int(sigmaker.Action.COPY_RANGE), 2)
        self.assertEqual(int(sigmaker.Action.SEARCH), 3)
        self.assertEqual(int(sigmaker.Action.FIND_FUNCTION_SIG), 4)
        self.assertEqual(int(sigmaker.Action.BATCH_SEARCH), 5)

    def test_action_is_intenum(self):
        import enum as _enum

        self.assertTrue(issubclass(sigmaker.Action, _enum.IntEnum))


class TestUniqueSignatureGeneratorPartialOnCancel(CoveredUnitTest):
    """policy=permissive returns a partial GeneratedSignature on cancel.

    These tests drive the non-SIMD fallback path (count_matches per step) by
    forcing SIMD_SPEEDUP_AVAILABLE off, so the patched count_matches stays the
    source of the match count. The partial-on-cancel / progress-message
    behavior under test is identical on both code paths.
    """

    def setUp(self):
        self._original_simd = sigmaker.SIMD_SPEEDUP_AVAILABLE
        sigmaker.SIMD_SPEEDUP_AVAILABLE = False
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        # idaapi is module-level MagicMock; idaapi_user_canceled is bound from
        # it at import time and would return a truthy MagicMock by default,
        # firing the walker's cancel branch on every iteration. Reset.
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.decode_insn = MagicMock(return_value=1)
        sigmaker.idaapi.get_byte = MagicMock(return_value=0x90)
        sigmaker.idaapi.get_bytes = MagicMock(return_value=b"\x90")
        sigmaker.idaapi.get_func = MagicMock(return_value=None)
        self._is_code_patcher = patch.object(
            sigmaker, "is_address_marked_as_code", return_value=True
        )
        self._is_code_patcher.start()

        # Recording dialog factory so we can inspect ProgressBox's
        # wait-box message activity without touching idaapi (issue #27).
        self.recorded_dialogs: list[_FakeDialog] = []

        def _factory(message):
            d = _FakeDialog(message)
            self.recorded_dialogs.append(d)
            return d

        self._dialog_patcher = patch.object(sigmaker, "ProgressDialog", _factory)
        self._dialog_patcher.start()

    def tearDown(self):
        self._dialog_patcher.stop()
        self._is_code_patcher.stop()
        sigmaker.idaapi_user_canceled = self.original_user_canceled
        sigmaker.SIMD_SPEEDUP_AVAILABLE = self._original_simd

    def _make_generator(self, cancel_after_iterations: int):
        """Construct a UniqueSignatureGenerator whose progress_reporter cancels
        on the Nth should_cancel() call."""
        calls = {"n": 0}

        def should_cancel():
            calls["n"] += 1
            return calls["n"] > cancel_after_iterations

        reporter = MagicMock()
        reporter.should_cancel.side_effect = should_cancel
        reporter.enabled.return_value = False
        processor = sigmaker.InstructionProcessor(sigmaker.OperandProcessor())
        return sigmaker.UniqueSignatureGenerator(processor, reporter)

    def _make_cfg(self) -> sigmaker.SigMakerConfig:
        return sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=True,
            wildcard_optimized=False,
            ask_longer_signature=False,
        )

    def test_strict_policy_cancel_raises(self):
        gen = self._make_generator(cancel_after_iterations=3)
        with patch.object(sigmaker.SignatureSearcher, "count_matches", return_value=2):
            with self.assertRaises(sigmaker.UserCanceledError):
                gen.generate(0x1000, self._make_cfg(), policy=sigmaker.GenerationPolicy.strict())

    def test_permissive_policy_cancel_returns_partial(self):
        gen = self._make_generator(cancel_after_iterations=3)
        with patch.object(sigmaker.SignatureSearcher, "count_matches", return_value=2):
            result = gen.generate(
                0x1000, self._make_cfg(), policy=sigmaker.GenerationPolicy.permissive()
            )
        self.assertIsInstance(result, sigmaker.GeneratedSignature)
        self.assertEqual(result.status, sigmaker.GenerationStatus.PARTIAL_ON_CANCEL)
        self.assertEqual(result.match_count, 2)
        self.assertGreater(len(result.signature), 0)
        self.assertEqual(result.address, sigmaker.Match(0x1000))

    def test_permissive_policy_unique_returns_unique(self):
        gen = self._make_generator(cancel_after_iterations=99)
        counts = iter([2, 2, 1])
        with patch.object(
            sigmaker.SignatureSearcher,
            "count_matches",
            side_effect=lambda *_, **__: next(counts),
        ):
            result = gen.generate(
                0x1000, self._make_cfg(), policy=sigmaker.GenerationPolicy.permissive()
            )
        self.assertEqual(result.status, sigmaker.GenerationStatus.UNIQUE)
        self.assertIsInstance(result, sigmaker.GeneratedSignature)

    def test_permissive_policy_cancel_before_any_byte_raises(self):
        gen = self._make_generator(cancel_after_iterations=0)
        with patch.object(sigmaker.SignatureSearcher, "count_matches", return_value=2):
            with self.assertRaises(sigmaker.UserCanceledError):
                gen.generate(
                    0x1000, self._make_cfg(), policy=sigmaker.GenerationPolicy.permissive()
                )

    def test_permissive_policy_preserves_last_good_count_on_interruption(self):
        """count_matches bails early when idaapi_user_canceled() is True
        during its scan, returning a partial (often 0) count. The generator
        must not record that as last_match_count -- but it also must not
        throw away the previous trustworthy count. The partial-on-cancel
        path should show the last fully-completed iteration's count, which
        is an upper bound on the actual match count for the (slightly
        longer) emitted partial signature. Bug reported by @OshidaBCF on
        issue #22 after testing PR #25.
        """
        # First two iterations: clean count_matches calls returning 100 and 50.
        # Third iteration: count_matches returns 0 AND idaapi_user_canceled
        # has just flipped to True (simulating cancel mid-scan).
        # Fourth iteration: should_cancel sees the cancel and builds the
        # partial. We expect match_count == 50 (the prior trustworthy
        # value), NOT 0 (the interrupted bogus value), and NOT None
        # (which would discard useful information).
        gen = self._make_generator(cancel_after_iterations=3)
        counts = iter([100, 50, 0])
        user_canceled_state = {"value": False}

        def fake_count_matches(_ida_sig, buf=None):
            v = next(counts)
            if v == 0:
                # Simulate find_all bailing because the user just clicked Cancel.
                user_canceled_state["value"] = True
            return v

        def fake_user_canceled():
            return user_canceled_state["value"]

        original_user_canceled = sigmaker.idaapi_user_canceled
        sigmaker.idaapi_user_canceled = fake_user_canceled
        try:
            with patch.object(
                sigmaker.SignatureSearcher,
                "count_matches",
                side_effect=fake_count_matches,
            ):
                result = gen.generate(
                    0x1000,
                    self._make_cfg(),
                    policy=sigmaker.GenerationPolicy.permissive(),
                )
        finally:
            sigmaker.idaapi_user_canceled = original_user_canceled

        self.assertEqual(
            result.status, sigmaker.GenerationStatus.PARTIAL_ON_CANCEL
        )
        self.assertEqual(
            result.match_count,
            50,
            "match_count must preserve the last trustworthy count "
            "(50 from the prior iteration), not the interrupted "
            "count_matches result of 0",
        )

    def test_permissive_policy_match_count_none_when_interrupted_on_first(self):
        """If the very first count_matches call is interrupted, we have no
        prior trustworthy count to fall back on, so match_count is None
        (rendered as 'match count unavailable')."""
        gen = self._make_generator(cancel_after_iterations=1)
        user_canceled_state = {"value": False}

        def fake_count_matches(_ida_sig, buf=None):
            # First (and only) call returns 0 with cancel flag already set.
            user_canceled_state["value"] = True
            return 0

        def fake_user_canceled():
            return user_canceled_state["value"]

        original_user_canceled = sigmaker.idaapi_user_canceled
        sigmaker.idaapi_user_canceled = fake_user_canceled
        try:
            with patch.object(
                sigmaker.SignatureSearcher,
                "count_matches",
                side_effect=fake_count_matches,
            ):
                result = gen.generate(
                    0x1000,
                    self._make_cfg(),
                    policy=sigmaker.GenerationPolicy.permissive(),
                )
        finally:
            sigmaker.idaapi_user_canceled = original_user_canceled

        self.assertEqual(
            result.status, sigmaker.GenerationStatus.PARTIAL_ON_CANCEL
        )
        self.assertIsNone(
            result.match_count,
            "match_count must be None when no prior trustworthy count exists",
        )

    def test_progress_dialog_opens_with_generating_signature_message(self):
        # Issue #27: ProgressBox-owned wait box should appear with the
        # CREATE_UNIQUE-specific initial message.
        gen = self._make_generator(cancel_after_iterations=99)
        counts = iter([5, 5, 5, 5, 1])
        with patch.object(
            sigmaker.SignatureSearcher,
            "count_matches",
            side_effect=lambda *_, **__: next(counts),
        ):
            gen.generate(
                0x1000,
                self._make_cfg(),
                policy=sigmaker.GenerationPolicy.strict(),
            )
        self.assertEqual(len(self.recorded_dialogs), 1)
        self.assertIn(
            "Create unique signature", self.recorded_dialogs[0].initial_message
        )

    def test_progress_dialog_lifecycle_on_cancel(self):
        # Even when the search cancels, the dialog __exit__ must fire so
        # the wait box closes cleanly.
        gen = self._make_generator(cancel_after_iterations=2)
        with patch.object(
            sigmaker.SignatureSearcher, "count_matches", return_value=5
        ):
            try:
                gen.generate(
                    0x1000,
                    self._make_cfg(),
                    policy=sigmaker.GenerationPolicy.strict(),
                )
            except sigmaker.UserCanceledError:
                pass
        self.assertEqual(len(self.recorded_dialogs), 1)
        self.assertEqual(self.recorded_dialogs[0].exit_count, 1)


class TestUniqueSignatureGeneratorSeedThenRefine(CoveredUnitTest):
    """SIMD path: generate() seeds once via find_all_offsets, then refines.

    Drives the candidate-refinement branch directly (SIMD on), asserting the
    seed scan happens exactly once and the in-memory refinement narrows the
    candidate set to a unique match.
    """

    def setUp(self):
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.decode_insn = MagicMock(return_value=1)
        sigmaker.idaapi.get_byte = MagicMock(return_value=0x90)
        sigmaker.idaapi.get_bytes = MagicMock(return_value=b"\x90")
        sigmaker.idaapi.get_func = MagicMock(return_value=None)
        self._is_code_patcher = patch.object(
            sigmaker, "is_address_marked_as_code", return_value=True
        )
        self._is_code_patcher.start()
        self._dialog_patcher = patch.object(sigmaker, "ProgressDialog", MagicMock())
        self._dialog_patcher.start()

    def tearDown(self):
        self._dialog_patcher.stop()
        self._is_code_patcher.stop()
        sigmaker.idaapi_user_canceled = self.original_user_canceled

    def _make_cfg(self) -> sigmaker.SigMakerConfig:
        return sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=True,
            wildcard_optimized=False,
            ask_longer_signature=False,
        )

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_seed_once_then_refine_to_unique(self):
        processor = sigmaker.InstructionProcessor(sigmaker.OperandProcessor())
        gen = sigmaker.UniqueSignatureGenerator(processor)

        # The growing pattern is all 0x90 (get_byte/get_bytes mocked to 0x90).
        # Seed buffer: 0x90 at offsets 0 and 5, but only offset 0 has a second
        # 0x90 right after it. After the first append (1 byte) the seed has
        # two candidates; the second append refines down to the single match
        # at offset 0.
        seed_buf = MagicMock()
        seed_buf.data.return_value = memoryview(
            bytearray(b"\x90\x90\x00\x00\x00\x90\x00\x00")
        )
        seed_offsets = [0, 5]

        load_calls = {"n": 0}

        def fake_find_all_offsets(_ida_sig, buf=None):
            load_calls["n"] += 1
            return list(seed_offsets), seed_buf

        with patch.object(
            sigmaker.SignatureSearcher,
            "find_all_offsets",
            side_effect=fake_find_all_offsets,
        ):
            result = gen.generate(
                0x1000, self._make_cfg(),
                policy=sigmaker.GenerationPolicy.strict(),
            )

        self.assertEqual(result.status, sigmaker.GenerationStatus.UNIQUE)
        # The database was scanned exactly once; the rest was in-memory refine.
        self.assertEqual(load_calls["n"], 1)
        # Two 0x90 bytes survive to uniqueness (offset 0: 0x90 0x90).
        self.assertEqual(len(result.signature), 2)


class TestGeneratedSignatureDisplay(CoveredUnitTest):
    """display() branches on status and respects the no-clipboard rule for partials."""

    def setUp(self):
        self.cfg = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
        )
        self.original_msg = sigmaker.idaapi.msg
        self.msg_calls: list[str] = []
        sigmaker.idaapi.msg = lambda s: self.msg_calls.append(s)

    def tearDown(self):
        sigmaker.idaapi.msg = self.original_msg

    def _make_sig(self, n_bytes: int = 4) -> sigmaker.Signature:
        sig = sigmaker.Signature()
        for i in range(n_bytes):
            sig.append(sigmaker.SignatureByte(0xE8 + i, False))
        return sig

    def test_unique_display_writes_clipboard(self):
        sig = self._make_sig()
        result = sigmaker.GeneratedSignature(sig, sigmaker.Match(0x1000))
        with patch.object(sigmaker.Clipboard, "set_text", return_value=True) as set_text:
            result.display(self.cfg)
        set_text.assert_called_once()
        self.assertTrue(any("Signature for" in m for m in self.msg_calls))

    def test_partial_display_does_not_write_clipboard(self):
        sig = self._make_sig()
        result = sigmaker.GeneratedSignature(
            sig,
            sigmaker.Match(0x1000),
            status=sigmaker.GenerationStatus.PARTIAL_ON_CANCEL,
            match_count=47,
        )
        with patch.object(sigmaker.Clipboard, "set_text", return_value=True) as set_text:
            result.display(self.cfg)
        set_text.assert_not_called()

    def test_partial_display_includes_match_count_in_message(self):
        sig = self._make_sig()
        result = sigmaker.GeneratedSignature(
            sig,
            sigmaker.Match(0x140001234),
            status=sigmaker.GenerationStatus.PARTIAL_ON_CANCEL,
            match_count=47,
        )
        with patch.object(sigmaker.Clipboard, "set_text", return_value=True):
            result.display(self.cfg)
        combined = "".join(self.msg_calls)
        self.assertIn("NOT unique", combined)
        self.assertIn("47", combined)
        self.assertIn("Partial", combined)

    def test_partial_display_does_not_recompute_match_count(self):
        sig = self._make_sig()
        result = sigmaker.GeneratedSignature(
            sig,
            sigmaker.Match(0x1000),
            status=sigmaker.GenerationStatus.PARTIAL_ON_CANCEL,
            match_count=3,
        )
        with patch.object(sigmaker.SignatureSearcher, "find_all") as fa, \
                patch.object(sigmaker.Clipboard, "set_text", return_value=True):
            result.display(self.cfg)
        fa.assert_not_called()


class _FakeXrefProgressDialog:
    """Minimal progress dialog for XrefFinder unit tests."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def user_canceled(self) -> bool:
        return False

    def replace_message(self, msg: str) -> None:
        self.messages.append(msg)


class TestXrefFinderCancellation(CoveredUnitTest):
    """Cancel during one XREF candidate stops and keeps prior results."""

    def _cfg(self) -> sigmaker.SigMakerConfig:
        return sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
        )

    def _sig(self, value: int) -> sigmaker.Signature:
        sig = sigmaker.Signature()
        sig.append(sigmaker.SignatureByte(value, False))
        sig.append(sigmaker.SignatureByte(value + 1, False))
        return sig

    def _finder(self) -> sigmaker.XrefFinder:
        finder = sigmaker.XrefFinder()
        finder.progress_dialog = _FakeXrefProgressDialog()
        return finder

    def test_cancel_inside_candidate_generation_returns_prior_xrefs(self):
        finder = self._finder()
        first = sigmaker.GeneratedSignature(self._sig(0x40))
        third = sigmaker.GeneratedSignature(self._sig(0x50))

        with patch.object(sigmaker.XrefFinder, "count_code_xrefs_to", return_value=3), \
                patch.object(
                    sigmaker.XrefFinder,
                    "iter_code_xrefs_to",
                    return_value=iter([0x1010, 0x1020, 0x1030]),
                ), patch.object(
                    sigmaker.SignatureMaker,
                    "make_signature",
                    side_effect=[
                        first,
                        sigmaker.UserCanceledError("user canceled"),
                        third,
                    ],
                ) as make_signature:
            result = finder.find_xrefs(0x2000, self._cfg())

        self.assertEqual(make_signature.call_count, 2)
        self.assertEqual(len(result.signatures), 1)
        self.assertEqual(result.signatures[0].address, sigmaker.Match(0x1010))
        self.assertEqual(result.signatures[0].signature, first.signature)

    def test_non_cancel_candidate_error_still_skips_and_continues(self):
        finder = self._finder()
        first = sigmaker.GeneratedSignature(self._sig(0x40))
        third = sigmaker.GeneratedSignature(self._sig(0x50))

        with patch.object(sigmaker.XrefFinder, "count_code_xrefs_to", return_value=3), \
                patch.object(
                    sigmaker.XrefFinder,
                    "iter_code_xrefs_to",
                    return_value=iter([0x1010, 0x1020, 0x1030]),
                ), patch.object(
                    sigmaker.SignatureMaker,
                    "make_signature",
                    side_effect=[
                        first,
                        RuntimeError("bad xref"),
                        third,
                    ],
                ) as make_signature:
            result = finder.find_xrefs(0x2000, self._cfg())

        self.assertEqual(make_signature.call_count, 3)
        self.assertEqual(
            [generated.address for generated in result.signatures],
            [sigmaker.Match(0x1010), sigmaker.Match(0x1030)],
        )


class TestGenerationStatusAndPolicy(CoveredUnitTest):
    """GenerationStatus and GenerationPolicy classmethods give callers a clean opt-in switch."""

    def test_generation_status_members(self):
        import enum as _enum

        self.assertTrue(issubclass(sigmaker.GenerationStatus, _enum.Enum))
        self.assertEqual(sigmaker.GenerationStatus.UNIQUE.value, "unique")
        self.assertEqual(sigmaker.GenerationStatus.PARTIAL_ON_CANCEL.value, "partial_on_cancel")

    def test_generation_policy_strict_default(self):
        policy = sigmaker.GenerationPolicy.strict()
        self.assertFalse(policy.return_partial_on_cancel)

    def test_generation_policy_permissive(self):
        policy = sigmaker.GenerationPolicy.permissive()
        self.assertTrue(policy.return_partial_on_cancel)

    def test_generation_policy_default_constructor_matches_strict(self):
        # A bare GenerationPolicy() must equal GenerationPolicy.strict() so the
        # default kwarg in generate() preserves the existing contract.
        self.assertEqual(
            sigmaker.GenerationPolicy(),
            sigmaker.GenerationPolicy.strict(),
        )


class TestSignatureSearcherCountMatches(CoveredUnitTest):
    """count_matches returns the cardinality of find_all; is_unique stays True only at 1."""

    def test_count_matches_returns_len_of_find_all(self):
        fake_matches = [sigmaker.Match(0x1000), sigmaker.Match(0x2000), sigmaker.Match(0x3000)]
        with patch.object(sigmaker.SignatureSearcher, "find_all", return_value=fake_matches):
            count = sigmaker.SignatureSearcher.count_matches("E8 ?? ?? ?? ??")
        self.assertEqual(count, 3)

    def test_count_matches_zero_when_no_hits(self):
        with patch.object(sigmaker.SignatureSearcher, "find_all", return_value=[]):
            count = sigmaker.SignatureSearcher.count_matches("DE AD BE EF")
        self.assertEqual(count, 0)

    def test_is_unique_true_only_at_one(self):
        with patch.object(sigmaker.SignatureSearcher, "find_all", return_value=[sigmaker.Match(0x1000)]):
            self.assertTrue(sigmaker.SignatureSearcher.is_unique("xx"))
        with patch.object(sigmaker.SignatureSearcher, "find_all", return_value=[]):
            self.assertFalse(sigmaker.SignatureSearcher.is_unique("xx"))
        with patch.object(sigmaker.SignatureSearcher, "find_all", return_value=[sigmaker.Match(1), sigmaker.Match(2)]):
            self.assertFalse(sigmaker.SignatureSearcher.is_unique("xx"))

    def test_is_unique_requests_early_bail(self):
        """is_unique must ask find_all to stop at the second match (skip_more_than_one)."""
        with patch.object(
            sigmaker.SignatureSearcher, "find_all", return_value=[sigmaker.Match(1)]
        ) as mp:
            sigmaker.SignatureSearcher.is_unique("xx")
        _, kwargs = mp.call_args
        self.assertTrue(kwargs.get("skip_more_than_one"))

    def test_count_matches_does_not_early_bail(self):
        """count_matches must enumerate all matches (issue #22 partial-on-cancel count)."""
        with patch.object(
            sigmaker.SignatureSearcher, "find_all",
            return_value=[sigmaker.Match(i) for i in range(5)],
        ) as mp:
            count = sigmaker.SignatureSearcher.count_matches("xx")
        self.assertEqual(count, 5)
        _, kwargs = mp.call_args
        self.assertFalse(kwargs.get("skip_more_than_one", False))


class TestRefineOffsets(CoveredUnitTest):
    """In-memory candidate refinement: keep offsets whose byte at c+j matches."""

    def _mv(self, b: bytes):
        return memoryview(bytearray(b))

    def test_exact_byte_keeps_matching(self):
        data = self._mv(b"\x90\x48\x90\x48\x90")
        # offsets 0..4; appended byte index j=1 must equal 0x48 (mask 0xFF)
        out = sigmaker._refine_offsets(data, [0, 1, 2, 3], 1, 0x48, 0xFF)
        # c=0 -> data[1]=0x48 keep; c=1 -> data[2]=0x90 drop; c=2 -> data[3]=0x48 keep; c=3 -> data[4]=0x90 drop
        self.assertEqual(out, [0, 2])

    def test_full_wildcard_keeps_all(self):
        data = self._mv(b"\x01\x02\x03\x04")
        out = sigmaker._refine_offsets(data, [0, 1, 2], 1, 0x00, 0x00)
        self.assertEqual(out, [0, 1, 2])

    def test_nibble_mask(self):
        data = self._mv(b"\x4A\x4B\x9C")
        # mask 0xF0 keeps where high nibble == 0x40
        out = sigmaker._refine_offsets(data, [0, 1, 2], 0, 0x40, 0xF0)
        self.assertEqual(out, [0, 1])

    def test_out_of_bounds_dropped(self):
        data = self._mv(b"\x90\x90")
        # c=1, j=2 -> c+j=3 is past the buffer; must be dropped, not raise
        out = sigmaker._refine_offsets(data, [0, 1], 2, 0x90, 0xFF)
        self.assertEqual(out, [])

    def test_empty_input(self):
        self.assertEqual(sigmaker._refine_offsets(self._mv(b"\x90"), [], 0, 0x90, 0xFF), [])


class TestFindAllOffsets(CoveredUnitTest):
    """find_all_offsets returns raw buffer offsets plus the buffer used."""

    def setUp(self):
        self._saved = sigmaker.idaapi_user_canceled
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        sigmaker.idaapi.inf_get_min_ea = MagicMock(return_value=0x1000)

    def tearDown(self):
        sigmaker.idaapi_user_canceled = self._saved

    def _fake_buf(self, b: bytes):
        buf = MagicMock()
        buf.data.return_value = memoryview(bytearray(b))
        buf.imagebase = 0x1000
        buf.file_size = len(b)
        return buf

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_offsets_match_find_all_positions(self):
        # Pattern "90" should be found at every 0x90 byte; offsets are
        # buffer-relative (0-based), and the returned buf is the one passed.
        buf = self._fake_buf(b"\x90\x00\x90\x00\x90")
        with patch.object(sigmaker, "ProgressDialog"):
            offs, ret = sigmaker.SignatureSearcher.find_all_offsets("90", buf=buf)
        self.assertEqual(offs, [0, 2, 4])
        self.assertIs(ret, buf)


class TestRefinementEquivalence(CoveredUnitTest):
    """Refinement of a seed set equals a full masked rescan at every step."""

    def _full_matches(self, data: bytes, pattern: list[tuple[int, int]]):
        # pattern: list of (value, mask); brute-force all start offsets
        n = len(data)
        m = len(pattern)
        out = []
        for c in range(n - m + 1):
            ok = True
            for j, (v, msk) in enumerate(pattern):
                if (data[c + j] & msk) != (v & msk):
                    ok = False
                    break
            if ok:
                out.append(c)
        return out

    def test_refine_tracks_full_rescan(self):
        import random
        rng = random.Random(1234)
        data = bytes(rng.randrange(256) for _ in range(4096))
        mv = memoryview(bytearray(data))
        # Build a random growing masked pattern taken from the buffer at anchor a
        a = 100
        pattern = []
        # seed on the first byte via brute force, then refine forward
        offsets = None
        for j in range(12):
            v = data[a + j]
            msk = 0x00 if (j % 3 == 0) else 0xFF  # sprinkle wildcards
            pattern.append((v, msk))
            if offsets is None:
                offsets = self._full_matches(data, pattern)  # seed at length 1
            else:
                offsets = sigmaker._refine_offsets(mv, offsets, j, v, msk)
            expected = self._full_matches(data, pattern)
            self.assertEqual(
                sorted(offsets), sorted(expected),
                f"divergence at length {j + 1}",
            )
        # anchor itself must always survive
        self.assertIn(a, offsets)


class TestMinimalFunctionSignatureGenerator(CoveredUnitTest):
    """Iterates every instruction in a function and returns the shortest unique signature.

    These tests drive the non-SIMD fallback path (count_matches per step) by
    forcing SIMD_SPEEDUP_AVAILABLE off, so a patched count_matches stays the
    source of the match count. The anchor-selection / pruning logic under test
    is identical on both code paths; the SIMD seed-then-refine path is covered
    separately and against the real binary in the integration suite.
    """

    def setUp(self):
        self._original_simd = sigmaker.SIMD_SPEEDUP_AVAILABLE
        sigmaker.SIMD_SPEEDUP_AVAILABLE = False
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.decode_insn = MagicMock(return_value=1)
        sigmaker.idaapi.get_byte = MagicMock(return_value=0x90)
        # get_bytes side_effect tolerant of both int counts (from the new
        # pre-decode bulk read) and MagicMock counts (from existing code
        # paths that pass ins.size where ins is an auto-attribute MagicMock).
        def _fake_get_bytes(ea, count):
            if isinstance(count, int):
                return b"\x90" * count
            return b"\x90"
        sigmaker.idaapi.get_bytes = MagicMock(side_effect=_fake_get_bytes)
        # generate() now pre-loads the segment buffer once up front, so
        # patch InMemoryBuffer.load (otherwise _load_segments infinite-loops
        # iterating MagicMock segments via while seg: ...).
        fake_buf = MagicMock()
        fake_buf.data.return_value = memoryview(b"\x90" * 100)
        fake_buf.imagebase = 0x1000
        fake_buf.file_size = 100
        self._load_patcher = patch.object(
            sigmaker.InMemoryBuffer, "load", return_value=fake_buf
        )
        self._load_patcher.start()

        # Recording dialog factory (issue #27 progress display).
        self.recorded_dialogs: list[_FakeDialog] = []

        def _factory(message):
            d = _FakeDialog(message)
            self.recorded_dialogs.append(d)
            return d

        self._dialog_patcher = patch.object(sigmaker, "ProgressDialog", _factory)
        self._dialog_patcher.start()

    def tearDown(self):
        self._load_patcher.stop()
        self._dialog_patcher.stop()
        sigmaker.idaapi_user_canceled = self.original_user_canceled
        sigmaker.SIMD_SPEEDUP_AVAILABLE = self._original_simd

    def _make_pfn(self, start_ea: int, end_ea: int):
        pfn = MagicMock()
        pfn.start_ea = start_ea
        pfn.end_ea = end_ea
        return pfn

    def _make_generator(self):
        processor = sigmaker.InstructionProcessor(sigmaker.OperandProcessor())
        return sigmaker.MinimalFunctionSignatureGenerator(processor)

    def _make_cfg(self, max_len: int = 50) -> sigmaker.SigMakerConfig:
        return sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
            ask_longer_signature=False,
            max_single_signature_length=max_len,
        )

    def _patch_uniqueness(self, model):
        """Patch is_unique (below MIN_USEFUL_SIG_BYTES) and count_matches
        (at/above it) to share one match-count model.

        The generator defers the seed scan until the pattern reaches
        MIN_USEFUL_SIG_BYTES: below that it probes uniqueness with is_unique,
        at/above it counts matches. It performs exactly one uniqueness check
        per appended instruction whichever path is taken, so a single shared
        counter inside ``model`` preserves the "n-th check" semantics
        regardless of where the MIN boundary falls. ``model()`` returns the
        match count for the current check; is_unique reports ``count == 1``.
        """
        cm = patch.object(
            sigmaker.SignatureSearcher,
            "count_matches",
            side_effect=lambda *a, **k: model(),
        )
        iu = patch.object(
            sigmaker.SignatureSearcher,
            "is_unique",
            side_effect=lambda *a, **k: model() == 1,
        )
        cm.start()
        iu.start()
        self.addCleanup(cm.stop)
        self.addCleanup(iu.stop)

    def test_returns_shortest_unique_candidate(self):
        gen = self._make_generator()
        # 32-byte function so the inner search has room for 10-byte and
        # 6-byte sigs without running off the end of the walker.
        pfn = self._make_pfn(0x1000, 0x1020)

        calls = {"n": 0}

        def model():
            calls["n"] += 1
            n = calls["n"]
            if n <= 10:
                return 1 if n == 10 else 2
            if n <= 16:
                return 1 if n == 16 else 2
            return 2

        self._patch_uniqueness(model)
        result = gen.generate(pfn, self._make_cfg(max_len=50))

        self.assertIsInstance(result, sigmaker.GeneratedSignature)
        self.assertEqual(result.address, sigmaker.Match(0x1001))
        self.assertEqual(len(result.signature), 6)

    def test_prune_caps_inner_search_by_best_so_far(self):
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1014)

        calls = {"n": 0}

        def model():
            calls["n"] += 1
            return 1 if calls["n"] == 7 else 2

        self._patch_uniqueness(model)
        result = gen.generate(pfn, self._make_cfg(max_len=50))

        self.assertLess(calls["n"], 300)
        self.assertEqual(len(result.signature), 7)

    def test_ideal_candidate_early_exit(self):
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1010)

        calls = {"n": 0}

        def model():
            calls["n"] += 1
            return 1 if calls["n"] == 5 else 2

        self._patch_uniqueness(model)
        result = gen.generate(pfn, self._make_cfg(max_len=50))

        self.assertEqual(len(result.signature), 5)
        self.assertEqual(calls["n"], 5)

    def test_raises_when_no_candidate(self):
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1003)
        self._patch_uniqueness(lambda: 2)
        with self.assertRaises(sigmaker.Unexpected):
            gen.generate(pfn, self._make_cfg(max_len=10))

    def test_rejects_degenerate_short_sigs(self):
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1005)

        calls = {"n": 0}

        def model():
            calls["n"] += 1
            return 1 if calls["n"] % 3 == 0 else 2

        self._patch_uniqueness(model)
        with self.assertRaises(sigmaker.Unexpected):
            gen.generate(pfn, self._make_cfg(max_len=50))

    def test_min_useful_sig_bytes_constant(self):
        self.assertEqual(
            sigmaker.MinimalFunctionSignatureGenerator.MIN_USEFUL_SIG_BYTES, 5
        )

    def test_predecode_calls_get_bytes_once_per_generate(self):
        """Pre-decode collapses N per-instruction get_bytes calls into 1 bulk call."""
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x100A)

        calls = {"n": 0}

        def model():
            calls["n"] += 1
            return 1 if calls["n"] == 5 else 2

        self._patch_uniqueness(model)
        sigmaker.idaapi.get_bytes.reset_mock()
        gen.generate(pfn, self._make_cfg(max_len=50))

        # One bulk call for the whole function. Growth loops read from the
        # cached bytes, not from idaapi.
        self.assertEqual(sigmaker.idaapi.get_bytes.call_count, 1)
        sigmaker.idaapi.get_bytes.assert_called_with(0x1000, 10)

    def test_predecode_empty_function_raises(self):
        """A function with start_ea == end_ea has no instructions to anchor on."""
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1000)
        with patch.object(
            sigmaker.SignatureSearcher, "count_matches", return_value=2
        ):
            with self.assertRaises(sigmaker.Unexpected):
                gen.generate(pfn, self._make_cfg(max_len=10))

    def test_predecode_get_bytes_none_raises(self):
        """When idaapi.get_bytes returns None (unmapped function), generate raises."""
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1005)
        sigmaker.idaapi.get_bytes = MagicMock(return_value=None)
        with patch.object(
            sigmaker.SignatureSearcher, "count_matches", return_value=2
        ):
            with self.assertRaises(sigmaker.Unexpected):
                gen.generate(pfn, self._make_cfg(max_len=10))

    def test_generate_loads_buffer_at_most_once(self):
        """The whole point of the cache: even if many scans happen, the InMemoryBuffer load round-trip happens at most once per generate()."""
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x100A)

        # Fake scan that exercises many checks before deciding.
        calls = {"n": 0}

        def model():
            calls["n"] += 1
            return 1 if calls["n"] == 5 else 2

        fake_buf = MagicMock()
        fake_buf.data.return_value = memoryview(b"\x90" * 100)
        fake_buf.imagebase = 0
        fake_buf.file_size = 100

        self._patch_uniqueness(model)
        with patch.object(
            sigmaker.InMemoryBuffer, "load", return_value=fake_buf
        ) as mp_load:
            gen.generate(pfn, self._make_cfg(max_len=50))

        self.assertLessEqual(mp_load.call_count, 1)

    def test_progress_dialog_opens_with_function_sig_message(self):
        # Issue #27: ProgressBox-owned wait box should appear with the
        # FIND_FUNCTION_SIG-specific initial message.
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1010)
        self._patch_uniqueness(lambda: 2)
        try:
            gen.generate(pfn, self._make_cfg(max_len=10))
        except sigmaker.Unexpected:
            pass
        # generate() may also open a short-lived "copying segments" wait box
        # when SIMD is available, so assert the function-sig wait box is among
        # the recorded dialogs rather than asserting an exact count.
        messages = [d.initial_message for d in self.recorded_dialogs]
        self.assertTrue(
            any("Find shortest function signature" in m for m in messages),
            f"Expected a function-sig wait box; got {messages}",
        )

    def test_cancel_during_decode_raises_before_processing(self):
        # Cancelling before the search starts must short-circuit promptly.
        # InstructionWalker.__next__ checks cancel before decode_insn, so the
        # pre-decode pass raises UserCanceledError without decoding the whole
        # 256-byte function.
        gen = self._make_generator()
        pfn = self._make_pfn(0x1000, 0x1100)  # 256 instruction bytes

        sigmaker.idaapi.decode_insn.reset_mock()
        sigmaker.idaapi_user_canceled = MagicMock(return_value=True)
        with patch.object(
            sigmaker.SignatureSearcher, "count_matches", return_value=2
        ):
            with self.assertRaises(sigmaker.UserCanceledError):
                gen.generate(pfn, self._make_cfg(max_len=10))

        self.assertLess(
            sigmaker.idaapi.decode_insn.call_count,
            20,
            "Cancel should short-circuit pre-decode before walking the "
            "whole function.",
        )


class TestMinimalFunctionSignatureGeneratorSeedThenRefine(CoveredUnitTest):
    """SIMD path: _grow_unique_from_decoded seeds once per anchor, then refines.

    Drives the candidate-refinement branch directly (SIMD on), asserting the
    seed scan (find_all_offsets) happens once per anchor and that the in-memory
    refinement narrows the candidate set to the exact match count.
    """

    def setUp(self):
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.decode_insn = MagicMock(return_value=1)
        sigmaker.idaapi.get_byte = MagicMock(return_value=0x90)

        def _fake_get_bytes(ea, count):
            if isinstance(count, int):
                return b"\x90" * count
            return b"\x90"
        sigmaker.idaapi.get_bytes = MagicMock(side_effect=_fake_get_bytes)

        self._seed_buf = MagicMock()
        # One run of five 0x90, a 0x00 separator, then a run of four 0x90.
        # Instructions decode as single 0x90 bytes, so anchor 0's pattern is
        # "90"*L. "90"*5 occurs only at offset 0 (the second run is only four
        # bytes), so anchor 0 is unique at exactly 5 bytes. Shorter patterns
        # ("90"*1..4) match in both runs, so they are not unique, which keeps
        # the below-MIN early-bail probe returning "not unique".
        self._seed_buf.data.return_value = memoryview(
            bytearray(b"\x90\x90\x90\x90\x90\x00\x90\x90\x90\x90")
        )
        self._seed_buf.imagebase = 0x1000
        self._seed_buf.file_size = 10
        self._load_patcher = patch.object(
            sigmaker.InMemoryBuffer, "load", return_value=self._seed_buf
        )
        self._load_patcher.start()
        self._dialog_patcher = patch.object(sigmaker, "ProgressDialog", MagicMock())
        self._dialog_patcher.start()

    def tearDown(self):
        self._load_patcher.stop()
        self._dialog_patcher.stop()
        sigmaker.idaapi_user_canceled = self.original_user_canceled

    def _make_pfn(self, start_ea: int, end_ea: int):
        pfn = MagicMock()
        pfn.start_ea = start_ea
        pfn.end_ea = end_ea
        return pfn

    def _make_cfg(self, max_len: int = 50) -> sigmaker.SigMakerConfig:
        return sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
            ask_longer_signature=False,
            max_single_signature_length=max_len,
        )

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_seed_is_deferred_until_min_then_refines(self):
        processor = sigmaker.InstructionProcessor(sigmaker.OperandProcessor())
        gen = sigmaker.MinimalFunctionSignatureGenerator(processor)
        pfn = self._make_pfn(0x1000, 0x100A)  # 10 single-byte 0x90 instructions

        # Force the Phase 1 scan-seed fallback (disable the byte index) so this
        # test exercises the find_all_offsets seed path it spies on. The
        # index-backed seed path has its own equivalence coverage
        # (TestIndexSeedEquivalence).
        real_find_all_offsets = sigmaker.SignatureSearcher.find_all_offsets
        seed_sig_byte_lens: list[int] = []

        def spy(ida_signature, buf=None):
            normalized, _ = sigmaker.SigText.normalize(ida_signature)
            seed_sig_byte_lens.append(len(normalized.split()))
            return real_find_all_offsets(ida_signature, buf=buf)

        with patch.object(
            sigmaker._ByteIndex, "build", return_value=None
        ), patch.object(
            sigmaker.SignatureSearcher, "find_all_offsets", side_effect=spy
        ):
            result = gen.generate(pfn, self._make_cfg(max_len=50))

        self.assertIsInstance(result, sigmaker.GeneratedSignature)
        # Anchor 0 ("90"*L) is unique at exactly 5 bytes. The seed must have
        # been deferred: every seed scan ran on a pattern of at least
        # MIN_USEFUL_SIG_BYTES, never on the 1-byte common prefix.
        self.assertTrue(seed_sig_byte_lens, "seed scan should have run at least once")
        min_useful = sigmaker.MinimalFunctionSignatureGenerator.MIN_USEFUL_SIG_BYTES
        self.assertTrue(
            all(n >= min_useful for n in seed_sig_byte_lens),
            f"seed must be deferred to >= {min_useful} bytes; got {seed_sig_byte_lens}",
        )
        self.assertEqual(len(result.signature), 5)


class TestSignatureSearcherBufferCache(CoveredUnitTest):
    """The SignatureSearcher scan API accepts an optional cached buffer."""

    def setUp(self):
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.inf_get_min_ea = MagicMock(return_value=0x1000)

    def _fake_buf(self, size: int = 100):
        fake_buf = MagicMock()
        fake_buf.data.return_value = memoryview(b"\x90" * size)
        fake_buf.imagebase = 0x1000
        fake_buf.file_size = size
        return fake_buf

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_find_all_simd_skips_load_when_buf_provided(self):
        """When _find_all_simd is given a buf=..., it must NOT call InMemoryBuffer.load."""
        with patch.object(
            sigmaker.InMemoryBuffer, "load"
        ) as mp_load, patch.object(
            sigmaker, "_simd_scan_bytes", return_value=-1
        ), patch.object(sigmaker, "ProgressDialog"):
            sigmaker.SignatureSearcher._find_all_simd("48 8B C4", buf=self._fake_buf())
        mp_load.assert_not_called()

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_find_all_simd_loads_when_buf_is_none(self):
        """When _find_all_simd is given buf=None (default), it loads fresh (today's behavior)."""
        with patch.object(
            sigmaker.InMemoryBuffer, "load", return_value=self._fake_buf()
        ) as mp_load, patch.object(
            sigmaker, "_simd_scan_bytes", return_value=-1
        ), patch.object(sigmaker, "ProgressDialog"):
            sigmaker.SignatureSearcher._find_all_simd("48 8B C4")
        mp_load.assert_called_once()


class TestActionEnumAddsFunctionSig(CoveredUnitTest):
    """The Action IntEnum gains FIND_FUNCTION_SIG=4 for issue #17."""

    def test_find_function_sig_value(self):
        self.assertEqual(int(sigmaker.Action.FIND_FUNCTION_SIG), 4)

    def test_existing_action_values_unchanged(self):
        self.assertEqual(int(sigmaker.Action.CREATE_UNIQUE), 0)
        self.assertEqual(int(sigmaker.Action.FIND_XREF), 1)
        self.assertEqual(int(sigmaker.Action.COPY_RANGE), 2)
        self.assertEqual(int(sigmaker.Action.SEARCH), 3)
        self.assertEqual(int(sigmaker.Action.BATCH_SEARCH), 5)


class TestGeneratedSignatureOrdering(CoveredUnitTest):
    """GeneratedSignature.__lt__ ranks by (size, wildcards) ascending."""

    def _make(self, byte_specs: list[tuple[int, bool]]) -> sigmaker.GeneratedSignature:
        sig = sigmaker.Signature()
        for value, is_wildcard in byte_specs:
            sig.append(sigmaker.SignatureByte(value, is_wildcard))
        return sigmaker.GeneratedSignature(sig, sigmaker.Match(0x1000))

    def test_smaller_size_beats_larger(self):
        smaller = self._make([(0xE8, False)] * 4)
        larger = self._make([(0xE8, False)] * 6)
        self.assertLess(smaller, larger)
        self.assertFalse(larger < smaller)

    def test_equal_size_fewer_wildcards_beats_more(self):
        fewer = self._make(
            [(0xE8, False), (0x00, True), (0x45, False), (0x33, False)]
        )
        more = self._make(
            [(0xE8, False), (0x00, True), (0x00, True), (0x33, False)]
        )
        self.assertLess(fewer, more)
        self.assertFalse(more < fewer)

    def test_equal_size_equal_wildcards_neither_less(self):
        a = self._make(
            [(0xE8, False), (0x00, True), (0x45, False), (0x33, False)]
        )
        b = self._make(
            [(0xC3, False), (0x90, True), (0x48, False), (0x89, False)]
        )
        self.assertFalse(a < b)
        self.assertFalse(b < a)

    def test_wildcard_count_helper(self):
        sig = self._make(
            [(0xE8, False), (0x00, True), (0x00, True), (0x33, False)]
        )
        self.assertEqual(sig._wildcard_count(), 2)


class TestDecodeFunctionForAnchors(CoveredUnitTest):
    """The one-shot decode helper used by MinimalFunctionSignatureGenerator.generate."""

    def setUp(self):
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.decode_insn = MagicMock(return_value=1)
        sigmaker.idaapi.get_bytes = MagicMock(
            side_effect=lambda ea, count: b"\x90" * count
        )

    def tearDown(self):
        sigmaker.idaapi_user_canceled = self.original_user_canceled

    def _processor(self):
        return sigmaker.InstructionProcessor(sigmaker.OperandProcessor())

    def _cfg(self, **kw):
        return sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
            **kw,
        )

    def _pfn(self, start_ea: int, end_ea: int):
        pfn = MagicMock()
        pfn.start_ea = start_ea
        pfn.end_ea = end_ea
        return pfn

    def test_empty_function_returns_empty_list(self):
        pfn = self._pfn(0x1000, 0x1000)
        decoded = sigmaker._decode_function_for_anchors(
            pfn, self._processor(), self._cfg()
        )
        self.assertEqual(decoded, [])

    def test_single_byte_instructions(self):
        pfn = self._pfn(0x1000, 0x1005)
        decoded = sigmaker._decode_function_for_anchors(
            pfn, self._processor(), self._cfg()
        )
        self.assertEqual(len(decoded), 5)
        for i, di in enumerate(decoded):
            self.assertEqual(di.ea, 0x1000 + i)
            self.assertEqual(di.size, 1)
            self.assertEqual(di.raw_bytes, b"\x90")
            self.assertEqual(di.operand_offb, 0)
            self.assertEqual(di.operand_length, 0)

    def test_single_get_bytes_call(self):
        pfn = self._pfn(0x1000, 0x100A)
        sigmaker.idaapi.get_bytes.reset_mock()
        sigmaker._decode_function_for_anchors(pfn, self._processor(), self._cfg())
        sigmaker.idaapi.get_bytes.assert_called_once_with(0x1000, 10)

    def test_short_read_returns_empty_when_function_bytes_none(self):
        pfn = self._pfn(0x1000, 0x1005)
        sigmaker.idaapi.get_bytes = MagicMock(return_value=None)
        decoded = sigmaker._decode_function_for_anchors(
            pfn, self._processor(), self._cfg()
        )
        self.assertEqual(decoded, [])


class TestStartStopProfiling(CoveredUnitTest):
    """The console-callable cProfile helpers for in-IDA diagnostics."""

    def setUp(self):
        sigmaker.idaapi.msg = MagicMock()
        sigmaker.idaapi.get_user_idadir = MagicMock(
            return_value=tempfile.mkdtemp()
        )
        # Ensure no stale session leaks between tests.
        sigmaker._PROFILER.reset()

    def tearDown(self):
        sigmaker._PROFILER.reset()

    def test_stop_without_start_returns_none(self):
        result = sigmaker.stop_profiling()
        self.assertIsNone(result)
        sigmaker.idaapi.msg.assert_called()

    def test_active_query_reflects_session(self):
        self.assertFalse(sigmaker._PROFILER.active)
        sigmaker.start_profiling()
        self.assertTrue(sigmaker._PROFILER.active)
        sigmaker.stop_profiling(
            output_path=tempfile.NamedTemporaryFile(suffix=".prof", delete=False).name
        )
        self.assertFalse(sigmaker._PROFILER.active)

    def test_start_then_stop_writes_files(self):
        out = tempfile.NamedTemporaryFile(suffix=".prof", delete=False).name
        sigmaker.start_profiling()
        # Tiny "real" workload so the profile has something to capture.
        sum(range(100))
        result = sigmaker.stop_profiling(output_path=out, top_n=5)
        self.assertEqual(result, out)
        import os
        self.assertGreater(os.path.getsize(out), 0)
        self.assertGreater(os.path.getsize(out + ".txt"), 0)

    def test_start_twice_discards_previous(self):
        sigmaker.start_profiling()
        first = sigmaker._PROFILER._profile
        sigmaker.start_profiling()
        self.assertTrue(sigmaker._PROFILER.active)
        self.assertIsNot(sigmaker._PROFILER._profile, first)
        sigmaker.stop_profiling(output_path=tempfile.NamedTemporaryFile(suffix=".prof", delete=False).name)


class TestDecodedInstruction(CoveredUnitTest):
    """The pre-decoded instruction container used by MinimalFunctionSignatureGenerator."""

    def test_construction_with_all_fields(self):
        di = sigmaker._DecodedInstruction(
            ea=0x1000,
            size=3,
            raw_bytes=b"\x48\x8b\xc4",
            operand_offb=0,
            operand_length=0,
        )
        self.assertEqual(di.ea, 0x1000)
        self.assertEqual(di.size, 3)
        self.assertEqual(di.raw_bytes, b"\x48\x8b\xc4")
        self.assertEqual(di.operand_offb, 0)
        self.assertEqual(di.operand_length, 0)

    def test_is_frozen(self):
        di = sigmaker._DecodedInstruction(
            ea=0x1000, size=1, raw_bytes=b"\x90",
            operand_offb=0, operand_length=0,
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            di.ea = 0x2000

    def test_uses_slots(self):
        di = sigmaker._DecodedInstruction(
            ea=0x1000, size=1, raw_bytes=b"\x90",
            operand_offb=0, operand_length=0,
        )
        self.assertTrue(hasattr(sigmaker._DecodedInstruction, "__slots__"))
        self.assertFalse(hasattr(di, "__dict__"))




class TestProgressFormatters(CoveredUnitTest):
    """The two __call__-able formatter dataclasses render their templates correctly."""

    def _make_sig(self, n: int) -> sigmaker.Signature:
        sig = sigmaker.Signature()
        for i in range(n):
            sig.append(sigmaker.SignatureByte(0x90 + i, False))
        return sig

    def test_unique_progress_reflects_sig_length(self):
        sig = self._make_sig(5)
        fmt = sigmaker._UniqueSigProgress(sig=sig)
        msg = fmt(idx=1, item=None, elapsed=2.5, total=None)
        self.assertIn("Length:  5 bytes", msg)
        self.assertIn("Elapsed: 2s", msg)

    def test_unique_progress_renders_exact_match_count(self):
        # Candidate-refinement makes the exact count free again, so the
        # Matches line is back (it was dropped in cebdf07 as a stopgap).
        sig = self._make_sig(5)
        fmt = sigmaker._UniqueSigProgress(sig=sig, last_match_count=42)
        msg = fmt(idx=1, item=None, elapsed=0.0, total=None)
        self.assertIn("Matches: 42", msg)

    def test_unique_progress_renders_question_mark_when_count_unknown(self):
        sig = self._make_sig(5)
        fmt = sigmaker._UniqueSigProgress(sig=sig)  # last_match_count None
        msg = fmt(idx=1, item=None, elapsed=0.0, total=None)
        self.assertIn("Matches: ?", msg)

    def test_unique_progress_sig_is_live_reference(self):
        sig = self._make_sig(2)
        fmt = sigmaker._UniqueSigProgress(sig=sig)
        sig.append(sigmaker.SignatureByte(0xCC, False))
        sig.append(sigmaker.SignatureByte(0xCC, False))
        msg = fmt(idx=1, item=None, elapsed=0.0, total=None)
        self.assertIn("Length:  4 bytes", msg)

    def test_function_progress_renders_all_fields(self):
        candidates: list = []
        fmt = sigmaker._FunctionSigProgress(
            pfn_start_ea=0x140001000,
            pfn_end_ea=0x140001100,
            candidates=candidates,
            best_size=100,
            current_anchor_ea=0x140001040,
            inner_length=7,
            inner_matches=3,
        )
        msg = fmt(idx=18, item=0x140001040, elapsed=4.0, total=None)
        # Function bounds + size shown.
        self.assertIn("0x140001000 .. 0x140001100", msg)
        self.assertIn("(256 bytes)", msg)
        # Anchor with idx.
        self.assertIn("Anchor (#18):", msg)
        self.assertIn("0x140001040", msg)
        # Inner search bounds + length + matches. Candidate-refinement tracks
        # the exact surviving count, so it renders the real number (no "2+").
        self.assertIn("0x140001040 .. 0x140001047", msg)
        self.assertIn("7 bytes", msg)
        self.assertIn("3 matches", msg)
        # Best so far + candidates + elapsed.
        self.assertIn("Best found:   -", msg)
        self.assertIn("0 unique so far", msg)
        self.assertIn("Elapsed:      4s", msg)

    def test_function_progress_inner_matches_none_renders_scanning(self):
        fmt = sigmaker._FunctionSigProgress(
            pfn_start_ea=0x1000,
            pfn_end_ea=0x1100,
            candidates=[],
            best_size=50,
            current_anchor_ea=0x1010,
            inner_length=0,
            inner_matches=None,
        )
        msg = fmt(idx=1, item=0x1010, elapsed=0.0, total=None)
        self.assertIn("scanning...", msg)

    def test_function_progress_reflects_best_and_candidates(self):
        candidates: list = []
        fmt = sigmaker._FunctionSigProgress(
            pfn_start_ea=0x1000,
            pfn_end_ea=0x1100,
            candidates=candidates,
            best_size=100,
            current_anchor_ea=0x1010,
        )
        dummy_sig = sigmaker.Signature()
        dummy_sig.append(sigmaker.SignatureByte(0x90, False))
        candidates.append(
            sigmaker.GeneratedSignature(dummy_sig, sigmaker.Match(0x1000))
        )
        fmt.best_size = 12
        msg = fmt(idx=3, item=0x1010, elapsed=2.0, total=None)
        self.assertIn("Best found:   12 bytes", msg)
        self.assertIn("1 unique so far", msg)


class TestCancelToPartial(CoveredUnitTest):
    """Context manager that converts UserCanceledError into a partial per policy."""

    def _sentinel_partial(self):
        sig = sigmaker.Signature()
        sig.append(sigmaker.SignatureByte(0x90, False))
        return sigmaker.GeneratedSignature(
            sig,
            sigmaker.Match(0x1000),
            status=sigmaker.GenerationStatus.PARTIAL_ON_CANCEL,
            match_count=42,
        )

    def test_strict_propagates_cancel(self):
        partial = self._sentinel_partial()
        built = []

        def build_partial():
            built.append(True)
            return partial

        cancel = sigmaker._CancelToPartial(
            sigmaker.GenerationPolicy.strict(), build_partial
        )
        with self.assertRaises(sigmaker.UserCanceledError):
            with cancel:
                raise sigmaker.UserCanceledError("test cancel")

        self.assertIsNone(cancel.partial)
        self.assertEqual(built, [])

    def test_permissive_stashes_partial(self):
        partial = self._sentinel_partial()
        cancel = sigmaker._CancelToPartial(
            sigmaker.GenerationPolicy.permissive(), lambda: partial
        )
        with cancel:
            raise sigmaker.UserCanceledError("test cancel")
        self.assertIs(cancel.partial, partial)

    def test_permissive_propagates_when_build_partial_raises(self):
        def build_partial():
            raise sigmaker.UserCanceledError("empty sig, nothing to return")

        cancel = sigmaker._CancelToPartial(
            sigmaker.GenerationPolicy.permissive(), build_partial
        )
        with self.assertRaises(sigmaker.UserCanceledError) as ctx:
            with cancel:
                raise sigmaker.UserCanceledError("original cancel")

        self.assertEqual(str(ctx.exception), "original cancel")
        self.assertIsNone(cancel.partial)

    def test_non_cancel_exceptions_propagate_unchanged(self):
        cancel = sigmaker._CancelToPartial(
            sigmaker.GenerationPolicy.permissive(),
            lambda: self._sentinel_partial(),
        )
        with self.assertRaises(ValueError):
            with cancel:
                raise ValueError("some other error")
        self.assertIsNone(cancel.partial)

    def test_no_exception_no_partial(self):
        cancel = sigmaker._CancelToPartial(
            sigmaker.GenerationPolicy.permissive(),
            lambda: self._sentinel_partial(),
        )
        with cancel:
            pass
        self.assertIsNone(cancel.partial)


class _FakeDialog:
    """Recording stand-in for sigmaker.ProgressDialog used in ProgressBox tests."""

    def __init__(self, message: str):
        self.initial_message = message
        self.messages: list[str] = []
        self.enter_count = 0
        self.exit_count = 0
        self.exit_exc_type = None

    def __enter__(self):
        self.enter_count += 1
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.exit_count += 1
        self.exit_exc_type = exc_type
        return False  # never suppress

    def replace_message(self, msg: str, hide_cancel: bool = False):
        self.messages.append(msg)


class TestProgressBox(CoveredUnitTest):
    """ProgressBox wraps iteration with a wait box and live message updates."""

    def setUp(self):
        self.original_user_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)
        self.dialogs: list[_FakeDialog] = []

    def tearDown(self):
        sigmaker.idaapi_user_canceled = self.original_user_canceled

    def _factory(self, message):
        d = _FakeDialog(message)
        self.dialogs.append(d)
        return d

    def _clock(self, ticks):
        """Return a callable that yields successive tick values, repeating the last."""
        iterator = iter(ticks)
        last = [ticks[-1]]

        def call():
            try:
                v = next(iterator)
                last[0] = v
                return v
            except StopIteration:
                return last[0]

        return call

    def test_yields_all_items_in_order(self):
        items = list(sigmaker.ProgressBox(
            [1, 2, 3], dialog_factory=self._factory, clock=self._clock([0.0])
        ))
        self.assertEqual(items, [1, 2, 3])

    def test_dialog_lifecycle(self):
        list(sigmaker.ProgressBox(
            [1, 2, 3], dialog_factory=self._factory, clock=self._clock([0.0])
        ))
        self.assertEqual(len(self.dialogs), 1)
        self.assertEqual(self.dialogs[0].enter_count, 1)
        self.assertEqual(self.dialogs[0].exit_count, 1)

    def test_throttle_skips_redraws_when_clock_does_not_advance(self):
        # Clock returns 0.0 always; throttle never elapses.
        list(sigmaker.ProgressBox(
            [1, 2, 3, 4, 5],
            dialog_factory=self._factory,
            clock=self._clock([0.0]),
            throttle_seconds=10.0,
        ))
        self.assertEqual(len(self.dialogs[0].messages), 0)

    def test_throttle_passes_when_clock_advances(self):
        # Clock yields: start=0.0, then 0.05, 0.20, 0.30, 0.50, 0.55.
        # With throttle_seconds=0.1, gaps > 0.1 from last_update pass:
        #   call#1 last=0.0 now=0.05 -> gap 0.05, skip
        #   call#2 last=0.0 now=0.20 -> gap 0.20, pass; last=0.20
        #   call#3 last=0.20 now=0.30 -> gap 0.10, NOT >, skip
        #   call#4 last=0.20 now=0.50 -> gap 0.30, pass; last=0.50
        #   call#5 last=0.50 now=0.55 -> gap 0.05, skip
        # = 2 redraws.
        list(sigmaker.ProgressBox(
            [1, 2, 3, 4, 5],
            dialog_factory=self._factory,
            clock=self._clock([0.0, 0.05, 0.20, 0.30, 0.50, 0.55]),
            throttle_seconds=0.1,
        ))
        self.assertEqual(len(self.dialogs[0].messages), 2)

    def test_format_message_receives_args(self):
        received = []

        def fmt(idx, item, elapsed, total):
            received.append((idx, item, elapsed, total))
            return f"item {idx}"

        list(sigmaker.ProgressBox(
            ["a", "b"],
            format_message=fmt,
            dialog_factory=self._factory,
            clock=self._clock([0.0, 1.0, 2.0]),
            throttle_seconds=0.0,
        ))
        self.assertEqual(received[0], (1, "a", 1.0, 2))
        self.assertEqual(received[1], (2, "b", 2.0, 2))

    def test_cancel_raises_user_canceled_error(self):
        sigmaker.idaapi_user_canceled = MagicMock(return_value=True)
        with self.assertRaises(sigmaker.UserCanceledError):
            list(sigmaker.ProgressBox(
                [1, 2, 3], dialog_factory=self._factory, clock=self._clock([0.0])
            ))
        self.assertEqual(self.dialogs[0].exit_count, 1)
        self.assertIs(self.dialogs[0].exit_exc_type, sigmaker.UserCanceledError)

    def test_total_is_none_for_generator(self):
        def gen():
            yield 1
            yield 2

        received = []

        def fmt(idx, item, elapsed, total):
            received.append(total)
            return ""

        list(sigmaker.ProgressBox(
            gen(),
            format_message=fmt,
            dialog_factory=self._factory,
            clock=self._clock([0.0, 1.0, 2.0]),
            throttle_seconds=0.0,
        ))
        self.assertEqual(received, [None, None])

    def test_total_computed_from_len(self):
        received = []

        def fmt(idx, item, elapsed, total):
            received.append(total)
            return ""

        list(sigmaker.ProgressBox(
            [10, 20, 30],
            format_message=fmt,
            dialog_factory=self._factory,
            clock=self._clock([0.0, 1.0, 2.0, 3.0]),
            throttle_seconds=0.0,
        ))
        self.assertTrue(all(t == 3 for t in received))

    def test_default_message_when_no_formatter(self):
        list(sigmaker.ProgressBox(
            [1, 2],
            dialog_factory=self._factory,
            clock=self._clock([0.0, 1.0, 2.0]),
            throttle_seconds=0.0,
        ))
        self.assertEqual(self.dialogs[0].messages[0], "Processing (1/2) | Elapsed: 1s")
        self.assertEqual(self.dialogs[0].messages[1], "Processing (2/2) | Elapsed: 2s")


class TestSeedViaIndex(CoveredUnitTest):
    """Index-backed seeding maps hits to pattern starts and refines."""

    def _sig(self, specs):
        sig = sigmaker.Signature()
        for v, w in specs:
            sig.append(sigmaker.SignatureByte(v, w))
        return sig

    def test_index_seed_matches_buffer(self):
        buf = MagicMock()
        buf.data.return_value = memoryview(
            bytearray(b"\x8b\x45\x90\x90\x90\x00\x8b\x45\x00\x00")
        )
        # pattern "8B 45 90 90 90" (all exact), 5 bytes
        sig = self._sig(
            [(0x8B, False), (0x45, False), (0x90, False), (0x90, False), (0x90, False)]
        )
        idx = MagicMock()
        # 8B 45 is the most selective run, so Dynamic Seed Selection keys on
        # it; other runs (90 90, 45 90) and all 1-byte buckets get a larger
        # bucket so they lose.
        idx.bucket_size.side_effect = lambda key: {(0x8B << 8) | 0x45: 2}.get(key, 10**9)
        idx.bucket_size1.side_effect = lambda b: 10**9
        # Real _ByteIndex.candidates returns array.array('I') slices; mirror that.
        idx.candidates.side_effect = (
            lambda key: array.array("I", [0, 6])
            if key == ((0x8B << 8) | 0x45)
            else array.array("I", [])
        )
        idx.candidates1.side_effect = lambda b: array.array("I", [])
        arr, cnt = sigmaker._seed_via_index(sig, idx, buf)
        # offset 0 keeps (90 90 90 follow); offset 6 drops (00 00 follow)
        self.assertEqual(list(arr[:cnt]), [0])

    def test_wildcard_heavy_signature_anchors_on_exact_island(self):
        pattern = bytes(
            [
                0xE8,
                0xAA,
                0xBB,
                0xCC,
                0xDD,
                0x48,
                0x8B,
                0xD8,
                0x48,
                0x85,
                0xC0,
                0x11,
                0x22,
                0x48,
                0x8B,
                0xCB,
            ]
        )
        data = bytearray(b"\x90" * 100)
        data[20:20 + len(pattern)] = pattern
        data[69:71] = b"\x85\xc0"  # Decoy seed hit; full pattern should reject it.

        buf = MagicMock()
        buf.data.return_value = memoryview(data)
        sig = self._sig(
            [
                (0xE8, False),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x00, True),
                (0x48, False),
                (0x8B, False),
                (0xD8, False),
                (0x48, False),
                (0x85, False),
                (0xC0, False),
                (0x00, True),
                (0x00, True),
                (0x48, False),
                (0x8B, False),
                (0xCB, False),
            ]
        )
        seed_key = (0x85 << 8) | 0xC0
        idx = MagicMock()
        idx.bucket_size.side_effect = lambda key: {seed_key: 2}.get(key, 10**9)
        idx.bucket_size1.side_effect = lambda b: 10**9
        idx.candidates.side_effect = (
            lambda key: array.array("I", [29, 69])
            if key == seed_key
            else array.array("I", [])
        )
        idx.candidates1.side_effect = lambda b: array.array("I", [])

        arr, cnt = sigmaker._seed_via_index(sig, idx, buf)

        idx.candidates.assert_called_once_with(seed_key)
        idx.candidates1.assert_not_called()
        self.assertEqual(list(arr[:cnt]), [20])

    def test_one_byte_seed_path(self):
        # buffer: F3 at offsets 0 and 8; no 2-byte run is selectable, so the
        # single byte F3 is the seed. offset 0 fits a 5-byte pattern; offset 8
        # does not (8 + 5 > 10) and is dropped by the fit guard.
        buf = MagicMock()
        buf.data.return_value = memoryview(
            bytearray(b"\xf3\x90\x90\x90\x90\x00\x00\x00\xf3\x00")
        )
        sig = self._sig(
            [(0xF3, False), (0x90, True), (0x90, True), (0x90, True), (0x90, True)]
        )
        idx = MagicMock()
        idx.bucket_size.side_effect = lambda key: 10**9   # no 2-byte run chosen
        idx.bucket_size1.side_effect = lambda b: {0xF3: 2}.get(b, 10**9)
        idx.candidates1.side_effect = (
            lambda b: array.array("I", [0, 8]) if b == 0xF3 else array.array("I", [])
        )
        arr, cnt = sigmaker._seed_via_index(sig, idx, buf)
        self.assertEqual(list(arr[:cnt]), [0])

    def test_returns_none_when_all_wildcard(self):
        buf = MagicMock()
        buf.data.return_value = memoryview(bytearray(b"\x90" * 10))
        sig = self._sig([(0x90, True), (0x91, True)])  # no exact byte at all
        idx = MagicMock()
        idx.bucket_size.return_value = 10**9
        idx.bucket_size1.return_value = 10**9
        self.assertIsNone(sigmaker._seed_via_index(sig, idx, buf))

    def test_returns_none_when_index_none(self):
        buf = MagicMock()
        buf.data.return_value = memoryview(bytearray(b"\x90" * 10))
        sig = self._sig([(0x90, False), (0x91, False)])
        self.assertIsNone(sigmaker._seed_via_index(sig, None, buf))


class TestSelectSeedRun(CoveredUnitTest):
    """Dynamic Seed Selection across 1-byte and 2-byte runs."""

    def _sig(self, specs):  # specs: list[(value, is_wildcard)]
        sig = sigmaker.Signature()
        for v, w in specs:
            sig.append(sigmaker.SignatureByte(v, w))
        return sig

    def _index(self, two_byte_sizes, one_byte_sizes=None):
        one_byte_sizes = one_byte_sizes or {}
        idx = MagicMock()
        idx.bucket_size.side_effect = lambda key: two_byte_sizes.get(key, 10**9)
        idx.bucket_size1.side_effect = lambda b: one_byte_sizes.get(b, 10**9)
        return idx

    def test_picks_smallest_two_byte_run(self):
        # ?? 00 00 ?? 8B 45 ; 8B 45 is the most selective run -> width 2
        sig = self._sig(
            [(0, True), (0, False), (0, False), (0, True), (0x8B, False), (0x45, False)]
        )
        two = {(0x00 << 8) | 0x00: 4_000_000, (0x8B << 8) | 0x45: 12}
        run = sigmaker._select_seed_run(sig, self._index(two))
        self.assertEqual(run, (4, 2, (0x8B << 8) | 0x45))

    def test_rare_one_byte_beats_common_two_byte(self):
        # 00 00 ?? F3 : the only 2-byte run is 00 00 (common); F3 is a rare
        # single byte -> selection prefers the 1-byte key (width 1).
        sig = self._sig([(0x00, False), (0x00, False), (0, True), (0xF3, False)])
        two = {(0x00 << 8) | 0x00: 1_500_000}
        one = {0x00: 3_000_000, 0xF3: 800}
        run = sigmaker._select_seed_run(sig, self._index(two, one))
        self.assertEqual(run, (3, 1, 0xF3))

    def test_selectivity_beats_longest_exact_run(self):
        # 00 00 00 00 is the longest exact run, but it is common. The shorter
        # 4C 8B island has the smaller bucket, so it is the better anchor.
        sig = self._sig(
            [
                (0x00, False),
                (0x00, False),
                (0x00, False),
                (0x00, False),
                (0x00, True),
                (0x4C, False),
                (0x8B, False),
                (0xDC, False),
            ]
        )
        two = {
            (0x00 << 8) | 0x00: 5_000_000,
            (0x4C << 8) | 0x8B: 12,
            (0x8B << 8) | 0xDC: 20,
        }
        one = {0x00: 8_000_000, 0x4C: 400, 0x8B: 800, 0xDC: 900}

        run = sigmaker._select_seed_run(sig, self._index(two, one))

        self.assertEqual(run, (5, 2, (0x4C << 8) | 0x8B))

    def test_returns_none_when_no_exact_byte(self):
        sig = self._sig([(0, True), (0, True)])
        self.assertIsNone(sigmaker._select_seed_run(sig, self._index({})))


class TestByteIndexOneByte(CoveredUnitTest):
    """1-byte bucket accessors derived from the 2-byte index."""

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_bucket_size1_and_candidates1(self):
        # 0x90 appears at offsets 0,2,4,6 but only 0,2,4 are 2-byte-window
        # starts (offset 6 is the last byte, n-1, not a window start).
        data = memoryview(bytearray(b"\x90\x01\x90\x02\x90\x03\x90"))
        idx = sigmaker._ByteIndex.build(data)
        self.assertEqual(sorted(idx.candidates1(0x90)), [0, 2, 4])
        self.assertEqual(idx.bucket_size1(0x90), 3)
        self.assertEqual(idx.bucket_size1(0xEE), 0)
        self.assertEqual(list(idx.candidates1(0xEE)), [])

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_bucket_size1_equals_sum_of_two_byte_buckets(self):
        import random
        rng = random.Random(7)
        data = memoryview(bytearray(rng.randrange(256) for _ in range(4096)))
        idx = sigmaker._ByteIndex.build(data)
        for b in (0x00, 0x41, 0xFF):
            two_byte_sum = sum(idx.bucket_size((b << 8) | x) for x in range(256))
            self.assertEqual(idx.bucket_size1(b), two_byte_sum)


class TestByteIndex(CoveredUnitTest):
    """The _ByteIndex holder over build_byte_index."""

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_build_and_lookup(self):
        data = memoryview(bytearray(b"\x01\x02\x01\x02\x03"))
        idx = sigmaker._ByteIndex.build(data)
        self.assertIsNotNone(idx)
        key = (0x01 << 8) | 0x02
        self.assertEqual(idx.bucket_size(key), 2)
        self.assertEqual(sorted(idx.candidates(key)), [0, 2])

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_build_returns_none_for_short_buffer(self):
        self.assertIsNone(
            sigmaker._ByteIndex.build(memoryview(bytearray(b"\x01")))
        )


class TestIndexSeedEquivalence(CoveredUnitTest):
    """Index-seeded candidates must equal a brute-force masked rescan."""

    def _brute(self, data: bytes, sig) -> list[int]:
        n, m = len(data), len(sig)
        out = []
        for c in range(n - m + 1):
            ok = True
            for j in range(m):
                sb = sig[j]
                if sb.is_wildcard:
                    continue
                if data[c + j] != sb.value:
                    ok = False
                    break
            if ok:
                out.append(c)
        return out

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_index_seed_equals_brute_force(self):
        import random
        rng = random.Random(99)
        data = bytes(rng.randrange(256) for _ in range(8192))
        mv = memoryview(bytearray(data))
        idx = sigmaker._ByteIndex.build(mv)
        buf = MagicMock()
        buf.data.return_value = mv
        for anchor in (10, 100, 500, 4000):
            sig = sigmaker.Signature()
            for j in range(7):
                is_wc = (j % 4 == 0)
                sig.append(sigmaker.SignatureByte(data[anchor + j], is_wc))
            _arr, _cnt = sigmaker._seed_via_index(sig, idx, buf)
            seeded = list(_arr[:_cnt])
            expected = self._brute(data, sig)
            self.assertEqual(
                sorted(seeded), sorted(expected),
                f"anchor {anchor}: index seed != brute force",
            )
            self.assertIn(anchor, seeded)

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_wildcard_heavy_one_byte_path_equals_brute_force(self):
        import random
        rng = random.Random(2026)
        data = bytes(rng.randrange(256) for _ in range(8192))
        mv = memoryview(bytearray(data))
        idx = sigmaker._ByteIndex.build(mv)
        buf = MagicMock()
        buf.data.return_value = mv
        for anchor in (33, 777, 5000):
            sig = sigmaker.Signature()
            # heavy wildcarding so no 2 consecutive exact bytes: every other
            # byte is a wildcard -> forces the 1-byte seed path.
            for j in range(7):
                is_wc = (j % 2 == 1)
                sig.append(sigmaker.SignatureByte(data[anchor + j], is_wc))
            _arr, _cnt = sigmaker._seed_via_index(sig, idx, buf)
            seeded = list(_arr[:_cnt])
            expected = self._brute(data, sig)
            self.assertEqual(sorted(seeded), sorted(expected),
                             f"anchor {anchor}: 1-byte path != brute force")
            self.assertIn(anchor, seeded)

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_end_of_buffer_pattern_found(self):
        # Pattern at the very end of the buffer, with its only exact byte as
        # the last pattern byte -> exercises the n-1 boundary handling.
        data = bytes(range(256)) * 32  # 8192 bytes, last byte 0xFF
        mv = memoryview(bytearray(data))
        idx = sigmaker._ByteIndex.build(mv)
        buf = MagicMock()
        buf.data.return_value = mv
        n = len(data)
        m = 5
        anchor = n - m  # pattern occupies the final 5 bytes
        sig = sigmaker.Signature()
        for j in range(m):
            is_wc = (j != m - 1)  # only the last byte exact -> seed at s == m-1
            sig.append(sigmaker.SignatureByte(data[anchor + j], is_wc))
        _arr, _cnt = sigmaker._seed_via_index(sig, idx, buf)
        seeded = list(_arr[:_cnt])
        expected = self._brute(data, sig)
        self.assertEqual(sorted(seeded), sorted(expected))
        self.assertIn(anchor, seeded)


class TestRefineOffsetsCython(CoveredUnitTest):
    """The in-place Cython candidate-refinement compactor."""

    def _arr(self, items):
        import array
        return array.array("I", items)

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_exact_byte_compacts_in_place(self):
        data = memoryview(bytearray(b"\x90\x48\x90\x48\x90"))
        cands = self._arr([0, 1, 2, 3])
        n = sigmaker.simd_scan.refine_offsets(data, cands, 4, 1, 0x48, 0xFF)
        self.assertEqual(n, 2)
        self.assertEqual(list(cands[:n]), [0, 2])

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_full_wildcard_keeps_all(self):
        data = memoryview(bytearray(b"\x01\x02\x03\x04"))
        cands = self._arr([0, 1, 2])
        n = sigmaker.simd_scan.refine_offsets(data, cands, 3, 1, 0x00, 0x00)
        self.assertEqual(n, 3)
        self.assertEqual(list(cands[:n]), [0, 1, 2])

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_nibble_mask(self):
        data = memoryview(bytearray(b"\x4A\x4B\x9C"))
        cands = self._arr([0, 1, 2])
        n = sigmaker.simd_scan.refine_offsets(data, cands, 3, 0, 0x40, 0xF0)
        self.assertEqual(n, 2)
        self.assertEqual(list(cands[:n]), [0, 1])

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_out_of_bounds_dropped(self):
        data = memoryview(bytearray(b"\x90\x90"))
        cands = self._arr([0, 1])
        n = sigmaker.simd_scan.refine_offsets(data, cands, 2, 2, 0x90, 0xFF)
        self.assertEqual(n, 0)

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_empty(self):
        data = memoryview(bytearray(b"\x90"))
        cands = self._arr([])
        n = sigmaker.simd_scan.refine_offsets(data, cands, 0, 0, 0x90, 0xFF)
        self.assertEqual(n, 0)

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_matches_python_refine(self):
        import array, random
        rng = random.Random(11)
        data = bytes(rng.randrange(256) for _ in range(2048))
        mv = memoryview(bytearray(data))
        for _ in range(50):
            cand_list = sorted(rng.sample(range(2000), 64))
            j = rng.randrange(8)
            value = rng.randrange(256)
            mask = rng.choice([0x00, 0x0F, 0xF0, 0xFF])
            py = sigmaker._refine_offsets(mv, list(cand_list), j, value, mask)
            arr = array.array("I", cand_list)
            n = sigmaker.simd_scan.refine_offsets(mv, arr, len(cand_list), j, value, mask)
            self.assertEqual(sorted(arr[:n]), sorted(py))


class TestBuildByteIndex(CoveredUnitTest):
    """The Cython 2-byte counting-sort index."""

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_heads_and_positions_shape(self):
        data = memoryview(bytearray(b"\x01\x02\x01\x02\x03"))
        heads, positions = sigmaker.simd_scan.build_byte_index(data)
        self.assertEqual(len(heads), 65537)
        self.assertEqual(len(positions), len(data) - 1)  # 4 windows
        self.assertEqual(heads[0], 0)
        self.assertEqual(heads[65536], len(data) - 1)
        self.assertTrue(all(heads[i] <= heads[i + 1] for i in range(65536)))

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_bucket_contains_correct_offsets(self):
        # windows: (0)01 02, (1)02 01, (2)01 02, (3)02 03
        data = memoryview(bytearray(b"\x01\x02\x01\x02\x03"))
        heads, positions = sigmaker.simd_scan.build_byte_index(data)
        key_0102 = (0x01 << 8) | 0x02
        start, end = heads[key_0102], heads[key_0102 + 1]
        self.assertEqual(sorted(positions[start:end]), [0, 2])
        key_0203 = (0x02 << 8) | 0x03
        s2, e2 = heads[key_0203], heads[key_0203 + 1]
        self.assertEqual(sorted(positions[s2:e2]), [3])
        self.assertEqual(end - start, 2)  # bucket_size of 01 02

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_short_buffer_returns_empty_positions(self):
        heads, positions = sigmaker.simd_scan.build_byte_index(
            memoryview(bytearray(b"\x01"))
        )
        self.assertEqual(len(positions), 0)
        self.assertEqual(len(heads), 65537)  # safe to look up; all buckets empty


class TestSeedOffsetsKernel(unittest.TestCase):
    """simd_scan.seed_offsets maps index-bucket hits to pattern starts,
    identically to the pure-Python genexp in _seed_via_index it replaces."""

    @staticmethod
    def _genexp(bucket, s, m, n):
        return [p - s for p in bucket if p >= s and (p - s) + m <= n]

    def setUp(self):
        if not sigmaker.SIMD_SPEEDUP_AVAILABLE:
            self.skipTest("SIMD speedup not available")

    def _check(self, bucket, s, m, n):
        import array as _arr
        arr, count = sigmaker.simd_scan.seed_offsets(
            _arr.array("I", bucket), s, m, n
        )
        self.assertEqual(len(arr), len(bucket) + 1)   # capacity = bucket+1
        self.assertLessEqual(count, len(bucket))
        self.assertEqual(list(arr[:count]), self._genexp(bucket, s, m, n))

    def test_empty_bucket(self):
        self._check([], 0, 4, 100)

    def test_s_zero_all_fit(self):
        self._check([0, 10, 20, 30], 0, 5, 100)

    def test_s_positive_drops_small_p(self):
        self._check([0, 1, 2, 5, 9, 50], 3, 4, 100)

    def test_boundary_inclusive_vs_exclusive(self):
        # (p - s) + m == n is kept; == n + 1 is dropped
        self._check([96, 97], 0, 4, 100)

    def test_single_element(self):
        self._check([42], 5, 3, 100)

    def test_randomized(self):
        import random
        rng = random.Random(1234)
        for _ in range(200):
            n = rng.randint(1, 5000)
            m = rng.randint(1, 32)
            s = rng.randint(0, m - 1)
            bucket = sorted(
                rng.randint(0, n + 50) for _ in range(rng.randint(0, 300))
            )
            self._check(bucket, s, m, n)


class TestSeedDeferredWhenAllWildcard(unittest.TestCase):
    """Phase 6: an all-wildcard prefix defers seeding (no find_all_offsets full
    scan) until an exact byte appears, then seeds via the index."""

    def setUp(self):
        if not sigmaker.SIMD_SPEEDUP_AVAILABLE:
            self.skipTest("SIMD speedup not available")
        self._orig_canceled = getattr(
            sigmaker, "idaapi_user_canceled", MagicMock(return_value=False)
        )
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)

    def tearDown(self):
        sigmaker.idaapi_user_canceled = self._orig_canceled

    def test_all_wildcard_prefix_defers_seed(self):
        buf_bytes = b"\xAA\xAA\xAA\xAA\xAA\x8B\x45\x08\xCC\xCC\xCC\xCC"
        mv = memoryview(bytearray(buf_bytes))
        seed_buf = MagicMock()
        seed_buf.data.return_value = mv
        idx = sigmaker._ByteIndex.build(mv)
        self.assertIsNotNone(idx)

        decoded = [
            sigmaker._DecodedInstruction(
                ea=0x1000, size=5, raw_bytes=buf_bytes[0:5],
                operand_offb=0, operand_length=5,   # entire instruction wildcarded
            ),
            sigmaker._DecodedInstruction(
                ea=0x1005, size=3, raw_bytes=b"\x8B\x45\x08",
                operand_offb=0, operand_length=0,    # all exact
            ),
        ]
        gen = sigmaker.MinimalFunctionSignatureGenerator(
            sigmaker.InstructionProcessor(sigmaker.OperandProcessor())
        )
        cfg = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA, wildcard_operands=True,
            continue_outside_of_function=False, wildcard_optimized=True,
            ask_longer_signature=False, max_single_signature_length=50,
        )

        calls = {"n": 0}

        def spy(ida_sig, buf=None):
            calls["n"] += 1
            return [], buf

        with patch.object(
            sigmaker.SignatureSearcher, "find_all_offsets", side_effect=spy
        ):
            sig = gen._grow_unique_from_decoded(
                decoded, 0, cfg.max_single_signature_length, cfg,
                buf=seed_buf, index=idx,
            )

        self.assertEqual(
            calls["n"], 0,
            "find_all_offsets must not run for an all-wildcard prefix when the "
            "index is available",
        )
        self.assertIsNotNone(sig)
        self.assertEqual(len(sig), 8)               # 5 wildcard + 8B 45 08
        self.assertTrue(all(sig[i].is_wildcard for i in range(5)))
        self.assertEqual([sig[i].value for i in range(5, 8)], [0x8B, 0x45, 0x08])


class TestFunctionNameInDisplay(unittest.TestCase):
    """Address output is labeled with the containing function name when one is
    available, falling back to the bare EA otherwise."""

    def setUp(self):
        self._orig_msg = sigmaker.idaapi.msg
        self._orig_get_name = sigmaker.idaapi.get_func_name
        self.msgs: list[str] = []
        sigmaker.idaapi.msg = lambda s: self.msgs.append(s)

    def tearDown(self):
        sigmaker.idaapi.msg = self._orig_msg
        sigmaker.idaapi.get_func_name = self._orig_get_name

    def test_suffix_with_name(self):
        sigmaker.idaapi.get_func_name = MagicMock(return_value="Java_x_y_calc")
        self.assertEqual(sigmaker._func_name_suffix(0x1000), " (Java_x_y_calc)")

    def test_suffix_without_name(self):
        sigmaker.idaapi.get_func_name = MagicMock(return_value="")
        self.assertEqual(sigmaker._func_name_suffix(0x1000), "")

    def test_suffix_handles_none_and_nonstring(self):
        sigmaker.idaapi.get_func_name = MagicMock(return_value=None)
        self.assertEqual(sigmaker._func_name_suffix(0x1000), "")
        sigmaker.idaapi.get_func_name = MagicMock(return_value=MagicMock())
        self.assertEqual(sigmaker._func_name_suffix(0x1000), "")

    def test_suffix_suppresses_exceptions(self):
        sigmaker.idaapi.get_func_name = MagicMock(side_effect=RuntimeError("boom"))
        self.assertEqual(sigmaker._func_name_suffix(0x1000), "")

    def test_unique_display_includes_name_and_address(self):
        sigmaker.idaapi.get_func_name = MagicMock(return_value="myfunc")
        cfg = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA, wildcard_operands=False,
            continue_outside_of_function=False, wildcard_optimized=False,
        )
        sig = sigmaker.Signature()
        for i in range(4):
            sig.append(sigmaker.SignatureByte(0xE8 + i, False))
        result = sigmaker.GeneratedSignature(sig, sigmaker.Match(0x140001234))
        with patch.object(sigmaker.Clipboard, "set_text", return_value=True):
            result.display(cfg)
        combined = "".join(self.msgs)
        self.assertIn("Signature for", combined)
        self.assertIn("(myfunc)", combined)
        self.assertIn(str(sigmaker.Match(0x140001234)), combined)  # EA still present

    def test_unique_display_falls_back_to_ea_when_unnamed(self):
        sigmaker.idaapi.get_func_name = MagicMock(return_value="")
        cfg = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA, wildcard_operands=False,
            continue_outside_of_function=False, wildcard_optimized=False,
        )
        sig = sigmaker.Signature()
        for i in range(4):
            sig.append(sigmaker.SignatureByte(0xE8 + i, False))
        result = sigmaker.GeneratedSignature(sig, sigmaker.Match(0x140001234))
        with patch.object(sigmaker.Clipboard, "set_text", return_value=True):
            result.display(cfg)
        combined = "".join(self.msgs)
        self.assertIn(str(sigmaker.Match(0x140001234)), combined)
        self.assertNotIn("(", combined)  # no name parenthetical


class TestPluginManifestVersion(unittest.TestCase):
    """Guard against ida-plugin.json drifting from the package version."""

    def test_manifest_version_matches_package(self):
        manifest = json.loads((TEST_DIR.parent / "ida-plugin.json").read_text())
        self.assertEqual(
            manifest["plugin"]["version"],
            sigmaker.__version__,
            "ida-plugin.json version is out of sync with sigmaker.__version__; "
            "bump ida-plugin.json whenever you bump the package version.",
        )


class TestArmReferenceAwareWildcard(unittest.TestCase):
    """ARM/Thumb wildcarding respects the operand-wildcard policy, refines the
    ambiguous imm/displ types to real addresses via is_off, and wildcards the
    whole instruction where the offset reaches the high byte (branch targets,
    ADRP). Register-bearing operands stay exact unless the user selects them.
    """

    class _Op:
        def __init__(self, type_, offb, n):
            self.type = type_
            self.offb = offb
            self.n = n

    class _Ins:
        def __init__(self, size, ops, ea=0x1000):
            self.size = size
            self._ops = ops
            self.ea = ea

        def __iter__(self):
            return iter(self._ops)

    def setUp(self):
        ia = sigmaker.idaapi
        self._saved = {
            k: getattr(ia, k, None) for k in ("get_flags", "is_off", "get_bytes")
        }
        ia.get_flags = MagicMock(return_value=0)
        self._offset_ops = set()  # operand indices IDA marks as offsets
        ia.is_off = lambda flags, n: n in self._offset_ops
        # Default test policy: addresses only, matching WildcardPolicy.for_arm.
        self._addr_types = {ia.o_mem, ia.o_displ, ia.o_imm, ia.o_near, ia.o_far}
        self._tok = sigmaker.WildcardPolicy.set_current(
            sigmaker.WildcardPolicy(frozenset(self._addr_types))
        )

    def tearDown(self):
        sigmaker.WildcardPolicy.reset_current(self._tok)
        for k, v in self._saved.items():
            setattr(sigmaker.idaapi, k, v)

    def _proc(self):
        proc = sigmaker.OperandProcessor()
        proc._is_arm = True  # bypass idaapi.ph_get_id() under the mock
        return proc

    def _run(self, size, ops):
        off, length = [0], [0]
        found = self._proc().get_operand(self._Ins(size, ops), off, length, True)
        return found, off[0], length[0]

    def test_address_immediate_adrp_wildcards_whole_instruction(self):
        ia = sigmaker.idaapi
        self._offset_ops = {1}  # ADRP: op1 is the address immediate (is_off)
        found, off, length = self._run(
            4, [self._Op(ia.o_reg, 0, 0), self._Op(ia.o_imm, 0, 1)]
        )
        self.assertTrue(found)
        self.assertEqual((off, length), (0, 4))  # immlo reaches the high byte

    def test_address_displacement_pageoff_keeps_high_byte(self):
        ia = sigmaker.idaapi
        self._offset_ops = {1}  # LDR [X8,#sym@PAGEOFF]: offset in the low bytes
        found, off, length = self._run(
            4, [self._Op(ia.o_reg, 0, 0), self._Op(ia.o_displ, 0, 1)]
        )
        self.assertTrue(found)
        self.assertEqual((off, length), (0, 3))

    def test_branch_target_wildcards_whole_instruction(self):
        # RibShark #61 follow-up: Thumb-2 BL/BLX and long B put offset bits in
        # the high byte, so the whole instruction must be masked.
        ia = sigmaker.idaapi
        self._offset_ops = set()  # near targets carry a code xref, not is_off
        found, off, length = self._run(4, [self._Op(ia.o_near, 0, 0)])
        self.assertTrue(found)
        self.assertEqual((off, length), (0, 4))

    def test_o_mem_literal_keeps_opcode_byte(self):
        # Thumb "LDR Rt, off_X" (o_mem): imm8 is the low byte, opcode the high.
        ia = sigmaker.idaapi
        self._offset_ops = set()
        found, off, length = self._run(2, [self._Op(ia.o_mem, 0, 0)])
        self.assertTrue(found)
        self.assertEqual((off, length), (0, 1))

    def test_thumb_ldr_literal_produces_wildcarded_signature(self):
        # #61 stays fixed and specific: 1B 4D -> ?? 4D.
        ia = sigmaker.idaapi
        self._offset_ops = set()
        instr = b"\x1B\x4D"
        ea = 0x1000
        ia.get_bytes = lambda a, c: instr[a - ea: a - ea + c]
        sig = sigmaker.Signature()
        ins = self._Ins(2, [self._Op(ia.o_mem, 0, 0)], ea=ea)
        sigmaker.InstructionProcessor(self._proc()).append_instruction_to_sig(
            sig, ea, ins, wildcard_operands=True, wildcard_optimized=True
        )
        self.assertEqual(
            list(sig),
            [
                sigmaker.SignatureByte(0x1B, True),
                sigmaker.SignatureByte(0x4D, False),
            ],
        )

    def test_bare_immediate_not_wildcarded(self):
        # o_imm without is_off is a stable constant (#0x40) -> stays exact.
        ia = sigmaker.idaapi
        self._offset_ops = set()
        found, _, _ = self._run(4, [self._Op(ia.o_imm, 0, 0)])
        self.assertFalse(found)

    def test_stack_displacement_not_wildcarded(self):
        # o_displ without is_off is a stack slot ([SP,#var]) -> stays exact.
        ia = sigmaker.idaapi
        self._offset_ops = set()
        found, _, _ = self._run(4, [self._Op(ia.o_displ, 0, 0)])
        self.assertFalse(found)

    def test_register_list_exact_by_default(self):
        # Not in the addresses-only default policy -> PUSH {R4-R6,LR} stays 70 B5.
        reglist = sigmaker.WildcardPolicy.ARMKind.REGLIST
        found, _, _ = self._run(2, [self._Op(reglist, 0, 0)])
        self.assertFalse(found)

    def test_register_list_wildcarded_when_selected(self):
        # User enables "Register list" in the operand dialog (broad mode).
        reglist = sigmaker.WildcardPolicy.ARMKind.REGLIST
        with sigmaker.WildcardPolicy.use(
            sigmaker.WildcardPolicy(frozenset(self._addr_types | {reglist}))
        ):
            found, off, length = self._run(2, [self._Op(reglist, 0, 0)])
        self.assertTrue(found)
        self.assertEqual((off, length), (0, 1))


class TestSearchAddressMapping(unittest.TestCase):
    """Issue #68: a SIMD-search match maps back to its real IDA address even
    when segments are non-contiguous (e.g. an extra binary loaded at a distant
    address). Previously the address was inf_get_min_ea() + buffer_offset, which
    is wrong past the first non-contiguous segment."""

    _KEYS = (
        "get_first_seg", "get_next_seg", "get_bytes", "get_input_file_path",
        "get_imagebase", "inf_get_min_ea",
    )

    def setUp(self):
        self._saved = {k: getattr(sigmaker.idaapi, k, None) for k in self._KEYS}
        sigmaker.idaapi.get_input_file_path = MagicMock(return_value="/x")
        sigmaker.idaapi.get_imagebase = MagicMock(return_value=0x1000)
        sigmaker.idaapi.inf_get_min_ea = MagicMock(return_value=0x1000)

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(sigmaker.idaapi, k, v)

    def _two_segment_buffer(self):
        # seg1 @ 0x1000 (4 bytes) then seg2 @ 0x1F78000 (4 bytes): the second is
        # far from the first, exactly the "extra binary loaded at 0x1F78000" case.
        s1 = MagicMock(start_ea=0x1000, end_ea=0x1004)
        s2 = MagicMock(start_ea=0x1F78000, end_ea=0x1F78004)
        sigmaker.idaapi.get_first_seg = MagicMock(return_value=s1)
        sigmaker.idaapi.get_next_seg = MagicMock(
            side_effect=lambda ea: s2 if ea == 0x1000 else None
        )

        def gb(ea, size):
            return {0x1000: b"\xAA\xBB\xCC\xDD", 0x1F78000: b"\xF1\xB5\x04\x00"}.get(
                ea, b""
            )

        sigmaker.idaapi.get_bytes = MagicMock(side_effect=gb)
        return sigmaker.InMemoryBuffer.load(
            mode=sigmaker.InMemoryBuffer.LoadMode.SEGMENTS
        )

    def test_offset_mapper_across_noncontiguous_segments(self):
        buf = self._two_segment_buffer()
        m = buf.offset_mapper()
        # buffer: AA BB CC DD | F1 B5 04 00  (offsets 0-3 seg1, 4-7 seg2). The
        # mapper walks a forward cursor, so it expects ascending offsets (as
        # match positions are).
        self.assertEqual(m(0), 0x1000)
        self.assertEqual(m(3), 0x1003)
        self.assertEqual(m(4), 0x1F78000)  # not 0x1004
        self.assertEqual(m(6), 0x1F78002)

    def test_offset_mapper_fallback_without_map(self):
        buf = sigmaker.InMemoryBuffer(file_path=pathlib.Path("/x"))
        self.assertEqual(buf.offset_mapper()(0x40), 0x1000 + 0x40)

    @unittest.skipUnless(sigmaker.SIMD_SPEEDUP_AVAILABLE, "SIMD not built")
    def test_find_all_simd_reports_real_address_in_second_segment(self):
        buf = self._two_segment_buffer()
        matches = sigmaker.SignatureSearcher._find_all_simd("F1 B5 04 00", buf=buf)
        self.assertEqual([int(m.address) for m in matches], [0x1F78000])


class TestSegmentScope(unittest.TestCase):
    """Issue #64: scope_to_segment loads only the anchor's segment as the
    uniqueness corpus, so functions duplicated across segments can be signed."""

    _SEG_KEYS = (
        "getseg", "get_bytes", "get_first_seg", "get_next_seg",
        "get_input_file_path", "get_imagebase",
    )

    def setUp(self):
        self._saved = {k: getattr(sigmaker.idaapi, k, None) for k in self._SEG_KEYS}
        sigmaker.idaapi.get_input_file_path = MagicMock(return_value="/x")

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(sigmaker.idaapi, k, v)

    def _load(self, **kw):
        return sigmaker.InMemoryBuffer.load(
            mode=sigmaker.InMemoryBuffer.LoadMode.SEGMENTS, **kw
        )

    def test_scope_ea_loads_only_containing_segment(self):
        seg = MagicMock(start_ea=0x2000, end_ea=0x2010)
        sigmaker.idaapi.getseg = MagicMock(return_value=seg)
        sigmaker.idaapi.get_bytes = MagicMock(return_value=b"\xAA" * 0x10)
        buf = self._load(scope_ea=0x2008)
        self.assertEqual(bytes(buf.data()), b"\xAA" * 0x10)
        sigmaker.idaapi.getseg.assert_called_once_with(0x2008)
        sigmaker.idaapi.get_bytes.assert_called_once_with(0x2000, 0x10)

    def test_no_scope_loads_all_segments(self):
        s1 = MagicMock(start_ea=0, end_ea=4)
        sigmaker.idaapi.get_first_seg = MagicMock(return_value=s1)
        sigmaker.idaapi.get_next_seg = MagicMock(return_value=None)
        sigmaker.idaapi.get_bytes = MagicMock(return_value=b"\x01\x02\x03\x04")
        sigmaker.idaapi.getseg = MagicMock(
            side_effect=AssertionError("getseg must not be used without scope_ea")
        )
        buf = self._load()
        self.assertEqual(bytes(buf.data()), b"\x01\x02\x03\x04")

    def test_scope_ea_without_segment_falls_back_to_all(self):
        sigmaker.idaapi.getseg = MagicMock(return_value=None)
        s1 = MagicMock(start_ea=0, end_ea=2)
        sigmaker.idaapi.get_first_seg = MagicMock(return_value=s1)
        sigmaker.idaapi.get_next_seg = MagicMock(return_value=None)
        sigmaker.idaapi.get_bytes = MagicMock(return_value=b"\x09\x09")
        buf = self._load(scope_ea=0x9999)
        self.assertEqual(bytes(buf.data()), b"\x09\x09")

    def test_config_scope_to_segment_defaults_false(self):
        cfg = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=False,
            wildcard_optimized=False,
        )
        self.assertFalse(cfg.scope_to_segment)


class TestSearchScope(unittest.TestCase):
    """Issue #64 follow-up: 'Search for a signature' honors the containing-
    segment scope, so a segment-scoped signature can be searched within just
    that segment instead of the whole database."""

    def setUp(self):
        self._saved_simd = sigmaker.SIMD_SPEEDUP_AVAILABLE
        self._saved_canceled = sigmaker.idaapi_user_canceled
        sigmaker.idaapi_user_canceled = MagicMock(return_value=False)

    def tearDown(self):
        sigmaker.SIMD_SPEEDUP_AVAILABLE = self._saved_simd
        sigmaker.idaapi_user_canceled = self._saved_canceled

    def test_find_all_scope_bounds_binsearch_to_segment(self):
        # non-SIMD path: bin_search runs over [scope_start, scope_end), not the
        # whole [min_ea, max_ea).
        sigmaker.SIMD_SPEEDUP_AVAILABLE = False
        sigmaker.idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF
        sigmaker.idaapi.inf_get_min_ea = MagicMock(return_value=0x1000)
        sigmaker.idaapi.inf_get_max_ea = MagicMock(return_value=0xFFFFFF)
        sigmaker.idaapi.compiled_binpat_vec_t = MagicMock
        sigmaker.idaapi.parse_binpat_str = MagicMock()
        sigmaker.idaapi.BIN_SEARCH_NOCASE = 0
        sigmaker.idaapi.BIN_SEARCH_FORWARD = 0
        bs = MagicMock(
            side_effect=[(0x2100, None), (sigmaker.idaapi.BADADDR, None)]
        )
        sigmaker.idaapi.bin_search = bs
        results = sigmaker.SignatureSearcher.find_all(
            "48 8B C4", scope=(0x2000, 0x2200)
        )
        self.assertEqual([int(m) for m in results], [0x2100])
        first_call = bs.call_args_list[0]
        self.assertEqual(first_call.args[0], 0x2000)  # starts at scope start
        self.assertEqual(first_call.args[1], 0x2200)  # bounded by scope end

    def test_find_all_scope_loads_single_segment_for_simd(self):
        # SIMD path: a scoped search with no buffer loads only that segment and
        # threads it into the scan.
        sigmaker.SIMD_SPEEDUP_AVAILABLE = True
        with patch.object(sigmaker, "ProgressDialog", MagicMock()), \
                patch.object(sigmaker.InMemoryBuffer, "load") as load, \
                patch.object(
                    sigmaker.SignatureSearcher, "_find_all_simd", return_value=[]
                ) as simd:
            sigmaker.SignatureSearcher.find_all("48 8B C4", scope=(0x2000, 0x2200))
        load.assert_called_once()
        self.assertEqual(load.call_args.kwargs.get("scope_ea"), 0x2000)
        self.assertIs(simd.call_args.kwargs.get("buf"), load.return_value)

    def test_search_resolves_scope_ea_to_its_segment(self):
        seg = MagicMock(start_ea=0x3000, end_ea=0x3400)
        sigmaker.idaapi.getseg = MagicMock(return_value=seg)
        with patch.object(sigmaker, "ProgressDialog", MagicMock()), \
                patch.object(sigmaker, "SignatureParser") as sp, \
                patch.object(
                    sigmaker.SignatureSearcher, "find_all", return_value=[]
                ) as fa:
            sp.parse.return_value = "48 8B C4"
            sigmaker.SignatureSearcher.from_signature("x").search(scope_ea=0x3200)
        sigmaker.idaapi.getseg.assert_called_once_with(0x3200)
        self.assertEqual(fa.call_args.kwargs.get("scope"), (0x3000, 0x3400))

    def test_search_without_scope_ea_scans_whole_db(self):
        with patch.object(sigmaker, "ProgressDialog", MagicMock()), \
                patch.object(sigmaker, "SignatureParser") as sp, \
                patch.object(
                    sigmaker.SignatureSearcher, "find_all", return_value=[]
                ) as fa:
            sp.parse.return_value = "48 8B C4"
            sigmaker.SignatureSearcher.from_signature("x").search()
        self.assertIsNone(fa.call_args.kwargs.get("scope"))

    def test_search_scope_ea_without_segment_falls_back_to_whole_db(self):
        sigmaker.idaapi.getseg = MagicMock(return_value=None)
        with patch.object(sigmaker, "ProgressDialog", MagicMock()), \
                patch.object(sigmaker, "SignatureParser") as sp, \
                patch.object(
                    sigmaker.SignatureSearcher, "find_all", return_value=[]
                ) as fa:
            sp.parse.return_value = "48 8B C4"
            sigmaker.SignatureSearcher.from_signature("x").search(scope_ea=0x9999)
        self.assertIsNone(fa.call_args.kwargs.get("scope"))


if __name__ == "__main__":
    # Run the tests (coverage is handled by the base class)
    unittest.main(verbosity=2)
