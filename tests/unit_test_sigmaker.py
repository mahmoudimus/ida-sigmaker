"""
unit_test_sigmaker.py - Unit tests for sigmaker

Tests the sigmaker module and related functionality with mocked system interfaces
to ensure reliable testing across different platforms and architectures.
"""

import gc
import logging
import pathlib
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


if __name__ == "__main__":
    # Run the tests (coverage is handled by the base class)
    unittest.main(verbosity=2)
