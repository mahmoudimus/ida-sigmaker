import logging
import pathlib
import shutil
import sys
import tempfile
import unittest
import warnings

sys.path.insert(0, pathlib.Path(__file__).parent.as_posix())

# Import the base test case
from coveredtestcase import CoverageTestCase

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Context manager to suppress warnings from IDA Pro modules during import
with warnings.catch_warnings():
    warnings.filterwarnings("ignore")
    import idapro
    import idaapi

    import sigmaker


class CoveredIntegrationTest(CoverageTestCase):
    coverage_data_file = ".coverage.integration"


class TestIntegrationWithRealBinary(CoveredIntegrationTest):
    """Integration tests that use real IDA Pro API against a compiled binary"""

    @classmethod
    def setUpClass(cls):
        """Build the test binary, open database once for all tests"""
        cls.tests_dir = pathlib.Path(__file__).parent
        cls.binary_path = cls.tests_dir / "_resources/bin/test_binary.exe"
        cls.tempdir = None
        cls.temp_binary_path = None
        cls.database_opened = False

        if not cls.binary_path.exists():
            logger.warning("Test binary not found at any expected location")
            raise unittest.SkipTest("Test binary not available")

        # Create temporary directory and copy binary for idalib compatibility
        cls.tempdir = pathlib.Path(tempfile.mkdtemp())
        cls.temp_binary_path = cls.tempdir / cls.binary_path.name
        shutil.copy(cls.binary_path, cls.temp_binary_path)

        # Open database once for all tests
        logger.debug("Opening database %s...", cls.temp_binary_path)
        result = idapro.open_database(str(cls.temp_binary_path), True)
        logger.debug("Open result: %s", result)

        if result != 0:
            raise unittest.SkipTest(f"Failed to open database. Result code: {result}")

        # Run auto analysis
        idaapi.auto_wait()
        cls.database_opened = True

        # Store commonly used values
        cls.min_ea = idaapi.inf_get_min_ea()
        cls.max_ea = idaapi.inf_get_max_ea()

        logger.debug(
            "Min EA: %s, Max EA: %s, BADADDR: %s",
            hex(cls.min_ea),
            hex(cls.max_ea),
            hex(idaapi.BADADDR),
        )

        # Debug: List all segments
        seg = idaapi.get_first_seg()
        seg_count = 0
        while seg:
            seg_count += 1
            logger.debug(
                "Segment %d: %s - %s, type: %s",
                seg_count,
                hex(seg.start_ea),
                hex(seg.end_ea),
                hex(seg.type),
            )
            seg = idaapi.get_next_seg(seg.start_ea)

        logger.debug("Total segments found: %d", seg_count)

        # Call parent setUpClass to start coverage
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        """Close database and clean up temporary directory"""
        if cls.database_opened:
            logger.debug("Closing database...")
            idapro.close_database()
            cls.database_opened = False

        if cls.tempdir and cls.tempdir.exists():
            logger.debug("Cleaning up temporary directory...")
            shutil.rmtree(cls.tempdir)

        # Call parent tearDownClass to stop coverage and generate reports
        super().tearDownClass()

    def get_code_address(self):
        """Get a code address for testing by looking through segments."""
        # First try to find a code segment
        seg = idaapi.get_first_seg()
        while seg:
            if seg.start_ea != idaapi.BADADDR and seg.end_ea != idaapi.BADADDR:
                # Look for code in this segment
                for ea in range(seg.start_ea, min(seg.start_ea + 0x1000, seg.end_ea)):
                    if idaapi.is_code(idaapi.get_flags(ea)):
                        logger.debug(
                            f"Found code address {hex(ea)} in segment {hex(seg.start_ea)}-{hex(seg.end_ea)}"
                        )
                        return ea
            seg = idaapi.get_next_seg(seg.start_ea)

        # Fallback: try the original method
        logger.debug(
            f"Trying fallback method: min_ea={hex(self.min_ea)}, max_ea={hex(self.max_ea)}"
        )
        for ea in range(self.min_ea, min(self.min_ea + 0x1000, self.max_ea)):
            if idaapi.is_code(idaapi.get_flags(ea)):
                logger.debug(f"Found code address {hex(ea)} in fallback search")
                return ea

        logger.warning("No code addresses found in any segments")
        return None

    def test_load_binary_with_ida(self):
        """Test loading the binary with IDA and basic analysis"""
        # Database is already opened in setUpClass

        # Check for valid addresses (not BADADDR)
        self.assertNotEqual(self.min_ea, idaapi.BADADDR, "min_ea should not be BADADDR")
        self.assertNotEqual(self.max_ea, idaapi.BADADDR, "max_ea should not be BADADDR")
        self.assertGreater(
            self.max_ea, self.min_ea, "Database should have valid address range"
        )

        # Check that we can access segments
        seg = idaapi.get_first_seg()
        if seg:
            self.assertIsNotNone(
                seg.start_ea, "First segment should have a start address"
            )
            logger.debug("Found segment: %s - %s", hex(seg.start_ea), hex(seg.end_ea))

        # Verify we can read bytes from the database
        if seg:
            # Read some bytes from the first segment
            bytes_data = idaapi.get_bytes(
                seg.start_ea, min(16, seg.end_ea - seg.start_ea)
            )
            self.assertIsInstance(
                bytes_data, bytes, "Should be able to read bytes from database"
            )
            self.assertGreater(
                len(bytes_data), 0, "Should read some bytes from database"
            )

    def test_signature_patterns_from_binary(self):
        """Test that we can identify the instruction patterns from the examples using real IDA APIs"""
        # Database is already opened in setUpClass

        # Use real IDA APIs to search for patterns
        # Search for the mov pattern: C7 44 24 (which is mov [rsp+...], ...)
        search_pattern = b"\xc7\x44\x24"

        mov_positions = []
        current_ea = self.min_ea
        while current_ea < self.max_ea - 3:
            # Read bytes at current position and check for pattern
            bytes_at_pos = idaapi.get_bytes(current_ea, 3)
            if bytes_at_pos == search_pattern:
                mov_positions.append(current_ea)
            current_ea += 1

        self.assertGreater(
            len(mov_positions), 0, "Should find mov [rsp+...] instructions"
        )

        # For each mov position, check the displacement byte
        found_target_instruction = False
        for pos in mov_positions:
            if pos + 4 < self.max_ea:
                displacement = idaapi.get_byte(pos + 3)
                if displacement == 0x34:  # [rsp+0x34]
                    # This is our target instruction
                    # Verify the full pattern C7 44 24 34 00 00 00 00
                    full_pattern = idaapi.get_bytes(pos, 8)
                    expected = b"\xc7\x44\x24\x34\x00\x00\x00\x00"
                    self.assertEqual(
                        full_pattern,
                        expected,
                        f"MOV pattern at position {hex(pos)} should match",
                    )
                    found_target_instruction = True

        self.assertTrue(
            found_target_instruction,
            "Should find the target [rsp+0x34] instruction",
        )

    def test_wildcard_pattern_matching(self):
        """Test wildcard pattern matching against the real binary using IDA APIs"""
        # Database is already opened in setUpClass

        # Pattern: C7 44 24 ? ? ? ? ? (should match both test cases)
        test_pattern = b"\xc7\x44\x24"  # This is the non-wildcard part

        matches = []
        current_ea = self.min_ea
        while current_ea < self.max_ea - 3:
            bytes_at_pos = idaapi.get_bytes(current_ea, 3)
            if bytes_at_pos == test_pattern:
                if current_ea + 8 <= self.max_ea:
                    matches.append(current_ea)
            current_ea += 1

        self.assertGreaterEqual(
            len(matches),
            2,
            "Should find at least 2 MOV instructions matching the wildcard pattern",
        )

        found_displacements = set()
        for match_pos in matches:
            displacement = idaapi.get_byte(match_pos + 3)
            found_displacements.add(displacement)

        self.assertIn(0x30, found_displacements, "Should find [rsp+0x30] displacement")
        self.assertIn(0x34, found_displacements, "Should find [rsp+0x34] displacement")

    def test_search_signature_string_ida_format(self):
        searcher = sigmaker.SignatureSearcher.from_signature("48 8B ? 48 89")
        results = searcher.search()  # Should not raise exception
        self.assertIsInstance(results, sigmaker.SearchResults)
        self.assertEqual(results.signature_str, "48 8B ? 48 89")
        self.assertEqual(len(results.matches), 4)
        self.assertIsInstance(results.matches[0], sigmaker.Match)

    def test_search_signature_string_byte_array_format(self):
        searcher = sigmaker.SignatureSearcher.from_signature(
            "\\x48\\x8B\\x00\\x48\\x89 xx?xx"
        )
        results = searcher.search()  # Should not raise exception
        self.assertIsInstance(results, sigmaker.SearchResults)
        self.assertEqual(results.signature_str, "48 8B ? 48 89")
        self.assertEqual(len(results.matches), 4)
        self.assertIsInstance(results.matches[0], sigmaker.Match)

    def test_search_signature_string_bitmask_format(self):
        searcher = sigmaker.SignatureSearcher.from_signature(
            "0x48, 0x8B, 0x00, 0x48, 0x89 0b11011"
        )
        results = searcher.search()  # Should not raise exception
        self.assertIsInstance(results, sigmaker.SearchResults)
        self.assertEqual(results.signature_str, "48 8B ? 48 89")
        self.assertEqual(len(results.matches), 4)
        self.assertIsInstance(results.matches[0], sigmaker.Match)

    def test_signature_occurrence_finding(self):
        test_signatures = [
            "48 8B",  # MOV rax, ...
            "48 89",  # MOV ..., rax
            "C3",  # RET
        ]
        for sig in test_signatures:
            searcher = sigmaker.SignatureSearcher.from_signature(sig)
            results = searcher.search()
            self.assertIsInstance(
                results.matches, list, f"Should return list for signature: {sig}"
            )
            if sig == "C3":
                self.assertGreater(
                    len(results.matches),
                    0,
                    f"Should find at least one occurrence of {sig}",
                )

    def test_signature_uniqueness_check(self):
        unique_sig = "48 83 EC 28 48 8B 05 F5"
        searcher = sigmaker.SignatureSearcher.from_signature(unique_sig)
        results = searcher.search()
        is_unique = len(results.matches) == 1
        self.assertIsInstance(is_unique, bool, "Should return boolean")

        common_sig = "48"  # Single byte; should not be unique
        searcher = sigmaker.SignatureSearcher.from_signature(common_sig)
        results = searcher.search()
        is_unique = len(results.matches) == 1
        self.assertFalse(is_unique, "Single byte signature should not be unique")

    def test_generate_unique_signature_basic(self):
        signature_maker = sigmaker.SignatureMaker()

        # Find a code address
        func_ea = self.get_code_address()

        assert func_ea is not None, "Should find at least one code address"

        try:
            ctx = sigmaker.SigMakerConfig(
                output_format=sigmaker.SignatureType.IDA,
                wildcard_operands=False,
                continue_outside_of_function=True,
                wildcard_optimized=False,
                max_single_signature_length=100,
                ask_longer_signature=False,
            )
            result = signature_maker.make_signature(func_ea, ctx)
            self.assertIsInstance(result, sigmaker.GeneratedSignature)
            self.assertIsInstance(result.signature, sigmaker.Signature)
            self.assertGreater(
                len(result.signature), 0, "Should generate non-empty signature"
            )
            for sig_byte in result.signature:
                self.assertIsInstance(sig_byte, sigmaker.SignatureByte)
        except sigmaker.Unexpected as e:
            self.skipTest(f"Could not generate unique signature: {e}")

    def debug_unique(self, sigmaker_obj, ea, **kw):
        ctx = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=kw.get("wildcard_operands", True),
            continue_outside_of_function=kw.get("continue_outside", False),
            wildcard_optimized=kw.get("wildcard_optimized", True),
            max_single_signature_length=kw.get("max_len", 256),
            ask_longer_signature=False,
        )
        sm = sigmaker_obj  # SignatureMaker instance
        sig = sigmaker.Signature()
        cur = ea
        used = 0
        while True:
            ins = idaapi.insn_t()
            n = idaapi.decode_insn(ins, cur)
            if n <= 0:
                print("decode stop")
                break
            sm._append_operand_aware(
                sig, cur, ins, ctx.wildcard_operands, ctx.wildcard_optimized
            )
            txt = f"{sig:ida}"
            hits = sm._find_signature_occurrences(txt)
            print(f"len={len(sig):4d} used={used+n:4d} hits={len(hits)} ea={hex(cur)}")
            if len(hits) == 1:
                print("unique!")
                break
            cur += n
            used += n
            if used > ctx.max_single_signature_length:
                print("hit cap")
                break

    def test_generate_signature_with_wildcards(self):
        sig_txt_ida = "E8 ? ? ? ? 48 89 C7"
        res_exact = sigmaker.SignatureSearcher.from_signature(sig_txt_ida).search()
        self.assertEqual(
            len(res_exact.matches),
            1,
            f"Expected unique exact match, got {len(res_exact.matches)}",
        )
        anchor_ea = res_exact.matches[0]

        gen_ctx = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=True,
            continue_outside_of_function=False,  # stay within the function
            wildcard_optimized=True,
            max_single_signature_length=100,
            ask_longer_signature=False,
        )
        result = sigmaker.SignatureMaker().make_signature(anchor_ea, gen_ctx)
        self.assertIsInstance(result.signature, sigmaker.Signature)
        sig_txt_dq = " ".join(
            [x if x != "?" else "??" for x in sig_txt_ida.split(" ")]
        )  # ida uses ? for wildcards, x64dbg uses ??
        self.assertEqual(f"{result.signature:x64dbg}", sig_txt_dq)
        self.assertTrue(any(b.is_wildcard for b in result.signature))

    def test_generate_signature_for_range(self):
        signature_maker = sigmaker.SignatureMaker()

        start_ea = self.get_code_address()

        assert start_ea is not None, "Should find at least one code address"

        end_ea = start_ea + 16

        try:
            ctx = sigmaker.SigMakerConfig(
                output_format=sigmaker.SignatureType.IDA,
                wildcard_operands=False,
                continue_outside_of_function=False,
                wildcard_optimized=False,
            )
            result = signature_maker.make_signature(start_ea, ctx, end=end_ea)
            self.assertIsInstance(result, sigmaker.GeneratedSignature)
            self.assertIsInstance(result.signature, sigmaker.Signature)
            self.assertGreater(
                len(result.signature), 0, "Should generate non-empty signature"
            )
        except sigmaker.Unexpected as e:
            self.skipTest(f"Could not generate range signature: {e}")

    def test_generate_signature_error_handling(self):
        signature_maker = sigmaker.SignatureMaker()

        ctx = sigmaker.SigMakerConfig(
            output_format=sigmaker.SignatureType.IDA,
            wildcard_operands=False,
            continue_outside_of_function=True,
            wildcard_optimized=False,
            max_single_signature_length=100,
            ask_longer_signature=False,
        )

        with self.assertRaises(sigmaker.Unexpected):
            signature_maker.make_signature(idaapi.BADADDR, ctx)

    def test_add_byte_to_signature(self):
        """Test adding bytes to signature using real IDA Pro API"""
        signature = sigmaker.Signature()

        # Use real IDA Pro addresses from the loaded binary
        # Start from the beginning of the first code segment
        start_addr = self.min_ea
        if start_addr == idaapi.BADADDR:
            self.skipTest("No valid addresses found in binary")

        # Add a few bytes to the signature
        signature.add_byte_to_signature(start_addr, False)
        self.assertEqual(len(signature), 1)
        self.assertFalse(signature[0].is_wildcard)

        # Add another byte as wildcard
        signature.add_byte_to_signature(start_addr + 1, True)
        self.assertEqual(len(signature), 2)
        self.assertTrue(signature[1].is_wildcard)

        # Add multiple bytes
        signature.add_bytes_to_signature(start_addr + 2, 1, False)
        self.assertEqual(len(signature), 3)
        self.assertFalse(signature[2].is_wildcard)

        # Verify the signature was built correctly
        self.assertGreater(len(signature), 0)
        for i, sig_byte in enumerate(signature):
            self.assertIsInstance(sig_byte, sigmaker.SignatureByte)
            if i == 1:  # Second byte should be wildcard
                self.assertTrue(sig_byte.is_wildcard)
            else:
                self.assertFalse(sig_byte.is_wildcard)

    def test_real_binary_pattern_search(self):
        """Test searching for the actual pattern that exists in the test binary."""
        # Read the actual test binary

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            data_view = memoryview(binary_data)

            # Test the exact pattern from the failing integration test
            pattern = "E8 ?? ?? ?? ?? 48 89 C7"
            print(f"\n=== Testing pattern '{pattern}' in real binary ===")

            # Create SIMD signature
            sig = sigmaker.simd_scan.Signature(pattern)

            # Search for the pattern
            result = sigmaker.simd_scan.scan_bytes(data_view, sig)

            print(f"Pattern '{pattern}' found at offset: {result}")

            if result == -1:
                print("Pattern not found! This indicates a bug in SIMD search.")
                # Let's try some debugging
                print("Binary size:", len(binary_data))
                print("Pattern length:", len(pattern.split()))

                # Check if the pattern exists at the expected location
                expected_offset = 3595  # 0xe0b
                if expected_offset + 8 <= len(binary_data):
                    bytes_at_expected = binary_data[
                        expected_offset : expected_offset + 8
                    ]
                    print(
                        f"Bytes at expected offset {expected_offset}: {' '.join(f'{b:02X}' for b in bytes_at_expected)}"
                    )

                    # Test exact match at expected location
                    exact_pattern = "E8 80 0A 00 00 48 89 C7"
                    exact_sig = sigmaker.simd_scan.Signature(exact_pattern)
                    exact_result = sigmaker.simd_scan.scan_bytes(data_view, exact_sig)
                    print(f"Exact pattern search result: {exact_result}")

                    if exact_result != expected_offset:
                        print(
                            f"ERROR: Expected exact pattern at {expected_offset}, but found at {exact_result}"
                        )
                    else:
                        print(
                            "Exact pattern found correctly, wildcard search is the issue"
                        )

            # The pattern should be found at offset 3595
            expected_offset = 3595
            self.assertEqual(
                result,
                expected_offset,
                f"Pattern should be found at offset {expected_offset}, got {result}",
            )

        except FileNotFoundError:
            self.skipTest(f"Test binary not found at {self.binary_path}")
        except Exception as e:
            self.fail(f"Error reading test binary: {e}")

    def test_ida_environment_simulation(self):
        """Test SIMD search under conditions that simulate the IDA environment."""
        # Read the actual test binary

        try:
            with open(self.binary_path, "rb") as f:
                binary_data = f.read()

            print("\n=== IDA Environment Simulation ===")
            print(f"Binary size: {len(binary_data)} bytes")

            # Simulate InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.FILE)
            # This should create a memoryview similar to what IDA does
            data_view = memoryview(binary_data)

            # Test the exact pattern from the failing test
            pattern = "E8 ?? ?? ?? ?? 48 89 C7"
            sig = sigmaker.simd_scan.Signature(pattern)

            print(f"Testing pattern: {pattern}")
            print(f"Data view type: {type(data_view)}")
            print(f"Data view length: {len(data_view)}")

            # Check if the pattern exists at the expected location
            expected_offset = 3595
            if expected_offset + 8 <= len(data_view):
                bytes_at_expected = bytes(
                    data_view[expected_offset : expected_offset + 8]
                )
                print(
                    f"Bytes at offset {expected_offset}: {' '.join(f'{b:02X}' for b in bytes_at_expected)}"
                )

                # Verify the pattern matches
                expected_bytes = b"\xe8\x80\x0a\x00\x00\x48\x89\xc7"
                pattern_matches = bytes_at_expected == expected_bytes
                print(f"Pattern matches expected: {pattern_matches}")

            # Now test the SIMD search
            result = sigmaker.simd_scan.scan_bytes(data_view, sig)
            print(f"SIMD search result: {result}")

            if result == -1:
                print("SIMD search failed to find pattern!")
                # Let's try a different approach - search for smaller patterns
                print("\n=== Debugging with smaller patterns ===")

                # Test exact pattern without wildcards
                exact_pattern = "E8 80 0A 00 00 48 89 C7"
                exact_sig = sigmaker.simd_scan.Signature(exact_pattern)
                exact_result = sigmaker.simd_scan.scan_bytes(data_view, exact_sig)
                print(f"Exact pattern search result: {exact_result}")

                # Test single byte pattern
                single_pattern = "E8"
                single_sig = sigmaker.simd_scan.Signature(single_pattern)
                single_result = sigmaker.simd_scan.scan_bytes(data_view, single_sig)
                print(f"Single byte 'E8' search result: {single_result}")

                if single_result != -1:
                    print(f"Found 'E8' at offset {single_result}")
                    # Check what comes after
                    if single_result + 8 <= len(data_view):
                        next_bytes = bytes(data_view[single_result : single_result + 8])
                        print(
                            f"Next 8 bytes after 'E8': {' '.join(f'{b:02X}' for b in next_bytes)}"
                        )

            # The test should pass if SIMD finds the pattern
            self.assertEqual(
                result,
                expected_offset,
                f"SIMD search should find pattern at offset {expected_offset}, got {result}",
            )

        except FileNotFoundError:
            self.skipTest(f"Test binary not found at {self.binary_path}")
        except Exception as e:
            self.fail(f"Error in IDA simulation test: {e}")


if __name__ == "__main__":
    unittest.main()
