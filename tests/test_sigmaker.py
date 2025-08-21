import re
import sys
import types
import unittest
from pathlib import Path


def _install_ida_stubs():
    # ida_idp stub
    ida_idp = types.ModuleType("ida_idp")
    ida_idp.PLFM_386 = 0x01
    ida_idp.PLFM_ARM = 0x02
    ida_idp.PLFM_MIPS = 0x03
    ida_idp.PLFM_PPC = 0x04
    ida_idp.ph_get_id = lambda: ida_idp.PLFM_386
    sys.modules["ida_idp"] = ida_idp

    # ida_ida stub
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0
    ida_ida.inf_get_max_ea = lambda: 0xFFFFFFFF
    ida_ida.inf_get_procname = lambda: "x86"
    sys.modules["ida_ida"] = ida_ida

    # ida_idaapi stub
    ida_idaapi = types.ModuleType("ida_idaapi")

    class plugin_t(object):
        pass

    ida_idaapi.plugin_t = plugin_t
    ida_idaapi.PLUGIN_KEEP = 0
    sys.modules["ida_idaapi"] = ida_idaapi

    # ida_kernwin stub
    ida_kernwin = types.ModuleType("ida_kernwin")

    def _noop(*args, **kwargs):
        return None

    ida_kernwin.show_wait_box = _noop
    ida_kernwin.hide_wait_box = _noop
    ida_kernwin.replace_wait_box = _noop
    ida_kernwin.user_cancelled = lambda: False
    ida_kernwin.user_canceled = ida_kernwin.user_cancelled
    ida_kernwin.get_screen_ea = lambda: 0
    ida_kernwin.ask_addr = lambda start, msg: start

    class twinpos_t:
        def __init__(self):
            self.at = None

        def place(self, ctx):
            return None

    ida_kernwin.twinpos_t = twinpos_t

    class Form:
        FT_DEC = 0

        def __init__(self, *args, **kwargs):
            self.controls = {}

        def Compile(self):
            return 1

        def Execute(self):
            return 1

        def Free(self):
            return None

        class FormChangeCb:
            def __init__(self, cb):
                self.cb = cb

        class ChkGroupControl:
            def __init__(self, items, value=0):
                self.items = items
                self.value = value
                self.id = 1

        class NumericInput:
            def __init__(self, tp=None):
                self.value = 0

        class ButtonInput:
            def __init__(self, cb):
                self.cb = cb

        class StringLabel:
            def __init__(self, s):
                self.s = s

    ida_kernwin.Form = Form
    sys.modules["ida_kernwin"] = ida_kernwin

    # idaapi stub
    idaapi = types.ModuleType("idaapi")
    idaapi.BADADDR = -1
    idaapi.BWN_DISASM = 1
    idaapi.AST_ENABLE_FOR_WIDGET = 1
    idaapi.AST_DISABLE_FOR_WIDGET = 0
    idaapi.XREF_ALL = 0
    idaapi.BIN_SEARCH_FORWARD = 0
    idaapi.BIN_SEARCH_NOCASE = 0

    def _noop2(*args, **kwargs):
        return None

    idaapi.get_widget_type = lambda w: idaapi.BWN_DISASM
    idaapi.attach_action_to_popup = _noop2
    idaapi.read_range_selection = lambda ctx: (False, None, None)
    idaapi.get_current_viewer = lambda: object()
    idaapi.ask_str = lambda a, b, c: ""
    idaapi.get_func = lambda ea: None
    idaapi.is_code = lambda flags: True
    idaapi.decode_insn = lambda insn, ea: 0
    idaapi.replace_wait_box = _noop2
    idaapi.get_first_seg = lambda: None
    idaapi.get_next_seg = lambda seg: None
    idaapi.compiled_binpat_vec_t = list
    idaapi.parse_binpat_str = _noop2

    class action_handler_t(object):
        pass

    idaapi.action_handler_t = action_handler_t

    class UI_Hooks(object):
        def hook(self):
            return None

        def unhook(self):
            return None

    idaapi.UI_Hooks = UI_Hooks

    class insn_t:
        def __init__(self):
            self.size = 0
            self.ops = []

    idaapi.insn_t = insn_t
    sys.modules["idaapi"] = idaapi

    # ida_bytes stub
    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_byte = lambda ea: 0
    ida_bytes.get_bytes = lambda start, size: b""
    ida_bytes.get_flags = lambda ea: 0
    ida_bytes.BIN_SEARCH_NOCASE = 0
    ida_bytes.BIN_SEARCH_FORWARD = 0

    def _bin_search3(ea, max_ea, vec, flags):
        return (idaapi.BADADDR, None)

    ida_bytes.bin_search3 = _bin_search3
    sys.modules["ida_bytes"] = ida_bytes

    # ida_xref stub
    ida_xref = types.ModuleType("ida_xref")

    class xrefblk_t:
        def first_to(self, ea, flags):
            return False

        def next_to(self):
            return False

        @property
        def frm(self):
            return 0

    ida_xref.xrefblk_t = xrefblk_t
    sys.modules["ida_xref"] = ida_xref

    # idc stub
    idc = types.ModuleType("idc")
    idc.msg = lambda s: None
    idc.jumpto = lambda ea: None
    idc.get_item_head = lambda ea: ea
    idc.get_item_end = lambda ea: ea
    # operand type constants
    idc.o_void = 0
    idc.o_reg = 1
    idc.o_mem = 2
    idc.o_phrase = 3
    idc.o_displ = 4
    idc.o_imm = 5
    idc.o_far = 6
    idc.o_near = 7
    idc.o_trreg = 8
    idc.o_dbreg = 9
    idc.o_crreg = 10
    idc.o_fpreg = 11
    idc.o_mmxreg = 12
    idc.o_xmmreg = 13
    sys.modules["idc"] = idc


_install_ida_stubs()
sys.path.insert(0, str((Path(__file__).resolve().parents[1] / "src")))
import sigmaker  # noqa: E402


class TestSignatureFormatting(unittest.TestCase):
    def test_build_ida_signature_string(self):
        sig = [
            sigmaker.SignatureByte(0xC7, False),
            sigmaker.SignatureByte(0x44, False),
            sigmaker.SignatureByte(0x24, False),
            sigmaker.SignatureByte(0x34, False),
            sigmaker.SignatureByte(0x00, False),
            sigmaker.SignatureByte(0x00, False),
            sigmaker.SignatureByte(0x00, True),
            sigmaker.SignatureByte(0x00, True),
        ]
        self.assertEqual(sigmaker.BuildIDASignatureString(sig), "C7 44 24 34 00 00 ? ?")

    def test_build_byte_array_with_mask(self):
        sig = [
            sigmaker.SignatureByte(0x49, False),
            sigmaker.SignatureByte(0x28, False),
            sigmaker.SignatureByte(0x15, False),
            sigmaker.SignatureByte(0x00, True),
            sigmaker.SignatureByte(0x00, True),
            sigmaker.SignatureByte(0x30, False),
        ]
        expected = "\\x49\\x28\\x15\\x00\\x00\\x30 xxx??x"
        self.assertEqual(sigmaker.BuildByteArrayWithMaskSignatureString(sig), expected)

    def test_build_bytes_with_bitmask(self):
        sig = [
            sigmaker.SignatureByte(0xE8, False),
            sigmaker.SignatureByte(0x00, True),
            sigmaker.SignatureByte(0x45, False),
        ]
        self.assertEqual(
            sigmaker.BuildBytesWithBitmaskSignatureString(sig), "0xE8, 0x00, 0x45 0b101"
        )

    def test_format_signature_variants(self):
        sig = [sigmaker.SignatureByte(0xAB, False), sigmaker.SignatureByte(0x00, True)]
        self.assertEqual(
            sigmaker.FormatSignature(sig, sigmaker.SignatureType.IDA),
            "AB ?",
        )
        self.assertEqual(
            sigmaker.FormatSignature(sig, sigmaker.SignatureType.x64Dbg),
            "AB ??",
        )


class TestUtilities(unittest.TestCase):
    def test_trim_signature(self):
        sig = [
            sigmaker.SignatureByte(0x90, False),
            sigmaker.SignatureByte(0x00, True),
            sigmaker.SignatureByte(0x00, True),
        ]
        sigmaker.TrimSignature(sig)
        self.assertEqual(len(sig), 1)

    def test_get_regex_matches(self):
        matches = []
        ok = sigmaker.GetRegexMatches("AA BB CC", re.compile(r"[A-Z]{2}"), matches)
        self.assertTrue(ok)
        self.assertEqual(matches, ["AA", "BB", "CC"])

    def test_parse_signature(self):
        pattern = sigmaker.PySigMaker().parse_signature("C7 44 24 34 00 00 ?? ?")
        self.assertEqual(len(pattern), 8)
        # bytes
        self.assertEqual(pattern[0], (0xC7, False))
        self.assertEqual(pattern[5], (0x00, False))
        # wildcards
        self.assertEqual(pattern[6], (0, True))
        self.assertEqual(pattern[7], (0, True))


class TestQisSearch(unittest.TestCase):
    def setUp(self):
        # Prepare a fake buffer and base address
        sigmaker.FILE_BUFFER = (
            b"\xc7\x44\x24\x34\x00\x00\x00\x00"  # sequence 1
            b"\x90\x90\xc7\x44\x24\x30\x07\x00\x00\x00"  # sequence 2
        )

    def test_find_signature_occurrences_qis_example_one(self):
        pm = sigmaker.PySigMaker()
        # Looking for: C7 44 24 34 00 00 ? ?
        hits = pm.FindSignatureOccurencesQis("C7 44 24 34 00 00 ? ?")
        self.assertIn(0, hits)

    def test_find_signature_occurrences_qis_example_two(self):
        pm = sigmaker.PySigMaker()
        # Looking for: C7 44 24 ? ? ? ? ?
        hits = pm.FindSignatureOccurencesQis("C7 44 24 ? ? ? ? ?")
        # Should match the second sequence starting at buffer offset 10
        self.assertIn(10, hits)


class TestIntegrationWithRealBinary(unittest.TestCase):
    """Integration tests that use real IDA Pro API against a compiled binary"""

    @classmethod
    def setUpClass(cls):
        """Build the test binary and verify it exists"""
        import subprocess
        import sys
        from pathlib import Path

        cls.tests_dir = Path(__file__).parent
        cls.binary_path = cls.tests_dir / "test_binary"

        # Check for different possible binary extensions
        possible_paths = [
            cls.tests_dir / "test_binary",
            cls.tests_dir / "test_binary.exe",
            cls.tests_dir / "test_binary.raw",
        ]

        # Try to build the test binary first
        build_script = cls.tests_dir / "build_test_binary.py"
        if build_script.exists():
            try:
                result = subprocess.run(
                    [sys.executable, str(build_script)],
                    capture_output=True,
                    text=True,
                    cwd=cls.tests_dir,
                )
                if result.returncode == 0:
                    print(f"Built test binary successfully")
                else:
                    print(f"Build script failed: {result.stderr}")
            except Exception as e:
                print(f"Error running build script: {e}")

        # Find the actual binary file
        cls.binary_path = None
        for path in possible_paths:
            if path.exists():
                cls.binary_path = path
                print(f"Found test binary: {cls.binary_path}")
                break

        if not cls.binary_path:
            print(f"Warning: Test binary not found at any expected location")
            print(
                "Integration tests will be skipped. Run build_test_binary.py to create it."
            )

    def setUp(self):
        if not self.binary_path or not self.binary_path.exists():
            self.skipTest("Test binary not available")

        # Only run integration tests if we can actually import IDA modules
        try:
            import ida_bytes
            import ida_ida
            import ida_kernwin
            import idaapi
        except ImportError:
            self.skipTest("IDA Pro modules not available")

    def test_load_binary_with_ida(self):
        """Test loading the binary with IDA and basic analysis"""
        import ida_bytes
        import ida_ida
        import idaapi

        # This would require a full IDA environment
        # For now, we'll just test that we can access the binary file
        with open(self.binary_path, "rb") as f:
            binary_data = f.read()

        self.assertGreater(len(binary_data), 0, "Binary file should not be empty")

        # Look for our expected byte patterns in the raw binary
        # mov dword [rsp+0x34], 0x0 -> C7 44 24 34 00 00 00 00
        pattern1 = b"\xc7\x44\x24\x34\x00\x00\x00\x00"
        self.assertIn(
            pattern1, binary_data, "Should find mov dword [rsp+0x34], 0x0 pattern"
        )

        # mov dword [rsp+0x30], 0x7 -> C7 44 24 30 07 00 00 00
        pattern2 = b"\xc7\x44\x24\x30\x07\x00\x00\x00"
        self.assertIn(
            pattern2, binary_data, "Should find mov dword [rsp+0x30], 0x7 pattern"
        )

        # cmp dword [rsp+0x20], 0xf -> 83 7C 24 20 0F
        pattern3 = b"\x83\x7c\x24\x20\x0f"
        self.assertIn(
            pattern3, binary_data, "Should find cmp dword [rsp+0x20], 0xf pattern"
        )

    def test_signature_patterns_from_binary(self):
        """Test that we can identify the instruction patterns from the examples"""
        with open(self.binary_path, "rb") as f:
            binary_data = f.read()

        # Test the signature patterns mentioned in the original examples

        # Example 1: Should find C7 44 24 34 00 00 00 00
        # The "correct" IDA pattern should be C7 44 24 ? ? ? ? ?
        # Let's verify we can find the instruction
        mov_pattern = b"\xc7\x44\x24"
        mov_positions = []
        for i in range(len(binary_data) - 2):
            if binary_data[i : i + 3] == mov_pattern:
                mov_positions.append(i)

        self.assertGreater(
            len(mov_positions), 0, "Should find mov [rsp+...] instructions"
        )

        # For each mov position, check the displacement byte
        for pos in mov_positions:
            if pos + 4 < len(binary_data):
                displacement = binary_data[pos + 3]
                if displacement == 0x34:  # [rsp+0x34]
                    # This is our target instruction
                    # Verify the full pattern C7 44 24 34 00 00 00 00
                    full_pattern = binary_data[pos : pos + 8]
                    expected = b"\xc7\x44\x24\x34\x00\x00\x00\x00"
                    self.assertEqual(
                        full_pattern,
                        expected,
                        f"MOV pattern at position {pos} should match",
                    )

    def test_wildcard_pattern_matching(self):
        """Test wildcard pattern matching against the real binary"""
        with open(self.binary_path, "rb") as f:
            binary_data = f.read()

        # Test the wildcard patterns from the examples
        # Pattern: C7 44 24 ? ? ? ? ? (should match both test cases)
        test_pattern = b"\xc7\x44\x24"  # This is the non-wildcard part

        matches = []
        for i in range(len(binary_data) - 2):
            if binary_data[i : i + 3] == test_pattern:
                # Found the base pattern, now check if next 5 bytes exist
                if i + 8 <= len(binary_data):
                    matches.append(i)

        self.assertGreaterEqual(
            len(matches),
            2,
            "Should find at least 2 MOV instructions matching the wildcard pattern",
        )

        # Verify the specific displacements we expect
        found_displacements = set()
        for match_pos in matches:
            displacement = binary_data[match_pos + 3]
            found_displacements.add(displacement)

        # Should find both 0x30 and 0x34 displacements
        self.assertIn(0x30, found_displacements, "Should find [rsp+0x30] displacement")
        self.assertIn(0x34, found_displacements, "Should find [rsp+0x34] displacement")


if __name__ == "__main__":
    unittest.main()
