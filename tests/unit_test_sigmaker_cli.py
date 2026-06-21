import enum
import io
import json
import pathlib
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


TEST_DIR = pathlib.Path(__file__).parent
SRC_DIR = TEST_DIR.parent / "src"
sys.path.insert(0, SRC_DIR.as_posix())

import sigmaker_cli


def _module(name, **attrs):
    mod = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(mod, key, value)
    return mod


class TestSigMakerCli(unittest.TestCase):
    def _ida_modules(self, *, imagebase=0x1000):
        calls = []

        def open_database(path, run_auto_analysis):
            calls.append(("open_database", path, run_auto_analysis))
            return 0

        def close_database():
            calls.append(("close_database",))

        def auto_wait():
            calls.append(("auto_wait",))

        idapro = _module(
            "idapro",
            open_database=open_database,
            close_database=close_database,
        )
        idaapi = _module(
            "idaapi",
            auto_wait=auto_wait,
            get_imagebase=lambda: imagebase,
        )
        return idapro, idaapi, calls

    def test_search_opens_database_and_formats_batch_results(self):
        idapro, idaapi, calls = self._ida_modules()
        search_calls = []

        class FakeBatchResults:
            error_count = 0

            def __init__(self, input_text, buf):
                self.input_text = input_text
                self.buf = buf

            def format(self, formatter):
                return f"{formatter}:{self.input_text}:{self.buf}\n"

        class FakeBatchSignatureSearcher:
            def __init__(self, input_text):
                self.input_text = input_text

            @classmethod
            def from_text(cls, input_text):
                search_calls.append(("from_text", input_text))
                return cls(input_text)

            def search(self, buf=None):
                search_calls.append(("search", buf))
                return FakeBatchResults(self.input_text, buf)

        class FakeLoadMode:
            SEGMENTS = "segments"

        class FakeInMemoryBuffer:
            LoadMode = FakeLoadMode

            @staticmethod
            def load(mode):
                search_calls.append(("load", mode))
                return "BUF"

        fake_sigmaker = _module(
            "sigmaker",
            SIMD_SPEEDUP_AVAILABLE=True,
            BatchSignatureSearcher=FakeBatchSignatureSearcher,
            InMemoryBuffer=FakeInMemoryBuffer,
        )

        with tempfile.NamedTemporaryFile() as db:
            stdout = io.StringIO()
            with patch.dict(
                sys.modules,
                {"idapro": idapro, "idaapi": idaapi, "sigmaker": fake_sigmaker},
            ), patch("sys.stdout", stdout):
                rc = sigmaker_cli.main(
                    ["search", db.name, "48 8B ?", "--format", "json"]
                )

        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue(), "json:48 8B ?:BUF\n")
        self.assertEqual(
            calls,
            [
                ("open_database", db.name, True),
                ("auto_wait",),
                ("close_database",),
            ],
        )
        self.assertEqual(
            search_calls,
            [
                ("load", "segments"),
                ("from_text", "48 8B ?"),
                ("search", "BUF"),
            ],
        )

    def test_make_generates_json_with_rva_and_file_offset(self):
        idapro, idaapi, calls = self._ida_modules(imagebase=0x1000)
        make_calls = []

        class FakeSignatureType(enum.Enum):
            IDA = "ida"
            x64Dbg = "x64dbg"
            Mask = "mask"
            BitMask = "bitmask"

        class FakeSigMakerConfig:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)
                self.max_single_signature_length = 100
                self.max_xref_signature_length = 250

        class FakeGenerationPolicy:
            @classmethod
            def strict(cls):
                return "strict"

            @classmethod
            def permissive(cls):
                return "permissive"

        class FakeSignature:
            def __format__(self, format_spec):
                return f"signature:{format_spec}"

        class FakeMatch:
            def __init__(self, address, *, rva=None, file_offset=None):
                self.address = address
                self.rva = rva
                self.file_offset = file_offset

            def __int__(self):
                return self.address

            def to_record(self):
                return {
                    "ea": self.address,
                    "rva": self.rva,
                    "file_offset": self.file_offset,
                }

        class FakeGeneratedSignature:
            signature = FakeSignature()
            address = FakeMatch(0x1234)
            status = types.SimpleNamespace(value="unique")
            match_count = 1

        class FakeSignatureMaker:
            def make_signature(self, ea, cfg, end=None, policy=None):
                make_calls.append((ea, cfg.output_format, end, policy))
                return FakeGeneratedSignature()

        class FakeSearchResults:
            @staticmethod
            def current_imagebase():
                return 0x1000

            @staticmethod
            def file_offsets_for_matches(matches):
                return {int(matches[0]): 0x234}

        fake_sigmaker = _module(
            "sigmaker",
            SignatureType=FakeSignatureType,
            SigMakerConfig=FakeSigMakerConfig,
            GenerationPolicy=FakeGenerationPolicy,
            SignatureMaker=FakeSignatureMaker,
            Match=FakeMatch,
            SearchResults=FakeSearchResults,
        )

        with tempfile.NamedTemporaryFile() as db:
            stdout = io.StringIO()
            with patch.dict(
                sys.modules,
                {"idapro": idapro, "idaapi": idaapi, "sigmaker": fake_sigmaker},
            ), patch("sys.stdout", stdout):
                rc = sigmaker_cli.main(
                    [
                        "make",
                        db.name,
                        "0x234",
                        "--rva",
                        "--format",
                        "x64dbg",
                        "--partial-on-cancel",
                        "--json",
                    ]
                )

        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["signature"], "signature:x64dbg")
        self.assertEqual(payload["format"], "x64dbg")
        self.assertEqual(payload["status"], "unique")
        self.assertEqual(payload["match_count"], 1)
        self.assertEqual(payload["address"], {"ea": 0x1234, "rva": 0x234, "file_offset": 0x234})
        self.assertEqual(
            make_calls,
            [(0x1234, FakeSignatureType.x64Dbg, None, "permissive")],
        )
        self.assertEqual(
            calls,
            [
                ("open_database", db.name, True),
                ("auto_wait",),
                ("close_database",),
            ],
        )

    def test_search_exits_nonzero_on_batch_errors_by_default(self):
        idapro, idaapi, _ = self._ida_modules()

        class FakeBatchResults:
            error_count = 1

            def format(self, formatter):
                return "error\n"

        class FakeBatchSignatureSearcher:
            @classmethod
            def from_text(cls, input_text):
                return cls()

            def search(self, buf=None):
                return FakeBatchResults()

        fake_sigmaker = _module(
            "sigmaker",
            SIMD_SPEEDUP_AVAILABLE=False,
            BatchSignatureSearcher=FakeBatchSignatureSearcher,
        )

        with tempfile.NamedTemporaryFile() as db:
            stdout = io.StringIO()
            with patch.dict(
                sys.modules,
                {"idapro": idapro, "idaapi": idaapi, "sigmaker": fake_sigmaker},
            ), patch("sys.stdout", stdout):
                rc = sigmaker_cli.main(["search", db.name, "not-a-signature"])

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "error\n")


if __name__ == "__main__":
    unittest.main()
