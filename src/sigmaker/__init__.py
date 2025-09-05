"""
sigmaker.py - IDA Python Signature Maker
https://github.com/mahmoudimus/ida-sigmaker

by @mahmoudimus (Mahmoud Abdelkader)
"""

from __future__ import annotations

import contextlib
import contextvars
import dataclasses
import enum
import os
import re
import string
import traceback
import typing

import idaapi
import idc

__author__ = "mahmoudimus"
__version__ = "1.4.0"

PLUGIN_NAME: str = "Signature Maker (py)"
PLUGIN_VERSION: str = __version__
PLUGIN_AUTHOR: str = __author__

WILDCARD_POLICY_CTX: contextvars.ContextVar["WildcardPolicy"] = contextvars.ContextVar(
    "wildcard_policy"
)


class Unexpected(Exception):
    """Exception type used throughout the module to indicate unexpected errors."""


def is_address_marked_as_code(ea: int) -> bool:
    """Returns True if the specified address (ea) is marked as code in the disassembled binary."""
    return idaapi.is_code(idaapi.get_flags(ea))


@dataclasses.dataclass
class SigMakerConfig:
    """Configuration for SigMaker operations.

    This class holds all the configuration parameters needed for
    SigMaker operations.
    """

    output_format: SignatureType
    wildcard_operands: bool
    continue_outside_of_function: bool
    wildcard_optimized: bool
    ask_longer_signature: bool = True
    print_top_x: int = 5
    max_single_signature_length: int = 100
    max_xref_signature_length: int = 250


@dataclasses.dataclass(slots=True, frozen=True, repr=False)
class Match:
    """Container for a single match.

    Acts like an int, but provides a more readable representation.
    """

    address: int

    def __repr__(self) -> str:
        return f"Match(address={hex(self.address)})"

    def __str__(self) -> str:
        return hex(self.address)

    def __int__(self) -> int:
        return self.address

    __index__ = __int__


class SignatureType(enum.Enum):
    """Enumeration representing the various supported signature output formats."""

    IDA = "ida"
    x64Dbg = "x64dbg"
    Mask = "mask"
    BitMask = "bitmask"

    @classmethod
    def at(cls, index: int) -> "SignatureType":
        """Return the enum member at a given index (definition order)."""
        return list(cls.__members__.values())[index]


class SignatureByte(typing.NamedTuple):
    """Container representing a single byte in a signature.

    The ``value`` attribute holds the byte value and ``is_wildcard`` indicates
    whether this byte should be treated as a wildcard in comparisons and output.
    """

    value: int
    is_wildcard: bool


class Signature(list[SignatureByte]):
    """
    A data container for a sequence of signature bytes.

    This class is responsible for storing and manipulating the raw data of a
    signature. It does not handle formatting into string representations.
    """

    def add_byte_to_signature(self, address: int, is_wildcard: bool) -> None:
        """Appends a single byte from the IDA database to the signature."""
        byte_value = idaapi.get_byte(address)
        self.append(SignatureByte(byte_value, is_wildcard))

    def add_bytes_to_signature(
        self, address: int, count: int, is_wildcard: bool
    ) -> None:
        """Appends multiple bytes from the IDA database to the signature."""
        # Using get_bytes is more efficient than a loop of get_byte
        bytes_data = idaapi.get_bytes(address, count)
        if bytes_data:
            self.extend(SignatureByte(b, is_wildcard) for b in bytes_data)

    def trim_signature(self) -> None:
        """Removes trailing wildcard bytes from the signature in-place."""
        n = len(self)
        while n > 0 and self[n - 1].is_wildcard:
            n -= 1
        # Efficiently truncate the list
        del self[n:]

    def __str__(self) -> str:
        """
        Provides the default string representation.
        This is equivalent to format(self, '').
        """
        return self.__format__("")

    def __format__(self, format_spec: str) -> str:
        """
        Formats the signature according to the provided format specifier.

        This method allows the Signature object to be used with f-strings
        and the format() built-in function.

        Supported format_spec values:
            - '' (default) or 'ida': "55 8B ? EC"
            - 'x64dbg': "55 8B ?? EC"
            - 'mask': "\\x55\\x8B\\x00\\xEC xx?x"
            - 'bitmask': "0x55, 0x8B, 0x00, 0xEC 0b1101"
        """
        # Use .lower() to make specifiers case-insensitive
        spec = format_spec.lower()
        try:
            formatter = FORMATTER_MAP[SignatureType(spec)]
        except KeyError:
            raise ValueError(
                f"Unknown format code '{format_spec}' for object of type 'Signature'"
            )
        return formatter.format(self)


class SignatureFormatter(typing.Protocol):
    """
    A protocol for objects that can format a Signature into a string.
    """

    def format(self, signature: "Signature") -> str:
        """Formats the given Signature object into a string."""
        ...


@dataclasses.dataclass(frozen=True, slots=True)
class IdaFormatter:
    """
    Formats a signature into the IDA style ('DE AD ? EF').
    The wildcard character can be configured.
    """

    wildcard_byte: str = "?"

    def format(self, signature: "Signature") -> str:
        parts = []
        for byte in signature:
            if byte.is_wildcard:
                parts.append(self.wildcard_byte)
            else:
                parts.append(f"{byte.value:02X}")
        return " ".join(parts)


@dataclasses.dataclass(frozen=True, slots=True)
class X64DbgFormatter(IdaFormatter):
    """
    Formats a signature for x64Dbg by specializing IdaFormatter
    to use '??' as the wildcard.
    """

    wildcard_byte: str = "??"


@dataclasses.dataclass(frozen=True, slots=True)
class MaskedBytesFormatter:
    """Formats into a C-style byte array and a mask string ('\\xDE\\xAD', 'xx?')."""

    wildcard_byte: str = "\\x00"
    mask: str = "x"
    wildcard_mask: str = "?"

    @staticmethod
    def build_signature_parts(
        signature: "Signature",
        byte_format: str,
        wildcard_byte: str,
        mask_char: str,
        wildcard_mask_char: str,
    ) -> tuple[list[str], list[str]]:
        """
        Iterates over a signature and builds lists of its pattern and mask parts.
        This is the common logic shared by multiple masked byte formatters.
        """
        pattern_parts = []
        mask_parts = []
        for byte in signature:
            if byte.is_wildcard:
                pattern_parts.append(wildcard_byte)
                mask_parts.append(wildcard_mask_char)
            else:
                pattern_parts.append(byte_format.format(byte.value))
                mask_parts.append(mask_char)
        return pattern_parts, mask_parts

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = self.build_signature_parts(
            signature,
            "\\x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        return "".join(pattern_parts) + " " + "".join(mask_parts)


@dataclasses.dataclass(frozen=True, slots=True)
class ByteArrayBitmaskFormatter:
    """Formats into a C-style byte array and a bitmask ('0xDE,', '0b1101')."""

    wildcard_byte: str = "0x00"
    mask: str = "1"
    wildcard_mask: str = "0"

    def format(self, signature: "Signature") -> str:
        pattern_parts, mask_parts = MaskedBytesFormatter.build_signature_parts(
            signature,
            "0x{:02X}",
            self.wildcard_byte,
            self.mask,
            self.wildcard_mask,
        )
        pattern_str = ", ".join(pattern_parts)
        mask_str = "".join(mask_parts)[::-1]
        return f"{pattern_str} 0b{mask_str}"


FORMATTER_MAP: typing.Dict[SignatureType, SignatureFormatter] = {
    SignatureType.IDA: IdaFormatter(),
    SignatureType.x64Dbg: X64DbgFormatter(),
    SignatureType.Mask: MaskedBytesFormatter(),
    SignatureType.BitMask: ByteArrayBitmaskFormatter(),
}


@dataclasses.dataclass(slots=True, frozen=True)
class WildcardPolicy:
    """
    Policy for which operand types are wildcardable.
    Stores allowed IDA operand type codes (ints).
    """

    allowed_types: frozenset[int]
    _ctx = WILDCARD_POLICY_CTX

    class RarelyWildcardable(enum.IntEnum):
        VOID = idaapi.o_void
        REG = idaapi.o_reg

    # Base operand types common to all architectures
    class BaseKind(enum.IntEnum):
        MEM = idaapi.o_mem
        PHRASE = idaapi.o_phrase
        DISPL = idaapi.o_displ
        IMM = idaapi.o_imm
        FAR = idaapi.o_far
        NEAR = idaapi.o_near

    # Architecture-specific operand types
    class X86Kind(enum.IntEnum):
        TRREG = idaapi.o_idpspec0  # Trace register
        DBREG = idaapi.o_idpspec1  # Debug register
        CRREG = idaapi.o_idpspec2  # Control register
        FPREG = idaapi.o_idpspec3  # Floating point register
        MMX = idaapi.o_idpspec4  # MMX register
        XMM = idaapi.o_idpspec5  # XMM register
        YMM = idaapi.o_idpspec5 + 1  # YMM register
        ZMM = idaapi.o_idpspec5 + 2  # ZMM register
        KREG = idaapi.o_idpspec5 + 3  # K register (mask)

    class ARMKind(enum.IntEnum):
        REGLIST = idaapi.o_idpspec1  # Register list (LDM/STM)
        CREGLIST = idaapi.o_idpspec2  # Coprocessor register list (CDP)
        CREG = idaapi.o_idpspec3  # Coprocessor register (LDC/STC)
        FPREGLIST = idaapi.o_idpspec4  # Floating point register list
        TEXT = idaapi.o_idpspec5  # Arbitrary text
        COND = idaapi.o_idpspec5 + 1  # ARM condition

    class MIPSKind(enum.IntEnum):
        # MIPS doesn't have specific operand types in the example
        pass

    class PPCKind(enum.IntEnum):
        SPR = idaapi.o_idpspec0  # Special purpose register
        TWOFPR = idaapi.o_idpspec1  # Two FPRs
        SHMBME = idaapi.o_idpspec2  # SH & MB & ME
        CRF = idaapi.o_idpspec3  # CR field
        CRB = idaapi.o_idpspec4  # CR bit
        DCR = idaapi.o_idpspec5  # Device control register

    # Hoisted context manager class
    @dataclasses.dataclass(slots=True)
    class _Use:
        """Context manager to temporarily override current policy."""

        policy: "WildcardPolicy"
        policy_class: type["WildcardPolicy"]
        token: contextvars.Token | None = None

        def __enter__(self):
            self.token = self.policy_class.set_current(self.policy)
            return self.policy

        def __exit__(self, exc_type, exc, tb):
            if self.token is not None:
                self.policy_class.reset_current(self.token)

    # ---- construction helpers ----
    @classmethod
    def for_x86(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.X86Kind))

    @classmethod
    def for_arm(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.ARMKind))

    @classmethod
    def for_mips(cls) -> "WildcardPolicy":
        return cls(frozenset({cls.BaseKind.MEM, cls.BaseKind.FAR, cls.BaseKind.NEAR}))

    @classmethod
    def for_ppc(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind) | frozenset(cls.PPCKind))

    @classmethod
    def default_generic(cls) -> "WildcardPolicy":
        return cls(frozenset(cls.BaseKind))

    @classmethod
    def detect_from_processor(cls) -> "WildcardPolicy":
        arch = idaapi.ph_get_id()
        if arch == idaapi.PLFM_386:
            return cls.for_x86()
        if arch == idaapi.PLFM_ARM:
            return cls.for_arm()
        if arch == idaapi.PLFM_MIPS:
            return cls.for_mips()
        if arch == idaapi.PLFM_PPC:
            return cls.for_ppc()
        return cls.default_generic()

    # ---- queries / adapters ----
    def allows_type(self, op_type: int) -> bool:
        return op_type in self.allowed_types

    def to_mask(self) -> int:
        """Compatibility bitmask: 1 << op.type for each allowed type."""
        return sum(1 << int(t) for t in self.allowed_types)

    @classmethod
    def from_mask(cls, mask: int) -> "WildcardPolicy":
        types = {t for t in range(0, 64) if (mask >> t) & 1}
        return cls(frozenset(types))

    @classmethod
    def current(cls) -> "WildcardPolicy":
        """Get current policy (falling back to arch-detected default)."""
        policy = cls._ctx.get(cls.detect_from_processor())
        cls._ctx.set(policy)
        return policy

    @classmethod
    def set_current(cls, policy: "WildcardPolicy") -> contextvars.Token:
        """Override current policy (returns token for reset)."""
        return cls._ctx.set(policy)

    @classmethod
    def reset_current(cls, token: contextvars.Token) -> None:
        cls._ctx.reset(token)

    @classmethod
    def use(cls, policy: "WildcardPolicy") -> "WildcardPolicy._Use":
        """Context manager to temporarily override current policy.

        Example:
        ```
        with WildcardPolicy.use(WildcardPolicy.for_x86()):
            sig = SignatureMaker().make_signature(anchor_ea, ctx)
            assert any(b.is_wildcard for b in sig.signature)
        ```
        """
        return cls._Use(policy, cls)


@dataclasses.dataclass(slots=True, frozen=True)
class GeneratedSignature:
    """Result container for signature generation operations."""

    signature: Signature
    address: Match | None = None

    def display(self, cfg: SigMakerConfig) -> None:
        """Display the signature result to the user."""
        if not self.signature:
            idaapi.msg("Error: Empty signature\n")
            return
        t = cfg.output_format.value
        fmted = format(self.signature, t)
        if self.address is not None:
            idaapi.msg(f"Signature for {self.address}: {fmted}\n")
        else:
            idaapi.msg(f"Signature: {fmted}\n")

        if not Clipboard.set_text(fmted):
            idaapi.msg("Failed to copy to clipboard!")

    def __lt__(self, other) -> bool:
        if not isinstance(other, GeneratedSignature):
            return NotImplemented
        return len(self.signature) < len(other.signature)


@dataclasses.dataclass(slots=True)
class XrefGeneratedSignature:
    """Result container for XREF signature finding operations."""

    signatures: list[GeneratedSignature]

    def display(self, cfg: SigMakerConfig) -> None:
        """Display the XREF signatures to the user."""
        if not self.signatures:
            idaapi.msg("No XREFs have been found for your address\n")
            return
        t = cfg.output_format.value
        top_length = min(cfg.print_top_x, len(self.signatures))
        idaapi.msg(
            f"Top {top_length} Signatures out of {len(self.signatures)} xrefs:\n"
        )
        for i, generated_signature in enumerate(self.signatures[:top_length], start=1):
            address = generated_signature.address
            signature = generated_signature.signature
            fmted = format(signature, t)
            idaapi.msg(f"XREF Signature #{i} @ {address}: {fmted}\n")
            if i == 0:
                Clipboard.set_text(fmted)


class SigText:
    """Signature normalizer with wildcard support ('?' per nibble)."""

    _HEX_SET = frozenset(string.hexdigits)
    _TRANS = str.maketrans(
        {
            ",": " ",
            ";": " ",
            ":": " ",
            "|": " ",
            "_": " ",
            "-": " ",
            "\t": " ",
            "\n": " ",
            "\r": " ",
            ".": "?",  # '.' → '?' (optional)
        }
    )

    @staticmethod
    def _tok_is_hex(s: str) -> bool:
        return len(s) > 0 and all(c in SigText._HEX_SET for c in s)

    @staticmethod
    def _split_hex_pairs(s: str) -> list[str]:
        # Split an even-length pure-hex string into HH pairs
        return [s[i : i + 2].upper() for i in range(0, len(s), 2)]

    @staticmethod
    def normalize(sig_str: str) -> tuple[str, list[tuple[int, bool]]]:
        if not sig_str:
            return "", []
        # 1) normalize separators -> spaces; remove 0x prefixes token-wise
        s = sig_str.translate(SigText._TRANS)
        raw = [t for t in s.split() if t]
        toks: list[str] = []
        for t in raw:
            t = t.strip()
            if t.startswith(("0x", "0X")):
                t = t[2:]
            if not t:
                continue
            toks.append(t)

        out: list[str] = []
        i = 0
        while i < len(toks):
            t = toks[i]

            # Fast path: canonical tokens we already accept
            if t == "??":
                out.append("??")
                i += 1
                continue

            if len(t) == 2 and SigText._tok_is_hex(t):
                out.append(t.upper())
                i += 1
                continue

            # Single hex nibble -> 'H?'
            if len(t) == 1 and t in SigText._HEX_SET:
                out.append((t + "?").upper())
                i += 1
                continue

            # Single '?'
            if t == "?":
                out.append("??")
                i += 1
                continue

            # Long pure-hex strings (must be even length)
            if SigText._tok_is_hex(t):
                if (len(t) & 1) != 0:
                    # odd-length => split into pairs and pad last nibble with '?' as high nibble
                    pairs = SigText._split_hex_pairs(t)
                    pairs_len = len(pairs)
                    # Last pair will be single character, make it '?X'
                    if pairs and len(pairs[pairs_len - 1]) == 1:
                        pairs[pairs_len - 1] = "?" + pairs[pairs_len - 1]
                    out.extend(pairs)
                    i += 1
                    continue
                else:
                    out.extend(SigText._split_hex_pairs(t))
                    i += 1
                    continue

            # Mixed 2-char forms with nibble wildcards: '?F', 'F?', '??'
            if len(t) == 2:
                hi, lo = t[0], t[1]
                if (hi in SigText._HEX_SET or hi == "?") and (
                    lo in SigText._HEX_SET or lo == "?"
                ):
                    out.append((hi + lo).upper())
                    i += 1
                    continue

            # Unrecognized token format
            raise ValueError(f"invalid signature token: {t!r}")

        # Build (value, wildcard) list
        pattern: list[tuple[int, bool]] = []
        for tok in out:
            hi, lo = tok[0], tok[1]
            wild = (hi == "?") or (lo == "?")
            hv = 0 if hi == "?" else int(hi, 16)
            lv = 0 if lo == "?" else int(lo, 16)
            pattern.append(((hv << 4) | lv, wild))

        return " ".join(out), pattern


class OperandProcessor:
    """Handles operand processing for signature generation (policy-driven).
    # TODO: refactor this to support more architectures, not just ARM/X64.
    """

    def __init__(self):
        self._is_arm = self._check_is_arm()

    @staticmethod
    def _check_is_arm() -> bool:
        return idaapi.ph_get_id() == idaapi.PLFM_ARM

    def _get_operand_offset_arm(
        self, ins: idaapi.insn_t, off: typing.List[int], length: typing.List[int]
    ) -> bool:
        policy = WildcardPolicy.current()
        for op in ins:
            if op.type in policy.allowed_types:
                off[0] = op.offb
                length[0] = 3 if ins.size == 4 else (7 if ins.size == 8 else 0)
                return True
        return False

    def get_operand(
        self,
        ins: idaapi.insn_t,
        off: typing.List[int],
        length: typing.List[int],
        wildcard_optimized: bool,
    ) -> bool:
        policy = WildcardPolicy.current()
        if self._is_arm:
            return self._get_operand_offset_arm(ins, off, length)
        for op in ins:
            if op.type == idaapi.o_void:
                continue
            if not policy.allows_type(op.type):
                continue
            if op.offb == 0 and not wildcard_optimized:
                continue
            off[0] = op.offb
            length[0] = ins.size - op.offb
            return True
        return False


class InstructionProcessor:
    """Processes a single instruction to append its bytes to a signature."""

    def __init__(self, operand_processor: OperandProcessor):
        self.operand_processor = operand_processor

    def append_instruction_to_sig(
        self,
        sig: Signature,
        ea: int,
        ins: idaapi.insn_t,
        wildcard_operands: bool,
        wildcard_optimized: bool,
    ) -> None:
        """
        Appends instruction bytes to the signature, optionally wildcarding operands.
        """
        if not wildcard_operands:
            # Default case: add the whole instruction as-is
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        off, length = [0], [0]
        has_operand = self.operand_processor.get_operand(
            ins, off, length, wildcard_optimized
        )
        if not has_operand or length[0] <= 0:
            sig.add_bytes_to_signature(ea, ins.size, is_wildcard=False)
            return

        # Add bytes before the operand
        if off[0] > 0:
            sig.add_bytes_to_signature(ea, off[0], is_wildcard=False)

        # Add the operand as a wildcard
        sig.add_bytes_to_signature(ea + off[0], length[0], is_wildcard=True)

        # Add bytes after the operand
        remaining_len = ins.size - (off[0] + length[0])
        if remaining_len > 0:
            sig.add_bytes_to_signature(
                ea + off[0] + length[0], remaining_len, is_wildcard=False
            )


@dataclasses.dataclass(slots=True)
class InstructionWalker:
    """
    A stateful iterator for walking instructions within a given address range.

    This class encapsulates the logic of decoding instructions and tracks the
    current address (cursor), which remains available for inspection after
    the iteration is complete.
    """

    start_ea: int
    end_ea: int = idaapi.BADADDR

    # Internal state fields
    cursor: int = dataclasses.field(init=False)
    _instruction: idaapi.insn_t = dataclasses.field(
        init=False, repr=False, default_factory=idaapi.insn_t
    )

    def __post_init__(self):
        if self.start_ea == idaapi.BADADDR:
            raise ValueError("Invalid start address for InstructionWalker")
        # Initialize the cursor to the starting address
        self.cursor = self.start_ea

    def __iter__(self):
        # Reset cursor to allow for re-iteration if needed
        self.cursor = self.start_ea
        return self

    def __next__(self) -> tuple[int, idaapi.insn_t, int]:
        """Decodes and returns the next instruction, advancing the cursor."""
        if self.end_ea != idaapi.BADADDR and self.cursor >= self.end_ea:
            raise StopIteration

        if idaapi.user_cancelled():
            raise StopIteration("Aborted by user")

        current_instruction_ea = self.cursor
        ins_len = idaapi.decode_insn(self._instruction, current_instruction_ea)

        if ins_len <= 0:
            raise StopIteration

        self.cursor += ins_len

        return current_instruction_ea, self._instruction, ins_len


class UniqueSignatureGenerator:
    """Strategy for generating a signature that is guaranteed to be unique."""

    def __init__(self, processor: InstructionProcessor):
        self.processor = processor

    def generate(self, ea: int, cfg: SigMakerConfig) -> Signature:
        if not is_address_marked_as_code(ea):
            raise Unexpected("Cannot create code signature for data")

        sig = Signature()
        start_fn = idaapi.get_func(ea)
        bytes_since_last_check = 0

        for cur_ea, ins, ins_len in InstructionWalker(ea):
            # Check length constraint
            if bytes_since_last_check > cfg.max_single_signature_length:
                if (
                    not cfg.ask_longer_signature
                    or idaapi.ask_yn(
                        idaapi.ASKBTN_NO,
                        f"Signature is already {len(sig)} bytes. Continue?",
                    )
                    != idaapi.ASKBTN_YES
                ):
                    raise Unexpected("Signature not unique within length constraints")
                bytes_since_last_check = 0  # Reset counter after user confirmation

            # Check function boundary constraint
            if (
                not cfg.continue_outside_of_function
                and start_fn
                and cur_ea >= start_fn.end_ea
            ):
                raise Unexpected("Signature left function scope without being unique")

            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )
            bytes_since_last_check += ins_len

            if SignatureSearcher.is_unique(f"{sig:ida}"):
                sig.trim_signature()
                return sig

        raise Unexpected("Signature not unique (reached end of analysis)")


class RangeSignatureGenerator:
    """Strategy for generating a signature for a fixed address range."""

    def __init__(self, processor: InstructionProcessor):
        self.processor = processor

    def generate(self, start_ea: int, end_ea: int, cfg: SigMakerConfig) -> Signature:
        sig = Signature()

        # Handle pure data ranges
        if not is_address_marked_as_code(start_ea):
            sig.add_bytes_to_signature(start_ea, end_ea - start_ea, is_wildcard=False)
            return sig

        # Iterate through instructions within the range
        walker = InstructionWalker(start_ea, end_ea)
        for cur_ea, ins, _ in walker:
            self.processor.append_instruction_to_sig(
                sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
            )

        # Add any remaining bytes if the last instruction was partially in range
        # or if the range ended in a data block.
        if walker.cursor < end_ea:
            remaining_bytes = end_ea - walker.cursor
            sig.add_bytes_to_signature(
                walker.cursor, remaining_bytes, is_wildcard=False
            )

        sig.trim_signature()
        return sig


@dataclasses.dataclass(slots=True)
class SignatureMaker:
    """
    Generates unique or range-based signatures.
    """

    _operand_processor: OperandProcessor = dataclasses.field(
        default_factory=OperandProcessor
    )

    # Internal components built from dependencies
    _instruction_processor: InstructionProcessor = dataclasses.field(init=False)
    _unique_generator: UniqueSignatureGenerator = dataclasses.field(init=False)
    _range_generator: RangeSignatureGenerator = dataclasses.field(init=False)

    def __post_init__(self):
        """Initialize internal components after the main object is created."""
        self._instruction_processor = InstructionProcessor(self._operand_processor)
        self._unique_generator = UniqueSignatureGenerator(self._instruction_processor)
        self._range_generator = RangeSignatureGenerator(self._instruction_processor)

    def make_signature(
        self, ea: int | Match, cfg: SigMakerConfig, end: int | None = None
    ) -> GeneratedSignature:
        """
        Creates a signature for a single address (unique) or an address range.
        """
        start_ea = int(ea)
        if start_ea == idaapi.BADADDR:
            raise Unexpected("Invalid start address")

        if end is None:
            # Delegate to the unique signature generation strategy
            sig = self._unique_generator.generate(start_ea, cfg)
            return GeneratedSignature(sig, Match(start_ea))

        if end <= start_ea:
            raise Unexpected("End address must be after start address")

        # Delegate to the range signature generation strategy
        sig = self._range_generator.generate(start_ea, end, cfg)
        return GeneratedSignature(sig)


class XrefFinder:
    """Handles finding and generating signatures for XREF addresses."""

    def __init__(self):
        self.progress_dialog = ProgressDialog()
        self.signature_maker = SignatureMaker()

    @classmethod
    def iter_code_xrefs_to(cls, ea: int) -> typing.Iterable[int]:
        """Yield code xref sources (xb.frm) that point *to* 'ea'."""
        xb = idaapi.xrefblk_t()
        if not xb.first_to(ea, idaapi.XREF_ALL):
            return

        while True:
            if is_address_marked_as_code(xb.frm):
                yield xb.frm
            if not xb.next_to():
                break

    @classmethod
    def count_code_xrefs_to(cls, ea: int) -> int:
        """Count code xrefs to 'ea' without duplicating traversal logic."""
        return sum(1 for _ in cls.iter_code_xrefs_to(ea))

    def find_xrefs(self, ea: int, cfg: SigMakerConfig) -> XrefGeneratedSignature:
        """Find XREF signatures to a given address."""
        xref_signatures: list[GeneratedSignature] = []

        total = self.count_code_xrefs_to(ea)
        if total == 0:
            return XrefGeneratedSignature([])

        # Non-interactive during xref search
        cfg_no_prompt = dataclasses.replace(cfg, ask_longer_signature=False)

        shortest_len = cfg.max_xref_signature_length + 1

        for i, frm_ea in enumerate(self.iter_code_xrefs_to(ea), start=1):
            if self.progress_dialog.user_canceled():
                break

            self.progress_dialog.replace_message(
                f"Processing xref {i} of {total} ({(i / total) * 100.0:.1f}%)...\n\n"
                f"Suitable Signatures: {len(xref_signatures)}\n"
                f"Shortest Signature: {shortest_len if shortest_len <= cfg.max_xref_signature_length else 0} Bytes"
            )

            try:
                # Public API: returns SignatureResult
                result = self.signature_maker.make_signature(frm_ea, cfg_no_prompt)
                sig: typing.Optional[Signature] = result.signature
            except Exception:
                sig = None

            if sig is None:
                continue

            if len(sig) < shortest_len:
                shortest_len = len(sig)
            xref_signatures.append(GeneratedSignature(sig, Match(frm_ea)))

        xref_signatures.sort()
        return XrefGeneratedSignature(xref_signatures)


@dataclasses.dataclass(slots=True)
class SearchResults:
    """Result container for signature search operations."""

    matches: list[Match]
    signature_str: str

    def display(self) -> None:
        """Display the search results to the user."""
        idaapi.msg(f"Signature: {self.signature_str}\n")

        if not self.matches:
            idaapi.msg("Signature does not match!\n")
            return

        for ea in self.matches:
            fn_name = None
            with contextlib.suppress(BaseException):
                fn_name = idaapi.get_func_name(int(ea))
            if fn_name:
                idaapi.msg(f"Match @ {ea} in {fn_name}\n")
            else:
                idaapi.msg(f"Match @ {ea}\n")


class SignatureParser:
    """Centralized, readable parsing for various signature input styles.

    Supported inputs (examples):
      - Mask notation:   bytes + mask string like "xxxx?x" or binary mask "0b10101"
      - Hex escapes:     "\x48\x8b\x05 ..."
      - 0x-prefixed run: "0x48 0x8B 0x05 ..." or "0x488B05..."
      - Loose hex:       "48 8B 05 ? ? 00"

    Output is an IDA-style signature string (space-separated; '?' for wildcards),
    or an empty string on failure.
    """

    _HEX_PAIR = re.compile(r"^[0-9A-Fa-f]{2}$")
    _ESCAPED_HEX = re.compile(r"\\x[0-9A-Fa-f]{2}")
    _RUN_0X = re.compile(r"(?:0x[0-9A-Fa-f]{2})+")

    # Regex to match a mask string consisting of 'x' and '?' characters, starting with 'x'
    _MASK_REGEX = re.compile(r"x(?:x|\?)+")
    # Regex to match a binary mask string, e.g., '0b10101'
    _BINARY_MASK_REGEX = re.compile(r"0b[01]+")

    @classmethod
    def parse(cls, input_str: str) -> str:
        mask = cls._extract_mask(input_str)
        parsed = ""
        if mask:
            # Try to pair mask with bytes from either escaped form or 0x run
            bytestr: list[str] = []
            if (bytestr := cls._ESCAPED_HEX.findall(input_str)) and len(bytestr) == len(
                mask
            ):
                parsed = cls._masked_bytes_to_ida(bytestr, mask, slice_from=2)

            elif (bytestr := cls._RUN_0X.findall(input_str)) and len(bytestr) == len(
                mask
            ):
                parsed = cls._masked_bytes_to_ida(bytestr, mask, slice_from=2)
            else:
                idaapi.msg(
                    f'Detected mask "{mask}" but failed to match corresponding bytes\n'
                )
        else:
            # Fallback: normalize a loose byte string into IDA format
            parsed = cls._normalize_loose_hex(input_str)
        return parsed.strip()

    # ---- internals ----

    @classmethod
    def _extract_mask(cls, s: str) -> str:
        """Extract mask from patterns like 'xxx?x' or binary '0b10101'."""

        m = cls._MASK_REGEX.search(s)
        if m:
            return m.group(0)

        m = cls._BINARY_MASK_REGEX.search(s)
        if not m:
            return ""
        bits = m.group(0)[2:]
        # Binary mask is LSB-first in original code; reverse to align with bytes
        return "".join("x" if b == "1" else "?" for b in bits[::-1])

    @staticmethod
    def _masked_bytes_to_ida(
        byte_tokens: list[str], mask: str, *, slice_from: int
    ) -> str:
        sig = Signature(
            [
                SignatureByte(int(tok[slice_from:], 16), mask[i] == "?")
                for i, tok in enumerate(byte_tokens)
            ]
        )
        return f"{sig:ida}"

    @classmethod
    def _normalize_loose_hex(cls, input_str: str) -> str:
        """Best-effort cleanup into 'AA BB CC ? DD ' format expected by downstream."""
        s = input_str
        s = re.sub(r"[\)\(\[\]]+", "", s)  # strip brackets
        s = re.sub(r"^\s+", "", s)  # lstrip
        s = re.sub(r"[? ]+$", "", s) + " "  # ensure trailing space
        s = re.sub(r"\\?\\x", "", s)  # drop any stray \x or escaped \x
        s = re.sub(r"\s+", " ", s)  # collapse whitespace

        # Also coerce any '??' or '?' tokens into a single '?' and ensure hex pairs are normalized
        tokens = [t.strip() for t in s.split() if t.strip()]
        out: list[str] = []
        for t in tokens:
            if t == "?" or t == "??":
                out.append("?")
                continue
            # accept '0xAA' or 'AA'; normalize to two hex chars upper
            if t.lower().startswith("0x"):
                t = t[2:]
            if not cls._HEX_PAIR.match(t):
                # If it's not a hex pair, treat as wildcard to be safe
                out.append("?")
                continue
            out.append(t.upper())

        return (" ".join(out) + " ") if out else ""


@dataclasses.dataclass(slots=True)
class SignatureSearcher:
    """Parses a signature string and searches the DB for matches."""

    input_signature: str = ""

    @classmethod
    def from_signature(cls, input_signature: str) -> "SignatureSearcher":
        return cls(input_signature=input_signature)

    def search(self) -> SearchResults:
        sig_str = SignatureParser.parse(self.input_signature)
        if not sig_str:
            idaapi.msg("Unrecognized signature type\n")
            return SearchResults([], "")
        matches = self.find_all(sig_str)
        return SearchResults(matches, sig_str)

    @staticmethod
    def find_all(ida_signature: str) -> list[Match]:
        binary = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binary, idaapi.inf_get_min_ea(), ida_signature, 16)
        out: list[Match] = []
        ea = idaapi.inf_get_min_ea()
        _bin_search = getattr(idaapi, "bin_search", None) or getattr(
            idaapi, "bin_search3"
        )
        while True:
            hit, _ = _bin_search(
                ea,
                idaapi.inf_get_max_ea(),
                binary,
                idaapi.BIN_SEARCH_NOCASE | idaapi.BIN_SEARCH_FORWARD,
            )
            if hit == idaapi.BADADDR:
                break
            out.append(Match(hit))
            ea = hit + 1
        return out

    @classmethod
    def is_unique(cls, ida_signature: str) -> bool:
        return len(cls.find_all(ida_signature)) == 1


# no cover: start
# we do not cover the below because this is mainly executing IDA GUI functionality.
# any logic here should be pulled out into a separate class and tested separately.
class ProgressDialog:
    """Context manager wrapping IDA wait boxes.

    When used as a context manager the progress dialog will display a wait box
    on entry and hide it on exit.

    The message may be updated via `replace_message()` and cancelation can be tested with `user_canceled()` from this class or `idaapi.user_cancelled()` from IDA API.
    """

    def __init__(self, message: str = "Please wait...", hide_cancel: bool = False):
        self._default_msg: str = message
        self.hide_cancel: bool = hide_cancel

    def _message(
        self,
        message: typing.Optional[str] = None,
        hide_cancel: typing.Optional[bool] = None,
    ) -> str:
        """Internal helper to assemble the full wait box message string."""
        display_msg = self._default_msg if message is None else message
        hide = self.hide_cancel if hide_cancel is None else hide_cancel
        prefix = "HIDECANCEL\n" if hide else ""
        return prefix + display_msg

    def configure(
        self, message: str = "Please wait...", hide_cancel: bool = False
    ) -> "ProgressDialog":
        """Configure the default message and cancel button visibility."""
        self._default_msg = message
        self.hide_cancel = hide_cancel
        return self

    __call__ = configure  # Allow calling instance to reconfigure.

    def __enter__(self) -> "ProgressDialog":
        idaapi.show_wait_box(self._message())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        idaapi.hide_wait_box()

    def replace_message(self, new_message: str, hide_cancel: bool = False) -> None:
        """Replace the currently displayed message."""
        msg = self._message(message=new_message, hide_cancel=hide_cancel)
        idaapi.replace_wait_box(msg)

    def user_canceled(self) -> bool:
        """Return True if the user has canceled the wait box."""
        return idaapi.user_cancelled()

    # Provide alias with alternative spelling for backwards compatibility.
    user_cancelled = user_canceled


class Clipboard:
    """Cross platform utilities for setting text on the system clipboard."""

    @staticmethod
    def _set_text_pyqt5(text: str) -> bool:
        """Set clipboard text via PyQt5 if available."""
        try:
            from PyQt5.QtWidgets import QApplication  # type: ignore

            QApplication.clipboard().setText(text)
            return True
        except (ImportError, Exception) as e:
            idaapi.msg(f"Error setting clipboard text: {e}")
            return False

    @classmethod
    def set_text(cls, text: str) -> bool:
        """Set the clipboard text on the current operating system.

        This method first attempts to use PyQt5 for cross-platform clipboard
        support and falls back to platform specific implementations.

        Parameters
        ----------
        text : str
            The text to place on the clipboard.

        Returns
        -------
        bool
            True on success, False on failure.
        """
        return cls._set_text_pyqt5(text)

    def __call__(self, text: str) -> bool:
        """Allow instances to be invoked directly as a function."""
        return self.set_text(text)


class ConfigureOperandWildcardBitmaskForm(idaapi.Form):
    """Interactive form to configure wildcardable operands using checkboxes."""

    def __init__(self) -> None:
        F = idaapi.Form
        # Define the form layout
        form_text = """BUTTON YES* OK
BUTTON CANCEL Cancel
Wildcardable Operands
{FormChangeCb}
Select operand types that should be wildcarded:

<General Register (al, ax, es, ds...):{opt1}>
<Direct Memory Reference (DATA) :{opt2}>
<Memory Ref [Base Reg + Index Reg] :{opt3}>
<Memory Ref [Base Reg + Index Reg + Displacement] :{opt4}>
<Immediate Value :{opt5}>
<Immediate Far Address (CODE) :{opt6}>
<Immediate Near Address (CODE) :{opt7}>"""
        registers: typing.List[str] = [
            "opt1",
            "opt2",
            "opt3",
            "opt4",
            "opt5",
            "opt6",
            "opt7",
        ]

        # Processor-specific operand types
        proc_arch = idaapi.ph_get_id()
        if proc_arch == idaapi.PLFM_386:
            form_text += """
<Trace Register :{opt8}>
<Debug Register :{opt9}>
<Control Register :{opt10}>
<Floating Point Register :{opt11}>
<MMX Register :{opt12}>
<XMM Register :{opt13}>
<YMM Register :{opt14}>
<ZMM Register :{opt15}>
<Opmask Register :{opt16}>{cWildcardableOperands}>"""
            registers.extend(
                [
                    "opt8",
                    "opt9",
                    "opt10",
                    "opt11",
                    "opt12",
                    "opt13",
                    "opt14",
                    "opt15",
                    "opt16",
                ]
            )
        elif proc_arch == idaapi.PLFM_ARM:
            form_text += """
<(Unused) :{opt8}>
<Register list (for LDM/STM) :{opt9}>
<Coprocessor register list (for CDP) :{opt10}>
<Coprocessor register (for LDC/STC) :{opt11}>
<Floating point register list :{opt12}>
<Arbitrary text stored in the operand :{opt13}>
<ARM condition as an operand :{opt14}>{cWildcardableOperands}>"""
            registers.extend(
                ["opt8", "opt9", "opt10", "opt11", "opt12", "opt13", "opt14"]
            )
        elif proc_arch == idaapi.PLFM_PPC:
            form_text += """
<Special purpose register :{opt8}>
<Two FPRs :{opt9}>
<SH & MB & ME :{opt10}>
<crfield :{opt11}>
<crbit :{opt12}>
<Device control register :{opt13}>{cWildcardableOperands}>"""
            registers.extend(["opt8", "opt9", "opt10", "opt11", "opt12", "opt13"])
        else:
            form_text += """{cWildcardableOperands}>
"""
        # Skip o_void visually (>>1) by shifting the bitmask
        options = WildcardPolicy.current().to_mask() >> 1

        controls = {
            "FormChangeCb": F.FormChangeCb(self.OnFormChange),
            "cWildcardableOperands": F.ChkGroupControl(
                tuple(registers),
                value=options,
            ),
        }
        super().__init__(form_text, controls)

    def OnFormChange(self, fid: int) -> int:
        """Callback invoked when the form state changes."""
        if fid == self.cWildcardableOperands.id:  # type: ignore
            # re-shift b/c we skipped o_void
            mask = self.GetControlValue(self.cWildcardableOperands) << 1  # type: ignore
            WildcardPolicy.set_current(WildcardPolicy.from_mask(mask))
        return 1


class ConfigureOptionsForm(idaapi.Form):
    """Interactive form to configure XREF and signature generation options."""

    def __init__(self) -> None:
        F = idaapi.Form

        # Define the form layout
        form_text = """BUTTON YES* OK
BUTTON CANCEL Cancel
Options

<#Print top X shortest signatures when generating xref signatures#Print top X XREF signatures     :{opt1}>
<#Stop after reaching X bytes when generating a single signature#Maximum single signature length :{opt2}>
<#Stop after reaching X bytes when generating xref signatures#Maximum xref signature length   :{opt3}>
"""

        self.controls = {
            "opt1": F.NumericInput(tp=F.FT_DEC),
            "opt2": F.NumericInput(tp=F.FT_DEC),
            "opt3": F.NumericInput(tp=F.FT_DEC),
        }
        super().__init__(form_text, self.controls)

    def ExecuteForm(self) -> int:
        """Execute the form and apply changes to global variables."""

        # Pre-fill form values
        self.controls["opt1"].value = SigMakerConfig.print_top_x
        self.controls["opt2"].value = SigMakerConfig.max_single_signature_length
        self.controls["opt3"].value = SigMakerConfig.max_xref_signature_length

        result = self.Execute()
        if result != 1:
            self.Free()
            return result

        SigMakerConfig.print_top_x = self.controls["opt1"].value
        SigMakerConfig.max_single_signature_length = self.controls["opt2"].value
        SigMakerConfig.max_xref_signature_length = self.controls["opt3"].value
        self.Free()
        return result


class SignatureMakerForm(idaapi.Form):
    """Main form presented when the user invokes the SigMaker plugin."""

    def __init__(self) -> None:
        F = idaapi.Form
        form_text = (
            f"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Signature Maker v{PLUGIN_VERSION}"""
            + r"""
{FormChangeCb}
Select action:
<#Select an address, and create a code signature for it#Create unique signature for current code address:{rCreateUniqueSig}>
<#Select an address or variable, and create code signatures for its references. Will output the shortest 5 signatures#Find shortest XREF signature for current data or code address:{rFindXRefSig}>
<#Select 1+ instructions, and copy the bytes using the specified output format#Copy selected code:{rCopyCode}>
<#Paste any string containing your signature/mask and find matches#Search for a signature:{rSearchSignature}>{rAction}>

Output format:
<#Example - E8 ? ? ? ? 45 33 F6 66 44 89 34 33#IDA Signature:{rIDASig}>
<#Example - E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33#x64Dbg Signature:{rx64DbgSig}>
<#Example - \\\xE8\\\x00\\\x00\\\x00\\\x00\\\x45\\\x33\\\xF6\\\x66\\\x44\\\x89\\\x34\\\x33 x????xxxxxxxx#C Byte Array String Signature + String mask:{rByteArrayMaskSig}>
<#Example - 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33 0b1111111100001#C Bytes Signature + Bitmask:{rRawBytesBitmaskSig}>{rOutputFormat}>

Quick Options:
<#Enable wildcarding for operands, to improve stability of created signatures#Wildcards for operands:{cWildcardOperands}>
<#Don't stop signature generation when reaching end of function#Continue when leaving function scope:{cContinueOutside}>
<#Wildcard the whole instruction when the operand (usually a register) is encoded into the operator#Wildcard optimized / combined instructions:{cWildcardOptimized}>{cGroupOptions}>

<Operand types...:{bOperandTypes}><Other options...:{bOtherOptions}>
"""
        )
        controls = {
            "cVersion": F.StringLabel(PLUGIN_VERSION),
            "FormChangeCb": F.FormChangeCb(self.OnFormChange),
            "rAction": F.RadGroupControl(
                ("rCreateUniqueSig", "rFindXRefSig", "rCopyCode", "rSearchSignature")
            ),
            "rOutputFormat": F.RadGroupControl(
                ("rIDASig", "rx64DbgSig", "rByteArrayMaskSig", "rRawBytesBitmaskSig")
            ),
            "cGroupOptions": idaapi.Form.ChkGroupControl(
                ("cWildcardOperands", "cContinueOutside", "cWildcardOptimized"),
                value=5,
            ),
            "bOperandTypes": F.ButtonInput(self.ConfigureOperandWildcardBitmask),
            "bOtherOptions": F.ButtonInput(self.ConfigureOptions),
        }
        super().__init__(form_text, controls)

    def OnFormChange(self, fid: int) -> int:
        """Optional form change handler; currently unused."""
        return 1

    def ConfigureOperandWildcardBitmask(self, code: int = 0) -> int:
        form = ConfigureOperandWildcardBitmaskForm()
        form.Compile()
        ok = form.Execute()
        if not ok:
            return 0
        return 1

    def ConfigureOptions(self, code: int = 0) -> int:
        """Launch the options configuration form."""
        form = ConfigureOptionsForm()
        form.Compile()
        return form.ExecuteForm()

    def __enter__(self) -> "SignatureMakerForm":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.Free()


class _ActionHandler(idaapi.action_handler_t):
    """Internal helper bridging IDA UI actions to plugin methods."""

    def __init__(self, action_function):
        super().__init__()
        self.action_function = action_function

    def activate(self, ctx: idaapi.action_ctx_base_t) -> int:
        self.action_function(ctx=ctx)
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t) -> int:
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class _PopupHook(idaapi.UI_Hooks):
    """Hook used to attach actions to IDA pop-ups."""

    def __init__(
        self,
        action_name: str,
        predicate=None,
        widget_populator=None,
        category: typing.Optional[str] = None,
    ) -> None:
        super().__init__()
        self.action_name = action_name
        self.predicate = predicate or self.is_disassembly_widget
        self.widget_populator = widget_populator or self._default_populator
        self.category = category

    @classmethod
    def is_disassembly_widget(cls, widget, popup, ctx) -> bool:
        """Return True if the given widget is a disassembly view."""
        return idaapi.get_widget_type(widget) == idaapi.BWN_DISASM

    def term(self) -> None:
        idaapi.unregister_action(self.action_name)

    @staticmethod
    def _default_populator(instance, widget, popup_handle, ctx) -> None:
        if instance.predicate(widget, popup_handle, ctx):
            args = [widget, popup_handle, instance.action_name]
            if instance.category:
                args.append(f"{instance.category}/")
            idaapi.attach_action_to_popup(*args)

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None) -> None:
        return self.widget_populator(self, widget, popup_handle, ctx)


class SigMakerPlugin(idaapi.plugin_t):
    """IDA Pro plugin class implementing signature generation and search."""

    flags = idaapi.PLUGIN_KEEP
    comment = f"{PLUGIN_NAME} v{PLUGIN_VERSION} for IDA Pro by {PLUGIN_AUTHOR}"
    help = "Select location in disassembly and press CTRL+ALT+S to open menu"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-S"

    ACTION_SHOW_SIGMAKER: str = "pysigmaker:show"

    def init(self) -> int:
        self._hooks = self._init_hooks(_PopupHook(self.ACTION_SHOW_SIGMAKER))
        self._register_actions()
        return idaapi.PLUGIN_KEEP

    def _init_hooks(self, *hooks) -> typing.Tuple[idaapi.UI_Hooks, ...]:
        for hook in hooks:
            hook.hook()
        return hooks

    def _deinit_hooks(self, *hooks) -> None:
        for hook in hooks:
            hook.unhook()

    def _register_actions(self) -> None:
        self._deregister_actions()
        idaapi.register_action(
            idaapi.action_desc_t(
                self.ACTION_SHOW_SIGMAKER,
                "SigMaker",
                _ActionHandler(self.run),
                self.wanted_hotkey,
                "Show the signature maker dialog.",
                154,
            )
        )

    def _deregister_actions(self) -> None:
        idaapi.unregister_action(self.ACTION_SHOW_SIGMAKER)

    def run(self, ctx) -> None:
        """Entry point called when the user activates the plugin."""
        with SignatureMakerForm() as form:
            form.Compile()
            ok = form.Execute()
            if not ok:
                return

            action = form.rAction.value  # type: ignore
            output_format = form.rOutputFormat.value  # type: ignore
            wildcard_operands = bool(form.cGroupOptions.value & 1)  # type: ignore
            continue_outside_of_function = bool(form.cGroupOptions.value & 2)  # type: ignore
            wildcard_optimized = bool(form.cGroupOptions.value & 4)  # type: ignore

        # Create SigMakerConfig
        config = SigMakerConfig(
            output_format=SignatureType.at(int(output_format)),
            wildcard_operands=wildcard_operands,
            continue_outside_of_function=continue_outside_of_function,
            wildcard_optimized=wildcard_optimized,
        )

        try:
            if action == 0:
                ea = idaapi.get_screen_ea()
                signature = SignatureMaker().make_signature(ea, config)
                signature.display(config)
            elif action == 1:
                ea = idaapi.get_screen_ea()
                signatures = XrefFinder().find_xrefs(ea, config)
                signatures.display(cfg=config)
            elif action == 2:
                start, end = self.get_selected_addresses(idaapi.get_current_viewer())
                if start and end:
                    signature = SignatureMaker().make_signature(start, config, end=end)
                    signature.display(config)
                else:
                    idaapi.msg("Select a range to copy the code!\n")
            elif action == 3:
                input_signature = idaapi.ask_str(
                    "", idaapi.HIST_SRCH, "Enter a signature"
                )
                if input_signature:
                    searcher = SignatureSearcher.from_signature(input_signature)
                    results = searcher.search()
                    results.display()
                else:
                    idaapi.msg("No signature entered!\n")
            else:
                idaapi.msg("Invalid action!\n")
        except Unexpected as e:
            idaapi.msg(f"Error: {str(e)}\n")
        except Exception as e:
            print(e, os.linesep, traceback.format_exc())
            return

    def term(self) -> None:
        self._deregister_actions()
        self._deinit_hooks(*self._hooks)

    @staticmethod
    def get_selected_addresses(
        ctx,
    ) -> typing.Tuple[typing.Optional[int], typing.Optional[int]]:
        """Return the start and end of the selection or current line."""
        is_selected, start_ea, end_ea = idaapi.read_range_selection(ctx)
        if is_selected:
            return start_ea, end_ea
        p0, p1 = idaapi.twinpos_t(), idaapi.twinpos_t()
        idaapi.read_selection(ctx, p0, p1)
        p0.place(ctx)
        p1.place(ctx)
        if p0.at and p1.at:
            start_ea = p0.at.toea()
            end_ea = p1.at.toea()
            if start_ea == end_ea:
                start_ea = idc.get_item_head(start_ea)
                end_ea = idc.get_item_end(start_ea)
                return start_ea, end_ea

        start_ea = idaapi.get_screen_ea()
        try:
            end_ea = idaapi.ask_addr(start_ea, "Enter end address for selection:")
        finally:
            idaapi.jumpto(start_ea)

        if end_ea and end_ea <= start_ea:
            print(
                f"Error: End address 0x{end_ea:X} must be greater than start address 0x{start_ea:X}."
            )
            end_ea = None
        if end_ea is None:
            end_ea = idc.get_item_end(start_ea)
            print(f"No end address selected, using line end: 0x{end_ea:X}")

        return start_ea, end_ea


def PLUGIN_ENTRY() -> SigMakerPlugin:
    """Entry point function required by IDA Pro to instantiate the plugin."""
    return SigMakerPlugin()


# no cover: stop
