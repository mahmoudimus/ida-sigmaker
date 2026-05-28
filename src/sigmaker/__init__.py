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
import functools
import logging
import os
import pathlib
import re
import string
import time
import traceback
import typing

import idaapi
import idc

__author__ = "mahmoudimus"
__version__ = "1.7.2"

PLUGIN_NAME: str = "Signature Maker (py)"
PLUGIN_VERSION: str = __version__
PLUGIN_AUTHOR: str = __author__


WILDCARD_POLICY_CTX: contextvars.ContextVar["WildcardPolicy"] = contextvars.ContextVar(
    "wildcard_policy"
)


SIMD_SPEEDUP_AVAILABLE = False
with contextlib.suppress(ImportError):
    from sigmaker._speedups import simd_scan

    _SimdSignature = simd_scan.Signature
    _simd_scan_bytes = simd_scan.scan_bytes

    SIMD_SPEEDUP_AVAILABLE = True


def _load_speedups_sibling() -> bool:
    """Load the compiled _speedups extension that sits next to this file.

    The package-level `from sigmaker._speedups import simd_scan` above
    resolves to whatever `sigmaker` is first on sys.path. In a dev or
    symlink layout (e.g. IDA loading this file from a source tree while a
    pip-installed `sigmaker` namespace package without a matching compiled
    extension shadows it), that import yields nothing. When this file lives
    in a real package directory with a sibling `_speedups/`, load the
    extension by path instead. Returns True on success.

    No-ops for the shipped single-file `sigmaker.py`, which has no sibling
    `_speedups/` directory and relies on the pip-installed extension.
    """
    global simd_scan, _SimdSignature, _simd_scan_bytes, SIMD_SPEEDUP_AVAILABLE
    import importlib.machinery
    import importlib.util

    speedups_dir = pathlib.Path(__file__).resolve().parent / "_speedups"
    if not speedups_dir.is_dir():
        return False
    for suffix in importlib.machinery.EXTENSION_SUFFIXES:
        candidate = speedups_dir / f"simd_scan{suffix}"
        if not candidate.exists():
            continue
        # The spec name's final component must be "simd_scan" so the C
        # extension loader finds its PyInit_simd_scan export.
        spec = importlib.util.spec_from_file_location(
            "sigmaker._speedups.simd_scan", candidate
        )
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        simd_scan = module
        _SimdSignature = module.Signature
        _simd_scan_bytes = module.scan_bytes
        SIMD_SPEEDUP_AVAILABLE = True
        return True
    return False


if not SIMD_SPEEDUP_AVAILABLE:
    with contextlib.suppress(Exception):
        _load_speedups_sibling()


def configure_logging(
    logger=None,
    logging_name="sigmaker",
    level=logging.INFO,
    handler_filters=None,
    fmt_str="[%(levelname)s] @ %(message)s",
):
    if logger is None:
        logger = logging.getLogger(logging_name)

    logger.propagate = False
    logger.setLevel(level)
    formatter = logging.Formatter(fmt_str)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.setLevel(level)

    # Add the custom filter if every_n is specified.
    if handler_filters is not None:
        for _filter in handler_filters:
            handler.addFilter(_filter)

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    if not logger.handlers:
        logger.addHandler(handler)
    return logger


LOGGER = configure_logging()

# Set to True to enable verbose debug logging for progress reporter initialization
DEBUGGING_MODE = False

# Wrapper for IDA's British English spelling
# IDA uses 'cancelled' but we use American English 'canceled' throughout our code
idaapi_user_canceled = idaapi.user_cancelled


def _load_qmessage_box_cls():
    """Load QMessageBox class compatible with IDA's Qt version.

    Returns the QMessageBox class for the Qt version in use, or None if unavailable.
    """
    try:
        if ida_version() < (9, 2):
            from PyQt5.QtWidgets import QMessageBox  # type: ignore
            return QMessageBox
        else:
            from PySide6.QtWidgets import QMessageBox  # type: ignore
            return QMessageBox
    except ImportError:
        return None


class UserCanceledError(Exception):
    """Exception raised when user cancels a long-running operation."""


class ProgressReporter(typing.Protocol):
    """Protocol for objects that can report progress and allow cancellation.

    This protocol defines the interface for progress reporting during long-running
    operations. Implementations can provide UI feedback, check for cancellation,
    and track progress metadata.
    """

    @property
    def elapsed_time(self) -> float:
        """Return the elapsed time since the operation started."""
        ...

    def should_cancel(self) -> bool:
        """Check if the operation should be canceled.

        Returns:
            True if the operation should be canceled, False otherwise
        """
        ...

    def enabled(self) -> bool:
        """Check if progress reporting is enabled.

        Returns:
            True if progress reporting is enabled, False otherwise
        """
        ...


@dataclasses.dataclass
class ExponentialBackoffTimer:
    """Manages exponential backoff timing for periodic prompts.

    This timer works with elapsed time (seconds since start) rather than
    absolute timestamps, making it easy to test without mocking time functions.

    The timer implements exponential backoff: after each prompt is acknowledged,
    the interval doubles. For example, with initial_interval=10:
    - First prompt at 10 seconds
    - User responds at 13 seconds → next prompt at 13 + 20 = 33 seconds
    - User responds at 36 seconds → next prompt at 36 + 40 = 76 seconds

    Attributes:
        initial_interval: Initial interval in seconds before first prompt
    """

    initial_interval: float
    _current_interval: float = dataclasses.field(init=False)
    _next_prompt_at: float = dataclasses.field(init=False)  # Elapsed time when next prompt should show

    def __post_init__(self):
        """Initialize timer with first prompt scheduled at initial_interval."""
        self._current_interval = self.initial_interval
        self._next_prompt_at = self.initial_interval

    def should_prompt(self, elapsed_time: float) -> bool:
        """Check if it's time to show a prompt given elapsed time since start.

        Args:
            elapsed_time: Seconds elapsed since the operation started

        Returns:
            True if elapsed_time >= next scheduled prompt time
        """
        return elapsed_time >= self._next_prompt_at

    def acknowledge_prompt(self, current_elapsed_time: float) -> None:
        """User responded to prompt. Schedule next one with doubled interval.

        Args:
            current_elapsed_time: Current elapsed time when user responded
        """
        self._current_interval *= 2
        self._next_prompt_at = current_elapsed_time + self._current_interval

    @property
    def current_interval(self) -> float:
        """Get the current backoff interval in seconds."""
        return self._current_interval

    @property
    def next_prompt_at(self) -> float:
        """Get when (in elapsed seconds) the next prompt should occur."""
        return self._next_prompt_at


@dataclasses.dataclass
class CheckContinuePrompt:
    """Progress reporter that prompts the user to continue when work takes too long.

    This class implements the ProgressReporter protocol and provides exponential
    backoff prompting. It can be used to wrap long-running operations and give
    users the ability to cancel if the operation takes too long.

    Attributes:
        metadata: Static metadata to display in prompts
        cancel_func: Function to call when user cancels (returns its value)
        enable_prompt: Whether to enable prompting (default: True)
        prompt_interval: Initial interval in seconds before first prompt (default: 120)
        logger: Optional logger for debug messages
    """

    metadata: typing.Optional[dict[str, typing.Any]] = None
    cancel_func: typing.Optional[typing.Callable[[], typing.Any]] = None
    enable_prompt: bool = True
    prompt_interval: int = 120
    logger: typing.Optional[logging.Logger] = None

    start_time: float = dataclasses.field(init=False)
    _timer: ExponentialBackoffTimer = dataclasses.field(init=False)
    _user_canceled: bool = dataclasses.field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        self.start_time = time.time()
        self._timer = ExponentialBackoffTimer(initial_interval=float(self.prompt_interval))
        if DEBUGGING_MODE and self.logger is not None:
            self.logger.info(
                "CheckContinuePrompt initialized: enable_prompt=%s, prompt_interval=%d seconds",
                self.enable_prompt,
                self.prompt_interval,
            )

    @property
    def elapsed_time(self) -> float:
        """Return the elapsed time since the operation started."""
        return time.time() - self.start_time

    def should_cancel(self) -> bool:
        """Check if the operation should be canceled.

        This method checks both if the user has already canceled and if
        it's time to prompt the user again based on elapsed time.

        Returns:
            True if the operation should be canceled, False otherwise

        Raises:
            UserCanceledError: If user cancels and no cancel_func is provided
        """
        # Already canceled
        if self._user_canceled:
            return True

        # Wait-box cancel: propagate regardless of whether prompts are enabled.
        if idaapi_user_canceled():
            self._user_canceled = True
            if self.logger is not None:
                self.logger.info(
                    "Wait-box cancel detected at %.1fs", self.elapsed_time
                )
            return True

        # Check if it's time to prompt
        if self._should_prompt() and self._timer.should_prompt(self.elapsed_time):
            if self.logger is not None:
                self.logger.info(
                    "Showing continue prompt at %.1f seconds (threshold: %.1f)",
                    self.elapsed_time,
                    self._timer.next_prompt_at,
                )
            message = self._format_message()
            if not self._ask_to_continue(message):
                self._user_canceled = True
                if self.logger is not None:
                    self.logger.info("User canceled operation")
                if self.cancel_func is None:
                    raise UserCanceledError("User canceled")
                return True

            # User chose to continue - update timer for next prompt with exponential backoff
            self._timer.acknowledge_prompt(self.elapsed_time)
            if self.logger is not None:
                self.logger.info(
                    "User chose to continue. Next prompt in %.1f seconds at %.1f seconds total (%.1f minutes)",
                    self._timer.current_interval,
                    self._timer.next_prompt_at,
                    self._timer.next_prompt_at / 60.0,
                )

        return False

    def _format_message(self, func_name: str = "Operation") -> str:
        """Format the prompt message with current progress information."""
        minutes = int(self.elapsed_time // 60)
        seconds = int(self.elapsed_time % 60)
        time_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
        message_lines = [f"{func_name} has been running for {time_str}.", ""]

        if self.metadata:
            for key, value in self.metadata.items():
                message_lines.append(f"{key}: {value}")
            message_lines.append("")

        message_lines.append("Continue?")
        return "\n".join(message_lines)

    def _ask_to_continue(self, message: str) -> bool:
        """Prompt the user to continue with Qt dialog or IDA fallback."""
        qmessagebox = _load_qmessage_box_cls()
        if qmessagebox is not None:
            reply = qmessagebox.question(
                None,
                "Continue execution?",
                message,
                qmessagebox.Yes | qmessagebox.No,
                qmessagebox.No,
            )
            return reply == qmessagebox.Yes

        # Fallback to IDA's built-in dialog
        reply = idaapi.ask_yn(idaapi.ASKBTN_NO, message)
        return reply == idaapi.ASKBTN_YES

    def _should_prompt(self) -> bool:
        """Check if prompting is enabled and configured."""
        return self.enable_prompt and self.prompt_interval > 0

    def enabled(self) -> bool:
        """Check if progress reporting is enabled.

        Returns:
            True if progress reporting is enabled, False otherwise
        """
        return self.enable_prompt


class Unexpected(Exception):
    """Exception type used throughout the module to indicate unexpected errors."""


@functools.total_ordering
@dataclasses.dataclass(frozen=True)
class IDAVersionInfo:
    major: int
    minor: int
    sdk_version: int

    def __eq__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) == (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) == tuple(other[:2])
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, IDAVersionInfo):
            return (self.major, self.minor) < (other.major, other.minor)
        if isinstance(other, tuple):
            return (self.major, self.minor) < tuple(other[:2])
        return NotImplemented

    @staticmethod
    @functools.cache
    def ida_version():
        """
        Returns an IDAVersionInfo instance for the current IDA kernel version.

        The returned object supports comparison with tuples, e.g.:
            if IDAVersionInfo.ida_version() >= (9, 2):
                ...
        """
        version_str: str = idaapi.get_kernel_version()  # e.g. "9.1"
        sdk_version: int = idaapi.IDA_SDK_VERSION
        major, minor = map(int, version_str.split("."))
        return IDAVersionInfo(major, minor, sdk_version)


ida_version = IDAVersionInfo.ida_version


def is_address_marked_as_code(ea: int) -> bool:
    """Returns True if the specified address (ea) is marked as code in the disassembled binary."""
    return idaapi.is_code(idaapi.get_flags(ea))


# Buffer used to cache the entire database when scanning for signatures.
@dataclasses.dataclass(slots=True)
class InMemoryBuffer:
    """
    Provides fast access to the IDA database as a contiguous buffer, supporting
    both segment-based and input-file-based loading. Also provides helpers to
    translate between file offsets and IDA addresses.
    """

    class LoadMode(enum.Enum):
        SEGMENTS = "segments"
        FILE = "file"

    file_path: pathlib.Path
    mode: LoadMode = dataclasses.field(default=LoadMode.SEGMENTS)
    _buffer: bytearray = dataclasses.field(
        default_factory=bytearray, init=False, repr=False
    )

    @property
    def file_size(self) -> int:
        return idaapi.retrieve_input_file_size()

    @property
    def imagebase(self) -> int:
        return idaapi.get_imagebase()

    def _load_segments(self):
        """Load all IDA segments into a single contiguous bytearray buffer."""
        buf = self._buffer
        seg = idaapi.get_first_seg()
        while seg:
            size = seg.end_ea - seg.start_ea
            data = idaapi.get_bytes(seg.start_ea, size)
            if data:
                buf.extend(data)
            seg = idaapi.get_next_seg(seg.start_ea)

    def _load_input_file(self):
        """Load the original input file into a buffer."""
        if not self.file_path.exists():
            raise RuntimeError(f"Input file {self.file_path} does not exist.")
        with self.file_path.open("rb") as f:
            self._buffer = bytearray(f.read())

    @classmethod
    def load(
        cls,
        file_path: str | pathlib.Path | None = None,
        mode: "InMemoryBuffer.LoadMode" = LoadMode.SEGMENTS,
    ) -> "InMemoryBuffer":
        """
        Load the buffer using the specified mode.
        mode: _LoadMode.SEGMENTS (default) or _LoadMode.FILE
        """
        if file_path is None:
            file_path = idaapi.get_input_file_path()
        if isinstance(file_path, str):
            file_path = pathlib.Path(file_path)
        instance = cls(file_path=file_path, mode=mode)
        if mode == cls.LoadMode.FILE:
            instance._load_input_file()
        else:
            instance._load_segments()
        return instance

    def data(self) -> memoryview:
        """
        Return a memoryview of the buffer, loading if necessary.
        mode: _LoadMode.SEGMENTS or _LoadMode.FILE
        """
        return memoryview(self._buffer)

    def clear(self):
        """Clear the buffer (for testing or reloading)."""
        self._buffer.clear()

    # Address translation helpers

    def file_offset_to_ida_addr(self, file_offset: int) -> int:
        """
        Convert a file offset (from the input file) to an IDA address.
        Only valid in 'file' mode.
        """
        if self.mode != self.LoadMode.FILE:
            raise RuntimeError("file_offset_to_ida_addr is only valid in 'file' mode.")
        return self.imagebase + file_offset

    def ida_addr_to_file_offset(self, ida_addr: int) -> int:
        """
        Convert an IDA address to a file offset (from the input file).
        Only valid in 'file' mode.
        """
        if self.mode != self.LoadMode.FILE:
            raise RuntimeError("ida_addr_to_file_offset is only valid in 'file' mode.")
        return ida_addr - self.imagebase

    def segment_offset_to_ida_addr(self, seg_offset: int) -> int:
        """
        Convert a segment buffer offset to an IDA address.
        Only valid in 'segments' mode.
        """
        if self.mode != self.LoadMode.SEGMENTS:
            raise RuntimeError(
                "segment_offset_to_ida_addr is only valid in 'segments' mode."
            )
        return self.imagebase + seg_offset

    def ida_addr_to_segment_offset(self, ida_addr: int) -> int:
        """
        Convert an IDA address to a segment buffer offset.
        Only valid in 'segments' mode.
        """
        if self.mode != self.LoadMode.SEGMENTS:
            raise RuntimeError(
                "ida_addr_to_segment_offset is only valid in 'segments' mode."
            )
        return ida_addr - self.imagebase


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
    enable_continue_prompt: bool = False
    ask_longer_signature: bool = True
    print_top_x: int = 5
    max_single_signature_length: int = 100
    max_xref_signature_length: int = 250
    # Seconds before first prompt. -1 (or 0) disables the periodic
    # "Continue?" popup -- the wait-box Cancel button still works.
    prompt_interval: int = -1
    # Issue #22: when True, cancelling a unique-signature search emits the
    # partial signature with its match count instead of nothing. Default off.
    output_partial_on_cancel: bool = False


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


class Action(enum.IntEnum):
    """User-selectable action in SignatureMakerForm.

    Values are bound to the rAction radio-group order:
    ("rCreateUniqueSig", "rFindXRefSig", "rCopyCode", "rSearchSignature",
     "rFindFunctionSig").
    Changing values requires updating the radio group too.
    """

    CREATE_UNIQUE = 0
    FIND_XREF = 1
    COPY_RANGE = 2
    SEARCH = 3
    FIND_FUNCTION_SIG = 4


class GenerationStatus(enum.Enum):
    """How a GeneratedSignature should be interpreted."""

    UNIQUE = "unique"
    PARTIAL_ON_CANCEL = "partial_on_cancel"


@dataclasses.dataclass(frozen=True)
class GenerationPolicy:
    """Behavioral knobs passed into generator strategies.

    Callers pick the policy that matches their tolerance for non-unique
    signatures. The default is strict (legacy behavior: cancel raises).
    """

    return_partial_on_cancel: bool = False

    @classmethod
    def strict(cls) -> "GenerationPolicy":
        """Cancel raises UserCanceledError (legacy behavior)."""
        return cls(return_partial_on_cancel=False)

    @classmethod
    def permissive(cls) -> "GenerationPolicy":
        """Cancel returns a partial GeneratedSignature instead of raising."""
        return cls(return_partial_on_cancel=True)


@dataclasses.dataclass(slots=True)
class _CancelToPartial:
    """Context manager that converts UserCanceledError into a partial result.

    If ``policy.return_partial_on_cancel`` is True and a UserCanceledError
    is raised inside the ``with`` block, calls ``build_partial()`` and
    stashes the result in ``.partial``, suppressing the original exception.
    If ``build_partial()`` itself raises UserCanceledError (the empty-sig
    case where there's nothing useful to return), the original
    UserCanceledError is allowed to propagate, not this new one.
    """

    policy: GenerationPolicy
    build_partial: typing.Callable[[], "GeneratedSignature"]
    partial: typing.Optional["GeneratedSignature"] = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is UserCanceledError and self.policy.return_partial_on_cancel:
            try:
                self.partial = self.build_partial()
            except UserCanceledError:
                return False  # propagate the ORIGINAL UserCanceledError
            return True  # suppress; partial is ready
        return False


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

    # construction helpers
    @classmethod
    def for_x86(cls) -> "WildcardPolicy":
        # Exclude BaseKind.IMM. An immediate like the 0x13371338 in
        # `mov rcx, 0x13371338` is a literal value baked into the
        # instruction encoding; it does not shift between binary builds,
        # so wildcarding it only removes bytes that would have made the
        # signature unique. MEM/FAR/NEAR still get wildcarded because
        # those operands DO encode addresses that move between builds.
        x86_base = frozenset(cls.BaseKind) - {cls.BaseKind.IMM}
        return cls(x86_base | frozenset(cls.X86Kind))

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
    status: GenerationStatus = GenerationStatus.UNIQUE
    match_count: int | None = None

    def display(self, cfg: SigMakerConfig) -> None:
        """Display the signature result to the user.

        UNIQUE: prints the formatted signature and copies to the clipboard.
        PARTIAL_ON_CANCEL: prints the partial with its match count; does NOT
        touch the clipboard so an accidental cancel cannot clobber the
        user's clipboard contents.
        """
        if not self.signature:
            idaapi.msg("Error: Empty signature\n")
            return
        t = cfg.output_format.value
        fmted = format(self.signature, t)

        if self.status == GenerationStatus.PARTIAL_ON_CANCEL:
            count_str = (
                f"{self.match_count} matches"
                if self.match_count is not None
                else "match count unavailable"
            )
            prefix = (
                f"Partial signature (NOT unique, {count_str}) for {self.address}"
                if self.address is not None
                else f"Partial signature (NOT unique, {count_str})"
            )
            idaapi.msg(f"{prefix}: {fmted}\n")
            return

        if self.address is not None:
            idaapi.msg(f"Signature for {self.address}: {fmted}\n")
        else:
            idaapi.msg(f"Signature: {fmted}\n")

        if not Clipboard.set_text(fmted):
            idaapi.msg("Failed to copy to clipboard!")

    def _wildcard_count(self) -> int:
        """Number of wildcard bytes in this signature."""
        return sum(1 for b in self.signature if b.is_wildcard)

    def __lt__(self, other) -> bool:
        if not isinstance(other, GeneratedSignature):
            return NotImplemented
        return (len(self.signature), self._wildcard_count()) < (
            len(other.signature),
            other._wildcard_count(),
        )


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


@dataclasses.dataclass(slots=True, frozen=True)
class _DecodedInstruction:
    """Pre-decoded instruction data; produced once per function and reused
    across anchor growth loops in MinimalFunctionSignatureGenerator.

    operand_offb / operand_length describe the byte range to wildcard for
    this cfg's operand policy. Both are 0 when no operand should be
    wildcarded (e.g. wildcard_operands=False, or the instruction has no
    operand that matches the current WildcardPolicy).
    """
    ea: int
    size: int
    raw_bytes: bytes
    operand_offb: int
    operand_length: int


@dataclasses.dataclass(slots=True)
class InstructionWalker:
    """
    A stateful iterator for walking instructions within a given address range.

    This class encapsulates the logic of decoding instructions and tracks the
    current address (cursor), which remains available for inspection after
    the iteration is complete.
    """

    start_ea: int
    # Resolve BADADDR lazily so tests that patch `idaapi.BADADDR` at runtime
    # actually take effect. With `default=idaapi.BADADDR`, the value was
    # evaluated at class-definition (module import) time, which under the
    # unit-test mock of `idaapi` froze it as a MagicMock attribute.
    end_ea: int = dataclasses.field(default_factory=lambda: idaapi.BADADDR)

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

        if idaapi_user_canceled():
            raise UserCanceledError("Aborted by user during instruction walk")

        current_instruction_ea = self.cursor
        ins_len = idaapi.decode_insn(self._instruction, current_instruction_ea)

        if ins_len <= 0:
            raise StopIteration

        self.cursor += ins_len

        return current_instruction_ea, self._instruction, ins_len


class UniqueSignatureGenerator:
    """Strategy for generating a signature that is guaranteed to be unique."""

    def __init__(
        self,
        processor: InstructionProcessor,
        progress_reporter: typing.Optional[ProgressReporter] = None,
    ):
        self.processor = processor
        self.progress_reporter = progress_reporter

    def generate(
        self,
        ea: int,
        cfg: SigMakerConfig,
        *,
        policy: GenerationPolicy = GenerationPolicy.strict(),
    ) -> GeneratedSignature:
        """Generate a unique signature starting at the given address.

        Args:
            ea: Starting address for signature generation
            cfg: Configuration for signature generation
            policy: Controls cancel-time behavior. Default strict() raises
                UserCanceledError on cancel (legacy contract). permissive()
                returns a partial GeneratedSignature with the most recently
                observed match count.

        Returns:
            A GeneratedSignature. status=UNIQUE on success;
            status=PARTIAL_ON_CANCEL when policy.return_partial_on_cancel
            is True and the user cancels after at least one byte has been
            appended.

        Raises:
            Unexpected: If signature cannot be made unique
            UserCanceledError: If user cancels and policy.return_partial_on_cancel
                is False, or if cancel happens before any byte is appended.
        """
        if not is_address_marked_as_code(ea):
            raise Unexpected("Cannot create code signature for data")

        sig = Signature()
        start_fn = idaapi.get_func(ea)
        bytes_since_last_check = 0
        progress = _UniqueSigProgress(sig=sig)

        def build_partial() -> GeneratedSignature:
            # Trim trailing wildcards, mirror the success path.
            sig.trim_signature()
            if len(sig) == 0:
                raise UserCanceledError("Signature generation canceled by user")
            return GeneratedSignature(
                sig,
                Match(ea),
                status=GenerationStatus.PARTIAL_ON_CANCEL,
                match_count=progress.last_match_count,
            )

        with _CancelToPartial(policy, build_partial) as cancel:
            for cur_ea, ins, ins_len in ProgressBox(
                InstructionWalker(ea),
                initial_message=(
                    "Create unique signature (from cursor address)\n\n"
                    "Growing a pattern from the current address until it "
                    "matches exactly one place in the binary.\n\n"
                    "Press Cancel to stop"
                ),
                format_message=progress,
            ):
                # Modal continue-prompt opt-in (issue #18) still goes through
                # the progress reporter. The wait-box cancel is already handled
                # by ProgressBox raising UserCanceledError.
                if (
                    self.progress_reporter is not None
                    and self.progress_reporter.should_cancel()
                ):
                    raise UserCanceledError("Signature generation canceled by user")

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

                count = SignatureSearcher.count_matches(f"{sig:ida}")
                # SignatureSearcher.find_all polls idaapi_user_canceled inside
                # its scan loop and bails when set, returning whatever partial
                # count it had so far (often 0). When the call was interrupted,
                # keep last_match_count at its prior trustworthy value (issue
                # #22): the reported number is an upper bound on the partial's
                # actual match count rather than a meaningless 0.
                if not idaapi_user_canceled():
                    progress.last_match_count = count
                    if count == 1:
                        sig.trim_signature()
                        return GeneratedSignature(sig, Match(ea))

        if cancel.partial is not None:
            return cancel.partial
        raise Unexpected("Signature not unique (reached end of analysis)")


def _decode_function_for_anchors(
    pfn: "idaapi.func_t",
    processor: "InstructionProcessor",
    cfg: "SigMakerConfig",
) -> list[_DecodedInstruction]:
    """Decode a function's instructions once and capture per-instruction
    data for use across all anchor growth loops.

    Reads all function bytes via one idaapi.get_bytes call, then walks
    instructions via InstructionWalker. The operand wildcard decision is
    baked in based on cfg.wildcard_operands / cfg.wildcard_optimized;
    operand_offb / operand_length are both 0 when no operand should be
    wildcarded.
    """
    total = pfn.end_ea - pfn.start_ea
    if total <= 0:
        return []
    func_bytes = idaapi.get_bytes(pfn.start_ea, total)
    if not func_bytes:
        return []

    decoded: list[_DecodedInstruction] = []
    for ea, ins, ins_len in InstructionWalker(pfn.start_ea, pfn.end_ea):
        offset = ea - pfn.start_ea
        if offset < 0 or offset + ins_len > len(func_bytes):
            break
        raw = bytes(func_bytes[offset:offset + ins_len])

        operand_offb = 0
        operand_length = 0
        if cfg.wildcard_operands:
            off, length = [0], [0]
            if processor.operand_processor.get_operand(
                ins, off, length, cfg.wildcard_optimized
            ):
                operand_offb = off[0]
                operand_length = length[0]

        decoded.append(_DecodedInstruction(
            ea=ea,
            size=ins_len,
            raw_bytes=raw,
            operand_offb=operand_offb,
            operand_length=operand_length,
        ))
    return decoded


class MinimalFunctionSignatureGenerator:
    """Find the shortest unique signature anywhere within a function body.

    Decodes the function once at the start of generate(), then iterates
    every instruction as a possible anchor over the pre-decoded list,
    growing a signature from each until unique (bounded by function end
    and by the size of the best candidate found so far). Returns the
    smallest unique signature with the fewest wildcards. Raises
    Unexpected if no unique signature exists within the function.
    """

    MIN_USEFUL_SIG_BYTES = 5

    def __init__(
        self,
        processor: InstructionProcessor,
        progress_reporter: typing.Optional[ProgressReporter] = None,
    ):
        self.processor = processor
        self.progress_reporter = progress_reporter

    def generate(
        self, pfn: "idaapi.func_t", cfg: SigMakerConfig
    ) -> GeneratedSignature:
        """Search the function body for the shortest unique signature.

        Args:
            pfn: The function to search (idaapi.func_t).
            cfg: Configuration. Uses max_single_signature_length as the
                initial budget; the budget shrinks monotonically as
                better candidates are found.

        Returns:
            The best unique GeneratedSignature found.

        Raises:
            Unexpected: If the function has no instructions, if its bytes
                cannot be read, or if no start point produces a unique
                signature within the length budget (or all candidates are
                degenerate, < MIN_USEFUL_SIG_BYTES bytes).
            UserCanceledError: If the progress reporter signals cancel.
        """
        candidates: list[GeneratedSignature] = []
        progress = _FunctionSigProgress(
            pfn_start_ea=int(pfn.start_ea),
            pfn_end_ea=int(pfn.end_ea),
            candidates=candidates,
            best_size=cfg.max_single_signature_length,
        )

        decoded = _decode_function_for_anchors(pfn, self.processor, cfg)
        if not decoded:
            raise Unexpected("No unique signature within function")

        # Load the segment buffer once and reuse it across every is_unique
        # call. Profiling against a real binary showed _load_segments was
        # 84% of generate() wall time when called per-is_unique.
        buf: typing.Optional["InMemoryBuffer"] = None
        if SIMD_SPEEDUP_AVAILABLE:
            with ProgressDialog("Please stand by, copying segments..."):
                buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)

        # Iterate the pre-decoded anchors inside a ProgressBox so the wait
        # box shows live progress (issue #27). enumerate() keeps the index
        # for slicing while leaving the yielded item a non-int, so
        # _FunctionSigProgress falls back to current_anchor_ea for display.
        for anchor_idx, di in ProgressBox(
            enumerate(decoded),
            total=len(decoded),
            initial_message=(
                "Find shortest function signature\n\n"
                "Trying every instruction in the function as a start point; "
                "growing each until unique and keeping the shortest.\n\n"
                "Press Cancel to stop"
            ),
            format_message=progress,
        ):
            if (
                self.progress_reporter is not None
                and self.progress_reporter.should_cancel()
            ):
                raise UserCanceledError(
                    "Function signature search canceled by user"
                )

            # Reset the inner-state fields for this anchor so the wait-box
            # display starts fresh rather than showing the previous anchor's
            # final state.
            progress.current_anchor_ea = di.ea
            progress.inner_length = 0
            progress.inner_matches = None

            sig = self._grow_unique_from_decoded(
                decoded, anchor_idx, progress.best_size, cfg,
                buf=buf, progress=progress,
            )
            if sig is None:
                continue
            if len(sig) < self.MIN_USEFUL_SIG_BYTES:
                continue

            candidate = GeneratedSignature(sig, Match(di.ea))
            candidates.append(candidate)
            progress.best_size = min(progress.best_size, len(sig))

            wildcard_count = sum(1 for b in sig if b.is_wildcard)
            if len(sig) <= self.MIN_USEFUL_SIG_BYTES and wildcard_count == 0:
                break

        if not candidates:
            raise Unexpected("No unique signature within function")

        candidates.sort()
        return candidates[0]

    def _grow_unique_from_decoded(
        self,
        decoded: list[_DecodedInstruction],
        anchor_idx: int,
        max_len: int,
        cfg: SigMakerConfig,
        buf: typing.Optional["InMemoryBuffer"] = None,
        progress: typing.Optional["_FunctionSigProgress"] = None,
    ) -> typing.Optional[Signature]:
        """Grow a signature from ``decoded[anchor_idx]`` forward until unique.

        Reads all instruction data from the pre-decoded list. The ``buf``
        argument is forwarded to the searcher so the segment buffer is
        reused across all uniqueness checks inside one generate() session.

        Uniqueness is decided with an early-bail scan (bail at the second
        match) rather than a full match count, so short common signatures
        do not enumerate every hit. If ``progress`` is supplied, the
        per-iteration sig length and the (capped) match count are written
        into its ``inner_length`` / ``inner_matches`` fields for the live
        wait-box display; ``inner_matches`` of 2 means "two or more".
        """
        sig = Signature()
        for i in range(anchor_idx, len(decoded)):
            if (
                self.progress_reporter is not None
                and self.progress_reporter.should_cancel()
            ):
                raise UserCanceledError(
                    "Function signature search canceled by user"
                )

            self._append_decoded_to_sig(sig, decoded[i])

            if len(sig) > max_len:
                return None

            unique = SignatureSearcher.is_unique(f"{sig:ida}", buf=buf)
            if progress is not None:
                progress.inner_length = len(sig)
                # is_unique early-bails at the second match, so we cannot
                # show an exact count here; 1 means unique, 2 means "2 or
                # more, keep growing".
                progress.inner_matches = 1 if unique else 2
            if unique:
                sig.trim_signature()
                return sig

        return None

    def _append_decoded_to_sig(
        self, sig: Signature, di: _DecodedInstruction
    ) -> None:
        """Append a pre-decoded instruction's bytes to ``sig``, honoring its
        baked operand-wildcard decision.

        Mirrors InstructionProcessor.append_instruction_to_sig but reads
        from di.raw_bytes instead of calling idaapi.get_bytes.
        """
        raw = di.raw_bytes
        if di.operand_length <= 0:
            sig.extend(SignatureByte(b, False) for b in raw)
            return

        end_operand = di.operand_offb + di.operand_length
        sig.extend(SignatureByte(b, False) for b in raw[:di.operand_offb])
        sig.extend(SignatureByte(b, True) for b in raw[di.operand_offb:end_operand])
        sig.extend(SignatureByte(b, False) for b in raw[end_operand:])


class RangeSignatureGenerator:
    """Strategy for generating a signature for a fixed address range."""

    def __init__(
        self,
        processor: InstructionProcessor,
        progress_reporter: typing.Optional[ProgressReporter] = None,
    ):
        self.processor = processor
        self.progress_reporter = progress_reporter

    def generate(
        self,
        start_ea: int,
        end_ea: int,
        cfg: SigMakerConfig,
    ) -> Signature:
        """Generate a signature for a specific address range.

        Args:
            start_ea: Starting address
            end_ea: Ending address (exclusive)
            cfg: Configuration for signature generation

        Returns:
            A signature for the specified range

        Raises:
            UserCanceledError: If user cancels via progress reporter
        """
        sig = Signature()

        # Handle pure data ranges
        if not is_address_marked_as_code(start_ea):
            sig.add_bytes_to_signature(start_ea, end_ea - start_ea, is_wildcard=False)
            return sig

        # Iterate through instructions within the range
        walker = InstructionWalker(start_ea, end_ea)
        instruction_count = 0

        for cur_ea, ins, _ in walker:
            # Check for cancellation via progress reporter
            if self.progress_reporter is not None and self.progress_reporter.should_cancel():
                raise UserCanceledError("Signature generation canceled by user")

            instruction_count += 1

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
    """Generates unique or range-based signatures.

    This class uses a factory method pattern to create the appropriate signature
    generator (UniqueSignatureGenerator or RangeSignatureGenerator) based on the
    operation being performed.

    Note: SignatureMaker instances are ephemeral - a new instance is created for
    each user action from the IDA UI. Therefore, caching generators would provide
    no performance benefit, and we create them on-demand via factory method.
    """

    _operand_processor: OperandProcessor = dataclasses.field(
        default_factory=OperandProcessor
    )

    # Internal components built from dependencies
    _instruction_processor: InstructionProcessor = dataclasses.field(init=False)

    def __post_init__(self):
        """Initialize internal components after the main object is created."""
        self._instruction_processor = InstructionProcessor(self._operand_processor)

    def _create_generator(
        self,
        for_range: bool,
        progress_reporter: typing.Optional[ProgressReporter],
    ) -> UniqueSignatureGenerator | RangeSignatureGenerator:
        """Factory method to create the appropriate signature generator.

        This method encapsulates the logic for creating signature generators,
        abstracting away the concrete generator types from make_signature().

        Args:
            for_range: True to create RangeSignatureGenerator, False for UniqueSignatureGenerator
            progress_reporter: Progress reporter to pass to the generator

        Returns:
            The appropriate generator instance configured with the progress reporter
        """
        if for_range:
            return RangeSignatureGenerator(self._instruction_processor, progress_reporter)
        return UniqueSignatureGenerator(self._instruction_processor, progress_reporter)

    def make_signature(
        self,
        ea: int | Match,
        cfg: SigMakerConfig,
        end: int | None = None,
        *,
        progress_reporter: typing.Optional[ProgressReporter] = None,
        policy: GenerationPolicy = GenerationPolicy.strict(),
    ) -> GeneratedSignature:
        """Creates a signature for a single address (unique) or an address range.

        Args:
            ea: Starting address for signature generation
            cfg: Configuration for signature generation
            end: Optional ending address for range-based signatures
            progress_reporter: Optional progress reporter for cancellation and updates.
                              If not provided, one will be created based on cfg.enable_continue_prompt.

        Returns:
            A GeneratedSignature containing the signature and metadata

        Raises:
            Unexpected: If address is invalid or end address is before start
            UserCanceledError: If user cancels via progress reporter
        """
        start_ea = int(ea)
        if start_ea == idaapi.BADADDR:
            raise Unexpected("Invalid start address")

        # Create progress reporter based on config if not provided
        if not progress_reporter:
            progress_reporter = CheckContinuePrompt(
                prompt_interval=cfg.prompt_interval,
                metadata={
                    "operation": "Signature generation",
                    "start_address": hex(start_ea),
                },
                logger=LOGGER,
                enable_prompt=cfg.enable_continue_prompt,
            )
            if DEBUGGING_MODE:
                LOGGER.info(
                    "Created CheckContinuePrompt: interval=%ds, enabled=%s",
                    cfg.prompt_interval,
                    cfg.enable_continue_prompt,
                )

        if end is None:
            # Create unique signature generator via factory method
            generator = self._create_generator(for_range=False, progress_reporter=progress_reporter)
            # UniqueSignatureGenerator.generate returns a GeneratedSignature
            # directly so it can carry status + match_count on cancel.
            return generator.generate(start_ea, cfg, policy=policy)

        if end <= start_ea:
            raise Unexpected("End address must be after start address")

        # Create range signature generator via factory method.
        # Range generator returns a bare Signature; policy is not applicable.
        generator = self._create_generator(for_range=True, progress_reporter=progress_reporter)
        sig = generator.generate(start_ea, end, cfg)
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
                f"Find shortest XREF signature\n\n"
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

        # Wrap the search in a ProgressDialog to allow cancellation
        with ProgressDialog(
            "Search for a signature\n\n"
            "Scanning the whole database for your pattern.\n\n"
            "Press Cancel to stop"
        ):
            matches = self.find_all(sig_str)

        return SearchResults(matches, sig_str)

    @staticmethod
    def _find_all_simd(
        ida_signature: str,
        skip_more_than_one: bool = False,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> list[Match]:
        simd_signature, _ = SigText.normalize(ida_signature)
        if buf is None:
            with ProgressDialog("Please stand by, copying segments..."):
                buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)
        data_mv = buf.data()
        LOGGER.debug(
            "searching for",
            simd_signature,
            "starting from",
            hex(buf.imagebase),
            "with size",
            hex(buf.file_size),
            "buf length:",
            len(data_mv),
        )

        sig = _SimdSignature(simd_signature)
        results: list[Match] = []
        base = idaapi.inf_get_min_ea()
        if (k := sig.size_bytes) == 0:
            return [Match(base)]

        n = len(data_mv)
        off = 0
        while off <= n - k:
            # Check for user cancellation
            if idaapi_user_canceled():
                LOGGER.info("Search canceled by user")
                break

            idx = _simd_scan_bytes(data_mv[off:], sig)
            if idx < 0:
                break
            ea = base + off + idx
            results.append(Match(ea))
            if skip_more_than_one and len(results) > 1:
                break
            off += idx + 1
        return results

    @staticmethod
    def find_all(
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
        skip_more_than_one: bool = False,
    ) -> list[Match]:
        # Use SIMD if available
        if SIMD_SPEEDUP_AVAILABLE:
            return SignatureSearcher._find_all_simd(
                ida_signature, skip_more_than_one=skip_more_than_one, buf=buf
            )
        binary = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binary, idaapi.inf_get_min_ea(), ida_signature, 16)
        out: list[Match] = []
        ea = idaapi.inf_get_min_ea()
        max_ea = idaapi.inf_get_max_ea()
        _bin_search = getattr(idaapi, "bin_search", None) or getattr(
            idaapi, "bin_search3"
        )
        flags = idaapi.BIN_SEARCH_NOCASE | idaapi.BIN_SEARCH_FORWARD
        while True:
            # Check for user cancellation
            if idaapi_user_canceled():
                LOGGER.info("Search canceled by user")
                break

            hit, _ = _bin_search(ea, max_ea, binary, flags)
            if hit == idaapi.BADADDR:
                break
            out.append(Match(hit))
            # is_unique only needs to know if there is more than one match;
            # bail at 2 instead of enumerating every match in the database.
            if skip_more_than_one and len(out) > 1:
                break
            ea = hit + 1
        return out

    @classmethod
    def count_matches(
        cls,
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> int:
        """Return the number of matches for the given IDA-format signature.

        Enumerates every match; callers that only need uniqueness should use
        is_unique (which bails at the second match).
        """
        return len(cls.find_all(ida_signature, buf=buf))

    @classmethod
    def is_unique(
        cls,
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> bool:
        """Return True iff the signature matches exactly one location.

        Bails at the second match. Enumerating all matches of a short,
        common signature is catastrophic on a large binary (observed:
        110M+ scan iterations for one function-signature search), and
        uniqueness only depends on whether the count is 0, 1, or 2+.
        """
        matches = cls.find_all(ida_signature, buf=buf, skip_more_than_one=True)
        return len(matches) == 1


_ACTIVE_PROFILE: typing.Any = None


def start_profiling() -> None:
    """Begin a cProfile session that captures whatever runs after this call.

    Intended for in-IDA diagnostics. Pair with stop_profiling().

        >>> import sigmaker
        >>> sigmaker.start_profiling()
        ... # run whatever (FIND_FUNCTION_SIG, FIND_XREF, etc.)
        >>> sigmaker.stop_profiling()    # dumps to {IDAUSR}/sigmaker_profile.*

    Calling start_profiling() twice without an intervening stop_profiling()
    discards the previous session and begins a fresh one.
    """
    import cProfile
    global _ACTIVE_PROFILE
    if _ACTIVE_PROFILE is not None:
        _ACTIVE_PROFILE.disable()
        idaapi.msg("start_profiling: discarding previous active session\n")
    pr = cProfile.Profile()
    pr.enable()
    _ACTIVE_PROFILE = pr
    idaapi.msg("start_profiling: profiling enabled\n")


def stop_profiling(
    output_path: typing.Optional[str] = None,
    top_n: int = 30,
    sort_by: str = "cumulative",
) -> typing.Optional[str]:
    """Stop the active cProfile session, dump the result, and print a summary.

    Args:
        output_path: Where to write the binary cProfile dump. None writes
            to {IDAUSR}/sigmaker_profile.prof. A .txt sibling with the
            top_n summary is always written next to the .prof file.
        top_n: How many functions to print in the text summary.
        sort_by: pstats sort key (cumulative, tottime, ncalls, ...).

    Returns:
        The .prof file path on success, or None if no profiling was active.
        Output is also printed via idaapi.msg so it appears in the IDA
        Output window.
    """
    import pstats
    import io as _io
    global _ACTIVE_PROFILE
    if _ACTIVE_PROFILE is None:
        idaapi.msg("stop_profiling: no active session; call start_profiling() first\n")
        return None
    pr = _ACTIVE_PROFILE
    _ACTIVE_PROFILE = None
    pr.disable()

    if output_path is None:
        idausr = idaapi.get_user_idadir()
        output_path = os.path.join(idausr, "sigmaker_profile.prof")
    text_path = output_path + ".txt" if not output_path.endswith(".txt") else output_path

    pr.dump_stats(output_path)

    buf = _io.StringIO()
    pstats.Stats(pr, stream=buf).sort_stats(sort_by).print_stats(top_n)
    text = buf.getvalue()

    header = (
        f"stop_profiling:\n"
        f"  prof dump:   {output_path}\n"
        f"  text dump:   {text_path}\n"
        f"  sort by:     {sort_by}\n"
        f"  top {top_n}:\n"
    )
    with open(text_path, "w") as f:
        f.write(header)
        f.write(text)

    idaapi.msg(header)
    idaapi.msg(text)
    return output_path


class ProgressDialog:
    """Context manager wrapping IDA wait boxes.

    When used as a context manager the progress dialog will display a wait box
    on entry and hide it on exit.

    The message may be updated via `replace_message()` and cancelation can be
    tested with `user_canceled()` from this class or `idaapi_user_canceled()`
    from this module.
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
        return idaapi_user_canceled()

    # Provide alias with alternative spelling for backwards compatibility.
    user_cancelled = user_canceled


@dataclasses.dataclass(slots=True)
class ProgressBox:
    """Wait-box-backed iteration progress reporter.

    Wraps an iterable, opens an IDA wait box via ``dialog_factory`` on
    iteration start, calls ``format_message(idx, item, elapsed, total)``
    on each tick (throttled to ``throttle_seconds``), and exits the
    dialog context manager on completion or cancel. Cancel via the
    wait-box Cancel button raises ``UserCanceledError``.

    ``clock`` and ``dialog_factory`` are injection points for testing:
    the default ``clock=time.monotonic`` and ``dialog_factory=ProgressDialog``
    give production behavior; tests pass fakes to drive throttling
    deterministically and to record dialog calls without touching idaapi.
    """

    iterable: typing.Iterable
    total: typing.Optional[int] = None
    initial_message: str = "Executing..."
    format_message: typing.Optional[
        typing.Callable[[int, typing.Any, float, typing.Optional[int]], str]
    ] = None
    throttle_seconds: float = 1.0
    clock: typing.Callable[[], float] = dataclasses.field(default=time.monotonic)
    # default_factory (not default=ProgressDialog) so tests that monkey-patch
    # sigmaker.ProgressDialog after class definition are honored: the lambda
    # re-resolves the name from module scope at each ProgressBox() construction.
    dialog_factory: typing.Callable[[str], typing.Any] = dataclasses.field(
        default_factory=lambda: ProgressDialog
    )

    def __post_init__(self):
        if self.total is None and self.iterable is not None:
            try:
                self.total = len(self.iterable)
            except (TypeError, AttributeError):
                self.total = None
        if self.total == float("inf"):
            self.total = None

    def __iter__(self):
        with self.dialog_factory(self.initial_message) as dialog:
            start = self.clock()
            last_update = 0.0
            for idx, item in enumerate(self.iterable, start=1):
                if idaapi_user_canceled():
                    raise UserCanceledError("Canceled by user")
                now = self.clock()
                if now - last_update > self.throttle_seconds:
                    elapsed = now - start
                    if self.format_message is not None:
                        msg = self.format_message(idx, item, elapsed, self.total)
                    elif self.total:
                        msg = f"Processing ({idx}/{self.total}) | Elapsed: {int(elapsed)}s"
                    else:
                        msg = f"Processing ({idx}) | Elapsed: {int(elapsed)}s"
                    dialog.replace_message(msg)
                    last_update = now
                yield item


@dataclasses.dataclass(slots=True)
class _UniqueSigProgress:
    """Formatter for the CREATE_UNIQUE wait-box message.

    Holds a live reference to the generator's growing Signature plus the
    most recently observed match count. ``__call__`` renders the template
    using the current state on every invocation; the generator updates
    ``last_match_count`` per iteration so the wait box stays current.
    """

    sig: "Signature"
    last_match_count: typing.Optional[int] = None
    _TEMPLATE: typing.ClassVar[str] = (
        "Create unique signature (from cursor address)\n"
        "Growing a pattern from the current address until it matches\n"
        "exactly one place in the binary.\n\n"
        "Length:  {length} bytes\n"
        "Elapsed: {elapsed}s\n\n"
        "Press Cancel to stop"
    )

    def __call__(self, idx, item, elapsed, total) -> str:
        return self._TEMPLATE.format(
            length=len(self.sig),
            elapsed=int(elapsed),
        )


@dataclasses.dataclass(slots=True)
class _FunctionSigProgress:
    """Formatter for the FIND_FUNCTION_SIG wait-box message.

    Holds live references to the function bounds, the candidates list,
    and the current best-size. The generator updates ``current_anchor_ea``
    at the top of every outer iteration; the inner ``_grow_unique_from``
    updates ``inner_length`` and ``inner_matches`` as the per-anchor
    search grows. ``__call__`` renders the template using whatever state
    is current at tick time (throttled by ProgressBox).
    """

    pfn_start_ea: int
    pfn_end_ea: int
    candidates: list
    best_size: int
    current_anchor_ea: int = 0
    inner_length: int = 0
    inner_matches: typing.Optional[int] = None
    _TEMPLATE: typing.ClassVar[str] = (
        "Find shortest function signature\n"
        "Trying every instruction as a start point; keeping the shortest unique one.\n"
        "\n"
        "Function:     {fn_bounds}  ({fn_size} bytes)\n"
        "Anchor (#{idx}): {anchor:#x}\n"
        "Inner search: {inner_bounds}  ({inner_length} bytes, {inner_matches_str})\n"
        "Best found:   {best}\n"
        "Candidates:   {candidates_count} unique so far\n"
        "Elapsed:      {elapsed}s\n"
        "\n"
        "Press Cancel to stop"
    )

    def __call__(self, idx, item, elapsed, total) -> str:
        fn_bounds = f"{self.pfn_start_ea:#x} .. {self.pfn_end_ea:#x}"
        fn_size = self.pfn_end_ea - self.pfn_start_ea
        anchor = item if isinstance(item, int) else self.current_anchor_ea
        inner_end = anchor + self.inner_length
        inner_bounds = f"{anchor:#x} .. {inner_end:#x}"
        if self.inner_matches is None:
            inner_matches_str = "scanning..."
        elif self.inner_matches >= 2:
            # Uniqueness is decided with an early-bail scan that stops at the
            # second match, so the exact count past 1 is unknown: show "2+".
            inner_matches_str = "2+ matches so far"
        else:
            inner_matches_str = f"{self.inner_matches} matches so far"
        best = f"{self.best_size} bytes" if self.candidates else "-"
        return self._TEMPLATE.format(
            fn_bounds=fn_bounds,
            fn_size=fn_size,
            idx=idx,
            anchor=anchor,
            inner_bounds=inner_bounds,
            inner_length=self.inner_length,
            inner_matches_str=inner_matches_str,
            best=best,
            candidates_count=len(self.candidates),
            elapsed=int(elapsed),
        )


# no cover: start
# we do not cover the below because this is mainly executing IDA GUI functionality.
# any logic here should be pulled out into a separate class and tested separately.
class Clipboard:
    """Cross platform utilities for setting text on the system clipboard."""

    @staticmethod
    def _set_text_pyqt5(text: str) -> bool:
        """Set clipboard text via PyQt if available."""
        try:
            if ida_version() < (9, 2):
                from PyQt5.QtWidgets import QApplication  # type: ignore
            else:
                import PySide6
                from PySide6.QtGui import (
                    QGuiApplication as QApplication,  # type: ignore
                )

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
<#Seconds before the first 'Continue?' prompt fires. -1 disables the prompt entirely (default).#Prompt interval (seconds, -1 disables):{opt4}>
"""

        self.controls = {
            "opt1": F.NumericInput(tp=F.FT_DEC),
            "opt2": F.NumericInput(tp=F.FT_DEC),
            "opt3": F.NumericInput(tp=F.FT_DEC),
            "opt4": F.NumericInput(tp=F.FT_DEC),
        }
        super().__init__(form_text, self.controls)

    def ExecuteForm(self) -> int:
        """Execute the form and apply changes to global variables."""

        # Pre-fill form values
        self.controls["opt1"].value = SigMakerConfig.print_top_x
        self.controls["opt2"].value = SigMakerConfig.max_single_signature_length
        self.controls["opt3"].value = SigMakerConfig.max_xref_signature_length
        self.controls["opt4"].value = SigMakerConfig.prompt_interval

        result = self.Execute()
        if result != 1:
            self.Free()
            return result

        SigMakerConfig.print_top_x = self.controls["opt1"].value
        SigMakerConfig.max_single_signature_length = self.controls["opt2"].value
        SigMakerConfig.max_xref_signature_length = self.controls["opt3"].value
        SigMakerConfig.prompt_interval = self.controls["opt4"].value
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
{PLUGIN_NAME} v{PLUGIN_VERSION} {"(SIMD ENABLED)" if SIMD_SPEEDUP_AVAILABLE else "(NO SIMD SPEEDUP)"}"""
            + r"""
{FormChangeCb}
Select action:
<#Select an address, and create a code signature for it#Create unique signature for current code address:{rCreateUniqueSig}>
<#Select an address or variable, and create code signatures for its references. Will output the shortest 5 signatures#Find shortest XREF signature for current data or code address:{rFindXRefSig}>
<#Select 1+ instructions, and copy the bytes using the specified output format#Copy selected code:{rCopyCode}>
<#Paste any string containing your signature/mask and find matches#Search for a signature:{rSearchSignature}>
<#Find the shortest unique signature anywhere inside the current function, with automatic xref fallback if the function body is not unique#Find shortest unique signature for current function:{rFindFunctionSig}>{rAction}>

Output format:
<#Example - E8 ? ? ? ? 45 33 F6 66 44 89 34 33#IDA Signature:{rIDASig}>
<#Example - E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33#x64Dbg Signature:{rx64DbgSig}>
<#Example - \\\xE8\\\x00\\\x00\\\x00\\\x00\\\x45\\\x33\\\xF6\\\x66\\\x44\\\x89\\\x34\\\x33 x????xxxxxxxx#C Byte Array String Signature + String mask:{rByteArrayMaskSig}>
<#Example - 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33 0b1111111100001#C Bytes Signature + Bitmask:{rRawBytesBitmaskSig}>{rOutputFormat}>

Quick Options:
<#Enable wildcarding for operands, to improve stability of created signatures#Wildcards for operands:{cWildcardOperands}>
<#Don't stop signature generation when reaching end of function#Continue when leaving function scope:{cContinueOutside}>
<#Wildcard the whole instruction when the operand (usually a register) is encoded into the operator#Wildcard optimized / combined instructions:{cWildcardOptimized}>
<#Opt-in -- show periodic 'Continue?' prompts while generating. Default is a wait-box with a Cancel button.#Enable continue prompt (opt-in):{cEnablePrompt}>
<#Opt-in -- when you cancel a unique-signature search, output the partial signature (with match count) instead of nothing. Default off. (Issue #22)#Output partial signature on cancel (opt-in):{cOutputPartialOnCancel}>{cGroupOptions}>

<Operand types...:{bOperandTypes}><Other options...:{bOtherOptions}>
"""
        )
        controls = {
            "cVersion": F.StringLabel(PLUGIN_VERSION),
            "FormChangeCb": F.FormChangeCb(self.OnFormChange),
            "rAction": F.RadGroupControl(
                (
                    "rCreateUniqueSig",
                    "rFindXRefSig",
                    "rCopyCode",
                    "rSearchSignature",
                    "rFindFunctionSig",
                )
            ),
            "rOutputFormat": F.RadGroupControl(
                ("rIDASig", "rx64DbgSig", "rByteArrayMaskSig", "rRawBytesBitmaskSig")
            ),
            "cGroupOptions": idaapi.Form.ChkGroupControl(
                (
                    "cWildcardOperands",
                    "cContinueOutside",
                    "cWildcardOptimized",
                    "cEnablePrompt",
                    "cOutputPartialOnCancel",
                ),
                # Bits: 1 (wildcards) + 4 (wildcard optimized). Bit 8 (enable
                # prompt) and bit 16 (output partial on cancel) default OFF.
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

    def __init__(self, action_function, always_enabled: bool = False):
        super().__init__()
        self.action_function = action_function
        self.always_enabled = always_enabled

    def activate(self, ctx: idaapi.action_ctx_base_t) -> int:
        self.action_function(ctx=ctx)
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t) -> int:
        if self.always_enabled:
            return idaapi.AST_ENABLE_ALWAYS
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
    ACTION_START_PROFILING: str = "pysigmaker:start_profiling"
    ACTION_STOP_PROFILING: str = "pysigmaker:stop_profiling"
    PROFILING_MENU_PATH: str = "Edit/Plugins/"

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
        idaapi.register_action(
            idaapi.action_desc_t(
                self.ACTION_START_PROFILING,
                "SigMaker: Start profiling",
                _ActionHandler(self._action_start_profiling, always_enabled=True),
                None,
                "Start a cProfile session capturing subsequent SigMaker activity.",
            )
        )
        idaapi.register_action(
            idaapi.action_desc_t(
                self.ACTION_STOP_PROFILING,
                "SigMaker: Stop profiling and dump",
                _ActionHandler(self._action_stop_profiling, always_enabled=True),
                None,
                "Stop the active cProfile session and write the dump to the user IDA dir.",
            )
        )
        idaapi.attach_action_to_menu(
            self.PROFILING_MENU_PATH, self.ACTION_START_PROFILING, idaapi.SETMENU_APP
        )
        idaapi.attach_action_to_menu(
            self.PROFILING_MENU_PATH, self.ACTION_STOP_PROFILING, idaapi.SETMENU_APP
        )

    def _deregister_actions(self) -> None:
        idaapi.unregister_action(self.ACTION_SHOW_SIGMAKER)
        idaapi.unregister_action(self.ACTION_START_PROFILING)
        idaapi.unregister_action(self.ACTION_STOP_PROFILING)

    def _action_start_profiling(self, ctx=None) -> None:
        start_profiling()

    def _action_stop_profiling(self, ctx=None) -> None:
        stop_profiling()

    def run(self, ctx) -> None:
        """Entry point called when the user activates the plugin."""
        with SignatureMakerForm() as form:
            form.Compile()
            ok = form.Execute()
            if not ok:
                return

            action = Action(int(form.rAction.value))  # type: ignore
            output_format = form.rOutputFormat.value  # type: ignore
            wildcard_operands = bool(form.cGroupOptions.value & 1)  # type: ignore
            continue_outside_of_function = bool(form.cGroupOptions.value & 2)  # type: ignore
            wildcard_optimized = bool(form.cGroupOptions.value & 4)  # type: ignore
            enable_continue_prompt = bool(form.cGroupOptions.value & 8)  # type: ignore
            output_partial_on_cancel = bool(form.cGroupOptions.value & 16)  # type: ignore

        # Create SigMakerConfig
        config = SigMakerConfig(
            output_format=SignatureType.at(int(output_format)),
            wildcard_operands=wildcard_operands,
            continue_outside_of_function=continue_outside_of_function,
            wildcard_optimized=wildcard_optimized,
            enable_continue_prompt=enable_continue_prompt,
            output_partial_on_cancel=output_partial_on_cancel,
        )

        try:
            if action == Action.CREATE_UNIQUE:
                ea = idaapi.get_screen_ea()
                policy = (
                    GenerationPolicy.permissive()
                    if config.output_partial_on_cancel
                    else GenerationPolicy.strict()
                )
                # ProgressBox inside UniqueSignatureGenerator.generate owns
                # the wait box; no outer wrapper needed.
                signature = SignatureMaker().make_signature(
                    ea, config, policy=policy
                )
                signature.display(config)
            elif action == Action.FIND_XREF:
                ea = idaapi.get_screen_ea()
                signatures = XrefFinder().find_xrefs(ea, config)
                signatures.display(cfg=config)
            elif action == Action.COPY_RANGE:
                start, end = self.get_selected_addresses(idaapi.get_current_viewer())
                if start and end:
                    with ProgressDialog(
                        "Copy selected code\n\n"
                        "Building a signature for the selected address "
                        "range.\n\n"
                        "Press Cancel to stop"
                    ):
                        signature = SignatureMaker().make_signature(
                            start, config, end=end
                        )
                    signature.display(config)
                else:
                    idaapi.msg("Select a range to copy the code!\n")
            elif action == Action.SEARCH:
                input_signature = idaapi.ask_str(
                    "", idaapi.HIST_SRCH, "Enter a signature"
                )
                if input_signature:
                    searcher = SignatureSearcher.from_signature(input_signature)
                    results = searcher.search()
                    results.display()
                else:
                    idaapi.msg("No signature entered!\n")
            elif action == Action.FIND_FUNCTION_SIG:
                self._run_find_function_sig(config)
            else:
                idaapi.msg("Invalid action!\n")
        except Unexpected as e:
            idaapi.msg(f"Error: {str(e)}\n")
        except UserCanceledError:
            # User cancellation is expected, not an error
            idaapi.msg("Operation canceled by user\n")
        except Exception as e:
            LOGGER.error("Exception occurred: %s%s%s", e, os.linesep, traceback.format_exc())
            return

    def _run_find_function_sig(self, config: SigMakerConfig) -> None:
        """Action.FIND_FUNCTION_SIG: shortest unique sig within the function,
        falling back to xref signatures if the function body is not unique."""
        ea = idaapi.get_screen_ea()
        pfn = idaapi.get_func(ea)
        if pfn is None:
            idaapi.msg("Place cursor inside a function first.\n")
            return

        try:
            # ProgressBox inside MinimalFunctionSignatureGenerator.generate
            # owns the wait box; no outer wrapper needed.
            generator = MinimalFunctionSignatureGenerator(
                InstructionProcessor(OperandProcessor())
            )
            result = generator.generate(pfn, config)
            offset = int(result.address) - int(pfn.start_ea)
            idaapi.msg(
                f"Function signature (offset +{hex(offset)} into function "
                f"{hex(pfn.start_ea)}):\n"
            )
            result.display(config)
            return
        except Unexpected:
            idaapi.msg(
                f"No unique signature inside function "
                f"{hex(pfn.start_ea)}; trying xref signatures...\n"
            )

        with ProgressDialog(
            "Falling back to xref signatures...\n\nPress Cancel to stop"
        ):
            xref_result = XrefFinder().find_xrefs(pfn.start_ea, config)

        if xref_result.signatures:
            best = xref_result.signatures[0]
            idaapi.msg(
                f"Xref signature into {hex(pfn.start_ea)} (from {best.address}):\n"
            )
            best.display(config)
        else:
            idaapi.msg(
                f"No unique signature found for function {hex(pfn.start_ea)} "
                f"(no unique sig within body and no usable xrefs)\n"
            )

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
            idaapi.msg(
                f"Error: End address 0x{end_ea:X} must be greater than start address 0x{start_ea:X}."
            )
            end_ea = None
        if end_ea is None:
            end_ea = idc.get_item_end(start_ea)
            idaapi.msg(f"No end address selected, using line end: 0x{end_ea:X}")

        return start_ea, end_ea


def PLUGIN_ENTRY() -> SigMakerPlugin:
    """Entry point function required by IDA Pro to instantiate the plugin."""
    return SigMakerPlugin()


# no cover: stop
