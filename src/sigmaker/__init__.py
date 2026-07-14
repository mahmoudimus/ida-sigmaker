"""
sigmaker.py - IDA Python Signature Maker
https://github.com/mahmoudimus/ida-sigmaker

by @mahmoudimus (Mahmoud Abdelkader)
"""

from __future__ import annotations

import array
import contextlib
import contextvars
import csv
import dataclasses
import enum
import functools
import io
import json
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
__version__ = "1.11.0"

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


# How many matches a scan loop processes between cancellation polls.
# idaapi.user_cancelled() is not a cheap predicate: it pumps the UI event
# loop, so each call costs on the order of a millisecond. A short, common
# pattern can match tens of millions of positions, so polling too often makes
# the poll itself a multi-second cost (observed: 4,755 polls = 6.7s at an 8192
# stride). Polling every 65536 matches keeps that overhead near a second while
# leaving cancel responsive: the inter-poll scan work is only tens of
# milliseconds.
_CANCEL_POLL_STRIDE: int = 65536


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
    # (buffer_offset, seg_start_ea, size) per loaded segment, in buffer order.
    # Segments are concatenated tightly, so a buffer offset does not equal an
    # address once segments are non-contiguous (e.g. an extra binary loaded at a
    # distant address). This maps a match offset back to its real address (#68).
    _segments: list = dataclasses.field(
        default_factory=list, init=False, repr=False
    )

    @property
    def file_size(self) -> int:
        return idaapi.retrieve_input_file_size()

    @property
    def imagebase(self) -> int:
        return idaapi.get_imagebase()

    def _load_segments(self):
        """Load all IDA segments into a single contiguous bytearray buffer,
        recording each segment's buffer offset so a match offset can be mapped
        back to its real address (segments need not be contiguous, #68)."""
        buf = self._buffer
        seg = idaapi.get_first_seg()
        while seg:
            size = seg.end_ea - seg.start_ea
            data = idaapi.get_bytes(seg.start_ea, size)
            if data:
                self._segments.append((len(buf), int(seg.start_ea), len(data)))
                buf.extend(data)
            seg = idaapi.get_next_seg(seg.start_ea)

    def offset_mapper(self) -> typing.Callable[[int], int]:
        """Return a callable that maps ASCENDING buffer offsets to real IDA
        addresses. Segments are concatenated tightly even when their addresses
        are not contiguous, so ``imagebase + offset`` is wrong past the first
        non-contiguous segment (#68). The callable walks the segment map with a
        forward cursor, so mapping a run of ascending match offsets costs
        amortized O(1) each (vs a per-match binary search). Falls back to
        ``imagebase + offset`` when there is no segment map (FILE mode).
        """
        segs = self._segments
        if not segs:
            imagebase = self.imagebase
            return lambda offset: imagebase + offset
        state = [0]

        def _map(offset: int) -> int:
            i = state[0]
            while i + 1 < len(segs) and segs[i + 1][0] <= offset:
                i += 1
            state[0] = i
            buf_off, seg_ea, _size = segs[i]
            return seg_ea + (offset - buf_off)

        return _map

    def _load_single_segment(self, ea: int):
        """Load only the segment containing ``ea`` (issue #64), recording it in
        the segment map so offset_mapper resolves match addresses correctly.

        Falls back to loading all segments when ``ea`` is not inside any
        segment, so callers never end up with an empty corpus by accident.
        """
        seg = idaapi.getseg(ea)
        if seg is None:
            self._load_segments()
            return
        data = idaapi.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
        if data:
            self._segments.append((len(self._buffer), int(seg.start_ea), len(data)))
            self._buffer.extend(data)

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
        scope_ea: typing.Optional[int] = None,
    ) -> "InMemoryBuffer":
        """
        Load the buffer using the specified mode.
        mode: _LoadMode.SEGMENTS (default) or _LoadMode.FILE
        scope_ea: in SEGMENTS mode, load only the segment containing this
            address instead of all segments (issue #64). Ignored in FILE mode.
        """
        if file_path is None:
            file_path = idaapi.get_input_file_path()
        if isinstance(file_path, str):
            file_path = pathlib.Path(file_path)
        instance = cls(file_path=file_path, mode=mode)
        if mode == cls.LoadMode.FILE:
            instance._load_input_file()
        elif scope_ea is not None:
            instance._load_single_segment(scope_ea)
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
    # Issue #64: when True, scope uniqueness to the segment containing the
    # anchor instead of the whole database. Lets you sign functions that are
    # duplicated across segments (e.g. a boot section and a main section) as
    # long as the eventual search is scoped to the same segment. Default off.
    scope_to_segment: bool = False


@dataclasses.dataclass(slots=True, frozen=True, repr=False)
class Match:
    """Container for a single match.

    Acts like an int, but can also carry optional derived address metadata.
    """

    #: Effective address of the match.
    address: int
    #: Imagebase-relative offset for this match, when known.
    rva: typing.Optional[int] = dataclasses.field(
        default=None, kw_only=True, compare=False, hash=False, repr=False
    )
    #: Input-file offset for this match, when IDA can resolve it.
    file_offset: typing.Optional[int] = dataclasses.field(
        default=None, kw_only=True, compare=False, hash=False, repr=False
    )

    def __repr__(self) -> str:
        return f"Match(address={hex(self.address)})"

    def __str__(self) -> str:
        return hex(self.address)

    def __int__(self) -> int:
        return self.address

    __index__ = __int__

    def __hash__(self) -> int:
        return hash((self.address,))

    def __format__(self, format_spec: str) -> str:
        """Format address metadata for this hit.

        Supported named fields:
            - '' / 'ea' / 'address': effective address
            - 'rva': imagebase-relative offset
            - 'fileoffset' / 'file_offset' / 'file': input-file offset

        A nested integer format can follow a colon, e.g. ``rva:x``. If a
        requested optional field is unavailable, formatting returns
        ``repr(self)`` so output still shows the hit EA.
        """
        if not format_spec:
            return str(self)

        field, separator, nested_spec = format_spec.partition(":")
        normalized = field.lower().replace("_", "").replace("-", "")
        value: typing.Optional[int]
        if normalized in {"ea", "address"}:
            value = self.address
        elif normalized == "rva":
            value = self.rva
        elif normalized in {"fileoffset", "file"}:
            value = self.file_offset
        else:
            return format(self.address, format_spec)

        if value is None:
            return repr(self)
        if separator:
            return format(value, nested_spec)
        return f"0x{value:X}"

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
        # Default to address-bearing operands only: direct memory references,
        # displacements, immediates, and near/far branch targets. is_off refines
        # the ambiguous imm/displ operands to actual addresses at match time
        # (see OperandProcessor._get_operand_offset_arm), so bare constants and
        # stack slots are not wildcarded. Register lists, coprocessor registers,
        # ARM conditions, arbitrary text, and plain registers are stable across
        # builds and are left out of the default; users who need register-
        # tolerant matching enable them in the operand-wildcard dialog.
        return cls(frozenset({
            cls.BaseKind.MEM,
            cls.BaseKind.DISPL,
            cls.BaseKind.IMM,
            cls.BaseKind.NEAR,
            cls.BaseKind.FAR,
        }))

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


def _func_name_suffix(ea: int) -> str:
    """Return ' (funcname)' when ``ea`` lies inside a named function, else ''.

    Labels addresses in human-facing output with the containing function name
    when one is available, falling back to the bare address. The isinstance
    guard keeps the suffix empty when idaapi.get_func_name returns a non-string
    (e.g. under a mocked idaapi in tests) or nothing.
    """
    with contextlib.suppress(BaseException):
        name = idaapi.get_func_name(ea)
        if isinstance(name, str) and name:
            return f" ({name})"
    return ""


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
            if self.address is not None:
                prefix = (
                    f"Partial signature (NOT unique, {count_str}) for "
                    f"{self.address}{_func_name_suffix(int(self.address))}"
                )
            else:
                prefix = f"Partial signature (NOT unique, {count_str})"
            idaapi.msg(f"{prefix}: {fmted}\n")
            return

        if self.address is not None:
            idaapi.msg(
                f"Signature for {self.address}"
                f"{_func_name_suffix(int(self.address))}: {fmted}\n"
            )
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
            idaapi.msg(
                f"XREF Signature #{i} @ {address}"
                f"{_func_name_suffix(int(address))}: {fmted}\n"
            )
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
        # Which operands to wildcard is driven by the user's operand-wildcard
        # policy (the "Configure operand wildcarding" dialog); the default is
        # address-bearing types only (see WildcardPolicy.for_arm). On top of the
        # policy we apply an is_off refinement for the two ambiguous types:
        # o_imm and o_displ carry both build-varying addresses (ADRP #x@PAGE,
        # LDR #x@PAGEOFF) and stable constants (#0x40) / stack slots ([SP,#var]).
        # We wildcard only the ones IDA resolved to an address (is_off), so
        # selecting "Immediate"/"Displacement" never masks a stable constant.
        #
        # Byte range: little-endian ARM/Thumb keeps the opcode+condition in the
        # high byte and the immediate/offset in the low bytes, so wildcarding the
        # low ins.size-1 bytes usually suffices (Thumb-1 = 2 bytes -> length 1;
        # ARM/Thumb-2 = 4 -> 3; 8 -> 7). But some offsets reach into the high
        # byte: branch targets (Thumb-2 BL/BLX and long B span all bytes) and
        # AArch64 ADRP (immlo sits in the high byte). For those we must wildcard
        # the whole instruction, or the offset bits left in the high byte make
        # the signature miss other builds (issue #61 follow-up).
        policy = WildcardPolicy.current()
        flags = idaapi.get_flags(ins.ea)
        for op in ins:
            if op.type == idaapi.o_void:
                continue
            if op.type not in policy.allowed_types:
                continue
            if op.type in (idaapi.o_imm, idaapi.o_displ) and not idaapi.is_off(
                flags, op.n
            ):
                continue
            # o_imm reaching here is is_off (an address immediate, e.g. ADRP);
            # together with branch targets its offset can span the high byte.
            spans_high_byte = op.type in (
                idaapi.o_near,
                idaapi.o_far,
                idaapi.o_imm,
            )
            if spans_high_byte:
                off[0] = 0
                length[0] = ins.size
            else:
                off[0] = op.offb
                length[0] = ins.size - 1 if ins.size in (2, 4, 8) else 0
            return True
        return False

    def get_operand(
        self,
        ins: idaapi.insn_t,
        off: typing.List[int],
        length: typing.List[int],
        wildcard_optimized: bool,
    ) -> bool:
        if self._is_arm:
            return self._get_operand_offset_arm(ins, off, length)
        policy = WildcardPolicy.current()
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

        # SIMD path: scan the database once to seed a candidate-offset set,
        # then refine that set in memory as the pattern grows instead of
        # re-scanning per appended instruction. offsets is None until the
        # first scan; buf holds the segment buffer the offsets index into.
        offsets: typing.Optional[list[int]] = None
        buf: typing.Optional["InMemoryBuffer"] = None
        if cfg.scope_to_segment:
            # Issue #64: scope uniqueness to the anchor's segment. Pre-load it so
            # the seed scan and every refinement stay within the segment.
            buf = InMemoryBuffer.load(
                mode=InMemoryBuffer.LoadMode.SEGMENTS, scope_ea=ea
            )

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

                prev_len = len(sig)
                self.processor.append_instruction_to_sig(
                    sig, cur_ea, ins, cfg.wildcard_operands, cfg.wildcard_optimized
                )
                bytes_since_last_check += ins_len

                if not SIMD_SPEEDUP_AVAILABLE:
                    # Non-SIMD builds have no in-memory buffer to refine
                    # against, so fall back to the per-step rescan.
                    count = SignatureSearcher.count_matches(f"{sig:ida}", buf=buf)
                elif offsets is None:
                    # Seed once: scan the whole database, keep every match
                    # offset. The candidate count is the exact match count.
                    offsets, buf = SignatureSearcher.find_all_offsets(
                        f"{sig:ida}", buf=buf
                    )
                    count = len(offsets)
                else:
                    # Refine the surviving candidates in memory for each byte
                    # appended this iteration; no rescan of the database.
                    data_mv = buf.data()
                    for j in range(prev_len, len(sig)):
                        sb = sig[j]
                        mask = 0x00 if sb.is_wildcard else 0xFF
                        offsets = _refine_offsets(data_mv, offsets, j, sb.value, mask)
                    count = len(offsets)
                # find_all_offsets polls idaapi_user_canceled inside its scan
                # loop and bails when set, returning whatever partial offsets
                # it had so far (often 0). When the call was interrupted, keep
                # last_match_count at its prior trustworthy value (issue #22):
                # the reported number is an upper bound on the partial's actual
                # match count rather than a meaningless 0. Refinement never
                # bails mid-pass, so its count is always trustworthy.
                if not idaapi_user_canceled():
                    progress.last_match_count = count
                    if count == 1:
                        sig.trim_signature()
                        return GeneratedSignature(sig, Match(ea))

        if cancel.partial is not None:
            return cancel.partial
        raise Unexpected("Signature not unique (reached end of analysis)")


def _refine_offsets(
    data_mv: memoryview,
    offsets: list[int],
    j: int,
    value: int,
    mask: int,
) -> list[int]:
    """Keep offsets c where (data_mv[c + j] & mask) == (value & mask).

    j is the pattern-relative index of the byte being checked; c is a match
    start offset into data_mv. Candidates whose c + j runs past the buffer
    cannot match and are dropped. Used to refine a shrinking candidate set
    as a signature grows, instead of re-scanning the whole database.
    """
    n = len(data_mv)
    target = value & mask
    return [c for c in offsets if c + j < n and (data_mv[c + j] & mask) == target]


def _refine_offsets_into(
    data_mv: memoryview,
    cands: "array.array",
    count: int,
    j: int,
    value: int,
    mask: int,
) -> int:
    """Refine the first ``count`` entries of the uint32 array ``cands`` in
    place (Cython when available), returning the new count. The function-sig
    path only reaches this on the SIMD path; the Python branch is a defensive
    fallback that mirrors _refine_offsets.
    """
    if SIMD_SPEEDUP_AVAILABLE:
        return simd_scan.refine_offsets(data_mv, cands, count, j, value, mask)
    n = len(data_mv)
    target = value & mask
    w = 0
    for r in range(count):
        c = cands[r]
        if c + j < n and (data_mv[c + j] & mask) == target:
            cands[w] = cands[r]
            w += 1
    return w


@dataclasses.dataclass(frozen=True, slots=True)
class _ByteIndex:
    """A 2-byte bucket position index over the segment buffer.

    Wraps simd_scan.build_byte_index. bucket_size is O(1) and candidates is
    O(bucket). Built once per generate() and discarded; reused across all
    anchors in that one search.
    """

    heads: "array.array"
    positions: "array.array"

    @classmethod
    def build(cls, data_mv: memoryview) -> typing.Optional["_ByteIndex"]:
        if not SIMD_SPEEDUP_AVAILABLE or len(data_mv) < 2:
            return None
        heads, positions = simd_scan.build_byte_index(data_mv)
        return cls(heads, positions)

    def bucket_size(self, key: int) -> int:
        return self.heads[key + 1] - self.heads[key]

    def candidates(self, key: int) -> "array.array":
        # positions is array.array('I'), so slicing yields array.array('I').
        return self.positions[self.heads[key]:self.heads[key + 1]]

    def bucket_size1(self, b: int) -> int:
        # 1-byte bucket for b: all 2-byte keys (b<<8)..((b+1)<<8 - 1) telescope
        # into one contiguous range, so its size is heads[(b+1)<<8]-heads[b<<8].
        return self.heads[(b + 1) << 8] - self.heads[b << 8]

    def candidates1(self, b: int) -> "array.array":
        return self.positions[self.heads[b << 8]:self.heads[(b + 1) << 8]]


def _select_seed_run(
    sig: "Signature", index: "_ByteIndex"
) -> typing.Optional[tuple[int, int, int]]:
    """Pick the unmasked run (2-byte or single byte) with the smallest index
    bucket (Dynamic Seed Selection), returning (offset, width, key).

    Minimizing over both widths is a superset of the 2-byte-only choice, so
    the chosen bucket is always <= a 2-byte-only pick: C0 is strictly
    smaller-or-equal. A rare single byte can beat a common 2-byte run.
    Returns None only when sig has no exact byte at all.
    """
    best: typing.Optional[tuple[int, int, int, int]] = None  # (size, offset, width, key)
    m = len(sig)
    for j in range(m - 1):
        a = sig[j]
        b = sig[j + 1]
        if a.is_wildcard or b.is_wildcard:
            continue
        key = (a.value << 8) | b.value
        size = index.bucket_size(key)
        if best is None or size < best[0]:
            best = (size, j, 2, key)
    for j in range(m):
        sb = sig[j]
        if sb.is_wildcard:
            continue
        size = index.bucket_size1(sb.value)
        if best is None or size < best[0]:
            best = (size, j, 1, sb.value)
    if best is None:
        return None
    return best[1], best[2], best[3]


def _seed_via_index(
    sig: "Signature",
    index: typing.Optional["_ByteIndex"],
    buf: "InMemoryBuffer",
) -> typing.Optional[tuple["array.array", int]]:
    """Seed the candidate set from the byte index instead of scanning.

    Picks the most selective unmasked run (1-byte or 2-byte) via Dynamic Seed
    Selection, maps its hits back to candidate pattern-starts, and refines
    against the rest of the pattern so the result equals matches(full pattern).
    Returns (candidates_array, count), or None if the index is unavailable or
    the pattern has no exact byte at all (caller falls back to a scan).
    """
    if index is None:
        return None
    run = _select_seed_run(sig, index)
    if run is None:
        return None
    s, width, key = run
    data_mv = buf.data()
    n = len(data_mv)
    m = len(sig)
    raw = index.candidates(key) if width == 2 else index.candidates1(key)
    # Map each hit at offset p back to a pattern start p - s, keeping only
    # candidates whose full pattern fits in the buffer. The Cython kernel does
    # this in one nogil pass; the genexp is the defensive fallback (unreachable
    # in practice, since index is None without SIMD).
    if SIMD_SPEEDUP_AVAILABLE:
        cands, count = simd_scan.seed_offsets(raw, s, m, n)
    else:
        cands = array.array(
            "I", (p - s for p in raw if p >= s and (p - s) + m <= n)
        )
        count = len(cands)
    # n-1 boundary: candidates1 is derived from 2-byte windows, which never see
    # offset n-1 as a window start, so a 1-byte hit at the final buffer byte is
    # missing. It can only yield a valid pattern start when the seed byte is the
    # pattern's last byte (s == m-1, giving start n-m). Add it explicitly and
    # let the refine validate. The kernel reserves one slot for it.
    if width == 1 and n >= 1 and data_mv[n - 1] == key:
        p = n - 1 - s
        if 0 <= p and p + m <= n:
            if count < len(cands):
                cands[count] = p
            else:
                cands.append(p)
            count += 1
    # Refine against every exact byte except the seed run's byte(s).
    seed_span = (s, s + 1) if width == 2 else (s,)
    for j in range(m):
        if j in seed_span:
            continue
        sb = sig[j]
        if sb.is_wildcard:
            continue
        count = _refine_offsets_into(data_mv, cands, count, j, sb.value, 0xFF)
    return cands, count


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
        index: typing.Optional["_ByteIndex"] = None
        if SIMD_SPEEDUP_AVAILABLE:
            with ProgressDialog("Please stand by, copying segments..."):
                buf = InMemoryBuffer.load(
                    mode=InMemoryBuffer.LoadMode.SEGMENTS,
                    scope_ea=int(pfn.start_ea) if cfg.scope_to_segment else None,
                )
            # Build the 2-byte position index once for the whole search so each
            # anchor seeds with an O(1) lookup instead of a full-buffer scan.
            index = _ByteIndex.build(buf.data())

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
                buf=buf, progress=progress, index=index,
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
        index: typing.Optional["_ByteIndex"] = None,
    ) -> typing.Optional[Signature]:
        """Grow a signature from ``decoded[anchor_idx]`` forward until unique.

        Reads all instruction data from the pre-decoded list. The ``buf``
        argument is the segment buffer loaded once in generate(); on the SIMD
        path it seeds an in-memory candidate-offset set that is refined per
        appended byte, so the database is scanned once per anchor rather than
        once per growth step. On non-SIMD builds (no in-memory buffer) it
        falls back to a per-step count_matches scan.

        The surviving candidate count is the exact match count, so if
        ``progress`` is supplied the per-iteration sig length and the exact
        match count are written into its ``inner_length`` / ``inner_matches``
        fields for the live wait-box display.
        """
        sig = Signature()
        # SIMD seed-then-refine state: candidates as a uint32 array.array plus a
        # live count, refined in place by the Cython refine_offsets.
        offsets: typing.Optional["array.array"] = None
        ocount = 0
        seed_buf = buf
        min_useful = self.MIN_USEFUL_SIG_BYTES
        for i in range(anchor_idx, len(decoded)):
            if (
                self.progress_reporter is not None
                and self.progress_reporter.should_cancel()
            ):
                raise UserCanceledError(
                    "Function signature search canceled by user"
                )

            prev_len = len(sig)
            self._append_decoded_to_sig(sig, decoded[i])

            if len(sig) > max_len:
                return None

            # Below MIN_USEFUL_SIG_BYTES the seed scan would enumerate every
            # match of a short, common prefix (e.g. a 1-byte instruction that
            # occurs hundreds of thousands of times) only for the caller to
            # discard the result for being too short. Probe uniqueness with a
            # cheap early-bail scan instead, and defer the (now selective)
            # seed-and-refine until the pattern is long enough to be a valid
            # answer. The early-bail probe preserves exact behavior: an anchor
            # that becomes unique below MIN still returns its short signature
            # here, which the caller discards, so the anchor contributes no
            # candidate, exactly as before.
            if len(sig) < min_useful:
                if progress is not None:
                    progress.inner_length = len(sig)
                    progress.inner_matches = None
                if SignatureSearcher.is_unique(f"{sig:ida}", buf=buf):
                    sig.trim_signature()
                    return sig
                continue

            if not SIMD_SPEEDUP_AVAILABLE or seed_buf is None:
                # Non-SIMD builds have no in-memory buffer to refine against,
                # so fall back to the per-step rescan.
                count = SignatureSearcher.count_matches(f"{sig:ida}", buf=buf)
            elif offsets is None:
                # Seed once. Prefer the byte index (Dynamic Seed Selection).
                seeded = _seed_via_index(sig, index, seed_buf)
                if seeded is not None:
                    offsets, ocount = seeded
                    count = ocount
                elif index is not None:
                    # No exact byte yet: an all-wildcard pattern matches at
                    # ~every position, so it cannot be unique. Defer the seed
                    # (skip the O(N) full scan) until an exact byte appears on a
                    # later iteration, then seed via the index. The first length
                    # that can be unique is unchanged, so the signature is too.
                    if progress is not None:
                        progress.inner_length = len(sig)
                        progress.inner_matches = None
                    continue
                else:
                    # Index genuinely unavailable (e.g. buffer < 2 bytes): keep
                    # the scan fallback so no anchor is silently skipped.
                    lst, seed_buf = SignatureSearcher.find_all_offsets(
                        f"{sig:ida}", buf=seed_buf
                    )
                    offsets = array.array("I", lst)
                    ocount = len(offsets)
                    count = ocount
            else:
                # Refine the surviving candidates in place for each byte
                # appended this iteration; no rescan of the database.
                data_mv = seed_buf.data()
                for j in range(prev_len, len(sig)):
                    sb = sig[j]
                    mask = 0x00 if sb.is_wildcard else 0xFF
                    ocount = _refine_offsets_into(
                        data_mv, offsets, ocount, j, sb.value, mask
                    )
                count = ocount

            if progress is not None:
                progress.inner_length = len(sig)
                progress.inner_matches = count
            if count == 1:
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
            except UserCanceledError:
                break
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
    """Result container for one signature search operation.

    ``signature_str`` is kept for compatibility. New code should use
    ``search_pattern`` for the parsed SigMaker search pattern and
    ``raw_pattern`` for the exact extracted user input.
    """

    #: Matched addresses for this search.
    matches: list[Match]
    #: Parsed SigMaker search pattern, kept for compatibility.
    signature_str: str
    #: Exact user input extracted for this search entry.
    raw_pattern: str = ""
    #: Optional user-supplied pattern name.
    name: str = ""
    #: One-based source line in batch input, or zero when unknown.
    source_line: int = 0
    #: Per-entry parse or search error; empty when the entry succeeded.
    error: str = ""
    #: Canonical matcher/cache pattern, preserving supported wildcard detail.
    canonical_pattern: str = ""
    #: Lazily resolved file offsets, including unavailable values.
    _file_offset_cache: dict[int, typing.Optional[int]] = dataclasses.field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    @property
    def search_pattern(self) -> str:
        """Parsed SigMaker search pattern, e.g. ``48 8B ? 4? ?F``."""
        return self.signature_str

    @property
    def normalized_signature(self) -> str:
        return self.canonical_pattern or self.signature_str

    @property
    def display_name(self) -> str:
        if self.name:
            return self.name
        if self.source_line:
            return f"Pattern line {self.source_line}"
        return "Pattern"

    @property
    def status(self) -> str:
        if self.error:
            return "error"
        if self.matches:
            return "matched"
        return "no_matches"

    @property
    def match_count(self) -> int:
        return len(self.matches)

    @staticmethod
    def current_imagebase(
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> typing.Optional[int]:
        if buf is not None:
            imagebase = getattr(buf, "imagebase", None)
            if isinstance(imagebase, int):
                return imagebase
        with contextlib.suppress(BaseException):
            imagebase = idaapi.get_imagebase()
            if isinstance(imagebase, int):
                return imagebase
        return None

    @staticmethod
    def _file_offset_for_ea(ea: int) -> typing.Optional[int]:
        with contextlib.suppress(Exception):
            file_offset = idaapi.get_fileregion_offset(ea)
            if (
                isinstance(file_offset, int)
                and file_offset >= 0
                and file_offset != idaapi.BADADDR
            ):
                return file_offset
        return None

    def file_offset_for_match(self, hit: Match) -> typing.Optional[int]:
        if hit.file_offset is not None:
            return hit.file_offset
        ea = int(hit)
        if ea not in self._file_offset_cache:
            self._file_offset_cache[ea] = self._file_offset_for_ea(ea)
        return self._file_offset_cache[ea]

    def _match_record(self, hit: Match) -> dict[str, typing.Optional[int]]:
        return {
            "ea": int(hit),
            "rva": hit.rva,
            "file_offset": self.file_offset_for_match(hit),
        }

    def to_record(self) -> dict[str, typing.Any]:
        return {
            "name": self.name,
            "source_line": self.source_line,
            "raw_pattern": self.raw_pattern,
            "search_pattern": self.search_pattern,
            "normalized_signature": self.normalized_signature,
            "status": self.status,
            "match_count": self.match_count,
            "matches": [
                self._match_record(hit) for hit in self.matches
            ],
            "error": self.error,
        }

    def display(self) -> None:
        """Display the search results to the user."""
        idaapi.msg(f"Signature: {self.search_pattern}\n")

        if self.error:
            idaapi.msg(f"Error: {self.error}\n")
            return

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


@dataclasses.dataclass(slots=True)
class BatchSearchResults:
    """Result container for batch signature searches."""

    #: Per-entry search results, in input order.
    results: list[SearchResults]
    #: Imagebase shared by the batch search, when known.
    imagebase: typing.Optional[int] = None

    def __iter__(self) -> typing.Iterator[SearchResults]:
        return iter(self.results)

    def __len__(self) -> int:
        return len(self.results)

    def __getitem__(
        self,
        index: typing.Union[int, slice],
    ) -> typing.Union[SearchResults, list[SearchResults]]:
        return self.results[index]

    def __str__(self) -> str:
        return self.format()

    def __format__(self, format_spec: str) -> str:
        return self.format(format_spec or None)

    @property
    def matched_count(self) -> int:
        return sum(1 for result in self.results if result.matches)

    @property
    def error_count(self) -> int:
        return sum(1 for result in self.results if result.error)

    def format(
        self,
        formatter: typing.Optional[
            typing.Union[str, "BatchSearchFormatter"]
        ] = None,
    ) -> str:
        formatter = _batch_search_formatter(formatter)
        return formatter.format(self)

    def display(
        self,
        output: typing.Optional[
            typing.Union[typing.TextIO, typing.Callable[[str], typing.Any]]
        ] = None,
        formatter: typing.Optional[
            typing.Union[str, "BatchSearchFormatter"]
        ] = None,
    ) -> None:
        text = self.format(formatter)
        if output is None:
            idaapi.msg(text)
            return

        writer = getattr(output, "write", None)
        if writer is not None:
            writer(text)
            return
        output(text)

    def to_record(self) -> dict[str, typing.Any]:
        return {
            "entry_count": len(self.results),
            "matched_count": self.matched_count,
            "error_count": self.error_count,
            "imagebase": self.imagebase,
            "entries": [
                result.to_record()
                for result in self.results
            ],
        }


class BatchSearchFormatter(typing.Protocol):
    """Protocol for objects that can format batch search results."""

    @classmethod
    def register(
        cls,
        name: str,
        suffixes: typing.Iterable[str] = (),
        *,
        override: bool = False,
    ) -> typing.Callable[[typing.Any], typing.Any]:
        """Register a batch formatter class or formatter object.

        Used as:
            @BatchSearchFormatter.register("myfmt", suffixes=(".mine",))
            class MyFormatter:
                def format(self, results): ...

        Duplicate names or suffixes raise ValueError without changing either
        registry. Pass override=True only when intentionally replacing an
        existing name or rebinding a suffix.
        """

        def decorator(formatter: typing.Any) -> typing.Any:
            instance = formatter() if isinstance(formatter, type) else formatter
            _register_batch_search_formatter(
                name,
                instance,
                suffixes,
                override=override,
            )
            return formatter

        return decorator

    def format(self, results: BatchSearchResults) -> str:
        """Format the given batch search results."""
        ...


#: Registered batch-search formatter instances, keyed by lowercase name.
_BATCH_SEARCH_FORMATTERS: dict[str, BatchSearchFormatter] = {}
#: Mapping from lowercase file suffix to registered formatter name.
_BATCH_SEARCH_FORMAT_SUFFIXES: dict[str, str] = {}


def _register_batch_search_formatter(
    name: str,
    formatter: BatchSearchFormatter,
    suffixes: typing.Iterable[str] = (),
    *,
    override: bool = False,
) -> None:
    normalized_name = name.strip().lower()
    if not normalized_name:
        raise ValueError("Batch search formatter name cannot be empty")

    normalized_suffixes: list[str] = []
    for suffix in suffixes:
        normalized_suffix = suffix.strip().lower()
        if not normalized_suffix:
            continue
        if not normalized_suffix.startswith("."):
            normalized_suffix = "." + normalized_suffix
        if normalized_suffix not in normalized_suffixes:
            normalized_suffixes.append(normalized_suffix)

    collisions: list[str] = []
    if normalized_name in _BATCH_SEARCH_FORMATTERS:
        collisions.append(f"name {normalized_name!r}")
    for normalized_suffix in normalized_suffixes:
        existing_name = _BATCH_SEARCH_FORMAT_SUFFIXES.get(normalized_suffix)
        if existing_name is not None:
            collisions.append(
                f"suffix {normalized_suffix!r} registered to {existing_name!r}"
            )
    if collisions and not override:
        details = ", ".join(collisions)
        raise ValueError(
            "Batch search formatter registration conflicts with "
            f"{details}; pass override=True if you are sure you want to "
            "replace the existing registration"
        )

    _BATCH_SEARCH_FORMATTERS[normalized_name] = formatter
    for normalized_suffix in normalized_suffixes:
        _BATCH_SEARCH_FORMAT_SUFFIXES[normalized_suffix] = normalized_name


def _hex_or_none(value: typing.Optional[int]) -> typing.Optional[str]:
    if value is None:
        return None
    return f"0x{value:X}"


@BatchSearchFormatter.register("text", suffixes=(".txt",))
@dataclasses.dataclass(frozen=True, slots=True)
class BatchSearchTextFormatter:
    """Human-readable batch search summary."""

    #: Include IDA function names next to previewed matches.
    include_function_names: bool = False
    #: Maximum number of matches to preview for each batch entry.
    max_preview_matches: int = 3

    def _format_match(self, entry: SearchResults, hit: Match) -> str:
        label = str(hit)
        details: list[str] = []
        rva = _hex_or_none(hit.rva)
        if rva is not None:
            details.append(f"rva {rva}")
        file_offset = _hex_or_none(entry.file_offset_for_match(hit))
        if file_offset is not None:
            details.append(f"file {file_offset}")
        if self.include_function_names:
            with contextlib.suppress(BaseException):
                fn_name = idaapi.get_func_name(int(hit))
                if fn_name:
                    details.append(fn_name)
        if details:
            return f"{label} ({', '.join(details)})"
        return label

    def format(self, results: BatchSearchResults) -> str:
        lines = [
            f"Batch search finished: {results.matched_count}/"
            f"{len(results)} matched, {results.error_count} error(s)",
        ]
        imagebase = _hex_or_none(results.imagebase)
        if imagebase is not None:
            lines.append(f"Imagebase: {imagebase}")
        for entry in results:
            label = entry.display_name
            if entry.error:
                lines.append(f"[{label}] ERROR: {entry.error}")
                continue
            lines.append(
                f"[{label}] {entry.match_count} match(es) for "
                f"{entry.search_pattern}"
            )
            if entry.matches:
                preview_matches = entry.matches[: self.max_preview_matches]
                preview = ", ".join(
                    self._format_match(entry, hit) for hit in preview_matches
                )
                if entry.match_count > self.max_preview_matches:
                    preview += (
                        f", ... (+{entry.match_count - self.max_preview_matches} more)"
                    )
                lines.append(f"  {preview}")
        return "\n".join(lines).rstrip() + "\n"


@BatchSearchFormatter.register("csv", suffixes=(".csv",))
class BatchSearchCsvFormatter:
    """CSV batch search result renderer."""

    @classmethod
    def _format_matches(cls, hits: list[Match]) -> str:
        return " | ".join(str(hit) for hit in hits)

    @classmethod
    def _format_rvas(cls, entry: SearchResults, hits: list[Match]) -> str:
        return " | ".join(
            _hex_or_none(hit.rva) or ""
            for hit in hits
        )

    @classmethod
    def _format_file_offsets(
        cls,
        entry: SearchResults,
        hits: list[Match],
    ) -> str:
        return " | ".join(
            _hex_or_none(entry.file_offset_for_match(hit)) or ""
            for hit in hits
        )

    def format(self, results: BatchSearchResults) -> str:
        output = io.StringIO()
        output.write(
            "name,source_line,status,match_count,search_pattern,"
            "normalized_signature,raw_pattern,imagebase,match_eas,match_rvas,"
            "match_file_offsets,error\n"
        )
        writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\n")
        for entry in results:
            writer.writerow(
                [
                    entry.name,
                    entry.source_line,
                    entry.status,
                    entry.match_count,
                    entry.search_pattern,
                    entry.normalized_signature,
                    entry.raw_pattern,
                    _hex_or_none(results.imagebase) or "",
                    self._format_matches(entry.matches),
                    self._format_rvas(entry, entry.matches),
                    self._format_file_offsets(entry, entry.matches),
                    entry.error,
                ]
            )
        return output.getvalue()


@BatchSearchFormatter.register("json", suffixes=(".json",))
class BatchSearchJsonFormatter:
    """JSON batch search result renderer."""

    def format(self, results: BatchSearchResults) -> str:
        return json.dumps(results.to_record(), indent=2, ensure_ascii=True) + "\n"


def _batch_search_formatter(
    formatter: typing.Optional[typing.Union[str, BatchSearchFormatter]] = None,
) -> BatchSearchFormatter:
    if formatter is None:
        return _BATCH_SEARCH_FORMATTERS["text"]
    if not isinstance(formatter, str):
        return formatter
    name = formatter.strip().lower()
    try:
        return _BATCH_SEARCH_FORMATTERS[name]
    except KeyError:
        raise ValueError(f"Unknown batch search format: {formatter}") from None


def _batch_search_formatter_for_path(path: pathlib.Path) -> BatchSearchFormatter:
    format_name = _BATCH_SEARCH_FORMAT_SUFFIXES.get(path.suffix.lower(), "text")
    return _batch_search_formatter(format_name)


class SignatureParser:
    """Centralized, readable parsing for various signature input styles.

    Supported inputs (examples):
      - Mask notation:   bytes + mask string like "xxxx?x" or binary mask "0b10101"
      - Hex escapes:     "\x48\x8b\x05 ..."
      - 0x-prefixed:     "0x48 0x8B 0x05 ..."
      - Explicit tokens: "48 8B 05 ? ? 4? ?F"
      - Compact tokens:  "488B05??4??F"

    Output is a SigMaker search pattern string (space-separated, '?' for
    full-byte wildcards, nibble wildcards preserved), or an empty string on
    failure.
    """

    _ESCAPED_HEX = re.compile(r"\\x[0-9A-Fa-f]{2}")
    _RUN_0X = re.compile(r"(?:0x[0-9A-Fa-f]{2})+")
    _EXPLICIT_TOKEN = re.compile(
        r"(?:[0-9A-Fa-f]{2}|[0-9A-Fa-f]\?|\?[0-9A-Fa-f]|\?\??)"
    )
    _COMPACT_PATTERN = re.compile(r"(?:[0-9A-Fa-f?]{2})+")
    _ESCAPED_RUN = re.compile(r"(?:\\x[0-9A-Fa-f]{2})+")
    _ESCAPED_EXPRESSION = re.compile(r"(?:\\x[0-9A-Fa-f]{2}|[\s,;])+")
    _PREFIXED_EXPRESSION = re.compile(r"(?:0x[0-9A-Fa-f]{2}|[\s,;])+")

    # Regex to match a mask string consisting of 'x' and '?' characters, starting with 'x'
    _MASK_REGEX = re.compile(r"x(?:x|\?)+")
    # Regex to match a binary mask string, e.g., '0b10101'
    _BINARY_MASK_REGEX = re.compile(r"0b[01]+")

    @classmethod
    def parse(cls, input_str: str) -> str:
        text = cls._strip_outer_wrapper(input_str)
        if text is None:
            return ""

        mask_match = cls._MASK_REGEX.search(text)
        if mask_match is None:
            mask_match = cls._BINARY_MASK_REGEX.search(text)
        if mask_match is not None:
            masked_pattern = cls._parse_masked_pattern(text, mask_match)
            if masked_pattern:
                return masked_pattern
        if cls._COMPACT_PATTERN.fullmatch(text):
            cells = [
                text[index : index + 2] for index in range(0, len(text), 2)
            ]
            return " ".join(
                "?" if cell == "??" else cell.upper() for cell in cells
            )
        return cls._normalize_explicit_pattern(text)

    # ---- internals ----

    @classmethod
    def _strip_outer_wrapper(cls, input_str: str) -> typing.Optional[str]:
        text = input_str.strip()
        if len(text) >= 2 and (text[0], text[-1]) in {
            ("(", ")"),
            ("[", "]"),
        }:
            text = text[1:-1].strip()
        if any(ch in text for ch in "()[]"):
            return None
        return text

    @classmethod
    def _parse_masked_pattern(
        cls,
        text: str,
        mask_match: re.Match[str],
    ) -> str:
        if text[mask_match.end() :].strip():
            return ""

        byte_expression = text[: mask_match.start()].strip()
        byte_tokens: list[str]
        if cls._ESCAPED_EXPRESSION.fullmatch(byte_expression):
            byte_tokens = cls._ESCAPED_HEX.findall(byte_expression)
        elif cls._PREFIXED_EXPRESSION.fullmatch(byte_expression):
            byte_tokens = re.findall(r"0x[0-9A-Fa-f]{2}", byte_expression)
        else:
            return ""

        mask_text = mask_match.group(0)
        if mask_text.startswith("0b"):
            mask = "".join(
                "x" if bit == "1" else "?" for bit in mask_text[2:][::-1]
            )
        else:
            mask = mask_text
        if len(byte_tokens) != len(mask):
            idaapi.msg(
                f'Detected mask "{mask}" but failed to match corresponding bytes\n'
            )
            return ""
        return cls._masked_bytes_to_ida(byte_tokens, mask, slice_from=2)

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
    def _normalize_explicit_pattern(cls, input_str: str) -> str:
        """Normalize a sequence of explicit byte and wildcard tokens."""
        tokens: list[str] = []
        for chunk in re.split(r"[\s,;]+", input_str):
            if not chunk:
                continue
            if cls._ESCAPED_RUN.fullmatch(chunk):
                tokens.extend(
                    token[2:].upper() for token in cls._ESCAPED_HEX.findall(chunk)
                )
            elif cls._RUN_0X.fullmatch(chunk):
                tokens.extend(
                    token[2:].upper()
                    for token in re.findall(r"0x[0-9A-Fa-f]{2}", chunk)
                )
            elif cls._EXPLICIT_TOKEN.fullmatch(chunk):
                tokens.append("?" if chunk in {"?", "??"} else chunk.upper())
            else:
                return ""
        return " ".join(tokens)


@dataclasses.dataclass(slots=True)
class SignatureSearcher:
    """Parses a signature string and searches the DB for matches."""

    input_signature: str = ""
    #: Optional user-supplied pattern name.
    name: typing.Optional[str] = dataclasses.field(default=None, kw_only=True)
    #: One-based source line in batch input, or zero when unknown.
    source_line: int = dataclasses.field(default=0, kw_only=True)

    _FENCE_RE: typing.ClassVar[re.Pattern[str]] = re.compile(r"^```")
    _NAMED_PATTERN_RE: typing.ClassVar[re.Pattern[str]] = re.compile(
        r"^([A-Za-z_]\w*)\s*(?::=|=)\s*(.+)$"
    )

    @classmethod
    def from_signature(
        cls,
        input_signature: str,
        *,
        name: typing.Optional[str] = None,
        source_line: int = 0,
    ) -> "SignatureSearcher":
        return cls(
            input_signature=input_signature,
            name=name,
            source_line=source_line,
        )

    @classmethod
    def from_many(cls, text: str) -> list["SignatureSearcher"]:
        """Create searchers from pasted named or unnamed signature lines."""
        searchers: list[SignatureSearcher] = []
        for source_line, statement in cls._split_statements(text):
            searcher = cls._from_statement(statement, source_line)
            if searcher is not None:
                searchers.append(searcher)
        return searchers

    @classmethod
    def _split_statements(cls, text: str) -> list[tuple[int, str]]:
        statements: list[tuple[int, str]] = []
        for source_line, raw_line in enumerate(text.splitlines(), start=1):
            statement = cls._strip_comments(raw_line).strip()
            if statement:
                statements.append((source_line, statement))
        return statements

    @classmethod
    def _from_statement(
        cls, statement: str, source_line: int
    ) -> typing.Optional["SignatureSearcher"]:
        line = statement.strip()
        if not line or cls._FENCE_RE.match(line):
            return None

        named_pattern = cls._NAMED_PATTERN_RE.match(line)
        if named_pattern:
            pattern = cls._strip_optional_quotes(named_pattern.group(2).strip())
            if pattern:
                return cls.from_signature(
                    pattern,
                    name=named_pattern.group(1),
                    source_line=source_line,
                )

        return cls.from_signature(line, source_line=source_line)

    @staticmethod
    def _strip_comments(line: str) -> str:
        in_quote = False
        escaped = False
        for idx, ch in enumerate(line):
            if ch == '"' and not escaped:
                in_quote = not in_quote
            if not in_quote:
                if ch == "#":
                    return line[:idx]
                if ch == "/" and idx + 1 < len(line) and line[idx + 1] == "/":
                    return line[:idx]
            escaped = ch == "\\" and not escaped
        return line

    @staticmethod
    def _strip_optional_quotes(pattern: str) -> str:
        if len(pattern) >= 2 and pattern[0] == '"' and pattern[-1] == '"':
            return pattern[1:-1].strip()
        return pattern

    @staticmethod
    def _has_nibble_wildcards(ida_signature: str) -> bool:
        normalized, _ = SigText.normalize(ida_signature)
        return any(
            len(token) == 2 and "?" in token and token != "??"
            for token in normalized.split()
        )

    @staticmethod
    def _scope_for_ea(
        scope_ea: typing.Optional[int],
    ) -> typing.Optional[tuple[int, int]]:
        if scope_ea is None:
            return None
        seg = idaapi.getseg(scope_ea)
        if seg is None:
            return None
        return int(seg.start_ea), int(seg.end_ea)

    @staticmethod
    def _parse_search_signature(input_signature: str) -> tuple[str, str]:
        """Return the display signature and canonical search signature."""
        try:
            sig_str = SignatureParser.parse(input_signature)
            if not sig_str:
                raise ValueError
            normalized, pattern = SigText.normalize(sig_str)
        except ValueError:
            raise ValueError("Unrecognized signature format") from None

        if not normalized or not any(
            not is_wildcard for _, is_wildcard in pattern
        ):
            raise ValueError("Unrecognized signature format")
        if (
            not SIMD_SPEEDUP_AVAILABLE
            and SignatureSearcher._has_nibble_wildcards(normalized)
        ):
            raise ValueError("Nibble wildcard search requires SIMD speedups")
        return sig_str, normalized

    def search(self, scope_ea: typing.Optional[int] = None) -> SearchResults:
        """Parse the signature and scan for matches.

        When ``scope_ea`` is given, the scan is limited to the segment
        containing it (issue #64: search a segment-scoped signature within the
        same segment). Falls back to the whole database when ``scope_ea`` is in
        no segment, so a scoped request never silently returns nothing.
        """
        try:
            sig_str, canonical_pattern = self._parse_search_signature(
                self.input_signature
            )
        except ValueError as exc:
            idaapi.msg("Unrecognized signature type\n")
            return SearchResults(
                [],
                "",
                raw_pattern=self.input_signature,
                name=self.name or "",
                source_line=self.source_line,
                error=str(exc),
            )

        scope = self._scope_for_ea(scope_ea)

        where = "the current segment" if scope else "the whole database"
        imagebase = SearchResults.current_imagebase()
        # Wrap the search in a ProgressDialog to allow cancellation
        with ProgressDialog(
            "Search for a signature\n\n"
            f"Scanning {where} for your pattern.\n\n"
            "Press Cancel to stop"
        ):
            matches = self.find_all(
                canonical_pattern,
                scope=scope,
                imagebase=imagebase,
            )

        return SearchResults(
            matches,
            sig_str,
            raw_pattern=self.input_signature,
            name=self.name or "",
            source_line=self.source_line,
            canonical_pattern=canonical_pattern,
        )

    @staticmethod
    def _find_all_simd(
        ida_signature: str,
        skip_more_than_one: bool = False,
        buf: typing.Optional["InMemoryBuffer"] = None,
        *,
        imagebase: typing.Optional[int] = None,
        raise_on_cancel: bool = False,
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
            return [
                Match(
                    base,
                    rva=None if imagebase is None else base - imagebase,
                )
            ]

        n = len(data_mv)
        off = 0
        # Matches arrive in ascending offset order, so map each offset to its
        # real address with a forward cursor (amortized O(1) per match); see
        # InMemoryBuffer.offset_mapper.
        to_addr = buf.offset_mapper()
        # Poll cancellation every _CANCEL_POLL_STRIDE matches (see
        # find_all_offsets) so per-match user_cancelled() overhead does not
        # dominate a scan over a short, common pattern.
        since_poll = 0
        while off <= n - k:
            since_poll += 1
            if since_poll >= _CANCEL_POLL_STRIDE:
                since_poll = 0
                if idaapi_user_canceled():
                    LOGGER.info("Search canceled by user")
                    if raise_on_cancel:
                        raise UserCanceledError("Search canceled by user")
                    break

            idx = _simd_scan_bytes(data_mv[off:], sig)
            if idx < 0:
                break
            address = to_addr(off + idx)
            results.append(
                Match(
                    address,
                    rva=None if imagebase is None else address - imagebase,
                )
            )
            if skip_more_than_one and len(results) > 1:
                break
            off += idx + 1
        return results

    @staticmethod
    def find_all_offsets(
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
    ) -> tuple[list[int], "InMemoryBuffer"]:
        """Return (offsets, buf): every match as a 0-based offset into
        buf.data(), plus the buffer used. The offsets seed an in-memory
        refinement; reusing the returned buf keeps subsequent refinement on
        the same bytes. SIMD path only.
        """
        simd_signature, _ = SigText.normalize(ida_signature)
        if buf is None:
            with ProgressDialog("Please stand by, copying segments..."):
                buf = InMemoryBuffer.load(mode=InMemoryBuffer.LoadMode.SEGMENTS)
        data_mv = buf.data()
        sig = _SimdSignature(simd_signature)
        offsets: list[int] = []
        k = sig.size_bytes
        if k == 0:
            return [0], buf
        n = len(data_mv)
        off = 0
        # Poll cancellation every _CANCEL_POLL_STRIDE matches rather than on
        # every match: idaapi.user_cancelled() costs ~0.5us per call and a
        # short, common seed can produce millions of matches, so per-match
        # polling alone can dominate the scan (observed: 44s of a 76s seed).
        since_poll = 0
        while off <= n - k:
            since_poll += 1
            if since_poll >= _CANCEL_POLL_STRIDE:
                since_poll = 0
                if idaapi_user_canceled():
                    break
            idx = _simd_scan_bytes(data_mv[off:], sig)
            if idx < 0:
                break
            offsets.append(off + idx)
            off += idx + 1
        return offsets, buf

    @staticmethod
    def find_all(
        ida_signature: str,
        buf: typing.Optional["InMemoryBuffer"] = None,
        skip_more_than_one: bool = False,
        scope: typing.Optional[tuple[int, int]] = None,
        *,
        imagebase: typing.Optional[int] = None,
        raise_on_cancel: bool = False,
    ) -> list[Match]:
        # Use SIMD if available
        if SIMD_SPEEDUP_AVAILABLE:
            if buf is None and scope is not None:
                # Scope the SIMD scan to one segment by loading only its bytes;
                # offset_mapper resolves the match offsets back to real
                # addresses (issue #64 search-scope, on top of #68).
                with ProgressDialog("Please stand by, copying the segment..."):
                    buf = InMemoryBuffer.load(
                        mode=InMemoryBuffer.LoadMode.SEGMENTS, scope_ea=scope[0]
                    )
            return SignatureSearcher._find_all_simd(
                ida_signature,
                skip_more_than_one=skip_more_than_one,
                buf=buf,
                imagebase=imagebase,
                raise_on_cancel=raise_on_cancel,
            )
        if SignatureSearcher._has_nibble_wildcards(ida_signature):
            raise ValueError("Nibble wildcard search requires SIMD speedups")
        binary = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binary, idaapi.inf_get_min_ea(), ida_signature, 16)
        out: list[Match] = []
        if scope is not None:
            ea, max_ea = scope
        else:
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
                if raise_on_cancel:
                    raise UserCanceledError("Search canceled by user")
                break

            hit, _ = _bin_search(ea, max_ea, binary, flags)
            if hit == idaapi.BADADDR:
                break
            out.append(
                Match(
                    hit,
                    rva=None if imagebase is None else hit - imagebase,
                )
            )
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


@dataclasses.dataclass(slots=True)
class BatchSignatureSearcher:
    """Search multiple pasted signatures in one operation."""

    #: Original pasted batch input.
    input_text: str
    #: Parsed per-entry signature searchers.
    searchers: list[SignatureSearcher] = dataclasses.field(default_factory=list)

    @classmethod
    def from_text(cls, input_text: str) -> "BatchSignatureSearcher":
        return cls(
            input_text=input_text,
            searchers=SignatureSearcher.from_many(input_text),
        )

    def search(
        self,
        *,
        buf: typing.Optional["InMemoryBuffer"] = None,
        scope_ea: typing.Optional[int] = None,
    ) -> BatchSearchResults:
        if buf is not None and scope_ea is not None:
            raise ValueError("buf and scope_ea cannot be provided together")

        searchers = self.searchers or SignatureSearcher.from_many(self.input_text)
        results: list[SearchResults] = []
        match_cache: dict[str, list[Match]] = {}
        scope = SignatureSearcher._scope_for_ea(scope_ea)
        active_buf = buf
        imagebase = SearchResults.current_imagebase(active_buf)

        for searcher in searchers:
            try:
                signature_str, normalized = SignatureSearcher._parse_search_signature(
                    searcher.input_signature
                )

                matches = match_cache.get(normalized)
                if matches is None:
                    if SIMD_SPEEDUP_AVAILABLE and active_buf is None:
                        message = (
                            "Please stand by, copying the segment..."
                            if scope is not None
                            else "Please stand by, copying segments..."
                        )
                        load_kwargs: dict[str, typing.Any] = {
                            "mode": InMemoryBuffer.LoadMode.SEGMENTS,
                        }
                        if scope is not None:
                            load_kwargs["scope_ea"] = scope[0]
                        with ProgressDialog(message):
                            active_buf = InMemoryBuffer.load(**load_kwargs)
                        imagebase = SearchResults.current_imagebase(active_buf)

                    matches = SignatureSearcher.find_all(
                        normalized,
                        buf=active_buf,
                        scope=None if SIMD_SPEEDUP_AVAILABLE else scope,
                        imagebase=imagebase,
                        raise_on_cancel=True,
                    )
                    match_cache[normalized] = matches

                result = SearchResults(
                    matches=list(matches),
                    signature_str=signature_str,
                    raw_pattern=searcher.input_signature,
                    name=searcher.name or "",
                    source_line=searcher.source_line,
                    canonical_pattern=normalized,
                )
            except UserCanceledError:
                raise
            except ValueError as exc:
                result = SearchResults(
                    [],
                    "",
                    raw_pattern=searcher.input_signature,
                    name=searcher.name or "",
                    source_line=searcher.source_line,
                    error=str(exc),
                )
            results.append(result)

        return BatchSearchResults(
            results=results,
            imagebase=imagebase,
        )


class Profiler:
    """Central holder for the optional cProfile session behind the Start/Stop
    Profiling actions.

    Encapsulates the single in-flight profile so there is no bare module global:
    inspect (``active``), flip (``start`` / ``stop``), and ``reset`` all live on
    one object. The module exposes a singleton ``_PROFILER``; ``start_profiling``
    and ``stop_profiling`` are thin console-facing wrappers around it.
    """

    def __init__(self) -> None:
        self._profile: typing.Any = None

    @property
    def active(self) -> bool:
        """True while a profiling session is running."""
        return self._profile is not None

    def start(self) -> None:
        """Begin a session, discarding any already-running one."""
        import cProfile

        if self._profile is not None:
            self._profile.disable()
            idaapi.msg("start_profiling: discarding previous active session\n")
        pr = cProfile.Profile()
        pr.enable()
        self._profile = pr
        idaapi.msg("start_profiling: profiling enabled\n")

    def stop(
        self,
        output_path: typing.Optional[str] = None,
        top_n: int = 30,
        sort_by: str = "cumulative",
    ) -> typing.Optional[str]:
        """Stop the active session, dump the result, and print a summary.

        Returns the .prof path on success, or None if no session was active.
        """
        import pstats
        import io as _io

        if self._profile is None:
            idaapi.msg(
                "stop_profiling: no active session; call start_profiling() first\n"
            )
            return None
        pr = self._profile
        self._profile = None
        pr.disable()

        if output_path is None:
            idausr = idaapi.get_user_idadir()
            output_path = os.path.join(idausr, "sigmaker_profile.prof")
        text_path = (
            output_path + ".txt" if not output_path.endswith(".txt") else output_path
        )

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

    def reset(self) -> None:
        """Discard any active session without dumping (safety / tests)."""
        if self._profile is not None:
            self._profile.disable()
        self._profile = None


_PROFILER = Profiler()


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
    _PROFILER.start()


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
    return _PROFILER.stop(output_path=output_path, top_n=top_n, sort_by=sort_by)


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
        "Matches: {matches}\n"
        "Elapsed: {elapsed}s\n\n"
        "Press Cancel to stop"
    )

    def __call__(self, idx, item, elapsed, total) -> str:
        match_str = "?" if self.last_match_count is None else str(self.last_match_count)
        return self._TEMPLATE.format(
            length=len(self.sig),
            matches=match_str,
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
        else:
            # Candidate-refinement tracks the exact surviving candidate count
            # at every step, so show the real number again (no "2+" cap).
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
<#Opt-in -- when you cancel a unique-signature search, output the partial signature (with match count) instead of nothing. Default off. (Issue #22)#Output partial signature on cancel (opt-in):{cOutputPartialOnCancel}>
<#Opt-in -- scope to the segment containing the anchor instead of the whole database, so functions duplicated across segments (e.g. a boot section and a main section) can be signed. Creation checks uniqueness within that segment; Search is scoped to the segment under your cursor. (Issue #64)#Limit uniqueness and search to the containing segment (opt-in):{cScopeToSegment}>{cGroupOptions}>

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
                    "cScopeToSegment",
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

    def init(self) -> int:
        self._register_actions()
        # Attach actions to the disassembly right-click popup via live UI
        # hooks rather than a one-shot attach_action_to_menu at init. The
        # static menu attach runs before IDA's menus are built and silently
        # no-ops; populating the popup on demand (as the main action already
        # does, and as d810 does for its submenu) is the reliable pattern.
        # The profiling actions live under a "SigMaker/" submenu.
        self._hooks = self._init_hooks(
            _PopupHook(self.ACTION_SHOW_SIGMAKER, category="SigMaker"),
            _PopupHook(self.ACTION_START_PROFILING, category="SigMaker"),
            _PopupHook(self.ACTION_STOP_PROFILING, category="SigMaker"),
        )
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
                "Start Profiling",
                _ActionHandler(self._action_start_profiling, always_enabled=True),
                None,
                "Start a cProfile session capturing subsequent SigMaker activity.",
            )
        )
        idaapi.register_action(
            idaapi.action_desc_t(
                self.ACTION_STOP_PROFILING,
                "Stop Profiling",
                _ActionHandler(self._action_stop_profiling, always_enabled=True),
                None,
                "Stop the active cProfile session and write the dump to the user IDA dir.",
            )
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
            scope_to_segment = bool(form.cGroupOptions.value & 32)  # type: ignore

        # Create SigMakerConfig
        config = SigMakerConfig(
            output_format=SignatureType.at(int(output_format)),
            wildcard_operands=wildcard_operands,
            continue_outside_of_function=continue_outside_of_function,
            wildcard_optimized=wildcard_optimized,
            enable_continue_prompt=enable_continue_prompt,
            output_partial_on_cancel=output_partial_on_cancel,
            scope_to_segment=scope_to_segment,
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
                    # Reuse the "containing segment" opt-in to scope the search
                    # to the segment under the cursor (issue #64).
                    scope_ea = (
                        idaapi.get_screen_ea()
                        if config.scope_to_segment
                        else None
                    )
                    searcher = SignatureSearcher.from_signature(input_signature)
                    results = searcher.search(scope_ea=scope_ea)
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
                f"{hex(pfn.start_ea)}{_func_name_suffix(int(pfn.start_ea))}):\n"
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
