"""
sigmaker.py - IDA Python Signature Maker
https://github.com/mahmoudimus/ida-sigmaker

by @mahmoudimus (Mahmoud Abdelkader)
"""

from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import enum
import os
import platform
import re
import traceback
import typing

import ida_bytes
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_xref
import idaapi
import idc

__author__ = "mahmoudimus"
__version__ = "1.3.0"

PLUGIN_NAME: str = "Signature Maker (py)"
PLUGIN_VERSION: str = __version__
PLUGIN_AUTHOR: str = __author__

# Toggle to enable QIS signature scanning; left disabled by default.
USE_QIS_SIGNATURE: bool = False  # _is_avx2_available()

# Default values controlling signature generation heuristics.
PRINT_TOP_X: int = 5
MAX_SINGLE_SIGNATURE_LENGTH: int = 1000
MAX_XREF_SIGNATURE_LENGTH: int = 250

# Buffer used to cache the entire database when scanning for signatures.
FILE_BUFFER: typing.Optional[bytes] = None

# Determine the current processor architecture for operand handling.
PROCESSOR_ARCH: int = ida_idp.ph_get_id()

# Global bitmask controlling which operand types may be wildcarded.
WILDCARD_OPTIMIZED_INSTRUCTION: bool = True
WildcardableOperandTypeBitmask: int = 0


def _is_processor_feature_present(feature: int) -> bool:
    """Return True if the given processor feature is present.

    Parameters
    ----------
    feature : int
        The numeric identifier of the processor feature to check.

    Returns
    -------
    bool
        True if the feature is present, False otherwise or on non-Windows
        platforms.
    """
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(feature))
    except Exception:
        return False


def _is_avx2_available() -> bool:
    """Return True if the CPU supports AVX2 instructions.

    This helper wraps `_is_processor_feature_present()` and simply checks
    whether the AVX2 instruction set is available.  AVX2 support can enable
    faster signature scanning routines.

    Returns
    -------
    bool
        True if AVX2 instructions are available, False otherwise.
    """
    # Check for AVX2 feature to enable QIS signature scanning.
    pf_avx2_instructions_available = 10
    return _is_processor_feature_present(pf_avx2_instructions_available)


def bit(x: int) -> int:
    """Return a bitmask with only bit ``x`` set.

    This is a convenience wrapper around the left-shift operator used
    throughout this module for constructing operand type masks.

    Parameters
    ----------
    x : int
        The bit number to set.

    Returns
    -------
    int
        ``1 << x``.
    """
    return 1 << x


class SignatureType(enum.Enum):
    """Enumeration representing the various supported signature output formats."""

    IDA = 0
    x64Dbg = 1
    Signature_Mask = 2
    SignatureByteArray_Bitmask = 3


@dataclasses.dataclass
class SignatureByte:
    """Container representing a single byte in a signature.

    The ``value`` attribute holds the byte value and ``is_wildcard`` indicates
    whether this byte should be treated as a wildcard in comparisons and output.
    """

    value: int
    is_wildcard: bool


Signature = typing.List[SignatureByte]


class ProgressDialog:
    """Context manager wrapping IDA wait boxes.

    When used as a context manager the progress dialog will display a wait box
    on entry and hide it on exit.  The message may be updated via
    `replace_message()` and cancellation can be tested with `user_canceled()`.
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
        ida_kernwin.show_wait_box(self._message())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        ida_kernwin.hide_wait_box()

    def replace_message(self, new_message: str, hide_cancel: bool = False) -> None:
        """Replace the currently displayed message."""
        msg = self._message(message=new_message, hide_cancel=hide_cancel)
        ida_kernwin.replace_wait_box(msg)

    def user_canceled(self) -> bool:
        """Return True if the user has canceled the wait box."""
        return ida_kernwin.user_cancelled()

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
            print(f"Error setting clipboard text: {e}")
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


def build_ida_signature_string(signature: Signature, double_qm: bool = False) -> str:
    """Render a signature into IDA or x64Dbg text format.

    Parameters
    ----------
    signature : list of SignatureByte
        The signature bytes to format.
    double_qm : bool, optional
        If True, wildcards are rendered as '??' instead of '?', by default False.

    Returns
    -------
    str
        The formatted signature string without trailing whitespace.
    """
    result: typing.List[str] = []
    for byte in signature:
        if byte.is_wildcard:
            result.append("??" if double_qm else "?")
        else:
            result.append(f"{byte.value:02X}")
        result.append(" ")
    return "".join(result).rstrip()


def build_byte_array_with_mask_signature_string(signature: Signature) -> str:
    """Render a signature into a C byte array string with a mask.

    The returned string contains an escaped hex byte sequence followed by a
    string mask indicating which bytes are significant.

    Parameters
    ----------
    signature : list of SignatureByte
        The signature bytes to format.

    Returns
    -------
    str
        The formatted pattern and mask separated by a space.
    """
    pattern_parts: typing.List[str] = []
    mask_parts: typing.List[str] = []
    for byte in signature:
        pattern_parts.append(
            f"\\x{byte.value:02X}" if not byte.is_wildcard else "\\x00"
        )
        mask_parts.append("x" if not byte.is_wildcard else "?")
    return "".join(pattern_parts) + " " + "".join(mask_parts)


def build_bytes_with_bitmask_signature_string(signature: Signature) -> str:
    """Render a signature into a C byte array followed by a bitmask string.

    The bitmask is constructed by reversing the order of the significance flags.

    Parameters
    ----------
    signature : list of SignatureByte
        The signature bytes to format.

    Returns
    -------
    str
        The formatted byte list and bitmask separated by a space.
    """
    pattern_parts: typing.List[str] = []
    mask_bits: typing.List[str] = []
    for byte in signature:
        pattern_parts.append(
            f"0x{byte.value:02X}, " if not byte.is_wildcard else "0x00, "
        )
        mask_bits.append("1" if not byte.is_wildcard else "0")
    pattern_str = "".join(pattern_parts).rstrip(", ")
    mask_str = "".join(mask_bits)[::-1]
    return f"{pattern_str} 0b{mask_str}"


def format_signature(signature: Signature, sig_type: SignatureType) -> str:
    """Format a signature according to the requested `SignatureType`.

    Parameters
    ----------
    signature : list of SignatureByte
        The signature to format.
    sig_type : SignatureType
        The desired output format.

    Returns
    -------
    str
        The formatted signature string, or an empty string if the type is not
        recognized.
    """
    if sig_type == SignatureType.IDA:
        return build_ida_signature_string(signature)
    if sig_type == SignatureType.x64Dbg:
        return build_ida_signature_string(signature, True)
    if sig_type == SignatureType.Signature_Mask:
        return build_byte_array_with_mask_signature_string(signature)
    if sig_type == SignatureType.SignatureByteArray_Bitmask:
        return build_bytes_with_bitmask_signature_string(signature)
    return ""


def add_byte_to_signature(signature: Signature, address: int, wildcard: bool) -> None:
    """Append a single byte from the IDA database to a signature.

    Parameters
    ----------
    signature : list of SignatureByte
        The signature to extend.
    address : int
        The linear address from which to read the byte.
    wildcard : bool
        Whether the added byte should be marked as a wildcard.
    """
    b = ida_bytes.get_byte(address)
    signature.append(SignatureByte(b, wildcard))


def add_bytes_to_signature(
    signature: Signature, address: int, count: int, wildcard: bool
) -> None:
    """Append multiple bytes from the IDA database to a signature.

    Parameters
    ----------
    signature : list of SignatureByte
        The signature to extend.
    address : int
        The starting linear address from which to read bytes.
    count : int
        Number of bytes to add.
    wildcard : bool
        Whether the added bytes should be marked as wildcards.
    """
    for i in range(count):
        add_byte_to_signature(signature, address + i, wildcard)


def trim_signature(signature: Signature) -> None:
    """Remove trailing wildcard bytes from a signature.

    This function modifies the signature list in place by popping off any
    wildcard bytes at the end.

    Parameters
    ----------
    signature : list of SignatureByte
        The signature to trim.
    """
    while signature and signature[-1].is_wildcard:
        signature.pop()


def get_regex_matches(
    string: str, regex: typing.Pattern[str], matches: typing.List[str]
) -> bool:
    """Find and return all matches of a regex in a string.

    Parameters
    ----------
    string : str
        The input string to search.
    regex : Pattern[str]
        The compiled regular expression to match.
    matches : list of str
        A list which will be cleared and extended with all matches.

    Returns
    -------
    bool
        True if at least one match was found, False otherwise.
    """
    matches.clear()
    matches.extend(re.findall(regex, string))
    return bool(matches)


class Unexpected(Exception):
    """Exception type used throughout the module to indicate unexpected errors."""


class ConfigureOperandWildcardBitmaskForm(ida_kernwin.Form):
    """Interactive form to configure wildcardable operands using checkboxes."""

    def __init__(self) -> None:
        F = ida_kernwin.Form
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
        proc_arch = ida_idp.ph_get_id()
        if proc_arch == ida_idp.PLFM_386:
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
        elif proc_arch == ida_idp.PLFM_ARM:
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
        elif proc_arch == ida_idp.PLFM_PPC:
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
        # Shift by one because we skip o_void
        options = WildcardableOperandTypeBitmask >> 1

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
        if fid == self.cWildcardableOperands.id:
            global WildcardableOperandTypeBitmask
            # Re-shift by one because we skipped o_void
            WildcardableOperandTypeBitmask = (
                self.GetControlValue(self.cWildcardableOperands) << 1
            )
        return 1


class ConfigureOptionsForm(ida_kernwin.Form):
    """Interactive form to configure XREF and signature generation options."""

    def __init__(self) -> None:
        F = ida_kernwin.Form

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
        global PRINT_TOP_X, MAX_SINGLE_SIGNATURE_LENGTH, MAX_XREF_SIGNATURE_LENGTH

        # Pre-fill form values
        self.controls["opt1"].value = PRINT_TOP_X
        self.controls["opt2"].value = MAX_SINGLE_SIGNATURE_LENGTH
        self.controls["opt3"].value = MAX_XREF_SIGNATURE_LENGTH

        result = self.Execute()
        if result != 1:
            self.Free()
            return result

        PRINT_TOP_X = self.controls["opt1"].value
        MAX_SINGLE_SIGNATURE_LENGTH = self.controls["opt2"].value
        MAX_XREF_SIGNATURE_LENGTH = self.controls["opt3"].value
        self.Free()
        return result


class SignatureMakerForm(ida_kernwin.Form):
    """Main form presented when the user invokes the SigMaker plugin."""

    def __init__(self) -> None:
        F = ida_kernwin.Form
        form_text = (
            f"""STARTITEM 0
BUTTON YES* OK
BUTTON CANCEL Cancel
Signature Maker v{PLUGIN_VERSION} {("(AVX2)" if USE_QIS_SIGNATURE else "")}"""
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
            "cGroupOptions": ida_kernwin.Form.ChkGroupControl(
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


def set_wildcardable_operand_type_bitmask() -> None:
    """Initialize the global WildcardableOperandTypeBitmask based on the processor."""
    global WildcardableOperandTypeBitmask

    # Default wildcard setting depending on processor arch
    if PROCESSOR_ARCH == ida_idp.PLFM_386:
        o_ymmreg = idc.o_xmmreg + 1
        o_zmmreg = o_ymmreg + 1
        o_kreg = o_zmmreg + 1
        WildcardableOperandTypeBitmask = (
            bit(idc.o_mem)
            | bit(idc.o_phrase)
            | bit(idc.o_displ)
            | bit(idc.o_far)
            | bit(idc.o_near)
            | bit(idc.o_imm)
            | bit(idc.o_trreg)
            | bit(idc.o_dbreg)
            | bit(idc.o_crreg)
            | bit(idc.o_fpreg)
            | bit(idc.o_mmxreg)
            | bit(idc.o_xmmreg)
            | bit(o_ymmreg)
            | bit(o_zmmreg)
            | bit(o_kreg)
        )
    elif PROCESSOR_ARCH == ida_idp.PLFM_ARM:
        WildcardableOperandTypeBitmask = (
            bit(idc.o_mem)
            | bit(idc.o_phrase)
            | bit(idc.o_displ)
            | bit(idc.o_far)
            | bit(idc.o_near)
            | bit(idc.o_imm)
        )
    elif PROCESSOR_ARCH == ida_idp.PLFM_MIPS:
        WildcardableOperandTypeBitmask = (
            bit(idc.o_mem) | bit(idc.o_far) | bit(idc.o_near)
        )
    else:
        WildcardableOperandTypeBitmask = (
            bit(idc.o_mem)
            | bit(idc.o_phrase)
            | bit(idc.o_displ)
            | bit(idc.o_far)
            | bit(idc.o_near)
            | bit(idc.o_imm)
        )


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


def is_disassembly_widget(widget, popup, ctx) -> bool:
    """Return True if the given widget is a disassembly view."""
    return idaapi.get_widget_type(widget) == idaapi.BWN_DISASM


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
        self.predicate = predicate or is_disassembly_widget
        self.widget_populator = widget_populator or self._default_populator
        self.category = category

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


class SigMaker(ida_idaapi.plugin_t):
    """IDA Pro plugin class implementing signature generation and search."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = f"{PLUGIN_NAME} v{PLUGIN_VERSION} for IDA Pro by {PLUGIN_AUTHOR}"
    help = "Select location in disassembly and press CTRL+ALT+S to open menu"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-S"

    IS_ARM: bool = False
    ACTION_SHOW_SIGMAKER: str = "pysigmaker:show"

    def init(self) -> int:
        self.progress_dialog = ProgressDialog()
        self._hooks = self._init_hooks(_PopupHook(self.ACTION_SHOW_SIGMAKER))
        self._register_actions()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg) -> None:
        self.run_plugin()

    def term(self) -> None:
        self._deregister_actions()
        self._deinit_hooks(*self._hooks)

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
                _ActionHandler(self.run_plugin),
                self.wanted_hotkey,
                "Show the signature maker dialog.",
                154,
            )
        )

    def _deregister_actions(self) -> None:
        idaapi.unregister_action(self.ACTION_SHOW_SIGMAKER)

    # -------------------------
    # Processor and operand handling
    # -------------------------
    def is_arm(self) -> bool:
        """Return True if the current processor is ARM."""
        procname = ida_ida.inf_get_procname()
        return "ARM" in procname.upper()

    def get_operand_offset_arm(
        self,
        instruction: idaapi.insn_t,
        operand_offset: typing.List[int],
        operand_length: typing.List[int],
    ) -> bool:
        """ARM specific operand extraction."""
        for op in instruction.ops:
            if op.type in {
                idaapi.o_mem,
                idaapi.o_far,
                idaapi.o_near,
                idaapi.o_phrase,
                idaapi.o_displ,
                idaapi.o_imm,
            }:
                operand_offset[0] = op.offb
                if instruction.size == 4:
                    operand_length[0] = 3
                elif instruction.size == 8:
                    operand_length[0] = 7
                else:
                    operand_length[0] = 0
                return True
        return False

    def get_operand(
        self,
        instruction: idaapi.insn_t,
        operand_offset: typing.List[int],
        operand_length: typing.List[int],
        wildcard_optimized: bool,
    ) -> bool:
        """Generic operand extraction respecting the wildcard bitmask."""
        if self.IS_ARM:
            return self.get_operand_offset_arm(
                instruction, operand_offset, operand_length
            )
        for op in instruction.ops:
            if op.type == idaapi.o_void:
                continue
            # Only process operands that are marked in our bitmask.
            if (bit(op.type) & WildcardableOperandTypeBitmask) == 0:
                continue
            is_optimized_instr = op.offb == 0
            if is_optimized_instr and not wildcard_optimized:
                continue
            operand_offset[0] = op.offb
            operand_length[0] = instruction.size - op.offb
            return True
        return False

    # -------------------------
    # QIS scanning support
    # -------------------------
    def read_segments_to_buffer(self) -> bytes:
        """Concatenate all segments of the IDA database into a single buffer."""
        buf = bytearray()
        seg = idaapi.get_first_seg()
        while seg:
            size = seg.end_ea - seg.start_ea
            data = ida_bytes.get_bytes(seg.start_ea, size)
            if data:
                buf.extend(data)
            seg = idaapi.get_next_seg(seg.start_ea)
        return bytes(buf)

    def parse_signature(self, sig_str: str) -> typing.List[typing.Tuple[int, bool]]:
        """Convert a signature string into a list of (value, is_wildcard) tuples."""
        tokens = sig_str.split()
        pattern: typing.List[typing.Tuple[int, bool]] = []
        for token in tokens:
            if "?" in token:
                pattern.append((0, True))
            else:
                try:
                    val = int(token, 16)
                except Exception:
                    val = 0
                pattern.append((val, False))
        return pattern

    def find_signature_occurrences_qis(
        self, ida_signature: str, skip_more_than_one: bool = False
    ) -> typing.List[int]:
        """Find occurrences of a signature by scanning a raw buffer (QIS)."""
        global FILE_BUFFER
        if not FILE_BUFFER:
            with ProgressDialog("Please stand by, copying segments..."):
                FILE_BUFFER = self.read_segments_to_buffer()
        qis_signature = ida_signature.replace("?", "??")
        pattern = self.parse_signature(qis_signature)
        results: typing.List[int] = []
        base_ea = ida_ida.inf_get_min_ea()
        data = FILE_BUFFER
        pat_len = len(pattern)
        i = 0
        while i <= len(data) - pat_len:
            match = True
            for j, (val, is_wildcard) in enumerate(pattern):
                if not is_wildcard and data[i + j] != val:
                    match = False
                    break
            if match:
                results.append(base_ea + i)
                if skip_more_than_one and len(results) > 1:
                    break
            i += 1
        return results

    def find_signature_occurrences(self, ida_signature: str) -> typing.List[int]:
        """Search for occurrences of a binary pattern using IDA's API."""
        if USE_QIS_SIGNATURE:
            return self.find_signature_occurrences_qis(ida_signature)
        binary_pattern = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(
            binary_pattern, ida_ida.inf_get_min_ea(), ida_signature, 16
        )
        results: typing.List[int] = []
        ea = ida_ida.inf_get_min_ea()
        _bin_search = getattr(ida_bytes, "bin_search", None)
        if not _bin_search:
            _bin_search = getattr(ida_bytes, "bin_search3")
        while True:
            occurence, _ = _bin_search(
                ea,
                ida_ida.inf_get_max_ea(),
                binary_pattern,
                ida_bytes.BIN_SEARCH_NOCASE | ida_bytes.BIN_SEARCH_FORWARD,
            )
            if occurence == idaapi.BADADDR:
                break
            results.append(occurence)
            ea = occurence + 1
        return results

    def is_signature_unique(self, ida_signature: str) -> bool:
        """Return True if the given signature occurs exactly once."""
        return len(self.find_signature_occurrences(ida_signature)) == 1

    # -------------------------
    # Signature generation for unique EA and a range
    # -------------------------
    def generate_unique_signature_for_ea(
        self,
        ea: int,
        wildcard_operands: bool,
        continue_outside_of_function: bool,
        wildcard_optimized: bool,
        max_signature_length: int = 1000,
        ask_longer_signature: bool = True,
    ) -> Signature:
        """Generate a unique signature for a single address."""
        if ea == idaapi.BADADDR:
            raise Unexpected("Invalid address")
        if not idaapi.is_code(ida_bytes.get_flags(ea)):
            raise Unexpected("Cannot create code signature for data")
        signature: Signature = []
        sig_part_length = 0
        current_function = idaapi.get_func(ea)
        current_address = ea

        while True:
            if idaapi.user_cancelled():
                raise Unexpected("Aborted")
            instruction = idaapi.insn_t()
            current_instruction_length = idaapi.decode_insn(
                instruction, current_address
            )
            if current_instruction_length <= 0:
                if not signature:
                    raise Unexpected("Failed to decode first instruction")
                idc.msg(
                    f"Signature reached end of executable code @ {current_address:X}\n"
                )
                sig_str = build_ida_signature_string(signature)
                idc.msg(f"NOT UNIQUE Signature for {ea:X}: {sig_str}\n")
                raise Unexpected("Signature not unique")
            if sig_part_length > max_signature_length:
                if ask_longer_signature:
                    result = idaapi.ask_yn(
                        idaapi.ASKBTN_YES,
                        f"Signature is already at {len(signature)} bytes. Continue?",
                    )
                    if result == 1:
                        sig_part_length = 0
                    elif result == 0:
                        sig_str = build_ida_signature_string(signature)
                        idc.msg(f"NOT UNIQUE Signature for {ea:X}: {sig_str}\n")
                        raise Unexpected("Signature not unique")
                    else:
                        raise Unexpected("Aborted")
                else:
                    raise Unexpected("Signature exceeded maximum length")
            sig_part_length += current_instruction_length

            operand_offset = [0]
            operand_length = [0]
            if (
                wildcard_operands
                and self.get_operand(
                    instruction, operand_offset, operand_length, wildcard_optimized
                )
                and operand_length[0] > 0
            ):
                add_bytes_to_signature(
                    signature, current_address, operand_offset[0], False
                )
                add_bytes_to_signature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    add_bytes_to_signature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                add_bytes_to_signature(
                    signature, current_address, current_instruction_length, False
                )

            current_sig = build_ida_signature_string(signature)
            if self.is_signature_unique(current_sig):
                trim_signature(signature)
                return signature

            current_address += current_instruction_length
            

            if (
                not continue_outside_of_function
                and current_function
                and current_address > current_function.end_ea
            ):
                raise Unexpected("Signature left function scope")
        raise Unexpected("Unknown")

    def generate_signature_for_ea_range(
        self,
        ea_start: int,
        ea_end: int,
        wildcard_operands: bool,
        wildcard_optimized: bool,
    ) -> Signature:
        """Generate a signature spanning an address range."""
        if ea_start == idaapi.BADADDR or ea_end == idaapi.BADADDR:
            raise Unexpected("Invalid address")
        signature: Signature = []
        sig_part_length = 0
        if not idaapi.is_code(ida_bytes.get_flags(ea_start)):
            add_bytes_to_signature(signature, ea_start, ea_end - ea_start, False)
            return signature

        current_address = ea_start
        while True:
            if idaapi.user_cancelled():
                raise Unexpected("Aborted")
            instruction = idaapi.insn_t()
            current_instruction_length = idaapi.decode_insn(
                instruction, current_address
            )
            if current_instruction_length <= 0:
                if not signature:
                    raise Unexpected("Failed to decode first instruction")
                idc.msg(
                    f"Signature reached end of executable code @ {current_address:X}\n"
                )
                if current_address < ea_end:
                    add_bytes_to_signature(
                        signature, current_address, ea_end - current_address, False
                    )
                trim_signature(signature)
                return signature
            sig_part_length += current_instruction_length

            operand_offset = [0]
            operand_length = [0]
            if (
                wildcard_operands
                and self.get_operand(
                    instruction, operand_offset, operand_length, wildcard_optimized
                )
                and operand_length[0] > 0
            ):
                add_bytes_to_signature(
                    signature, current_address, operand_offset[0], False
                )
                add_bytes_to_signature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    add_bytes_to_signature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                add_bytes_to_signature(
                    signature, current_address, current_instruction_length, False
                )
            current_address += current_instruction_length

            if current_address >= ea_end:
                trim_signature(signature)
                return signature
        raise Unexpected("Unknown")

    # -------------------------
    # Output functions
    # -------------------------
    def print_signature_for_ea(
        self, signature: Signature, ea: int, sig_type: SignatureType
    ) -> None:
        """Print a formatted signature for an address and copy it to the clipboard."""
        if not signature:
            idc.msg(f"Error: {signature}\n")
            return
        sig_str = format_signature(signature, sig_type)
        idc.msg(f"Signature for {ea:X}: {sig_str}\n")
        if not Clipboard.set_text(sig_str):
            idc.msg("Failed to copy to clipboard!")

    def find_xrefs(
        self,
        ea: int,
        wildcard_operands: bool,
        continue_outside_of_function: bool,
        wildcard_optimized: bool,
        xref_signatures: typing.List[typing.Tuple[int, Signature]],
        max_signature_length: int,
    ) -> None:
        """Find XREF signatures to a given address."""
        xref_count = 0
        xb = ida_xref.xrefblk_t()
        if xb.first_to(ea, ida_xref.XREF_ALL):
            while True:
                if idaapi.is_code(ida_bytes.get_flags(xb.frm)):
                    xref_count += 1
                if not xb.next_to():
                    break
        xb = ida_xref.xrefblk_t()
        if not xb.first_to(ea, ida_xref.XREF_ALL):
            return
        i = 0
        shortest_signature_length = max_signature_length + 1
        while True:
            if self.progress_dialog.user_canceled():
                break
            if not idaapi.is_code(ida_bytes.get_flags(xb.frm)):
                if not xb.next_to():
                    break
                continue
            i += 1
            idaapi.replace_wait_box(
                f"Processing xref {i} of {xref_count} ({(i / xref_count) * 100.0:.1f}%)...\n\n"
                f"Suitable Signatures: {len(xref_signatures)}\n"
                f"Shortest Signature: {shortest_signature_length if shortest_signature_length <= max_signature_length else 0} Bytes"
            )
            try:
                sig = self.generate_unique_signature_for_ea(
                    xb.frm,
                    wildcard_operands,
                    continue_outside_of_function,
                    wildcard_optimized,
                    max_signature_length,
                    False,
                )
            except Exception:
                sig = None
            if sig:
                if len(sig) < shortest_signature_length:
                    shortest_signature_length = len(sig)
                xref_signatures.append((xb.frm, sig))
            if not xb.next_to():
                break
        xref_signatures.sort(key=lambda tup: len(tup[1]))

    def print_xref_signatures_for_ea(
        self,
        ea: int,
        xref_signatures: typing.List[typing.Tuple[int, Signature]],
        sig_type: SignatureType,
        top_count: int,
    ) -> None:
        """Print and copy the top N XREF signatures."""
        if not xref_signatures:
            idc.msg("No XREFs have been found for your address\n")
            return
        top_length = min(top_count, len(xref_signatures))
        idc.msg(
            f"Top {top_length} Signatures out of {len(xref_signatures)} xrefs for {ea:X}:\n"
        )
        for i in range(top_length):
            origin_address, signature = xref_signatures[i]
            sig_str = format_signature(signature, sig_type)
            idc.msg(f"XREF Signature #{i+1} @ {origin_address:X}: {sig_str}\n")
            if i == 0:
                Clipboard.set_text(sig_str)

    def print_selected_code(
        self,
        start: int,
        end: int,
        sig_type: SignatureType,
        wildcard_operands: bool,
        wildcard_optimized: bool,
    ) -> None:
        """Print and copy a signature for the selected address range."""
        selection_size = end - start
        if selection_size <= 0:
            idc.msg("Invalid selection size\n")
            return
        try:
            signature = self.generate_signature_for_ea_range(
                start, end, wildcard_operands, wildcard_optimized
            )
        except Unexpected as e:
            idc.msg(f"Error: {str(e)}\n")
            return
        sig_str = format_signature(signature, sig_type)
        idc.msg(f"Code for {start:X}-{end:X}: {sig_str}\n")
        Clipboard.set_text(sig_str)

    def search_signature_string(self, input_str: str) -> None:
        """Parse a signature string and search the database for matches."""
        converted_signature_string = ""
        string_mask = ""
        # Try to detect a string mask like "xx????xx?xx"
        m = re.search(r"x(?:x|\?)+", input_str)
        if m:
            string_mask = m.group(0)
        else:
            m = re.search(r"0b(?:[01]+)", input_str)
            if m:
                bits = m.group(0)[2:]
                reversed_bits = bits[::-1]
                string_mask = "".join("x" if b == "1" else "?" for b in reversed_bits)
        if string_mask:
            raw_byte_strings: typing.List[str] = []
            if get_regex_matches(
                input_str,
                re.compile(r"\\x[0-9A-F]{2}", re.IGNORECASE),
                raw_byte_strings,
            ) and len(raw_byte_strings) == len(string_mask):
                converted_signature: Signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = build_ida_signature_string(
                    converted_signature
                )
            elif get_regex_matches(
                input_str,
                re.compile(r"(?:0x[0-9A-F]{2})+", re.IGNORECASE),
                raw_byte_strings,
            ) and len(raw_byte_strings) == len(string_mask):
                converted_signature: Signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = build_ida_signature_string(
                    converted_signature
                )
            else:
                idc.msg(
                    f'Detected mask "{string_mask}" but failed to match corresponding bytes\n'
                )
        else:
            s = re.sub(r"[\)\(\[\]]+", "", input_str)
            s = re.sub(r"^\s+", "", s)
            s = re.sub(r"[? ]+$", "", s) + " "
            s = re.sub(r"\\?\\x", "", s)
            s = re.sub(r"\s+", " ", s)
            converted_signature_string = s

        if not converted_signature_string:
            idc.msg("Unrecognized signature type\n")
            return

        idc.msg(f"Signature: {converted_signature_string}\n")
        signature_matches = self.find_signature_occurrences(converted_signature_string)
        if not signature_matches:
            idc.msg("Signature does not match!\n")
            return
        for ea in signature_matches:
            fn_name = None
            with contextlib.suppress(BaseException):
                fn_name = idaapi.get_func_name(ea)
            if fn_name:
                idc.msg(f"Match @ {ea:X} in {fn_name}\n")
            else:
                idc.msg(f"Match @ {ea:X}\n")

    # -------------------------
    # Main plugin UI and dispatch
    # -------------------------
    def run_plugin(self, ctx=None) -> None:
        """Entry point called when the user activates the plugin."""
        self.IS_ARM = self.is_arm()
        set_wildcardable_operand_type_bitmask()

        form = SignatureMakerForm()
        form.Compile()
        ok = form.Execute()
        if not ok:
            form.Free()
            return

        action = form.rAction.value
        output_format = form.rOutputFormat.value
        wildcard_operands = bool(form.cGroupOptions.value & 1)
        continue_outside_of_function = bool(form.cGroupOptions.value & 2)
        wildcard_optimized = bool(form.cGroupOptions.value & 4)
        form.Free()

        sig_type = SignatureType(output_format)

        try:
            if action == 0:
                ea = ida_kernwin.get_screen_ea()
                with self.progress_dialog("Generating signature..."):
                    sig = self.generate_unique_signature_for_ea(
                        ea,
                        wildcard_operands,
                        continue_outside_of_function,
                        wildcard_optimized,
                        MAX_SINGLE_SIGNATURE_LENGTH,
                    )
                    self.print_signature_for_ea(sig, ea, sig_type)
            elif action == 1:
                ea = ida_kernwin.get_screen_ea()
                xref_signatures: typing.List[typing.Tuple[int, Signature]] = []
                with self.progress_dialog(
                    "Finding references and generating signatures. This can take a while..."
                ):
                    self.find_xrefs(
                        ea,
                        wildcard_operands,
                        continue_outside_of_function,
                        wildcard_optimized,
                        xref_signatures,
                        MAX_XREF_SIGNATURE_LENGTH,
                    )
                    self.print_xref_signatures_for_ea(
                        ea, xref_signatures, sig_type, PRINT_TOP_X
                    )
            elif action == 2:
                start, end = get_selected_addresses(idaapi.get_current_viewer())
                if start and end:
                    with self.progress_dialog("Please stand by..."):
                        self.print_selected_code(
                            start, end, sig_type, wildcard_operands, wildcard_optimized
                        )
                else:
                    idc.msg("Select a range to copy the code!\n")
            elif action == 3:
                input_signature = idaapi.ask_str(
                    "", idaapi.HIST_SRCH, "Enter a signature"
                )
                if input_signature:
                    with self.progress_dialog("Searching..."):
                        self.search_signature_string(input_signature)
        except Unexpected as e:
            idc.msg(f"Error: {str(e)}\n")
        except Exception as e:
            print(e, os.linesep, traceback.format_exc())
            return


def get_selected_addresses(
    ctx,
) -> typing.Tuple[typing.Optional[int], typing.Optional[int]]:
    """Return the start and end of the selection or current line."""
    is_selected, start_ea, end_ea = idaapi.read_range_selection(ctx)
    if is_selected:
        return start_ea, end_ea
    p0, p1 = ida_kernwin.twinpos_t(), ida_kernwin.twinpos_t()
    ida_kernwin.read_selection(ctx, p0, p1)
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
        end_ea = ida_kernwin.ask_addr(start_ea, "Enter end address for selection:")
    finally:
        idc.jumpto(start_ea)

    if end_ea and end_ea <= start_ea:
        print(
            f"Error: End address 0x{end_ea:X} must be greater than start address 0x{start_ea:X}."
        )
        end_ea = None
    if end_ea is None:
        end_ea = idc.get_item_end(start_ea)
        print(f"No end address selected, using line end: 0x{end_ea:X}")

    return start_ea, end_ea


def PLUGIN_ENTRY() -> SigMaker:
    """Entry point function required by IDA Pro to instantiate the plugin."""
    return SigMaker()
