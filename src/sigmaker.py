"""
sigmaker.py - IDA Python port of Signature Maker (from A200K)
https://github.com/mahmoudimus/ida-pysigmaker

by @mahmoudimus (Mahmoud Abdelkader)
"""

import ctypes
import enum
import os
import platform
import re
import sys
import traceback

import ida_bytes
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_xref
import idaapi
import idc


def _IsProcessorFeaturePresent(feature: int) -> bool:
    if platform.system() != "Windows":
        return False

    try:
        is_present = ctypes.windll.kernel32.IsProcessorFeaturePresent(feature)
    except Exception:
        is_present = False
    return is_present


def _IsAVX2Available() -> bool:
    # Check for AVX2 feature to enable QIS signature scanning.
    PF_AVX2_INSTRUCTIONS_AVAILABLE = 10
    return _IsProcessorFeaturePresent(PF_AVX2_INSTRUCTIONS_AVAILABLE)


# Globals
__author__ = "mahmoudimus"
__version__ = "1.1.2"

PLUGIN_NAME = "Signature Maker (py)"
PLUGIN_VERSION = __version__
PLUGIN_AUTHOR = __author__
USE_QIS_SIGNATURE = False  # _IsAVX2Available()  # TODO: add this later
PRINT_TOP_X = 5
MAX_SINGLE_SIGNATURE_LENGTH = 1000
MAX_XREF_SIGNATURE_LENGTH = 250
FILE_BUFFER = None
PROCESSOR_ARCH = ida_idp.ph_get_id()  # Check what processor we have
WILDCARD_OPTIMIZED_INSTRUCTION = True
WildcardableOperandTypeBitmask = 0  # Will be set based on processor

# Helpers


def BIT(x):
    return 1 << x


class ProgressDialog:
    def __init__(self, message="Please wait...", hide_cancel=False):
        self._default_msg: str
        self.hide_cancel: bool
        self.configure(message, hide_cancel)

    def _message(self, message=None, hide_cancel=None):
        display_msg = self._default_msg if message is None else message
        hide_cancel = self.hide_cancel if hide_cancel is None else hide_cancel
        prefix = "HIDECANCEL\n" if hide_cancel else ""
        return prefix + display_msg

    def configure(self, message="Please wait...", hide_cancel=False):
        self._default_msg = message
        self.hide_cancel = hide_cancel
        return self

    __call__ = configure

    def __enter__(self):
        ida_kernwin.show_wait_box(self._message())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        ida_kernwin.hide_wait_box()

    def replace_message(self, new_message, hide_cancel=False):
        msg = self._message(message=new_message, hide_cancel=hide_cancel)
        ida_kernwin.replace_wait_box(msg)

    def user_canceled(self):
        return ida_kernwin.user_cancelled()

    user_cancelled = user_canceled


class Clipboard:
    @staticmethod
    def _set_text_windows(text: str) -> bool:
        import ctypes.util
        from ctypes import wintypes as w

        GMEM_MOVEABLE = 0x0002
        GMEM_ZEROINIT = 0x0040
        CF_TEXT = 1

        user32 = ctypes.WinDLL("user32")
        kernel32 = ctypes.WinDLL("kernel32")

        OpenClipboard = user32.OpenClipboard
        OpenClipboard.argtypes = (w.HWND,)
        OpenClipboard.restype = w.BOOL

        EmptyClipboard = user32.EmptyClipboard
        EmptyClipboard.restype = w.BOOL

        GlobalAlloc = kernel32.GlobalAlloc
        GlobalAlloc.argtypes = (w.UINT, w.UINT)
        GlobalAlloc.restype = w.HGLOBAL

        GlobalLock = kernel32.GlobalLock
        GlobalLock.argtypes = (w.HGLOBAL,)
        GlobalLock.restype = w.LPVOID

        GlobalUnlock = kernel32.GlobalUnlock
        GlobalUnlock.argtypes = (w.HGLOBAL,)
        GlobalUnlock.restype = w.BOOL

        SetClipboardData = user32.SetClipboardData
        SetClipboardData.argtypes = (w.UINT, w.HANDLE)
        SetClipboardData.restype = w.HANDLE

        CloseClipboard = user32.CloseClipboard
        CloseClipboard.restype = w.BOOL

        if not text:
            return False

        if not OpenClipboard(None) or not EmptyClipboard():
            return False

        h_mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len(text) + 1)
        if not h_mem:
            CloseClipboard()
            return False

        lp_str = GlobalLock(h_mem)
        if not lp_str:
            kernel32.GlobalFree(h_mem)
            CloseClipboard()
            return False

        ctypes.memmove(lp_str, text.encode("utf-8"), len(text))
        GlobalUnlock(h_mem)

        if not SetClipboardData(CF_TEXT, h_mem):
            kernel32.GlobalFree(h_mem)
            CloseClipboard()
            return False

        CloseClipboard()
        return True

    @staticmethod
    def _set_text_macos(text: str) -> bool:
        import subprocess

        try:
            process = subprocess.Popen(
                ["pbcopy"], stdin=subprocess.PIPE, close_fds=True
            )
            process.communicate(input=text.encode("utf-8"))
            return process.returncode == 0
        except Exception as e:
            print(f"Error setting clipboard text on macOS: {e}")
            return False

    @staticmethod
    def _set_text_linux(text: str) -> bool:
        import subprocess

        try:
            process = subprocess.Popen(
                ["xclip", "-selection", "clipboard"],
                stdin=subprocess.PIPE,
                close_fds=True,
            )
            process.communicate(input=text.encode("utf-8"))
            return process.returncode == 0
        except Exception as e:
            print(f"Error setting clipboard text on Linux: {e}")
            return False

    @staticmethod
    def _set_text_pyqt5(text: str) -> bool:
        try:
            from PyQt5.QtWidgets import QApplication

            QApplication.clipboard().setText(text)
            return True
        except ImportError:
            return False
        except Exception as e:
            print(f"Error setting clipboard text on PyQt5: {e}")
            return False

    @classmethod
    def set_text(cls, text: str) -> bool:
        """
        Sets the clipboard text on the current operating system.
        Returns True on success, False on failure.
        """
        # Try to use PyQt5 to set the clipboard text, since
        # that is cross-platform and doesn't require any
        # external dependencies.
        success = cls._set_text_pyqt5(text)
        if success:
            return success

        # Otherwise, use the platform-specific method.
        if sys.platform.startswith("win"):
            return cls._set_text_windows(text)
        elif sys.platform == "darwin":
            return cls._set_text_macos(text)
        elif sys.platform.startswith("linux"):
            return cls._set_text_linux(text)
        else:
            print("Unsupported operating system")
            return False

    def __call__(self, text: str) -> bool:
        """
        Allow instances of Clipboard to be called like a function.
        """
        return self.set_text(text)


SetClipboardText = Clipboard.set_text


# -------------------------
# Signature structures and output functions
# -------------------------


class SignatureType(enum.Enum):
    IDA = 0
    x64Dbg = 1
    Signature_Mask = 2
    SignatureByteArray_Bitmask = 3


class SignatureByte:
    def __init__(self, value: int, isWildcard: bool):
        self.value = value
        self.isWildcard = isWildcard


Signature = list  # list of SignatureByte


def BuildIDASignatureString(signature: Signature, doubleQM: bool = False) -> str:
    result = []
    # Build hex pattern
    for byte in signature:
        if byte.isWildcard:
            result.append("??" if doubleQM else "?")
        else:
            result.append(f"{byte.value:02X}")
        result.append(" ")
    s = "".join(result).rstrip()
    return s


def BuildByteArrayWithMaskSignatureString(signature: Signature) -> str:
    pattern = []
    mask = []
    for byte in signature:
        pattern.append(f"\\x{byte.value:02X}" if not byte.isWildcard else "\\x00")
        mask.append("x" if not byte.isWildcard else "?")
    return "".join(pattern) + " " + "".join(mask)


def BuildBytesWithBitmaskSignatureString(signature: Signature) -> str:
    pattern = []
    mask = []
    for byte in signature:
        pattern.append(f"0x{byte.value:02X}, " if not byte.isWildcard else "0x00, ")
        mask.append("1" if not byte.isWildcard else "0")
    pattern_str = "".join(pattern).rstrip(", ")
    mask_str = "".join(mask)[::-1]  # Reverse the bitmask
    return pattern_str + " 0b" + mask_str


def FormatSignature(signature: Signature, sig_type: SignatureType) -> str:
    if sig_type == SignatureType.IDA:
        return BuildIDASignatureString(signature)
    elif sig_type == SignatureType.x64Dbg:
        return BuildIDASignatureString(signature, True)
    elif sig_type == SignatureType.Signature_Mask:
        return BuildByteArrayWithMaskSignatureString(signature)
    elif sig_type == SignatureType.SignatureByteArray_Bitmask:
        return BuildBytesWithBitmaskSignatureString(signature)
    return ""


# -------------------------
# Utility functions (signature byte addition, trim, clipboard, regex)
# -------------------------


def AddByteToSignature(signature: Signature, address, wildcard: bool):
    b = ida_bytes.get_byte(address)
    signature.append(SignatureByte(b, wildcard))


def AddBytesToSignature(signature: Signature, address, count: int, wildcard: bool):
    for i in range(count):
        AddByteToSignature(signature, address + i, wildcard)


def TrimSignature(signature: Signature):
    # Remove trailing wildcards
    while signature and signature[-1].isWildcard:
        signature.pop()


def GetRegexMatches(string: str, regex: re.Pattern, matches: list) -> bool:
    matches.clear()
    matches.extend(re.findall(regex, string))
    return bool(matches)


# -------------------------
# Exception for errors
# -------------------------
class Unexpected(Exception):
    pass


class ConfigureOperandWildcardBitmaskForm(ida_kernwin.Form):
    """Interactive Form to configure wildcardable operands using checkboxes."""

    def __init__(self):
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
        registers = ["opt1", "opt2", "opt3", "opt4", "opt5", "opt6", "opt7"]

        # Processor-specific operand types
        PROCESSOR_ARCH = ida_idp.ph_get_id()
        if PROCESSOR_ARCH == ida_idp.PLFM_386:
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
        elif PROCESSOR_ARCH == ida_idp.PLFM_ARM:
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
        elif PROCESSOR_ARCH == ida_idp.PLFM_PPC:
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
        # Define checkboxes
        controls = {
            "FormChangeCb": F.FormChangeCb(self.OnFormChange),
            "cWildcardableOperands": F.ChkGroupControl(
                tuple(registers),
                value=options,
            ),
        }
        # Initialize form
        super().__init__(form_text, controls)

    def OnFormChange(self, fid):
        """Handle form changes."""
        if fid == self.cWildcardableOperands.id:
            global WildcardableOperandTypeBitmask
            # print(f"cWildcardableOperands changed: {self.GetControlValue(self.cWildcardableOperands):06x}")
            # Re-shift by one because we skipped o_void
            WildcardableOperandTypeBitmask = (
                self.GetControlValue(self.cWildcardableOperands) << 1
            )
        return 1


class ConfigureOptionsForm(ida_kernwin.Form):
    """Interactive Form to configure XREF and signature generation options."""

    def __init__(self):
        F = ida_kernwin.Form

        # Define the form layout
        form_text = """BUTTON YES* OK
BUTTON CANCEL Cancel
Options

<#Print top X shortest signatures when generating xref signatures#Print top X XREF signatures     :{opt1}>
<#Stop after reaching X bytes when generating a single signature#Maximum single signature length :{opt2}>
<#Stop after reaching X bytes when generating xref signatures#Maximum xref signature length   :{opt3}>
"""

        # Define numerical input fields (corresponding to `u` in C++)
        self.controls = {
            "opt1": F.NumericInput(tp=F.FT_DEC),  # PRINT_TOP_X
            "opt2": F.NumericInput(tp=F.FT_DEC),  # MAX_SINGLE_SIGNATURE_LENGTH
            "opt3": F.NumericInput(tp=F.FT_DEC),  # MAX_XREF_SIGNATURE_LENGTH
        }

        # Initialize form
        super().__init__(form_text, self.controls)

    def ExecuteForm(self):
        """Execute the form and apply changes."""
        global PRINT_TOP_X, MAX_SINGLE_SIGNATURE_LENGTH, MAX_XREF_SIGNATURE_LENGTH

        # Pre-fill form values
        self.controls["opt1"].value = PRINT_TOP_X
        self.controls["opt2"].value = MAX_SINGLE_SIGNATURE_LENGTH
        self.controls["opt3"].value = MAX_XREF_SIGNATURE_LENGTH

        result = self.Execute()
        # Show form
        if result != 1:
            self.Free()
            return result

        # Apply the new values to the global variables
        PRINT_TOP_X = self.controls["opt1"].value
        MAX_SINGLE_SIGNATURE_LENGTH = self.controls["opt2"].value
        MAX_XREF_SIGNATURE_LENGTH = self.controls["opt3"].value
        self.Free()
        return result


class SignatureMakerForm(ida_kernwin.Form):
    def __init__(self):
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
<#Example - \\xE8\\x00\\x00\\x00\\x00\\x45\\x33\\xF6\\x66\\x44\\x89\\x34\\x33 x????xxxxxxxx#C Byte Array String Signature + String mask:{rByteArrayMaskSig}>
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
            # Radio group for selecting the main action.
            "rAction": F.RadGroupControl(
                ("rCreateUniqueSig", "rFindXRefSig", "rCopyCode", "rSearchSignature")
            ),
            # Radio group for selecting output format.
            "rOutputFormat": F.RadGroupControl(
                ("rIDASig", "rx64DbgSig", "rByteArrayMaskSig", "rRawBytesBitmaskSig")
            ),
            # Checkboxes for quick options.
            "cGroupOptions": ida_kernwin.Form.ChkGroupControl(
                ("cWildcardOperands", "cContinueOutside", "cWildcardOptimized"),
                value=5,
            ),
            # Buttons for further configuration.
            "bOperandTypes": F.ButtonInput(self.ConfigureOperandWildcardBitmask),
            "bOtherOptions": F.ButtonInput(self.ConfigureOptions),
        }
        super().__init__(form_text, controls)

    def OnFormChange(self, fid):
        # (Optional: add code to respond to field changes.)
        # print(f"Form changed, fid: {fid}", self.rAction.id, self.rOutputFormat.id, self.cGroupOptions.id)
        # if fid == self.rAction.id:
        #     print(
        #         f"Action [{fid}] rAction changed: {self.GetControlValue(self.rAction):06x}"
        #     )
        # elif fid == self.rOutputFormat.id:
        #     print(
        #         f"Action [{fid}] rOutputFormat changed: {self.GetControlValue(self.rOutputFormat):06x}"
        #     )
        # elif fid == self.cGroupOptions.id:
        #     print(
        #         f"Action [{fid}] cGroupOptions changed: {self.GetControlValue(self.cGroupOptions):06x}"
        #     )
        # else:
        #     print(">>fid:%d" % fid)
        return 1

    def ConfigureOperandWildcardBitmask(self, code=0):
        form = ConfigureOperandWildcardBitmaskForm()
        form.Compile()
        ok = form.Execute()
        if not ok:
            return 0
        return 1

    def ConfigureOptions(self, code=0):
        """Launch the options configuration form."""
        form = ConfigureOptionsForm()
        form.Compile()
        return form.ExecuteForm()


# -------------------------
# The main plugin class
# -------------------------


def set_wildcardable_operand_type_bitmask():
    global WildcardableOperandTypeBitmask

    # Default wildcard setting depending on processor arch
    if PROCESSOR_ARCH == ida_idp.PLFM_386:
        o_ymmreg = idc.o_xmmreg + 1
        o_zmmreg = o_ymmreg + 1
        o_kreg = o_zmmreg + 1
        WildcardableOperandTypeBitmask = (
            BIT(idc.o_mem)
            | BIT(idc.o_phrase)
            | BIT(idc.o_displ)
            | BIT(idc.o_far)
            | BIT(idc.o_near)
            | BIT(idc.o_imm)
            | BIT(idc.o_trreg)
            | BIT(idc.o_dbreg)
            | BIT(idc.o_crreg)
            | BIT(idc.o_fpreg)
            | BIT(idc.o_mmxreg)
            | BIT(idc.o_xmmreg)
            | BIT(o_ymmreg)
            | BIT(o_zmmreg)
            | BIT(o_kreg)
        )
    elif PROCESSOR_ARCH == ida_idp.PLFM_ARM:
        WildcardableOperandTypeBitmask = (
            BIT(idc.o_mem)
            | BIT(idc.o_phrase)
            | BIT(idc.o_displ)
            | BIT(idc.o_far)
            | BIT(idc.o_near)
            | BIT(idc.o_imm)
        )
    elif PROCESSOR_ARCH == ida_idp.PLFM_MIPS:
        WildcardableOperandTypeBitmask = (
            BIT(idc.o_mem) | BIT(idc.o_far) | BIT(idc.o_near)
        )
    else:
        WildcardableOperandTypeBitmask = (
            BIT(idc.o_mem)
            | BIT(idc.o_phrase)
            | BIT(idc.o_displ)
            | BIT(idc.o_far)
            | BIT(idc.o_near)
            | BIT(idc.o_imm)
        )


class _ActionHandler(idaapi.action_handler_t):

    def __init__(self, action_function):
        super().__init__()
        self.action_function = action_function

    def activate(self, ctx):
        self.action_function(ctx=ctx)
        return 1

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_DISASM:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


def is_disassembly_widget(widget, popup, ctx):
    return idaapi.get_widget_type(widget) == idaapi.BWN_DISASM


class _PopupHook(idaapi.UI_Hooks):

    def __init__(
        self, action_name, predicate=None, widget_populator=None, category=None
    ):
        super().__init__()
        self.action_name = action_name
        self.predicate = predicate or is_disassembly_widget
        self.widget_populator = widget_populator or self._default_populator
        self.category = category

    def term(self):
        idaapi.unregister_action(self.action_name)

    @staticmethod
    def _default_populator(instance, widget, popup_handle, ctx):
        if instance.predicate(widget, popup_handle, ctx):
            args = [widget, popup_handle, instance.action_name]
            if instance.category:
                args.append(f"{instance.category}/")
            idaapi.attach_action_to_popup(*args)

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        return self.widget_populator(self, widget, popup_handle, ctx)


class PySigMaker(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = f"{PLUGIN_NAME} v{PLUGIN_VERSION} for IDA Pro by {PLUGIN_AUTHOR}"
    help = "Select location in disassembly and press CTRL+ALT+S to open menu"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-S"
    IS_ARM = False

    ACTION_SHOW_SIGMAKER = "pysigmaker:show"

    def init(self):
        self.progress_dialog = ProgressDialog()
        self._hooks = self._init_hooks(_PopupHook(self.ACTION_SHOW_SIGMAKER))
        self._register_actions()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.run_plugin()

    def term(self):
        # unregister our actions & free their resources
        self._deregister_actions()
        # unhook our plugin hooks
        self._deinit_hooks(*self._hooks)

    def _init_hooks(self, *hooks):
        for hook in hooks:
            hook.hook()
        return hooks

    def _deinit_hooks(self, *hooks):
        for hook in hooks:
            hook.unhook()

    def _register_actions(self):
        # If the action is already registered, unregister it first.
        self._deregister_actions()
        # Describe the action using python3 copy
        idaapi.register_action(
            idaapi.action_desc_t(
                self.ACTION_SHOW_SIGMAKER,  # The action name.
                "SigMaker",  # The action text.
                _ActionHandler(self.run_plugin),  # The action handler.
                self.wanted_hotkey,  # Optional: action shortcut
                "Show the signature maker dialog.",  # Optional: tooltip
                154,  # magnifying glass icon
            )
        )

    def _deregister_actions(self):
        return idaapi.unregister_action(self.ACTION_SHOW_SIGMAKER)

    # -------------------------
    # Processor and operand handling
    # -------------------------
    def IsARM(self) -> bool:
        procname = ida_ida.inf_get_procname()
        return "ARM" in procname.upper()

    def GetOperandOffsetARM(self, instruction, operand_offset, operand_length) -> bool:
        # For ARM: assume operand is 3 bytes if size==4, 7 bytes if size==8.
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

    def GetOperand(
        self, instruction, operand_offset, operand_length, wildcard_optimized
    ) -> bool:
        # For non-ARM: iterate over operands and apply the bitmask and optimized–instruction check.
        if self.IS_ARM:
            return self.GetOperandOffsetARM(instruction, operand_offset, operand_length)
        for op in instruction.ops:
            if op.type == idaapi.o_void:
                continue
            # Only process operands that are marked in our bitmask.
            if (BIT(op.type) & WildcardableOperandTypeBitmask) == 0:
                continue
            isOptimizedInstr = op.offb == 0
            if isOptimizedInstr and not wildcard_optimized:
                continue
            operand_offset[0] = op.offb
            operand_length[0] = instruction.size - op.offb
            return True
        return False

    # -------------------------
    # QIS scanning support
    # -------------------------
    def ReadSegmentsToBuffer(self) -> bytes:
        buf = bytearray()
        seg = idaapi.get_first_seg()
        while seg:
            size = seg.end_ea - seg.start_ea
            data = ida_bytes.get_bytes(seg.start_ea, size)
            if data:
                buf.extend(data)
            seg = idaapi.get_next_seg(seg)
        return bytes(buf)

    def parse_signature(self, sig_str: str):
        # Convert a signature string (tokens separated by whitespace)
        # into a list of tuples (value, is_wildcard)
        tokens = sig_str.split()
        pattern = []
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

    def FindSignatureOccurencesQis(
        self, ida_signature: str, skip_more_than_one: bool = False
    ) -> list:
        global FILE_BUFFER
        if not FILE_BUFFER:
            with ProgressDialog("Please stand by, copying segments..."):
                FILE_BUFFER = self.ReadSegmentsToBuffer()
        # Convert to QIS signature string: simply double each '?'
        qis_signature = ida_signature.replace("?", "??")
        pattern = self.parse_signature(qis_signature)
        results = []
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

    def FindSignatureOccurences(self, ida_signature: str) -> list:
        if USE_QIS_SIGNATURE:
            return self.FindSignatureOccurencesQis(ida_signature)
        # Otherwise use IDA’s built-in binary pattern search.
        binary_pattern = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(
            binary_pattern, ida_ida.inf_get_min_ea(), ida_signature, 16
        )
        results = []
        ea = ida_ida.inf_get_min_ea()
        _bin_search = getattr(ida_bytes, "bin_search", None)
        # See https://github.com/mahmoudimus/ida-pysigmaker/pull/2
        # In particular this discussion:
        # https://github.com/mahmoudimus/ida-pysigmaker/pull/2#discussion_r1991913976
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

    def IsSignatureUnique(self, ida_signature: str) -> bool:
        return len(self.FindSignatureOccurences(ida_signature)) == 1

    # -------------------------
    # Signature generation for unique EA and a range
    # -------------------------
    def GenerateUniqueSignatureForEA(
        self,
        ea,
        wildcard_operands,
        continue_outside_of_function,
        wildcard_optimized,
        max_signature_length=1000,
        ask_longer_signature=True,
    ):
        if ea == idaapi.BADADDR:
            raise Unexpected("Invalid address")
        if not idaapi.is_code(ida_bytes.get_flags(ea)):
            raise Unexpected("Cannot create code signature for data")
        signature = []
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
                sig_str = BuildIDASignatureString(signature)
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
                        sig_str = BuildIDASignatureString(signature)
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
                and self.GetOperand(
                    instruction, operand_offset, operand_length, wildcard_optimized
                )
                and operand_length[0] > 0
            ):
                AddBytesToSignature(
                    signature, current_address, operand_offset[0], False
                )
                AddBytesToSignature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    AddBytesToSignature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                AddBytesToSignature(
                    signature, current_address, current_instruction_length, False
                )

            current_sig = BuildIDASignatureString(signature)
            if self.IsSignatureUnique(current_sig):
                TrimSignature(signature)
                return signature

            current_address += current_instruction_length

            if (
                not continue_outside_of_function
                and current_function
                and idaapi.get_func(current_address) != current_function
            ):
                raise Unexpected("Signature left function scope")
        raise Unexpected("Unknown")

    def GenerateSignatureForEARange(
        self, ea_start, ea_end, wildcard_operands, wildcard_optimized
    ):
        if ea_start == idaapi.BADADDR or ea_end == idaapi.BADADDR:
            raise Unexpected("Invalid address")
        signature = []
        sig_part_length = 0
        if not idaapi.is_code(ida_bytes.get_flags(ea_start)):
            AddBytesToSignature(signature, ea_start, ea_end - ea_start, False)
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
                    AddBytesToSignature(
                        signature, current_address, ea_end - current_address, False
                    )
                TrimSignature(signature)
                return signature
            sig_part_length += current_instruction_length

            operand_offset = [0]
            operand_length = [0]
            if (
                wildcard_operands
                and self.GetOperand(
                    instruction, operand_offset, operand_length, wildcard_optimized
                )
                and operand_length[0] > 0
            ):
                AddBytesToSignature(
                    signature, current_address, operand_offset[0], False
                )
                AddBytesToSignature(
                    signature,
                    current_address + operand_offset[0],
                    operand_length[0],
                    True,
                )
                if operand_offset[0] == 0:
                    AddBytesToSignature(
                        signature,
                        current_address + operand_length[0],
                        current_instruction_length - operand_length[0],
                        False,
                    )
            else:
                AddBytesToSignature(
                    signature, current_address, current_instruction_length, False
                )
            current_address += current_instruction_length

            if current_address >= ea_end:
                TrimSignature(signature)
                return signature
        raise Unexpected("Unknown")

    # -------------------------
    # Output functions
    # -------------------------
    def PrintSignatureForEA(self, signature, ea, sig_type):
        if not signature:
            idc.msg(f"Error: {signature}\n")
            return
        sig_str = FormatSignature(signature, sig_type)
        idc.msg(f"Signature for {ea:X}: {sig_str}\n")
        if not SetClipboardText(sig_str):
            idc.msg("Failed to copy to clipboard!")

    def FindXRefs(
        self,
        ea,
        wildcard_operands,
        continue_outside_of_function,
        wildcard_optimized,
        xref_signatures,
        max_signature_length,
    ):
        # Count code xrefs.
        xref_count = 0
        xb = ida_xref.xrefblk_t()
        if xb.first_to(ea, ida_xref.XREF_ALL):
            while True:
                if idaapi.is_code(ida_bytes.get_flags(xb.frm)):
                    xref_count += 1
                if not xb.next_to():
                    break
        # Process each xref.
        xb = ida_xref.xrefblk_t()
        if not xb.first_to(ea, ida_xref.XREF_ALL):
            return
        i = 0
        shortest_signature_length = max_signature_length + 1
        while True:
            if self.progress_dialog.user_cancelled():
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
                sig = self.GenerateUniqueSignatureForEA(
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

    def PrintXRefSignaturesForEA(self, ea, xref_signatures, sig_type, top_count):
        if not xref_signatures:
            idc.msg("No XREFs have been found for your address\n")
            return
        top_length = min(top_count, len(xref_signatures))
        idc.msg(
            f"Top {top_length} Signatures out of {len(xref_signatures)} xrefs for {ea:X}:\n"
        )
        for i in range(top_length):
            origin_address, signature = xref_signatures[i]
            sig_str = FormatSignature(signature, sig_type)
            idc.msg(f"XREF Signature #{i+1} @ {origin_address:X}: {sig_str}\n")
            if i == 0:
                SetClipboardText(sig_str)

    def PrintSelectedCode(
        self, start, end, sig_type, wildcard_operands, wildcard_optimized
    ):
        selection_size = end - start
        if selection_size <= 0:
            idc.msg("Invalid selection size\n")
            return
        try:
            signature = self.GenerateSignatureForEARange(
                start, end, wildcard_operands, wildcard_optimized
            )
        except Unexpected as e:
            idc.msg(f"Error: {str(e)}\n")
            return
        sig_str = FormatSignature(signature, sig_type)
        idc.msg(f"Code for {start:X}-{end:X}: {sig_str}\n")
        SetClipboardText(sig_str)

    def SearchSignatureString(self, input_str: str):
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
            raw_byte_strings = []
            if GetRegexMatches(
                input_str,
                re.compile(r"\\x[0-9A-F]{2}", re.IGNORECASE),
                raw_byte_strings,
            ) and len(raw_byte_strings) == len(string_mask):
                converted_signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = BuildIDASignatureString(
                    converted_signature
                )
            elif GetRegexMatches(
                input_str,
                re.compile(r"(?:0x[0-9A-F]{2})+", re.IGNORECASE),
                raw_byte_strings,
            ) and len(raw_byte_strings) == len(string_mask):
                converted_signature = []
                for i, m in enumerate(raw_byte_strings):
                    b = SignatureByte(int(m[2:], 16), string_mask[i] == "?")
                    converted_signature.append(b)
                converted_signature_string = BuildIDASignatureString(
                    converted_signature
                )
            else:
                idc.msg(
                    f'Detected mask "{string_mask}" but failed to match corresponding bytes\n'
                )
        else:
            # Remove extraneous characters and normalize
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
        signature_matches = self.FindSignatureOccurences(converted_signature_string)
        if not signature_matches:
            idc.msg("Signature does not match!\n")
            return
        for ea in signature_matches:
            idc.msg(f"Match @ {ea:X}\n")

    # -------------------------
    # Main plugin UI and dispatch
    # -------------------------
    def run_plugin(self, ctx=None):
        # Determine processor type and set globals.
        self.IS_ARM = self.IsARM()

        set_wildcardable_operand_type_bitmask()

        # Show the main form.
        form = SignatureMakerForm()
        form.Compile()
        ok = form.Execute()
        if not ok:
            form.Free()
            return

        action = form.rAction.value
        output_format = form.rOutputFormat.value
        wildcard_operands = form.cGroupOptions.value & 1
        continue_outside_of_function = form.cGroupOptions.value & 2
        wildcard_optimized = form.cGroupOptions.value & 4

        # If the configuration buttons were pressed, they may have updated globals.
        form.Free()

        sig_type = SignatureType(output_format)

        try:
            if action == 0:
                # Create unique signature for current code address.
                ea = ida_kernwin.get_screen_ea()
                with self.progress_dialog("Generating signature..."):
                    sig = self.GenerateUniqueSignatureForEA(
                        ea,
                        wildcard_operands,
                        continue_outside_of_function,
                        wildcard_optimized,
                        MAX_SINGLE_SIGNATURE_LENGTH,
                    )
                    self.PrintSignatureForEA(sig, ea, sig_type)
            elif action == 1:
                # Find XREF signatures.
                ea = ida_kernwin.get_screen_ea()
                xref_signatures = []
                with self.progress_dialog(
                    "Finding references and generating signatures. This can take a while..."
                ):
                    self.FindXRefs(
                        ea,
                        wildcard_operands,
                        continue_outside_of_function,
                        wildcard_optimized,
                        xref_signatures,
                        MAX_XREF_SIGNATURE_LENGTH,
                    )
                    self.PrintXRefSignaturesForEA(
                        ea, xref_signatures, sig_type, PRINT_TOP_X
                    )
            elif action == 2:
                # Copy selected code.
                start, end = get_selected_addresses(idaapi.get_current_viewer())
                if start and end:
                    with self.progress_dialog("Please stand by..."):
                        self.PrintSelectedCode(
                            start, end, sig_type, wildcard_operands, wildcard_optimized
                        )
                else:
                    idc.msg("Select a range to copy the code!\n")
            elif action == 3:
                # Search for a signature.
                input_signature = idaapi.ask_str(
                    "", idaapi.HIST_SRCH, "Enter a signature"
                )
                if input_signature:
                    with self.progress_dialog("Searching..."):
                        self.SearchSignatureString(input_signature)
        except Unexpected as e:
            idc.msg(f"Error: {str(e)}\n")
        except Exception as e:
            print(e, os.linesep, traceback.format_exc())
            return


def get_selected_addresses(ctx):
    is_selected, start_ea, end_ea = idaapi.read_range_selection(ctx)
    if is_selected:
        return start_ea, end_ea

    # maybe it's the same line?
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

    # if we are here, we haven't selected anything, so we use the current address
    start_ea = idaapi.get_screen_ea()
    try:
        end_ea = ida_kernwin.ask_addr(start_ea, "Enter end address for selection:")
    finally:
        # restore the cursor to the original address
        idc.jumpto(start_ea)

    if end_ea and end_ea <= start_ea:
        print(
            f"Error: End address 0x{end_ea:X} must be greater than start address 0x{start_ea:X}."
        )
        end_ea = None

    if end_ea is None:
        # if we canceled the dialog, let's assume the user wants
        # to select just the line they're on
        end_ea = idc.get_item_end(start_ea)
        print(f"No end address selected, using line end: 0x{end_ea:X}")

    return start_ea, end_ea


def PLUGIN_ENTRY():
    return PySigMaker()
