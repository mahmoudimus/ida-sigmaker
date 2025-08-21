# ida-pysigmaker

An IDA Pro 9.0+ cross-platform port of @A200K's [IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker) to Python. Works on MacOS/Linux/Windows.

Signature Maker Plugin for IDA Pro 9.0+

## Requirements

- IDA Python
- Python 3

## Installation

This python port of sigmaker's main value proposition is its cross-platform (Windows, macOS, Linux) Python 3 support. It takes zero third party dependencies, making the code both portable and easy to install.

- Copy `sigmaker.py` into the /plugins/ folder to the plugin directory!
- Restart your disassembler.

That's it!

### Need to find your plugin directory?

From IDA's Python console run the following command to find its plugin directory:

```python
import idaapi, os; print(os.path.join(idaapi.get_user_idadir(), "plugins"))
```

### Where and what is my default user directory?

The user directory is a location where IDA stores some of the global settings and which can be used for some additional customization.
Default location:

- On Windows: `%APPDATA%/Hex-Rays/IDA Pro`
- On Linux and Mac: `$HOME/.idapro`

## Usage

In disassembly view, select a line you want to generate a signature for, and press
**CTRL+ALT+S**
![](https://i.imgur.com/b4MKkca.png)

The generated signature will be printed to the output console, as well as copied to the clipboard:
![](https://i.imgur.com/mTFbKce.png)

___

| Signature type | Example preview |
| --- | ----------- |
| IDA Signature | E8 ? ? ? ? 45 33 F6 66 44 89 34 33 |
| x64Dbg Signature | E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33 |
| C Byte Array Signature + String mask | \xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33 x????xxxxxxxx |
| C Raw Bytes Signature + Bitmask | 0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33  0b1111111100001 |

___

### Finding XREFs

Generating code Signatures by data or code xrefs and finding the shortest ones is also supported:
![](https://i.imgur.com/P0VRIFQ.png)

___

### Signature searching

Searching for Signatures works for supported formats:

![](https://i.imgur.com/lD4Zfwb.png)

Just enter any string containing your Signature, it will automatically try to figure out what kind of Signature format is being used:

![](https://i.imgur.com/oWMs7LN.png)

Currently, all output formats you can generate are supported.

Match(es) of your signature will be printed to console:

![](https://i.imgur.com/Pe4REkX.png)
