# Signature Maker Plugin for IDA Pro 9.0+

<img src="https://github.com/mahmoudimus/ida-sigmaker/blob/main/assets/sigmaker-logo.png?raw=true" width="104px" height="100px" alt="Magnifying glass with the word 'sigmaker' and a cross-hair over the 'A' in sigmaker" /> [![ida-sigmaker tests](https://github.com/mahmoudimus/ida-sigmaker/actions/workflows/python.yml/badge.svg)](https://github.com/mahmoudimus/ida-sigmaker/actions/workflows/python.yml)

An IDA Pro 9.0+ cross-platform signature maker plugin that works on MacOS/Linux/Windows. The primary goal of this plugin is to work with future versions of IDA without needing to compile against the IDA SDK as well as to allow for easier community contributions.

## Installation

sigmaker's main value proposition is its cross-platform (Windows, macOS, Linux) Python 3 support. It uses zero third party dependencies, making the code both portable and easy to install.

### Quick Install

- Copy [`src/sigmaker/__init__.py`](./src/sigmaker/__init__.py) into the /plugins/ folder to the plugin directory!
- Rename it to `sigmaker.py`
- Restart your disassembler.

### From Releases

- Download the latest release from the [Releases page](https://github.com/mahmoudimus/ida-sigmaker/releases)
- Extract `sigmaker.py` from the release package
- Copy it to your IDA Pro plugins directory
- Restart IDA Pro

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

## Requirements

- IDA Pro 9.0+
- IDA Python
- Python 3.10+

## What is a "sigmaker"?

Sigmaker stands for "signature maker." It enables users to create unique binary pattern signatures that can identify specific addresses or routines within a binary, even after the binary has been updated.

In malware analysis or binary reverse engineering, a common challenge is pinpointing an important address, such as a function or global variable. However, when the binary is updated, all the effort spent identifying these locations can be lost if their addresses change.

To preserve this work, reverse engineers take advantage of the fact that most programs do not change drastically between updates. While some functions or data may be modified, much of the binary remains the same. Most often, previously identified addresses are simply relocated. This is where `sigmaker` comes in.

Sigmaker lets you create unique patterns to track important parts of a program, making your analysis more resilient to updates. By generating signatures for specific functions, data references, or other critical locations, you can quickly relocate these points in a new version of the binary, saving time and effort in future reverse engineering tasks.

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

## Acknowledgements

Thank you to to [@A200K](https://github.com/A200K)'s [IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker) plugin which served as an inspiration and the initial port of this plugin.

## Development & Releases

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Contact

ping me on x [@mahmoudimus](https://x.com/mahmoudimus) or you may contact me from any one of the addresses on [mahmoudimus.com](https://mahmoudimus.com).
