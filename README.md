# Signature Maker Plugin for IDA Pro 9.0+

<img src="https://github.com/mahmoudimus/ida-sigmaker/blob/main/assets/sigmaker-logo.png?raw=true" width="104px" height="100px" alt="Magnifying glass with the word 'sigmaker' and a cross-hair over the 'A' in sigmaker" /> [![ida-sigmaker tests](https://github.com/mahmoudimus/ida-sigmaker/actions/workflows/python.yml/badge.svg)](https://github.com/mahmoudimus/ida-sigmaker/actions/workflows/python.yml)

An IDA Pro 9.0+ zero-dependency cross-platform signature maker plugin with optional SIMD (e.g. AVX2/NEON/SSE2) speedups that works on MacOS/Linux/Windows. The primary goal of this plugin is to work with future versions of IDA without needing to compile against the IDA SDK as well as to allow for easier community contributions.

## Installation

sigmaker's main value proposition is its cross-platform (Windows, macOS, Linux) Python 3 support. It uses zero third party dependencies, making the code both portable and easy to install.

### Quick Install

- Copy [`src/sigmaker/__init__.py`](./src/sigmaker/__init__.py) into the /plugins/ folder to the plugin directory!
- Rename it to `sigmaker.py`
- *OPTIONALLY*, if you would like `SIMD` speedups, just `pip install sigmaker`
- Restart IDA Pro.

### From Releases

- Download the latest conveniently renamed `sigmaker.py` release from the [Releases page](https://github.com/mahmoudimus/ida-sigmaker/releases)
- Copy it to your IDA Pro plugins directory
- *OPTIONALLY*, if you would like `SIMD` speedups, just `pip install sigmaker`
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

## SIMD Speedups

If you just followed the installation above and ran `pip install sigmaker`, then based on your system and architecture (i.e. Windows (x64), Linux (x64), Mac (x64), Mac (ARM/Silicon)), the plugin will install the appropriate wheel and will automatically use them if they're available. You do not have to do anything else. The plugin is designed to display the status of whether or not SIMD speedups are installed. They are shown in the top right menu bar of the plugin:

### SIMD Enabled

![](./assets/simd_enabled.png)

### No SIMD Speedups

![](./assets/no_simd_speedup.png)

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
**CTRL+ALT+S**:
![](./assets/gen_signature.png)

*OR* *Right-Click* and select *SigMaker*:
![](./assets/right_click.png)

The generated signature will be printed to the output console, **as well as copied to the clipboard**:
![](./assets/output_sig.png)

___

| Signature type | Example preview |
| --- | ----------- |
| IDA Signature | `E8 ? ? ? ? 45 33 F6 66 44 89 34 33` |
| x64Dbg Signature | `E8 ?? ?? ?? ?? 45 33 F6 66 44 89 34 33` |
| C Byte Array Signature + String mask | `\xE8\x00\x00\x00\x00\x45\x33\xF6\x66\x44\x89\x34\x33 x????xxxxxxxx` |
| C Raw Bytes Signature + Bitmask | `0xE8, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xF6, 0x66, 0x44, 0x89, 0x34, 0x33  0b1111111100001` |

___

### Finding XREFs

Generating code Signatures by data or code xrefs and finding the shortest ones is also supported:
![](./assets/xref_search.png)

___

### Signature searching

Searching for Signatures works for supported formats:

![](./assets/sig_search.png)

It also supports wildcard nibble search support:

![](./assets/nibble_wildcard_search.png)

Just enter any string containing your Signature, it will automatically try to figure out what kind of Signature format is being used:

![](./assets/smart_format_sig_search.png)

Currently, all output formats you can generate are supported.

Match(es) of your signature will be printed to console alongside the containing function name:

![](./assets/matches_console.png)

If the matched address is not a function name or has no function name, it falls back to just printing the address:

![](./assets/matches_console_no_func.png)

### Signature Configuration

`sigmaker` also supports configurable wildcardable operands for unique signature creation:

![](./assets/operand_selection.png)

There are also various options that be configured via the `Other options` button:

![](./assets/optional_configuration.png)

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
