# Signature Maker Plugin for IDA Pro 9.0+

<img src="https://github.com/mahmoudimus/ida-sigmaker/blob/main/assets/sigmaker-logo.png?raw=true" width="104px" height="100px" alt="Magnifying glass with the word 'sigmaker' and a cross-hair over the 'A' in sigmaker" /> [![ida-sigmaker tests](https://github.com/mahmoudimus/ida-sigmaker/actions/workflows/python.yml/badge.svg)](https://github.com/mahmoudimus/ida-sigmaker/actions/workflows/python.yml)

An IDA Pro 9.0+ zero-dependency cross-platform signature maker plugin with optional SIMD (e.g. AVX2/NEON/SSE2) speedups that works on MacOS/Linux/Windows. The primary goal of this plugin is to work with future versions of IDA without needing to compile against the IDA SDK as well as to allow for easier community contributions.

Background reading on [mahmoudimus.com](https://mahmoudimus.com):

- [IDA Pro and Cython: super-charging the work-horse of reverse engineering](https://mahmoudimus.com/blog/2025/08/ida-pro-and-cython-super-charging-the-work-horse-of-reverse-engineering/): how the optional SIMD speedups were built.
- [Growing a unique function signature without rescanning the binary](https://mahmoudimus.com/blog/2026/05/growing-a-unique-function-signature-without-rescanning-the-binary/): the search algorithm, with interactive visualizations.
- [How do you know your Cython hot loop is fast enough?](https://mahmoudimus.com/blog/2026/05/how-do-you-know-your-cython-hot-loop-is-fast-enough/): how I confirmed those kernels are already optimal (memory-bound, not compute-bound).

## Table of contents

- [Installation](#installation)
  - [Quick Install](#quick-install)
  - [From Releases](#from-releases)
  - [Install with hcli](#install-with-hcli)
  - [Need to find your plugin directory?](#need-to-find-your-plugin-directory)
  - [Where and what is my default user directory?](#where-and-what-is-my-default-user-directory)
- [SIMD Speedups](#simd-speedups)
- [Requirements](#requirements)
- [What is a "sigmaker"?](#what-is-a-sigmaker)
- [Usage](#usage)
  - [Finding XREFs](#finding-xrefs)
  - [Signature searching](#signature-searching)
  - [Batch signature search](#batch-signature-search)
  - [Signature Configuration](#signature-configuration)
- [Performance](#performance)
  - [Benchmarks](#benchmarks)
  - [How it works](#how-it-works)
- [Using SigMaker as a library](#using-sigmaker-as-a-library)
  - [Batch search API](#batch-search-api)
  - [Custom batch search formatters](#custom-batch-search-formatters)
  - [Stability contract](#stability-contract)
  - [Used by](#used-by)
- [Acknowledgements](#acknowledgements)
- [Development & Releases](#development--releases)
  - [Contributing](#contributing)
- [Contact](#contact)

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

### Install with hcli

[`hcli`](https://hcli.docs.hex-rays.com/) is Hex-Rays' command-line tool, and it can install sigmaker from the IDA Plugin Repository. Install `hcli` once:

```bash
curl -LsSf https://hcli.docs.hex-rays.com/install | sh        # macOS/Linux
iwr -useb https://hcli.docs.hex-rays.com/install.ps1 | iex    # Windows (PowerShell)
```

Then authenticate (see the [hcli docs](https://hcli.docs.hex-rays.com/)) and install the plugin:

```bash
hcli plugin search sigmaker
hcli plugin install SigMaker
```

`hcli` downloads the plugin and places it in `$IDAUSR/plugins` (`~/.idapro/plugins` on macOS/Linux), where IDA loads it on the next launch. Requires IDA 9.0+. For `SIMD` speedups, also run `pip install sigmaker` as above.

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

### Batch signature search

To search several signatures at once, choose **Batch search signatures** from the main SigMaker dialog. Paste one signature per line, or separate entries with semicolons.

Batch search accepts named and unnamed patterns:

```text
print = "48 8B ?? ??"
update := E8 ? ? ? ? 48 89 C7
tick = 90 90 CC; draw = "48 89 C7"
48 8B ?? ?? 89
```

Names are optional and must use `name := pattern` or `name = pattern`. Quoted patterns are supported only as the right-hand side of a named pattern. SigMaker does not parse C declarations or join patterns across multiple lines. If a pattern has no name, SigMaker labels it by source line in the result list. `#` and `//` comments are ignored outside quoted strings, and Markdown fence lines are skipped so you can paste snippets from issues or notes.

Each pattern is normalized through the same parser used by regular signature search. Invalid patterns are reported per entry instead of aborting the whole batch. Patterns must contain at least one exact byte; an all-wildcard pattern such as `?? ?? ??` is rejected because it matches almost everywhere and is not a useful search key.

Results are printed to the IDA output window with:

- the normalized signature,
- match count,
- a short address preview,
- containing function names when IDA can resolve them,
- RVA relative to the imagebase,
- file offset when IDA can map the address back to the input file.

After the search, SigMaker can export the batch result list:

| Extension | Format |
| --- | --- |
| `.txt` | Human-readable text report |
| `.csv` | Quoted CSV with name, source line, status, signature, EAs, RVAs, file offsets, and errors |
| `.json` | Structured JSON with imagebase and per-match `ea`, `rva`, and `file_offset` records |

Unknown export suffixes default to the text formatter. SigMaker does not currently write automatic batch history; exports happen only when you choose to write a file.

### Signature Configuration

`sigmaker` also supports configurable wildcardable operands for unique signature creation:

![](./assets/operand_selection.png)

There are also various options that be configured via the `Other options` button:

![](./assets/optional_configuration.png)

## Performance

SigMaker's "find the shortest unique signature for the current function" search has been heavily optimized. On a real 16 MB module, a single worst-case function search once took **462 seconds (7.7 minutes)**. A stack of four optimizations brought the heaviest searches down to the tens-of-seconds range and typical ones to near-instant. One user [reported](https://github.com/mahmoudimus/ida-sigmaker/issues/27#issuecomment-4577775008) the progress wait-box now "barely show[s] up for a 26 byte signature."

The full derivation, including the match-set math, the counting-sort index, the selectivity proof, and what is novel about the approach, is written up in **[ALGORITHM.md](./ALGORITHM.md)**.

### Benchmarks

Measured on the largest function (8486 bytes) of a 16 MB module via native idalib on Apple Silicon. The effects are cumulative across the four phases:

| Optimization | Effect | PR |
| --- | --- | --- |
| Phase 1: seed-then-refine candidate refinement | ~13x faster function search | [#33](https://github.com/mahmoudimus/ida-sigmaker/pull/33) |
| Phase 2: 2-byte bucket position index | additional ~2.48x on large databases, widening as the database grows | [#35](https://github.com/mahmoudimus/ida-sigmaker/pull/35) |
| Phase 3: dynamic seed selection (1- or 2-byte) | per-anchor seed scans cut from 206 to 2 | [#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36) |
| Phase 4: Cython in-place refinement | per-byte refinement ~14 s to ~0.28 s (~50x); function total ~24 s to ~15.6 s | [#36](https://github.com/mahmoudimus/ida-sigmaker/pull/36) |

Signature output is byte-identical before and after every optimization. The test suite cross-checks each fast path against a brute-force oracle and diffs the generated signatures across the entire test binary.

### How it works

A short tour (see [ALGORITHM.md](./ALGORITHM.md) for the math):

- **Seed, then refine.** The set of database matches can only shrink as a signature grows, so instead of rescanning the whole database for every candidate length, SigMaker scans once to seed a candidate set and then filters that set in place as each byte is appended.
- **Index the database once.** A counting-sort index over every adjacent byte pair lets the seed be drawn from the *rarest* exact run in the pattern, in time proportional to that run's frequency rather than to the database size. The same index serves both 1-byte and 2-byte runs for free, so the most selective anchor is always chosen.
- **Push the hot loops into C.** With the optional `pip install sigmaker` SIMD wheel, the index build and the per-byte refinement run as `nogil` C over typed buffers with zero per-call allocation, and the raw byte scan uses AVX2/NEON/SSE2. Without the wheel, pure-Python fallbacks produce identical results.

## Using SigMaker as a library

Beyond the IDA plugin, `sigmaker` is imported directly as a Python library by other tools (for example, batch signature-generation pipelines). The core types are usable from any IDAPython or idalib context:

```python
import sigmaker

cfg = sigmaker.SigMakerConfig(
    output_format=sigmaker.SignatureType.IDA,
    wildcard_operands=True,
    continue_outside_of_function=False,
    wildcard_optimized=True,
    ask_longer_signature=False,
)
result = sigmaker.SignatureMaker().make_signature(ea, cfg)
print(f"{result.signature:ida}")   # IDA-style string
print(len(result.signature))       # byte length

# Cross-references:
xrefs = sigmaker.XrefFinder().find_xrefs(ea, cfg)
for gen in xrefs.signatures:
    print(str(gen.address), f"{gen.signature:ida}")
```

### Batch search API

The batch search feature is also available to scripts:

```python
import sigmaker

text = """
print = "48 8B ?? ??"
update := E8 ? ? ? ? 48 89 C7
"""

results = sigmaker.BatchSignatureSearcher.from_text(text).search()
print(results.format())       # text
print(results.format("csv"))  # registered CSV formatter
print(results.format("json")) # registered JSON formatter

for result in results:
    print(result.display_name, result.status, result.match_count)
    print(result.raw_pattern, result.search_pattern, result.normalized_signature)
    for hit in result.matches:
        print(f"{hit:ea}", f"{hit:rva}", f"{hit:fileoffset}")
```

`BatchSearchResults` is iterable, so `list(results)` gives the per-pattern `SearchResults` objects. `SearchResults.raw_pattern` is the extracted user input, `SearchResults.search_pattern` is the parsed SigMaker search pattern, and `SearchResults.normalized_signature` is the canonical matcher/cache pattern. Nibble wildcard patterns such as `4? ?F ??` keep their nibble masks in both parsed and normalized forms; full-byte wildcards display as `?` in `search_pattern` and normalize to `??` in `normalized_signature`. `SearchResults.signature_str` remains available as a compatibility alias for the search pattern. `SearchResults.matches` remains the main match list, and each `Match` still acts like an int while also carrying optional `rva` and `file_offset` metadata when SigMaker can resolve it.
`Match` supports f-string fields such as `f"{hit:ea}"`, `f"{hit:rva}"`, and `f"{hit:fileoffset}"`. `:rva` and `:fileoffset` do not fall back to `:ea`, because that would label an absolute address as a derived offset. If a derived field is unavailable, the formatted value is `repr(hit)`, so output still shows the hit EA. Check `hit.rva is not None` or `hit.file_offset is not None` before formatting optional fields in strict output formats.

`BatchSearchResults.display()` writes the selected formatter to `idaapi.msg` by default, or to any text file-like object or callable sink:

```python
import io

buf = io.StringIO()
results.display(output=buf, formatter="json")
payload = buf.getvalue()
```

The built-in batch formats are `text`, `csv`, and `json`. Export suffix lookup uses `batch_search_formatter_for_path(path)`, so `.txt`, `.csv`, and `.json` select the matching built-in formatter. Loadable formatter examples live in [`examples/`](./examples/).

### Custom batch search formatters

Power users can add project-specific output formats without changing SigMaker core:

```python
import sigmaker


@sigmaker.BatchSearchFormatter.register("labels", suffixes=(".labels",))
class LabelFormatter:
    def format(self, results: sigmaker.BatchSearchResults) -> str:
        lines = []
        for result in results:
            if len(result.matches) != 1:
                continue
            name = result.name or result.display_name
            hit = result.matches[0]
            address = f"{hit:rva}" if hit.rva is not None else f"{hit:ea}"
            lines.append(f"{name}: {address}")
        return "\n".join(lines) + "\n"
```

After registration, `results.format("labels")` uses the formatter by name, and exporting to `something.labels` uses it by suffix. Formatter classes are instantiated once at registration time; formatter objects can be registered the same way.

To install a formatter permanently, paste the formatter registration code into `idapythonrc.py` in your IDA user directory. IDA sources that file during startup, so the formatter is available in each new IDA session. For example:

```python
# $IDAUSR/idapythonrc.py
import sigmaker


@sigmaker.BatchSearchFormatter.register("labels", suffixes=(".labels",))
class LabelFormatter:
    def format(self, results: sigmaker.BatchSearchResults) -> str:
        lines = []
        for result in results:
            if len(result.matches) != 1:
                continue
            name = result.name or result.display_name
            hit = result.matches[0]
            address = f"{hit:rva}" if hit.rva is not None else f"{hit:ea}"
            lines.append(f"{name}: {address}")
        return "\n".join(lines) + "\n"
```

If `sigmaker` is not already importable from your IDA Python environment, add the SigMaker plugin directory to `sys.path` before the formatter code.

See [`examples/batch_search_c_formatter.py`](./examples/batch_search_c_formatter.py) for a complete C-style formatter template that emits absolute EAs, RVAs, and file offsets while keeping C output out of the built-in format list.

### Stability contract

If you embed `sigmaker`, you can rely on the following. These are treated as a contract and are checked before any change to the public surface:

1. **Append-only config.** `SigMakerConfig` fields are never reordered or removed. New behavior arrives as new fields with safe defaults, so existing constructions keep working.
2. **Stable public names.** These names and their documented attributes are not renamed or removed: `SignatureMaker`, `SigMakerConfig`, `SignatureType` (`IDA`, `x64Dbg`, `Mask`, `BitMask`), `XrefFinder`, `GeneratedSignature` (`signature`, `address`, `status`, `match_count`), `XrefGeneratedSignature` (`signatures`), `Match` (`__str__` returns the hex address, `__format__` supports `ea`, `rva`, and `fileoffset`), `Signature` (`__len__`, `__format__`), `SearchResults` (`matches`, `signature_str`, `raw_pattern`, `search_pattern`, `normalized_signature`), `GenerationPolicy`, `GenerationStatus`, `BatchSignatureSearcher`, `BatchSignatureQuery`, `BatchSearchResults`, `BatchSearchFormatter`.
3. **Stable method signatures.** `SignatureMaker.make_signature(ea, cfg, end=None, *, progress_reporter=None, policy=GenerationPolicy.strict())`, `XrefFinder.find_xrefs(ea, cfg)`, `XrefFinder.count_code_xrefs_to(ea)`, and `XrefFinder.iter_code_xrefs_to(ea)`.
4. **Stable format specs.** `f"{sig:ida}"`, `f"{sig:x64dbg}"`, `f"{sig:mask}"`, and `f"{sig:bitmask}"` keep producing their current output exactly. Batch search keeps the registered built-in formatter names `text`, `csv`, and `json`.
5. **Byte-identical defaults.** Production defaults are unchanged across optimizations: a script that does not opt into a new flag gets byte-identical signatures to previous versions.

### Used by

Projects that build on or embed the `sigmaker` library:

- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), an AI reverse-engineering MCP server (8.9k+ stars), vendors a stripped, engine-only copy of `sigmaker` and exposes signature tools through `SigMakerConfig`, `SignatureType`, `SignatureMaker().make_signature`, and `XrefFinder().find_xrefs`.
- [koyzdev/sigdrift](https://github.com/koyzdev/sigdrift) is a batch signature-generation script that imports the library and calls `SignatureMaker().make_signature(ea, SigMakerConfig(...))` and `XrefFinder()`, formatting results via `f"{sig:ida}"` and `f"{sig:mask}"`.

Building something on top of `sigmaker`? Open a PR or an issue and I will add it here.

## Acknowledgements

Thank you to [@A200K](https://github.com/A200K)'s [IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker) plugin, which served as inspiration and the basis for the initial port of this plugin. I would also like to acknowledge [@kweatherman](https://github.com/kweatherman)'s [sigmakerex](https://github.com/kweatherman/sigmakerex) as independent prior work within the SigMaker ecosystem. While the initial port did not draw from sigmakerex, members of the community later requested compatibility and feature parity with parts of its functionality (for example, see [issue #17](https://github.com/mahmoudimus/ida-sigmaker/issues/17)). As documented in [sigmakerex's README credits](https://github.com/kweatherman/sigmakerex#credits), there is a long history of SigMaker authors and contributors, and I would like to thank and acknowledge them as well:

> thanks to the previous creators of the original SigMaker tool back from the gamedeception.net days up to the current C/C++ and Python iteration authors:
> P4TR!CK, bobbysing, xero|hawk, ajkhoury, and zoomgod et al.
>
> Thanks to Wojciech Mula for his SIMD programming resources.

## Development & Releases

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

The version lives in one place, `__version__` in `src/sigmaker/__init__.py`. To keep `ida-plugin.json` in step with it automatically, enable the repo's git hook once per clone:

```bash
git config core.hooksPath .githooks
```

The pre-commit hook (`.githooks/pre-commit`) runs `tools/sync_plugin_version.py`, which copies `__version__` into `ida-plugin.json` and stages it, so the manifest the IDA Plugin Repository reads can never drift behind a version bump. CI runs the same check (`TestPluginManifestVersion`) as a backstop for commits that skip the hook.

## Contact

ping me on x [@mahmoudimus](https://x.com/mahmoudimus) or you may contact me from any one of the addresses on [mahmoudimus.com](https://mahmoudimus.com).
