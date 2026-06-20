"""Example: register a C-style batch search formatter from IDA Python.

Drop this into an IDA user startup script after sigmaker is importable, or paste
it into IDA's Python console after loading the plugin. It adds `.c` and `.h`
export handling without making C output a built-in sigmaker format.
"""

import re

import sigmaker


@sigmaker.BatchSearchFormatter.register(
    "c",
    suffixes=(".c", ".h", ".hpp", ".cpp"),
)
class CBatchSearchFormatter:
    @staticmethod
    def _symbol_name(name: str, fallback: str) -> str:
        cleaned = re.sub(r"\W+", "_", name).strip("_")
        if not cleaned:
            cleaned = fallback
        if cleaned[0].isdigit():
            cleaned = "_" + cleaned
        return cleaned

    @staticmethod
    def _comment(text: str) -> str:
        return text.replace("*/", "* /").replace("\n", " ")

    def format(self, results: sigmaker.BatchSearchResults) -> str:
        lines = [
            "/* SigMaker batch search address results. */",
            "#include <stdint.h>",
            "",
        ]
        if results.imagebase is not None:
            lines.extend(
                [
                    f"static const uint64_t sigmaker_imagebase = "
                    f"0x{results.imagebase:X}ULL;",
                    "",
                ]
            )

        for idx, entry in enumerate(results, start=1):
            name = self._symbol_name(
                entry.name or entry.display_name,
                f"pattern_{idx}",
            )
            if entry.error:
                lines.append(f"/* {name}: error - {self._comment(entry.error)} */")
                continue
            if not entry.matches:
                lines.append(f"/* {name}: no matches */")
                continue
            if len(entry.matches) != 1:
                lines.append(f"/* {name}: {len(entry.matches)} matches */")
                continue

            hit = entry.matches[0]
            lines.append(f"static const uint64_t {name}_ea = {hit:ea}ULL;")
            if hit.rva is not None:
                lines.append(f"static const uint64_t {name}_rva = {hit:rva}ULL;")
            if hit.file_offset is not None:
                lines.append(
                    f"static const uint64_t {name}_file_offset = "
                    f"{hit:fileoffset}ULL;"
                )

        return "\n".join(lines).rstrip() + "\n"
