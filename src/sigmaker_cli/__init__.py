"""Command-line entrypoint for SigMaker through IDA's idalib runtime.

This module intentionally avoids importing ``sigmaker`` at module import time.
External IDA runs must import ``idapro`` before ``idaapi`` and before the plugin
package, so all IDA imports happen inside the command handlers.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import pathlib
import sys
import typing
import warnings


class CliError(Exception):
    """User-facing CLI error."""


def _parse_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc


@contextlib.contextmanager
def _open_database(
    database_path: pathlib.Path,
    *,
    auto_wait: bool = True,
) -> typing.Iterator[typing.Any]:
    with contextlib.redirect_stdout(sys.stderr):
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            try:
                import idapro
                import idaapi
            except ModuleNotFoundError as exc:
                if exc.name in {"idapro", "idaapi"}:
                    raise CliError(
                        "IDA idalib modules are unavailable; run this command from "
                        "an IDA Pro Python environment"
                    ) from exc
                raise

        result = idapro.open_database(str(database_path), True)
    if result != 0:
        raise CliError(f"failed to open database {database_path!s}: {result}")

    try:
        if auto_wait:
            with contextlib.redirect_stdout(sys.stderr):
                idaapi.auto_wait()
        yield idaapi
    finally:
        with contextlib.suppress(BaseException):
            with contextlib.redirect_stdout(sys.stderr):
                idapro.close_database()


def _import_sigmaker() -> typing.Any:
    return importlib.import_module("sigmaker")


def _read_search_input(args: argparse.Namespace) -> str:
    if args.pattern and args.input:
        raise CliError("use either PATTERN or --input, not both")

    if args.input:
        if args.input == "-":
            return sys.stdin.read()
        return pathlib.Path(args.input).read_text(encoding="utf-8")

    if args.pattern:
        return args.pattern

    if not sys.stdin.isatty():
        return sys.stdin.read()

    raise CliError("search requires PATTERN, --input PATH, or piped stdin")


def _write_output(text: str, output_path: str | None) -> None:
    if output_path:
        pathlib.Path(output_path).write_text(text, encoding="utf-8")
        return
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")


def _signature_type(sigmaker: typing.Any, value: str) -> typing.Any:
    normalized = value.lower()
    for member in sigmaker.SignatureType:
        if member.value.lower() == normalized or member.name.lower() == normalized:
            return member
    valid = ", ".join(member.value for member in sigmaker.SignatureType)
    raise CliError(f"unknown signature format {value!r}; expected one of: {valid}")


def _build_config(sigmaker: typing.Any, args: argparse.Namespace) -> typing.Any:
    cfg = sigmaker.SigMakerConfig(
        output_format=_signature_type(sigmaker, args.signature_format),
        wildcard_operands=args.wildcard_operands,
        continue_outside_of_function=args.continue_outside_function,
        wildcard_optimized=args.wildcard_optimized,
        enable_continue_prompt=False,
        ask_longer_signature=False,
        output_partial_on_cancel=args.partial_on_cancel,
    )
    if args.max_single_signature_length is not None:
        cfg.max_single_signature_length = args.max_single_signature_length
    if args.max_xref_signature_length is not None:
        cfg.max_xref_signature_length = args.max_xref_signature_length
    return cfg


def _resolve_ea(idaapi: typing.Any, value: int, *, is_rva: bool = False) -> int:
    if not is_rva:
        return value
    return idaapi.get_imagebase() + value


def _load_search_buffer(sigmaker: typing.Any, args: argparse.Namespace) -> typing.Any:
    if not args.preload_segments:
        return None
    if not getattr(sigmaker, "SIMD_SPEEDUP_AVAILABLE", False):
        return None
    return sigmaker.InMemoryBuffer.load(mode=sigmaker.InMemoryBuffer.LoadMode.SEGMENTS)


def _run_search(args: argparse.Namespace) -> int:
    input_text = _read_search_input(args)
    with _open_database(args.database, auto_wait=args.auto_wait):
        sigmaker = _import_sigmaker()
        buf = _load_search_buffer(sigmaker, args)
        results = sigmaker.BatchSignatureSearcher.from_text(input_text).search(buf=buf)
        _write_output(results.format(args.formatter), args.output)
        if results.error_count and not args.allow_errors:
            return 1
    return 0


def _match_record(sigmaker: typing.Any, match: typing.Any) -> dict[str, int | None]:
    ea = int(match)
    imagebase = sigmaker.SearchResults.current_imagebase()
    file_offsets = sigmaker.SearchResults.file_offsets_for_matches([match])
    enriched = sigmaker.Match(
        ea,
        rva=ea - imagebase if imagebase is not None else None,
        file_offset=file_offsets.get(ea),
    )
    return enriched.to_record()


def _generated_signature_record(
    sigmaker: typing.Any,
    generated: typing.Any,
    signature_text: str,
    cfg: typing.Any,
) -> dict[str, typing.Any]:
    address = (
        _match_record(sigmaker, generated.address)
        if generated.address is not None
        else None
    )
    status = getattr(generated.status, "value", str(generated.status))
    return {
        "signature": signature_text,
        "format": cfg.output_format.value,
        "status": status,
        "match_count": generated.match_count,
        "address": address,
    }


def _run_make(args: argparse.Namespace) -> int:
    with _open_database(args.database, auto_wait=args.auto_wait) as idaapi:
        sigmaker = _import_sigmaker()
        cfg = _build_config(sigmaker, args)
        ea = _resolve_ea(idaapi, args.address, is_rva=args.rva)
        end = (
            _resolve_ea(idaapi, args.end, is_rva=args.end_rva)
            if args.end is not None
            else None
        )
        policy = (
            sigmaker.GenerationPolicy.permissive()
            if args.partial_on_cancel
            else sigmaker.GenerationPolicy.strict()
        )
        generated = sigmaker.SignatureMaker().make_signature(
            ea,
            cfg,
            end=end,
            policy=policy,
        )
        signature_text = format(generated.signature, cfg.output_format.value)
        if args.json_output:
            text = json.dumps(
                _generated_signature_record(sigmaker, generated, signature_text, cfg),
                indent=2,
                sort_keys=True,
            )
            text += "\n"
        else:
            text = signature_text + "\n"
        _write_output(text, args.output)
    return 0


def _add_database_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("database", type=pathlib.Path, help="input binary or IDB path")
    parser.add_argument(
        "--no-auto-wait",
        dest="auto_wait",
        action="store_false",
        default=True,
        help="do not wait for IDA auto-analysis after opening the database",
    )


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        dest="signature_format",
        default="ida",
        help="signature output format: ida, x64dbg, mask, or bitmask",
    )
    parser.add_argument(
        "--wildcard-operands",
        dest="wildcard_operands",
        action="store_true",
        default=True,
        help="wildcard instruction operands while generating signatures",
    )
    parser.add_argument(
        "--no-wildcard-operands",
        dest="wildcard_operands",
        action="store_false",
        help="keep instruction operands exact while generating signatures",
    )
    parser.add_argument(
        "--continue-outside-function",
        action="store_true",
        default=False,
        help="allow unique signature generation to continue past function end",
    )
    parser.add_argument(
        "--wildcard-optimized",
        dest="wildcard_optimized",
        action="store_true",
        default=True,
        help="wildcard optimized combined instruction bytes",
    )
    parser.add_argument(
        "--no-wildcard-optimized",
        dest="wildcard_optimized",
        action="store_false",
        help="keep optimized combined instruction bytes exact",
    )
    parser.add_argument(
        "--max-single-signature-length",
        type=int,
        default=None,
        help="maximum generated signature length for one address",
    )
    parser.add_argument(
        "--max-xref-signature-length",
        type=int,
        default=None,
        help="maximum generated signature length for xref candidates",
    )
    parser.add_argument(
        "--partial-on-cancel",
        action="store_true",
        help="return a partial signature instead of failing on cancellation",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sigmaker",
        description="Run SigMaker from an IDA idalib-capable Python environment.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    search = subparsers.add_parser(
        "search",
        aliases=("batch-search",),
        help="search one or more signatures in a database",
    )
    _add_database_args(search)
    search.add_argument(
        "pattern",
        nargs="?",
        help="signature text; omit when using --input or piped stdin",
    )
    search.add_argument(
        "-i",
        "--input",
        help="file containing one or more search patterns; use '-' for stdin",
    )
    search.add_argument(
        "-f",
        "--format",
        dest="formatter",
        default="text",
        help="batch result formatter name, such as text, csv, or json",
    )
    search.add_argument("-o", "--output", help="write formatted results to this path")
    search.add_argument(
        "--allow-errors",
        action="store_true",
        help="exit zero even when individual batch entries have errors",
    )
    search.add_argument(
        "--no-preload-segments",
        dest="preload_segments",
        action="store_false",
        default=True,
        help="do not preload the segment buffer for SIMD batch searches",
    )
    search.set_defaults(func=_run_search)

    make = subparsers.add_parser(
        "make",
        aliases=("generate",),
        help="generate a signature at an address",
    )
    _add_database_args(make)
    make.add_argument("address", type=_parse_int, help="effective address or RVA")
    make.add_argument("--rva", action="store_true", help="treat ADDRESS as an RVA")
    make.add_argument("--end", type=_parse_int, help="optional range end address")
    make.add_argument("--end-rva", action="store_true", help="treat --end as an RVA")
    _add_config_args(make)
    make.add_argument("--json", dest="json_output", action="store_true")
    make.add_argument("-o", "--output", help="write output to this path")
    make.set_defaults(func=_run_make)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        parser.exit(2, f"sigmaker: error: {exc}\n")


__all__ = ["build_parser", "main"]
