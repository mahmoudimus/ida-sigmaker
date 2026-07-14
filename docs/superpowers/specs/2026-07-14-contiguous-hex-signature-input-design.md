# Contiguous Hex Signature Input Design

## Goal

Allow users to paste an unprefixed, contiguous sequence of hexadecimal bytes
into the existing signature parser. For example, `488B9090` must parse as
`48 8B 90 90`.

This is explicit byte syntax, not fuzzy source-code extraction. The parser must
remain strict for malformed or ambiguous input.

## Parsing Contract

`SignatureParser.parse()` accepts an all-hex token containing an even number of
characters and splits it into two-character byte tokens. Parsing is
case-insensitive and output remains uppercase and space-separated.

The raw-run rule applies only when the complete pattern, after removing an
optional supported outer wrapper, is one unprefixed hexadecimal token. It does
not make glued chunks valid inside mixed expressions such as `488B ?? 90`.

Examples:

- `488B9090` -> `48 8B 90 90`
- `488b9090` -> `48 8B 90 90`
- `48` -> `48` through the existing explicit-byte path

The parser continues to reject:

- odd-length runs such as `488B9`;
- long integer notation such as `0x488B9090`;
- contiguous wildcard expressions such as `488B??90`;
- declarations, prose, unsupported separators, and mixed invalid characters.

Existing spaced byte, wildcard, nibble-wildcard, escaped-byte, repeated
`0xHH`, mask, and bitmask formats remain unchanged.

## Scope

The change belongs in `SignatureParser`, which is already shared by ordinary
and batch signature search. A named batch entry such as
`handler := 488B9090` therefore receives the same behavior without separate
batch parsing logic.

The scanner, SIMD implementation, search cache, scope handling, cancellation,
and result formatting are unchanged. Parsing performs one linear validation
and split over the pasted token and does not affect search hot paths.

## Error Handling

The parser returns an empty string for invalid input, preserving its current
contract. Ordinary search converts that failure into its structured error
result, while batch search records the error on the affected entry.

No partial recovery is allowed. If any character or byte pair is invalid, the
entire signature is rejected.

## Tests

Tests must cover:

- uppercase and lowercase contiguous byte runs;
- conversion to the display and normalized search patterns;
- named batch input using a contiguous run;
- rejection of odd-length, `0x`-prefixed long, wildcard-containing, and mixed
  invalid runs;
- preservation of existing explicit-token and nibble-wildcard parsing;
- a large raw byte run to guard against pathological processing behavior.
