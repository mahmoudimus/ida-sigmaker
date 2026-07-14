# Compact Signature Input Design

## Goal

Allow users to paste an unprefixed, contiguous signature into the existing
signature parser. Compact input is composed of fixed two-character cells, so
`488B??9090` parses as `48 8B ? 90 90`.

This is explicit signature syntax, not fuzzy source-code extraction. The
parser must continue to reject malformed or ambiguous input.

## Parsing Contract

`SignatureParser.parse()` accepts a complete compact token containing an even
number of characters. Each two-character cell must be one of:

- `HH` for an exact byte;
- `??` for a full-byte wildcard;
- `H?` for a low-nibble wildcard;
- `?H` for a high-nibble wildcard.

`H` is any hexadecimal digit. Parsing is case-insensitive, exact and nibble
tokens are uppercased, and a `??` cell uses SigMaker's display form `?`.

The compact rule applies only when the complete pattern, after removing an
optional supported outer wrapper, is one unprefixed token. It does not make
glued chunks valid inside mixed expressions such as `488B ?? 90`.

Examples:

- `488B9090` -> `48 8B 90 90`
- `488b??9090` -> `48 8B ? 90 90`
- `488B4??F90` -> `48 8B 4? ?F 90`
- `[488B??9090]` -> `48 8B ? 90 90`
- `48` -> `48`, equivalent to the existing explicit-byte path

The parser continues to reject:

- odd-length runs such as `488B?9090` or `488B9`;
- long integer notation such as `0x488B9090`;
- hybrid glued syntax such as `488B ?? 90`;
- invalid cells such as `GG`;
- declarations, prose, unsupported separators, and mixed invalid characters.

Existing spaced byte, wildcard, nibble-wildcard, escaped-byte, repeated
`0xHH`, mask, and bitmask formats remain unchanged. Existing search validation
continues to reject patterns made entirely from wildcards after parsing.
A valid mask or bitmask expression is attempted first and retains its existing
meaning. If mask parsing does not recognize a complete byte-and-mask
expression, an otherwise valid compact token is still eligible for compact
parsing; for example, standalone `0b1010` represents bytes `0B 10 10`.

## Scope

The change belongs in `SignatureParser`, which is already shared by ordinary
and batch signature search. A named batch entry such as
`handler := 488B??9090` therefore receives the same behavior without separate
batch parsing logic.

The scanner, SIMD implementation, search cache, scope handling, cancellation,
and result formatting are unchanged. Parsing performs one linear validation
and split over the pasted token and does not affect search hot paths.

## Error Handling

The parser returns an empty string for invalid input, preserving its current
contract. Ordinary search converts that failure into its structured error
result, while batch search records the error on the affected entry.

No partial recovery is allowed. If any character or two-character cell is
invalid, the entire signature is rejected.

## Tests

Tests must cover:

- uppercase and lowercase compact exact-byte runs;
- compact full-byte and nibble wildcards;
- conversion to display and normalized search patterns;
- named batch input using a compact wildcard pattern;
- rejection of odd-length, `0x`-prefixed long, hybrid, and invalid-cell runs;
- preservation of existing explicit-token, mask, and bitmask parsing;
- a large compact pattern to guard against pathological processing behavior.
