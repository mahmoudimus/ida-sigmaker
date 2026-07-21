# x86-64 Minimal Signature Fixture

`minimal_signature.o` is a little-endian x86-64 relocatable ELF object built
from the adjacent `minimal_signature.s`. It contains three functions with the
same RIP-relative `lea` prefix and distinct two-byte discriminators. IDA marks
the four-byte relocation displacement as an offset, allowing the integration
tests to exercise operand wildcarding and minimal-signature growth against real
decoded instructions.

The source is maintained in this repository and covered by the project license.
It was built with Apple Clang 21.0.0 (`clang-2100.1.1.101`):

```text
clang -target x86_64-none-elf -c \
    tests/_resources/x86_64/minimal_signature.s \
    -o tests/_resources/x86_64/minimal_signature.o
```

Fixture SHA-256:

```text
9aafcd428d0ea53d76a412a180da369ffce4f6740d3598a2e25a79cf83a0202e
```
