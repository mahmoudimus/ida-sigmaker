# AArch64 Relocation Fixture

`aarch64_relocations.o` is a little-endian AArch64 relocatable object built
from the adjacent `aarch64_relocations.s`. It contains
`R_AARCH64_ADR_PREL_PG_HI21`, `R_AARCH64_ADD_ABS_LO12_NC`, and
`R_AARCH64_CALL26` relocations, plus a stable literal instruction used as a
negative wildcarding control.

The source is maintained in this repository and covered by the project
license. It was built with Apple Clang 21.0.0
(`clang-2100.1.1.101`):

```text
clang -target aarch64-none-elf -c \
    tests/_resources/arm/aarch64/aarch64_relocations.s \
    -o tests/_resources/arm/aarch64/aarch64_relocations.o
```

Fixture SHA-256:

```text
3be9e894133f07070f9fd8dda5da8874d990315176ba9de4ad030010067dabad
```
