# ARMv7 A32 Relocation Fixture

`armv7_relocations.o` is a little-endian ARMv7 A32 relocatable object built
from the adjacent `armv7_relocations.s`. It contains `R_ARM_MOVW_ABS_NC`,
`R_ARM_MOVT_ABS`, and `R_ARM_CALL` relocations, plus a stable literal
instruction used as a negative wildcarding control.

The source is maintained in this repository and covered by the project
license. It was built with Apple Clang 21.0.0
(`clang-2100.1.1.101`):

```text
clang -target armv7-none-eabi -march=armv7-a -c \
    tests/_resources/arm/armv7/armv7_relocations.s \
    -o tests/_resources/arm/armv7/armv7_relocations.o
```

Fixture SHA-256:

```text
23bfdffc3582a0c057bfaa4f2a55682ee983b8035a4aaa416bc47964f588f43b
```
