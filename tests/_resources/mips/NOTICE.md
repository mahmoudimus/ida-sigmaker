# MIPS HI16/LO16 Fixture

`hi16_lo16.o` is a MIPSEL relocatable object built from the adjacent
`hi16_lo16.s`. It creates one `R_MIPS_HI16` and one `R_MIPS_LO16` relocation
for `sigmaker_mips_target + 0x10004`.

The source is maintained in this repository and is covered by the project
license. It was built with GNU binutils 2.40:

```text
mipsel-linux-gnu-as tests/_resources/mips/hi16_lo16.s \
    -o tests/_resources/mips/hi16_lo16.o
```

Fixture SHA-256:

```text
9216038fa4f85d7431760b1845a45be1aa6ca8468234416df506cccca6f62769
```
