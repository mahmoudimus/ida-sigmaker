.text
// Issue #100 cross-build fixture. sigmaker_cross_build_target holds the
// latest build of the function from issue #97 (18 instructions) padded with
// NOPs so its CBZ (+0x290), B.EQ (+0x78) and B (+0x54) targets lie inside it.
// sigmaker_cross_build_decoy shares its first 5 instructions, so a
// signature over only those is not unique.
.globl sigmaker_cross_build_target
.type sigmaker_cross_build_target, %function
.p2align 2
sigmaker_cross_build_target:
    .inst 0x34001483
    .inst 0xa9b67bfd
    .inst 0x910003fd
    .inst 0xa90363f7
    .inst 0x2a0303f7
    .inst 0xd28a8003
    .inst 0x8b030018
    .inst 0xa90153f3
    .inst 0x2a0103f4
    .inst 0xa9025bf5
    .inst 0xaa0003f6
    .inst 0xa9046bf9
    .inst 0xaa0203f9
    .inst 0xb9404b13
    .inst 0x3100067f
    .inst 0x540001e0
    .inst 0xf96a301a
    .inst 0x14000004
    .rept 146
    nop
    .endr
    ret
.size sigmaker_cross_build_target, . - sigmaker_cross_build_target

.globl sigmaker_cross_build_decoy
.type sigmaker_cross_build_decoy, %function
.p2align 2
sigmaker_cross_build_decoy:
    .inst 0x34001483
    .inst 0xa9b67bfd
    .inst 0x910003fd
    .inst 0xa90363f7
    .inst 0x2a0303f7
    .rept 16
    nop
    .endr
    ret
.size sigmaker_cross_build_decoy, . - sigmaker_cross_build_decoy
