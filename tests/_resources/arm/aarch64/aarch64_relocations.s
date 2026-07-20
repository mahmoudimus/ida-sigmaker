.text
.globl sigmaker_aarch64_relocations
.type sigmaker_aarch64_relocations, %function
sigmaker_aarch64_relocations:
    adrp x0, sigmaker_aarch64_target
    add x0, x0, :lo12:sigmaker_aarch64_target
    bl sigmaker_aarch64_target_fn
    mov w1, #7
    ret

.section .text.sigmaker_target, "ax", %progbits
.type sigmaker_aarch64_target_fn, %function
sigmaker_aarch64_target_fn:
    ret

.data
.p2align 3
sigmaker_aarch64_target:
    .xword 0
