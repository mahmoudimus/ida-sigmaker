.syntax unified
.arch armv7-a
.arm

.text
.globl sigmaker_armv7_relocations
.type sigmaker_armv7_relocations, %function
sigmaker_armv7_relocations:
    movw r0, #:lower16:sigmaker_armv7_target
    movt r0, #:upper16:sigmaker_armv7_target
    bl sigmaker_armv7_target_fn
    mov r1, #7
    bx lr

.section .text.sigmaker_target, "ax", %progbits
.type sigmaker_armv7_target_fn, %function
sigmaker_armv7_target_fn:
    bx lr

.data
.align 2
sigmaker_armv7_target:
    .word 0
