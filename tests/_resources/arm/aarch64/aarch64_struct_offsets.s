.text
.globl sigmaker_aarch64_struct_offsets
.type sigmaker_aarch64_struct_offsets, %function
sigmaker_aarch64_struct_offsets:
    mov x3, #0x5400
    add x24, x0, x3
    ldr w19, [x24, #0x48]
    cmn w19, #1
    ldr x26, [x0, #0x5460]
    stp x19, x20, [sp, #0x10]
    stp x21, x22, [x24, #0x20]
    mov w20, w1
    ret
