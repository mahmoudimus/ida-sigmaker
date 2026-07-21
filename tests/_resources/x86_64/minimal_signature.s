.text

.p2align 4
.globl sigmaker_minimal_target
.type sigmaker_minimal_target, @function
sigmaker_minimal_target:
    lea sigmaker_minimal_data(%rip), %rax
    mov $0x31, %al
    ret
.size sigmaker_minimal_target, .-sigmaker_minimal_target

.p2align 4
.globl sigmaker_minimal_decoy_a
.type sigmaker_minimal_decoy_a, @function
sigmaker_minimal_decoy_a:
    lea sigmaker_minimal_data(%rip), %rax
    mov $0x32, %al
    ret
.size sigmaker_minimal_decoy_a, .-sigmaker_minimal_decoy_a

.p2align 4
.globl sigmaker_minimal_decoy_b
.type sigmaker_minimal_decoy_b, @function
sigmaker_minimal_decoy_b:
    lea sigmaker_minimal_data(%rip), %rax
    mov $0x33, %al
    ret
.size sigmaker_minimal_decoy_b, .-sigmaker_minimal_decoy_b

.p2align 4
.globl sigmaker_minimal_short_unique
.type sigmaker_minimal_short_unique, @function
sigmaker_minimal_short_unique:
    syscall
    ret
.size sigmaker_minimal_short_unique, .-sigmaker_minimal_short_unique

.data
.p2align 3
sigmaker_minimal_data:
    .quad 0
