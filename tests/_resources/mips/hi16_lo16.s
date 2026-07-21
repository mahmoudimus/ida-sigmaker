.set noreorder
.text
.globl sigmaker_mips_relocations
.type sigmaker_mips_relocations, @function

sigmaker_mips_relocations:
    lui     $v0, %hi(sigmaker_mips_target + 0x10004)
    move    $a0, $zero
    addiu   $v0, $v0, %lo(sigmaker_mips_target + 0x10004)
    jr      $ra
    nop

.data
.align 2
sigmaker_mips_target:
    .word 0
