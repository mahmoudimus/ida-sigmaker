; ----------------------------------------------------------------------------------------
; Test binary for sigmaker testing
; Contains specific instruction patterns for signature generation testing
; This is a minimal binary that just contains the instruction patterns we want to test
;
; To assemble (Linux/ELF):
;     nasm -f elf64 test_binary.asm -o test_binary.o
;     ld test_binary.o -o test_binary
;
; To assemble (macOS):
;     nasm -f macho64 test_binary.asm -o test_binary.o
;     ld test_binary.o -o test_binary
;
; To assemble (Windows):
;     nasm -f win64 test_binary.asm -o test_binary.obj
;     link test_binary.obj /out:test_binary.exe
;     (on macos though, /opt/homebrew/bin/x86_64-w64-mingw32-gcc test_binary.obj -o test_binary.exe
; ----------------------------------------------------------------------------------------

; Platform-specific setup
%ifidn __OUTPUT_FORMAT__, macho64
          global    _main
%elifidn __OUTPUT_FORMAT__, elf64
          global    main
%else
          global    main
%endif

          section   .text

; Platform-specific entry point
%ifidn __OUTPUT_FORMAT__, macho64
_main:
%else
main:
%endif

          ; Example 1: mov dword [rsp+0x34], 0x0
          ; This should generate: C7 44 24 34 00 00 00 00
          sub       rsp, 0x40                ; allocate stack space
          mov       dword [rsp+0x34], 0x0

          ; Example 2: mov dword [rsp+0x30], 0x7
          ; This should generate: C7 44 24 30 07 00 00 00
          mov       dword [rsp+0x30], 0x7

          ; Example 3: cmp dword [rsp+0x20], 0xf
          ; This should generate: 83 7C 24 20 0F
          cmp       dword [rsp+0x20], 0xf

          ; Example 4: mov edx, dword [rsp+0x24]
          ; This should generate: 8B 54 24 24
          mov       edx, dword [rsp+0x24]

          ; Example 5: mov rax, 0x1528 followed by mov qword [rax], 0x30
          ; This creates pattern: 48 B8 28 15 00 00 00 00 00 00 (for mov rax, 0x1528)
          ; We want to test wildcard pattern: 49 28 15 ?? ?? 30
          mov       rax, 0x1528
          mov       qword [rax], 0x30

          ; Example 6: 
          ; The following instruction causes assembler warnings/errors in 64-bit mode:
          ;   sub     cs:140301474h, dl  ; 49 28 15 00 00 30 00
          ; This is because segment overrides (like cs:) and direct memory addressing
          ; with a 32-bit absolute address are not supported in 64-bit mode.
          ; 
          ; To resolve this, we use the 'db' directive to emit the bytes directly:
          db 0x49, 0x28, 0x15, 0x00, 0x00, 0x30, 0x00
          mov     rax, 0xB883480000001528 ; 48 B8 28 15 00 00 00 48 83 B8
          
          ; Exit cleanly
          add       rsp, 0x40               ; restore stack
          mov       rax, 0                  ; return 0
          ret
