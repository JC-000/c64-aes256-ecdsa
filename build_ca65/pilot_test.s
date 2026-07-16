; =============================================================================
; pilot_test.s - THROWAWAY synthetic ca65 program for the ca65-port pilot task.
;
; NOT real project code. Proves, end-to-end:
;   - ca65/ld65 can build a bootable $0801 BASIC-stub PRG (same trick as
;     src/boot.asm: SYS into machine code)
;   - a couple of jsr()-callable subroutines work
;   - a data table can be forced to a page-aligned $7800 address via the
;     linker config's QSTAB memory area
;
; Assemble/link:
;   ca65 pilot_test.s -o pilot_test.o
;   ld65 -C linker.cfg -o pilot_test.prg -Ln pilot_test.labels pilot_test.o
; =============================================================================

.export code_start, main, inc_counter, copy_bytes
.export counter_byte, copy_len, copy_src, copy_dst, qstab_table

.segment "LOADADDR"
        .word $0801

.segment "STARTUP"

; --- BASIC stub: "10 SYS 2061" -------------------------------------------
; Header is exactly 12 bytes ($0801-$080C): link(2) + line#(2) + token(1) +
; "2061" ascii(4) + end-of-line null(1) + end-of-program null word(2).
; code_start therefore falls at $0801 + 12 = $080D = 2061 decimal, which is
; exactly the literal text below - this is hand-verified, not automatic.
basic_stub:
        .word basic_end        ; link to next BASIC line
        .word 10                ; line number 10
        .byte $9e                ; SYS token
        .byte "2061"            ; decimal address of code_start, as ASCII
        .byte 0                  ; end of BASIC line
basic_end:
        .word 0                  ; end of BASIC program

code_start:
        jmp main

; --- test subroutine 1: increment a memory location -----------------------
; jsr-callable. Increments counter_byte by 1 and returns.
inc_counter:
        inc counter_byte
        rts

; --- test subroutine 2: copy bytes -----------------------------------------
; jsr-callable. Copies copy_len bytes from copy_src to copy_dst.
; Uses a simple indexed loop (Y register), no zero-page pointers needed
; since source/dest are fixed absolute addresses for this synthetic test.
copy_bytes:
        ldy #0
@loop:
        cpy copy_len
        beq @done
        lda copy_src,y
        sta copy_dst,y
        iny
        bne @loop
@done:
        rts

; --- main: harmless infinite loop so the CPU has somewhere safe to sit ----
; after BASIC's SYS returns control (mirrors the harness pattern of writing
; a JMP-to-self trampoline; here we just build it into the program itself).
main:
        jmp main

; --- data used by the subroutines ------------------------------------------
.segment "DATA"
counter_byte:
        .byte 0

copy_len:
        .byte 8

copy_src:
        .byte $11,$22,$33,$44,$55,$66,$77,$88

copy_dst:
        .res 8, 0

; --- page-aligned quarter-square-table-region proof ------------------------
; Placed in the QSTAB segment, which the linker config maps to a MEMORY
; area fixed at $7800, size $0400 (1KB). .align 256 makes the alignment
; constraint explicit/self-checking even though the MEMORY area start
; already guarantees it for a single-segment case like this.
.segment "QSTAB"
        .align 256
qstab_table:
        ; recognizable byte pattern: qstab_table[i] = i (mod 256), for the
        ; first 16 bytes, to make read_bytes() verification unambiguous.
        .byte 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
