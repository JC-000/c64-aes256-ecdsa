; =============================================================================
; ecdsa_mod.s - Modular arithmetic for ECDSA P-256
; fp_mod_add, fp_mod_sub, fp_mod_reduce, fp_mod_mul, fp_mod_inv,
; result registers fp_r0-r3
; ca65 port note: ACME anonymous labels ('+' / '-') were converted to ca65
; anonymous labels (':' defined, ':+' / ':-' referenced) at the three sites
; that used them (originally lines 259/261, 276/278, 285/287 of the .asm
; source) - see docs/ca65_translation_notes.md.
; =============================================================================

        .segment "LIB_AES256ECDSA_CODE"

.importzp fp_src1, fp_src2, fp_dst, fp_misc, fp_carry
.import chrout
.import fp_wide
.import fp_add, fp_sub, fp_cmp, fp_copy, fp_zero, fp_rshift1, fp_mul
.import print_hex_byte

; --- Full EXPORTS list per src/exports.inc's ecdsa_mod.s entry ---
.export fp_mod_add, fp_mod_sub, fp_mod_reduce, fp_mod_mul, fp_mod_inv
.export fp_r0, fp_r1, fp_r2

; =============================================================================
; fp_mod_add: (fp_dst) = ((fp_src1) + (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_add:
        jsr fp_add
        lda fp_carry
        bne @reduce

        ; Compare dst with modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_cmp
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        bcc @done

@reduce:
        ; dst -= modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_sub
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:  rts

; =============================================================================
; fp_mod_sub: (fp_dst) = ((fp_src1) - (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_sub:
        jsr fp_sub
        lda fp_carry
        beq @done

        ; Underflow: add modulus
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda fp_src2
        pha
        lda fp_src2+1
        pha
        lda fp_dst
        sta fp_src1
        lda fp_dst+1
        sta fp_src1+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add
        pla
        sta fp_src2+1
        pla
        sta fp_src2
        pla
        sta fp_src1+1
        pla
        sta fp_src1
@done:  rts

; =============================================================================
; fp_mod_reduce: reduce 512-bit fp_wide mod (fp_misc) -> fp_r0
; Binary long division: for each of 512 bits, shift into remainder
; and conditionally subtract modulus.
; =============================================================================
fp_mod_reduce:
        ; Clear 33-byte remainder
        ldy #32
        lda #0
@clr:   sta fp_rem,y
        dey
        bpl @clr

        lda #0
        sta fp_bc              ; byte counter in fp_wide
        lda #$80
        sta fp_bm              ; bit mask

@bitlp:
        ; Shift remainder left 1
        clc
        ldy #32
@shl:   lda fp_rem,y
        rol
        sta fp_rem,y
        dey
        bpl @shl

        ; OR in next bit from fp_wide
        ldy fp_bc
        lda fp_wide,y
        and fp_bm
        beq @nobit
        lda fp_rem+32
        ora #1
        sta fp_rem+32
@nobit:
        ; Compare remainder with modulus
        lda fp_rem              ; overflow byte
        bne @dosub

        ldy #0
@cmplp: lda fp_rem+1,y
        cmp (fp_misc),y
        bcc @nosub
        bne @dosub
        iny
        cpy #32
        bne @cmplp
        ; Equal: subtract

@dosub:
        sec
        ldy #31
@sublp: lda fp_rem+1,y
        sbc (fp_misc),y
        sta fp_rem+1,y
        dey
        bpl @sublp
        lda fp_rem
        sbc #0
        sta fp_rem

@nosub:
        ; Next bit
        lsr fp_bm
        bne @bitlp
        lda #$80
        sta fp_bm
        inc fp_bc
        lda fp_bc
        cmp #64
        bne @bitlp

        ; Copy result
        ldy #0
@cpy:   lda fp_rem+1,y
        sta fp_r0,y
        iny
        cpy #32
        bne @cpy
        rts

fp_rem: .res 33, 0
fp_bc:  .byte 0
fp_bm:  .byte 0

; =============================================================================
; fp_mod_mul: fp_r0 = ((fp_src1) * (fp_src2)) mod (fp_misc)
; =============================================================================
fp_mod_mul:
        jsr fp_mul
        jsr fp_mod_reduce
        rts

; =============================================================================
; fp_mod_inv: fp_r0 = (fp_src1)^(-1) mod (fp_misc)
; Binary extended GCD algorithm.
; =============================================================================
fp_mod_inv:
        ; u = src1, v = mod, x1 = 1, x2 = 0
        lda #0
        sta fp_inv_iter
        sta fp_inv_iter+1
        lda fp_dst
        pha
        lda fp_dst+1
        pha

        ; Copy u = src1
        lda #<fp_inv_u
        sta fp_dst
        lda #>fp_inv_u
        sta fp_dst+1
        jsr fp_copy

        ; Copy v = mod
        lda fp_misc
        sta fp_src1
        lda fp_misc+1
        sta fp_src1+1
        lda #<fp_inv_v
        sta fp_dst
        lda #>fp_inv_v
        sta fp_dst+1
        jsr fp_copy

        ; x1 = 1
        lda #<fp_inv_x1
        sta fp_dst
        lda #>fp_inv_x1
        sta fp_dst+1
        jsr fp_zero
        lda #1
        sta fp_inv_x1+31

        ; x2 = 0
        lda #<fp_inv_x2
        sta fp_dst
        lda #>fp_inv_x2
        sta fp_dst+1
        jsr fp_zero

        pla
        sta fp_dst+1
        pla
        sta fp_dst

@mainlp:
        ; Debug: show iteration count
        inc fp_inv_iter
        bne :+
        inc fp_inv_iter+1
:
        ; Show progress every 16 iterations
        lda fp_inv_iter
        and #$0f
        bne @skip_dbg
        lda #'.'
        jsr chrout
@skip_dbg:

        ; Check u == 1
        lda #<fp_inv_u
        sta fp_src1
        lda #>fp_inv_u
        sta fp_src1+1
        jsr fp_chk_one
        bne :+
        jmp @u_one
:
        ; Check v == 1
        lda #<fp_inv_v
        sta fp_src1
        lda #>fp_inv_v
        sta fp_src1+1
        jsr fp_chk_one
        bne :+
        jmp @v_one
:

        ; While u is even
@halfu: lda fp_inv_u+31
        and #1
        bne @halfv

        lda #'H'
        jsr chrout

        lda #<fp_inv_u
        sta fp_src1
        lda #>fp_inv_u
        sta fp_src1+1
        jsr fp_rshift1

        lda fp_inv_x1+31
        and #1
        beq @x1ev_nocarry
        ; x1 += mod
        lda #<fp_inv_x1
        sta fp_src1
        sta fp_dst
        lda #>fp_inv_x1
        sta fp_src1+1
        sta fp_dst+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add
        jmp @x1do_shift
@x1ev_nocarry:
        lda #0
        sta fp_carry
@x1do_shift:
        ; x1 >>= 1, with carry from fp_add shifted in as MSB
        lda fp_carry            ; carry from x1+mod (0 or 1)
        lsr                     ; shift into 6502 carry flag
        ldy #0
        ldx #32
@x1sh:  lda fp_inv_x1,y
        ror                     ; rotate carry in from left
        sta fp_inv_x1,y
        iny
        dex
        bne @x1sh
        jmp @halfu

        ; While v is even
@halfv: lda fp_inv_v+31
        and #1
        bne @comp

        lda #'V'
        jsr chrout

        lda #<fp_inv_v
        sta fp_src1
        lda #>fp_inv_v
        sta fp_src1+1
        jsr fp_rshift1

        lda fp_inv_x2+31
        and #1
        beq @x2ev_nocarry
        lda #<fp_inv_x2
        sta fp_src1
        sta fp_dst
        lda #>fp_inv_x2
        sta fp_src1+1
        sta fp_dst+1
        lda fp_misc
        sta fp_src2
        lda fp_misc+1
        sta fp_src2+1
        jsr fp_add
        jmp @x2do_shift
@x2ev_nocarry:
        lda #0
        sta fp_carry
@x2do_shift:
        ; x2 >>= 1, with carry from fp_add shifted in as MSB
        lda fp_carry
        lsr                     ; into 6502 carry
        ldy #0
        ldx #32
@x2sh:  lda fp_inv_x2,y
        ror
        sta fp_inv_x2,y
        iny
        dex
        bne @x2sh
        jmp @halfv

@comp:
        lda #'C'
        jsr chrout
        ; Compare u vs v
        lda #<fp_inv_u
        sta fp_src1
        lda #>fp_inv_u
        sta fp_src1+1
        lda #<fp_inv_v
        sta fp_src2
        lda #>fp_inv_v
        sta fp_src2+1
        jsr fp_cmp
        bcc @vbig

        ; u >= v: u -= v, x1 -= x2 mod m
        lda #<fp_inv_u
        sta fp_dst
        lda #>fp_inv_u
        sta fp_dst+1
        jsr fp_sub

        lda #<fp_inv_x1
        sta fp_src1
        lda #>fp_inv_x1
        sta fp_src1+1
        lda #<fp_inv_x2
        sta fp_src2
        lda #>fp_inv_x2
        sta fp_src2+1
        lda #<fp_inv_x1
        sta fp_dst
        lda #>fp_inv_x1
        sta fp_dst+1
        jsr fp_mod_sub
        jmp @mainlp

@vbig:
        ; v -= u, x2 -= x1 mod m
        lda #<fp_inv_v
        sta fp_src1
        lda #>fp_inv_v
        sta fp_src1+1
        lda #<fp_inv_u
        sta fp_src2
        lda #>fp_inv_u
        sta fp_src2+1
        lda #<fp_inv_v
        sta fp_dst
        lda #>fp_inv_v
        sta fp_dst+1
        jsr fp_sub

        lda #<fp_inv_x2
        sta fp_src1
        lda #>fp_inv_x2
        sta fp_src1+1
        lda #<fp_inv_x1
        sta fp_src2
        lda #>fp_inv_x1
        sta fp_src2+1
        lda #<fp_inv_x2
        sta fp_dst
        lda #>fp_inv_x2
        sta fp_dst+1
        jsr fp_mod_sub
        jmp @mainlp

@u_one: ; Result = x1
        ; Debug: print iteration count
        lda #$0d
        jsr chrout
        lda #'U'
        jsr chrout
        lda fp_inv_iter+1
        jsr print_hex_byte
        lda fp_inv_iter
        jsr print_hex_byte
        lda #$0d
        jsr chrout
        ldy #31
@cu:    lda fp_inv_x1,y
        sta fp_r0,y
        dey
        bpl @cu
        rts

@v_one: ; Result = x2
        lda #$0d
        jsr chrout
        lda #'V'
        jsr chrout
        lda fp_inv_iter+1
        jsr print_hex_byte
        lda fp_inv_iter
        jsr print_hex_byte
        lda #$0d
        jsr chrout
        ldy #31
@cv:    lda fp_inv_x2,y
        sta fp_r0,y
        dey
        bpl @cv
        rts

fp_inv_iter: .word 0

; Check if (fp_src1) == 1: Z flag set if yes
fp_chk_one:
        ldy #0
@lp:    lda (fp_src1),y
        bne @no
        iny
        cpy #31
        bne @lp
        lda (fp_src1),y
        cmp #1                  ; Z set if byte 31 == 1
        rts
@no:    lda #$ff                ; clear Z
        rts

fp_inv_u:   .res 32, 0
fp_inv_v:   .res 32, 0
fp_inv_x1:  .res 32, 0
fp_inv_x2:  .res 32, 0

; =============================================================================
; Working registers
; =============================================================================
fp_r0:      .res 32, 0        ; primary result register
fp_r1:      .res 32, 0
fp_r2:      .res 32, 0
fp_r3:      .res 32, 0
