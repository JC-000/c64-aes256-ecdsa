; =============================================================================
; ECDSA P-256 Implementation for Commodore 64
; File: ecdsa_p256.asm
; Include after main program code with: !source "ecdsa_p256.asm"
;
; All 256-bit values: big-endian (MSB at byte 0, LSB at byte 31)
; =============================================================================

; --- Zero-page pointers for big-number operations ---
; Using free ZP locations $22-$2B (not used by KERNAL or BASIC)
fp_src1         = $22           ; 2 bytes: pointer to first operand
fp_src2         = $24           ; 2 bytes: pointer to second operand
fp_dst          = $26           ; 2 bytes: pointer to destination
fp_misc         = $28           ; 2 bytes: misc pointer (modulus)
fp_carry        = $2a           ; 1 byte: carry/borrow result
fp_loop         = $2b           ; 1 byte: loop counter

; Multiply working ZP ($39-$3E: free)
fp_mul_i        = $39           ; outer loop index
fp_mul_j        = $3a           ; inner loop index

; Quarter-square table addresses (page-aligned for speed)
sqtab_lo        = $7800         ; 512 bytes: low bytes of floor(n^2/4)
sqtab_hi        = $7a00         ; 512 bytes: high bytes

; =============================================================================
; fp_init_sqtab - build quarter-square lookup table at $7800-$7BFF
; Must be called once before any multiplications.
; Uses identity: f(i) = floor(i^2/4) and recurrence i^2 = (i-1)^2 + 2i-1
; =============================================================================
fp_init_sqtab:
        lda #0
        sta sq_acc
        sta sq_acc+1
        sta sq_acc+2
        sta sq_i
        sta sq_i+1

@loop:
        ; Compute f(i) = sq_acc >> 2
        lda sq_acc+2
        lsr
        sta sq_sh+2
        lda sq_acc+1
        ror
        sta sq_sh+1
        lda sq_acc
        ror
        sta sq_sh
        lsr sq_sh+2
        ror sq_sh+1
        ror sq_sh

        ; Store in table at index sq_i (0..511)
        ldx sq_i                ; low byte of index
        lda sq_i+1
        beq @pg0
        ; Page 1 (256..511)
        lda sq_sh
        sta sqtab_lo+256,x
        lda sq_sh+1
        sta sqtab_hi+256,x
        jmp @advance
@pg0:
        lda sq_sh
        sta sqtab_lo,x
        lda sq_sh+1
        sta sqtab_hi,x

@advance:
        ; sq_acc += 2*i + 1
        lda sq_i
        asl
        sta sq_ad
        lda sq_i+1
        rol
        sta sq_ad+1
        inc sq_ad
        bne +
        inc sq_ad+1
+
        clc
        lda sq_acc
        adc sq_ad
        sta sq_acc
        lda sq_acc+1
        adc sq_ad+1
        sta sq_acc+1
        lda sq_acc+2
        adc #0
        sta sq_acc+2

        inc sq_i
        bne +
        inc sq_i+1
+       lda sq_i+1
        cmp #2
        beq @done
        jmp @loop
@done:  rts

sq_acc: !fill 3, 0
sq_sh:  !fill 3, 0
sq_ad:  !fill 2, 0
sq_i:   !fill 2, 0

; =============================================================================
; fp_copy: copy 32 bytes from (fp_src1) to (fp_dst)
; =============================================================================
fp_copy:
        ldy #31
@lp:    lda (fp_src1),y
        sta (fp_dst),y
        dey
        bpl @lp
        rts

; =============================================================================
; fp_zero: zero 32 bytes at (fp_dst)
; =============================================================================
fp_zero:
        lda #0
        ldy #31
@lp:    sta (fp_dst),y
        dey
        bpl @lp
        rts

; =============================================================================
; fp_cmp: compare (fp_src1) vs (fp_src2), 32 bytes big-endian
; Carry set if src1 >= src2, clear if src1 < src2. Zero if equal.
; =============================================================================
fp_cmp:
        ldy #0
@lp:    lda (fp_src1),y
        cmp (fp_src2),y
        bne @done
        iny
        cpy #32
        bne @lp
@done:  rts

; =============================================================================
; fp_add: (fp_dst) = (fp_src1) + (fp_src2). Carry in fp_carry.
; =============================================================================
fp_add:
        clc
        ldy #31
@lp:    lda (fp_src1),y
        adc (fp_src2),y
        sta (fp_dst),y
        dey
        bpl @lp
        lda #0
        adc #0
        sta fp_carry
        rts

; =============================================================================
; fp_sub: (fp_dst) = (fp_src1) - (fp_src2). Borrow in fp_carry (1=borrow).
; =============================================================================
fp_sub:
        sec
        ldy #31
@lp:    lda (fp_src1),y
        sbc (fp_src2),y
        sta (fp_dst),y
        dey
        bpl @lp
        lda #0
        adc #0
        eor #1
        sta fp_carry
        rts

; =============================================================================
; fp_is_zero: test if (fp_src1) == 0. Z flag set if zero.
; =============================================================================
fp_is_zero:
        ldy #0
        lda #0
@lp:    ora (fp_src1),y
        iny
        cpy #32
        bne @lp
        cmp #0
        rts

; =============================================================================
; fp_rshift1: right-shift (fp_src1) by 1 bit in place
; =============================================================================
fp_rshift1:
        clc
        ldy #0
@lp:    lda (fp_src1),y
        ror
        sta (fp_src1),y
        iny
        cpy #32
        bne @lp
        rts

; =============================================================================
; fp_mul: 256x256 -> 512 bit multiply
; (fp_src1) * (fp_src2) -> fp_wide (64 bytes)
; Schoolbook with quarter-square 8x8 lookup.
; =============================================================================
fp_mul:
        ; Clear 64-byte result
        ldy #63
        lda #0
@clr:   sta fp_wide,y
        dey
        bpl @clr

        lda #31
        sta fp_mul_i
@outer:
        ldy fp_mul_i
        lda (fp_src1),y
        sta fp_a_byte
        bne @do_inner
        jmp @skip_o

@do_inner:
        lda #31
        sta fp_mul_j
@inner:
        ldy fp_mul_j
        lda (fp_src2),y
        beq @skip_i
        sta fp_b_byte

        ; a*b via quarter-square: sqtab[a+b] - sqtab[|a-b|]
        lda fp_a_byte
        clc
        adc fp_b_byte
        tax                     ; X = (a+b) low
        lda #0
        adc #0
        sta fp_s_hi             ; sum page (0 or 1)

        lda fp_a_byte
        sec
        sbc fp_b_byte
        bcs +
        eor #$ff
        adc #1
+       tay                     ; Y = |a-b| (always page 0)

        lda fp_s_hi
        beq @s0
        ; sum page 1
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta fp_p_lo
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta fp_p_hi
        jmp @add_prod
@s0:    lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta fp_p_lo
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta fp_p_hi

@add_prod:
        ; Add 16-bit product to fp_wide[i+j+1] (lo) and [i+j] (hi)
        lda fp_mul_i
        clc
        adc fp_mul_j
        tax
        inx                     ; X = i+j+1

        clc
        lda fp_wide,x
        adc fp_p_lo
        sta fp_wide,x
        dex                     ; X = i+j
        lda fp_wide,x
        adc fp_p_hi
        sta fp_wide,x
        bcc @skip_i
        ; Propagate carry
@prop:  dex
        bmi @skip_i
        lda fp_wide,x
        adc #0
        sta fp_wide,x
        bcs @prop

@skip_i:
        dec fp_mul_j
        bmi @skip_o
        jmp @inner
@skip_o:
        dec fp_mul_i
        bmi @mul_done
        jmp @outer
@mul_done:
        rts

fp_a_byte:  !byte 0
fp_b_byte:  !byte 0
fp_s_hi:    !byte 0
fp_p_lo:    !byte 0
fp_p_hi:    !byte 0
fp_wide:    !fill 64, 0

; =============================================================================
; Layer 2: Modular Arithmetic
; =============================================================================

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

fp_rem: !fill 33, 0
fp_bc:  !byte 0
fp_bm:  !byte 0

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
        bne +
        inc fp_inv_iter+1
+
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
        bne +
        jmp @u_one
+
        ; Check v == 1
        lda #<fp_inv_v
        sta fp_src1
        lda #>fp_inv_v
        sta fp_src1+1
        jsr fp_chk_one
        bne +
        jmp @v_one
+

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
@x1sh:  lda fp_inv_x1,y
        ror                     ; rotate carry in from left
        sta fp_inv_x1,y
        iny
        cpy #32
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
@x2sh:  lda fp_inv_x2,y
        ror
        sta fp_inv_x2,y
        iny
        cpy #32
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

fp_inv_iter: !word 0

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

fp_inv_u:   !fill 32, 0
fp_inv_v:   !fill 32, 0
fp_inv_x1:  !fill 32, 0
fp_inv_x2:  !fill 32, 0

; =============================================================================
; Working registers
; =============================================================================
fp_r0:      !fill 32, 0        ; primary result register
fp_r1:      !fill 32, 0
fp_r2:      !fill 32, 0
fp_r3:      !fill 32, 0

; =============================================================================
; P-256 Curve Parameters
; =============================================================================
ec_p:   ; Field prime
        !byte $FF, $FF, $FF, $FF, $00, $00, $00, $01
        !byte $00, $00, $00, $00, $00, $00, $00, $00
        !byte $00, $00, $00, $00, $FF, $FF, $FF, $FF
        !byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
ec_n:   ; Group order
        !byte $FF, $FF, $FF, $FF, $00, $00, $00, $00
        !byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FF
        !byte $BC, $E6, $FA, $AD, $A7, $17, $9E, $84
        !byte $F3, $B9, $CA, $C2, $FC, $63, $25, $51
ec_a:   ; Coefficient a = p - 3
        !byte $FF, $FF, $FF, $FF, $00, $00, $00, $01
        !byte $00, $00, $00, $00, $00, $00, $00, $00
        !byte $00, $00, $00, $00, $FF, $FF, $FF, $FF
        !byte $FF, $FF, $FF, $FF, $FF, $FF, $FF, $FC
ec_b:   ; Coefficient b
        !byte $5A, $C6, $35, $D8, $AA, $3A, $93, $E7
        !byte $B3, $EB, $BD, $55, $76, $98, $86, $BC
        !byte $65, $1D, $06, $B0, $CC, $53, $B0, $F6
        !byte $3B, $CE, $3C, $3E, $27, $D2, $60, $4B
ec_gx:  ; Generator x
        !byte $6B, $17, $D1, $F2, $E1, $2C, $42, $47
        !byte $F8, $BC, $E6, $E5, $63, $A4, $40, $F2
        !byte $77, $03, $7D, $81, $2D, $EB, $33, $A0
        !byte $F4, $A1, $39, $45, $D8, $98, $C2, $96
ec_gy:  ; Generator y
        !byte $4F, $E3, $42, $E2, $FE, $1A, $7F, $9B
        !byte $8E, $E7, $EB, $4A, $7C, $0F, $9E, $16
        !byte $2B, $CE, $33, $57, $6B, $31, $5E, $CE
        !byte $CB, $B6, $40, $68, $37, $BF, $51, $F5

; =============================================================================
; RFC 6979 A.2.5 Test Vector (P-256/SHA-256, msg="sample")
; Verified against OpenSSL
; =============================================================================
ecdsa_test_privkey:
        !byte $C9, $AF, $A9, $D8, $45, $BA, $75, $16
        !byte $6B, $5C, $21, $57, $67, $B1, $D6, $93
        !byte $4E, $50, $C3, $DB, $36, $E8, $9B, $12
        !byte $7B, $8A, $62, $2B, $12, $0F, $67, $21
ecdsa_test_k:
        !byte $A6, $E3, $C5, $7D, $D0, $1A, $BE, $90
        !byte $08, $65, $38, $39, $83, $55, $DD, $4C
        !byte $3B, $17, $AA, $87, $33, $82, $B0, $F2
        !byte $4D, $61, $29, $49, $3D, $8A, $AD, $60
ecdsa_test_hash:  ; SHA-256("sample")
        !byte $AF, $2B, $DB, $E1, $AA, $9B, $6E, $C1
        !byte $E2, $AD, $E1, $D6, $94, $F4, $1F, $C7
        !byte $1A, $83, $1D, $02, $68, $E9, $89, $15
        !byte $62, $11, $3D, $8A, $62, $AD, $D1, $BF
ecdsa_test_r:
        !byte $EF, $D4, $8B, $2A, $AC, $B6, $A8, $FD
        !byte $11, $40, $DD, $9C, $D4, $5E, $81, $D6
        !byte $9D, $2C, $87, $7B, $56, $AA, $F9, $91
        !byte $C3, $4D, $0E, $A8, $4E, $AF, $37, $16
ecdsa_test_s:
        !byte $F7, $CB, $1C, $94, $2D, $65, $7C, $41
        !byte $D4, $36, $C7, $A1, $B6, $E2, $9F, $65
        !byte $F3, $E9, $00, $DB, $B9, $AF, $F4, $06
        !byte $4D, $C4, $AB, $2F, $84, $3A, $CD, $A8
ecdsa_test_pubx:
        !byte $60, $FE, $D4, $BA, $25, $5A, $9D, $31
        !byte $C9, $61, $EB, $74, $C6, $35, $6D, $68
        !byte $C0, $49, $B8, $92, $3B, $61, $FA, $6C
        !byte $E6, $69, $62, $2E, $60, $F2, $9F, $B6
ecdsa_test_puby:
        !byte $79, $03, $FE, $10, $08, $B8, $BC, $99
        !byte $A4, $1A, $E9, $E9, $56, $28, $BC, $64
        !byte $F2, $F1, $B2, $0C, $2D, $7E, $9F, $51
        !byte $77, $A3, $C2, $94, $D4, $46, $22, $99
; Known intermediate: 2*G
ecdsa_test_2gx:
        !byte $7C, $F2, $7B, $18, $8D, $03, $4F, $7E
        !byte $8A, $52, $38, $03, $04, $B5, $1A, $C3
        !byte $C0, $89, $69, $E2, $77, $F2, $1B, $35
        !byte $A6, $0B, $48, $FC, $47, $66, $99, $78
ecdsa_test_2gy:
        !byte $07, $77, $55, $10, $DB, $8E, $D0, $40
        !byte $29, $3D, $9A, $C6, $9F, $74, $30, $DB
        !byte $BA, $7D, $AD, $E6, $3C, $E9, $82, $29
        !byte $9E, $04, $B7, $9D, $22, $78, $73, $D1

; =============================================================================
; Layer 3: Elliptic Curve Point Operations (Jacobian Coordinates)
; =============================================================================
; Point = (X,Y,Z) each 32 bytes = 96 bytes total. Affine = X/Z^2, Y/Z^3.
; Point at infinity: Z = 0.
; All field arithmetic is mod ec_p.
;
; To reduce the enormous pointer-setup overhead, we use helper routines
; that set up fp_src1/fp_src2/fp_dst/fp_misc from A/Y (lo/hi of each).
; =============================================================================

; --- Point storage ---
ec_p1:  !fill 96, 0            ; working point (Jacobian)
ec_p2:  !fill 96, 0            ; second point (affine X,Y only used)
ec_p3:  !fill 96, 0            ; result point (Jacobian)

; --- Temporaries for point math (mod p) ---
ec_t1:  !fill 32, 0
ec_t2:  !fill 32, 0
ec_t3:  !fill 32, 0
ec_t4:  !fill 32, 0
ec_t5:  !fill 32, 0
ec_t6:  !fill 32, 0

; --- Helper: set fp_misc = ec_p ---
ec_set_modp:
        lda #<ec_p
        sta fp_misc
        lda #>ec_p
        sta fp_misc+1
        rts

; --- Helper: set fp_misc = ec_n ---
ec_set_modn:
        lda #<ec_n
        sta fp_misc
        lda #>ec_n
        sta fp_misc+1
        rts

; --- Helper: modular multiply mod p, result -> (fp_dst) ---
; fp_src1, fp_src2 already set. Result goes through fp_r0 then copied to dst.
ec_mulp:
        jsr ec_set_modp
        jsr fp_mod_mul          ; result in fp_r0
        ; Copy fp_r0 -> (fp_dst)
        lda fp_src1
        pha
        lda fp_src1+1
        pha
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        jsr fp_copy
        pla
        sta fp_src1+1
        pla
        sta fp_src1
        rts

; --- Helper macros as subroutines ---
; ec_setup_ss: set fp_src1 and fp_src2 from ec_arg1/ec_arg2
; ec_setup_sd: set fp_src1 and fp_dst from ec_arg1/ec_arg3
; (We use a register-passing scheme via ec_arg* variables)

; Rather than macros, we use inline setup. The pattern is repetitive
; but each call is only 12 bytes. Let's define the operations we need.

; =============================================================================
; ec_point_double: ec_p3 = 2 * ec_p1 (Jacobian)
; Formula for a = -3 (P-256):
;   M = 3*(X1 - Z1^2)*(X1 + Z1^2)
;   S = 4*X1*Y1^2
;   X3 = M^2 - 2*S
;   Y3 = M*(S - X3) - 8*Y1^4
;   Z3 = 2*Y1*Z1
; =============================================================================
ec_point_double:
        ; Check Z1 == 0 (point at infinity)
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        jsr fp_is_zero
        bne @notinf
        ; Result = infinity
        ldy #95
        lda #0
@ci:    sta ec_p3,y
        dey
        bpl @ci
        rts

@notinf:
        jsr ec_set_modp

        ; t1 = Z1^2
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_mulp             ; t1 = Z1^2

        ; t2 = X1 - t1
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr fp_mod_sub          ; t2 = X1 - Z1^2

        ; t3 = X1 + t1
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_add          ; t3 = X1 + Z1^2

        ; t4 = t2 * t3 = (X1-Z^2)(X1+Z^2)
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = X1^2 - Z1^4

        ; M = 3*t4: t5 = 2*t4, t2 = t5+t4 = 3*t4
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr fp_mod_add          ; t5 = 2*t4

        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr fp_mod_add          ; t2 = M = 3*(X1^2 - Z1^4)

        ; t3 = Y1^2
        lda #<(ec_p1+32)
        sta fp_src1
        lda #>(ec_p1+32)
        sta fp_src1+1
        lda #<(ec_p1+32)
        sta fp_src2
        lda #>(ec_p1+32)
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp             ; t3 = Y1^2

        ; t4 = X1 * Y1^2
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = X1*Y1^2

        ; S = 4*X1*Y1^2 = 4*t4
        ; t5 = 2*t4
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr fp_mod_add          ; t5 = 2*X1*Y1^2

        ; t1 = S = 2*t5 = 4*X1*Y1^2
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t5
        sta fp_src2
        lda #>ec_t5
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr fp_mod_add          ; t1 = S = 4*X1*Y1^2

        ; X3 = M^2 - 2*S
        ; t4 = M^2
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = M^2

        ; t5 = 2*S
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr fp_mod_add          ; t5 = 2*S

        ; X3 = t4 - t5
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t5
        sta fp_src2
        lda #>ec_t5
        sta fp_src2+1
        lda #<ec_p3
        sta fp_dst
        lda #>ec_p3
        sta fp_dst+1
        jsr fp_mod_sub          ; X3 = M^2 - 2S

        ; Y3 = M*(S - X3) - 8*Y1^4
        ; t4 = S - X3
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_p3
        sta fp_src2
        lda #>ec_p3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr fp_mod_sub          ; t4 = S - X3

        ; t5 = M*(S-X3)
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr ec_mulp             ; t5 = M*(S-X3)

        ; t4 = Y1^4 = (Y1^2)^2 = t3^2
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = Y1^4

        ; 8*Y1^4: t6 = 2*t4, t4 = 2*t6 = 4*Y1^4, t6 = 2*t4 = 8*Y1^4
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_add          ; t6 = 2*Y1^4

        lda #<ec_t6
        sta fp_src1
        lda #>ec_t6
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr fp_mod_add          ; t4 = 4*Y1^4

        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_add          ; t6 = 8*Y1^4

        ; Y3 = t5 - t6
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<(ec_p3+32)
        sta fp_dst
        lda #>(ec_p3+32)
        sta fp_dst+1
        jsr fp_mod_sub          ; Y3 = M*(S-X3) - 8*Y1^4

        ; Z3 = 2*Y1*Z1
        ; t1 = Y1*Z1
        lda #<(ec_p1+32)
        sta fp_src1
        lda #>(ec_p1+32)
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_mulp             ; t1 = Y1*Z1

        ; Z3 = 2*t1
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<(ec_p3+64)
        sta fp_dst
        lda #>(ec_p3+64)
        sta fp_dst+1
        jsr fp_mod_add          ; Z3 = 2*Y1*Z1

        rts

; =============================================================================
; ec_point_add: ec_p3 = ec_p1 + ec_p2
; P1 is Jacobian (X1,Y1,Z1). P2 is AFFINE (X2,Y2, Z2 assumed 1).
;
;   U2 = X2*Z1^2,  S2 = Y2*Z1^3
;   H = U2 - X1,   R = S2 - Y1
;   If H==0: if R==0 -> double, else -> infinity
;   X3 = R^2 - H^3 - 2*X1*H^2
;   Y3 = R*(X1*H^2 - X3) - Y1*H^3
;   Z3 = H*Z1
; =============================================================================
ec_point_add:
        ; If P1 is infinity (Z1==0): result = P2 with Z=1
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        jsr fp_is_zero
        bne @p1ok

        ; Copy P2 to P3 as Jacobian with Z=1
        ldy #31
@cpx:   lda ec_p2,y
        sta ec_p3,y
        dey
        bpl @cpx
        ldy #31
@cpy:   lda ec_p2+32,y
        sta ec_p3+32,y
        dey
        bpl @cpy
        ldy #31
        lda #0
@clz:   sta ec_p3+64,y
        dey
        bpl @clz
        lda #1
        sta ec_p3+95            ; Z = 1
        rts

@p1ok:
        jsr ec_set_modp

        ; t1 = Z1^2
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr ec_mulp             ; t1 = Z1^2

        ; t2 = X2*Z1^2 = U2
        lda #<ec_p2
        sta fp_src1
        lda #>ec_p2
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_mulp             ; t2 = U2

        ; t3 = Z1^3 = Z1*t1
        lda #<(ec_p1+64)
        sta fp_src1
        lda #>(ec_p1+64)
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp             ; t3 = Z1^3

        ; t4 = Y2*Z1^3 = S2
        lda #<(ec_p2+32)
        sta fp_src1
        lda #>(ec_p2+32)
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = S2

        ; H = U2 - X1 = t2 - X1 -> t1
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_p1
        sta fp_src2
        lda #>ec_p1
        sta fp_src2+1
        lda #<ec_t1
        sta fp_dst
        lda #>ec_t1
        sta fp_dst+1
        jsr fp_mod_sub          ; t1 = H = U2 - X1

        ; R = S2 - Y1 = t4 - Y1 -> t2
        lda #<ec_t4
        sta fp_src1
        lda #>ec_t4
        sta fp_src1+1
        lda #<(ec_p1+32)
        sta fp_src2
        lda #>(ec_p1+32)
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr fp_mod_sub          ; t2 = R = S2 - Y1

        ; Check H == 0
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        jsr fp_is_zero
        bne @h_nonzero

        ; H == 0: check R
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        jsr fp_is_zero
        bne @set_inf
        ; H==0, R==0: points are equal, double P1
        jmp ec_point_double

@set_inf:
        ; H==0, R!=0: inverse points, result = infinity
        ldy #95
        lda #0
@sinf:  sta ec_p3,y
        dey
        bpl @sinf
        rts

@h_nonzero:
        ; t3 = H^2
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp             ; t3 = H^2

        ; t4 = H^3 = H*H^2
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t4
        sta fp_dst
        lda #>ec_t4
        sta fp_dst+1
        jsr ec_mulp             ; t4 = H^3

        ; t5 = X1*H^2
        lda #<ec_p1
        sta fp_src1
        lda #>ec_p1
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr ec_mulp             ; t5 = X1*H^2

        ; X3 = R^2 - H^3 - 2*X1*H^2
        ; t3 = R^2
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp             ; t3 = R^2

        ; t3 = R^2 - H^3
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_sub          ; t3 = R^2 - H^3

        ; t6 = 2*X1*H^2
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t5
        sta fp_src2
        lda #>ec_t5
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr fp_mod_add          ; t6 = 2*X1*H^2

        ; X3 = t3 - t6
        lda #<ec_t3
        sta fp_src1
        lda #>ec_t3
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<ec_p3
        sta fp_dst
        lda #>ec_p3
        sta fp_dst+1
        jsr fp_mod_sub          ; X3

        ; Y3 = R*(X1*H^2 - X3) - Y1*H^3
        ; t3 = X1*H^2 - X3 = t5 - X3
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_p3
        sta fp_src2
        lda #>ec_p3
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr fp_mod_sub          ; t3 = X1*H^2 - X3

        ; t5 = R * t3
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_t5
        sta fp_dst
        lda #>ec_t5
        sta fp_dst+1
        jsr ec_mulp             ; t5 = R*(X1*H^2 - X3)

        ; t6 = Y1*H^3
        lda #<(ec_p1+32)
        sta fp_src1
        lda #>(ec_p1+32)
        sta fp_src1+1
        lda #<ec_t4
        sta fp_src2
        lda #>ec_t4
        sta fp_src2+1
        lda #<ec_t6
        sta fp_dst
        lda #>ec_t6
        sta fp_dst+1
        jsr ec_mulp             ; t6 = Y1*H^3

        ; Y3 = t5 - t6
        lda #<ec_t5
        sta fp_src1
        lda #>ec_t5
        sta fp_src1+1
        lda #<ec_t6
        sta fp_src2
        lda #>ec_t6
        sta fp_src2+1
        lda #<(ec_p3+32)
        sta fp_dst
        lda #>(ec_p3+32)
        sta fp_dst+1
        jsr fp_mod_sub          ; Y3

        ; Z3 = H*Z1 = t1*Z1
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<(ec_p1+64)
        sta fp_src2
        lda #>(ec_p1+64)
        sta fp_src2+1
        lda #<(ec_p3+64)
        sta fp_dst
        lda #>(ec_p3+64)
        sta fp_dst+1
        jsr ec_mulp             ; Z3 = H*Z1

        rts

; =============================================================================
; ec_scalar_mul: ec_p3 = k * G
; k is a 32-byte scalar pointed to by ec_scalar_ptr.
; Uses double-and-add with the base point G (affine).
; Result in ec_p3 (Jacobian).
; =============================================================================
ec_scalar_ptr   = $3b           ; ZP pointer to 32-byte scalar k

ec_scalar_mul:
        ; Initialize ec_p1 = point at infinity (Z=0)
        ldy #95
        lda #0
@clr:   sta ec_p1,y
        dey
        bpl @clr

        ; Load G into ec_p2 (affine)
        ldy #31
@cgx:   lda ec_gx,y
        sta ec_p2,y
        dey
        bpl @cgx
        ldy #31
@cgy:   lda ec_gy,y
        sta ec_p2+32,y
        dey
        bpl @cgy

        ; Process 256 bits of k, MSB first
        lda #0
        sta ec_sc_byte          ; byte index 0..31
        lda #$80
        sta ec_sc_mask          ; bit mask

@bitloop:
        ; Double: ec_p1 = 2*ec_p1 (via ec_p3)
        jsr ec_point_double     ; ec_p3 = 2*ec_p1
        ; Copy ec_p3 -> ec_p1
        ldy #95
@cp1:   lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @cp1

        ; Test bit of k
        ldy ec_sc_byte
        lda (ec_scalar_ptr),y
        and ec_sc_mask
        beq @nobit

        ; Add: ec_p1 = ec_p1 + ec_p2 (via ec_p3)
        jsr ec_point_add        ; ec_p3 = ec_p1 + G
        ; Copy ec_p3 -> ec_p1
        ldy #95
@cp2:   lda ec_p3,y
        sta ec_p1,y
        dey
        bpl @cp2

@nobit:
        ; Advance to next bit
        lsr ec_sc_mask
        bne @bitloop
        ; Next byte - show progress
        jsr ec_show_progress
        lda #$80
        sta ec_sc_mask
        inc ec_sc_byte
        lda ec_sc_byte
        cmp #32
        beq @done
        jmp @bitloop

@done:
        ; Result is in ec_p1; copy to ec_p3
        ldy #95
@cfin:  lda ec_p1,y
        sta ec_p3,y
        dey
        bpl @cfin
        rts

ec_sc_byte:     !byte 0
ec_sc_mask:     !byte 0

; Progress display for scalar multiply
ec_show_progress:
        ; Print byte number every 8 bits (when mask resets)
        lda ec_sc_byte
        jsr print_decimal
        lda #' '
        jsr chrout
        rts

; =============================================================================
; ec_jacobian_to_affine: convert ec_p3 (Jacobian) to affine (x,y)
; Result: ec_affine_x, ec_affine_y (32 bytes each)
; Computes x = X/Z^2, y = Y/Z^3 using modular inverse.
; =============================================================================
ec_affine_x:    !fill 32, 0
ec_affine_y:    !fill 32, 0

ec_jacobian_to_affine:
        jsr ec_set_modp

        ; Compute Z^(-1)
        lda #<(ec_p3+64)
        sta fp_src1
        lda #>(ec_p3+64)
        sta fp_src1+1
        jsr fp_mod_inv          ; fp_r0 = Z^(-1)

        ; Copy Z^(-1) to ec_t1
        ldy #31
@czi:   lda fp_r0,y
        sta ec_t1,y
        dey
        bpl @czi

        ; t2 = Z^(-2) = Z^(-1) * Z^(-1)
        lda #<ec_t1
        sta fp_src1
        lda #>ec_t1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_mulp             ; t2 = Z^(-2)

        ; t3 = Z^(-3) = Z^(-2) * Z^(-1)
        lda #<ec_t2
        sta fp_src1
        lda #>ec_t2
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t3
        sta fp_dst
        lda #>ec_t3
        sta fp_dst+1
        jsr ec_mulp             ; t3 = Z^(-3)

        ; x = X * Z^(-2)
        lda #<ec_p3
        sta fp_src1
        lda #>ec_p3
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        lda #<ec_affine_x
        sta fp_dst
        lda #>ec_affine_x
        sta fp_dst+1
        jsr ec_mulp             ; affine_x = X*Z^(-2)

        ; y = Y * Z^(-3)
        lda #<(ec_p3+32)
        sta fp_src1
        lda #>(ec_p3+32)
        sta fp_src1+1
        lda #<ec_t3
        sta fp_src2
        lda #>ec_t3
        sta fp_src2+1
        lda #<ec_affine_y
        sta fp_dst
        lda #>ec_affine_y
        sta fp_dst+1
        jsr ec_mulp             ; affine_y = Y*Z^(-3)

        rts

; =============================================================================
; Layer 4: ECDSA Signing
; =============================================================================
; ecdsa_sign: compute signature (r,s) for a 32-byte hash
;
; Inputs:
;   ecdsa_hash_ptr   -> 32-byte hash (e.g. SHA-256 of message)
;   ecdsa_privkey_ptr -> 32-byte private key (scalar d)
;   ecdsa_k_ptr      -> 32-byte ephemeral nonce k
;
; Outputs:
;   ecdsa_sig_r (32 bytes)
;   ecdsa_sig_s (32 bytes)
;
; Algorithm:
;   (x1,y1) = k*G
;   r = x1 mod n
;   s = k^(-1) * (hash + r*d) mod n
; =============================================================================
ecdsa_hash_ptr:  !fill 2, 0
ecdsa_privkey_ptr: !fill 2, 0
ecdsa_k_ptr:     !fill 2, 0

ecdsa_sig_r:     !fill 32, 0
ecdsa_sig_s:     !fill 32, 0

ecdsa_sign:
        ; Step 1: compute k*G
        lda ecdsa_k_ptr
        sta ec_scalar_ptr
        lda ecdsa_k_ptr+1
        sta ec_scalar_ptr+1
        jsr ec_scalar_mul       ; ec_p3 = k*G (Jacobian)

        ; Convert to affine
        jsr ec_jacobian_to_affine  ; ec_affine_x/y

        ; Step 2: r = affine_x mod n
        ; Copy affine_x to fp_wide (as 256-bit, zero-extend to 512)
        ldy #63
        lda #0
@clw:   sta fp_wide,y
        dey
        bpl @clw
        ldy #31
@cax:   lda ec_affine_x,y
        sta fp_wide+32,y        ; lower 256 bits of 512-bit value
        dey
        bpl @cax

        jsr ec_set_modn
        jsr fp_mod_reduce       ; fp_r0 = affine_x mod n

        ; Save r
        ldy #31
@sr:    lda fp_r0,y
        sta ecdsa_sig_r,y
        dey
        bpl @sr

        ; Step 3: compute s = k^(-1) * (hash + r*d) mod n
        ; First: r * d mod n
        lda #<ecdsa_sig_r
        sta fp_src1
        lda #>ecdsa_sig_r
        sta fp_src1+1
        lda ecdsa_privkey_ptr
        sta fp_src2
        lda ecdsa_privkey_ptr+1
        sta fp_src2+1
        jsr ec_set_modn
        jsr fp_mod_mul          ; fp_r0 = r*d mod n

        ; Copy r*d to ec_t1
        ldy #31
@crd:   lda fp_r0,y
        sta ec_t1,y
        dey
        bpl @crd

        ; hash + r*d mod n
        lda ecdsa_hash_ptr
        sta fp_src1
        lda ecdsa_hash_ptr+1
        sta fp_src1+1
        lda #<ec_t1
        sta fp_src2
        lda #>ec_t1
        sta fp_src2+1
        lda #<ec_t2
        sta fp_dst
        lda #>ec_t2
        sta fp_dst+1
        jsr ec_set_modn
        jsr fp_mod_add          ; ec_t2 = hash + r*d mod n

        ; k^(-1) mod n
        lda ecdsa_k_ptr
        sta fp_src1
        lda ecdsa_k_ptr+1
        sta fp_src1+1
        jsr ec_set_modn
        jsr fp_mod_inv          ; fp_r0 = k^(-1) mod n

        ; s = k^(-1) * (hash + r*d) mod n
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        lda #<ec_t2
        sta fp_src2
        lda #>ec_t2
        sta fp_src2+1
        jsr ec_set_modn
        jsr fp_mod_mul          ; fp_r0 = s

        ; Save s
        ldy #31
@ss:    lda fp_r0,y
        sta ecdsa_sig_s,y
        dey
        bpl @ss
        rts

; =============================================================================
; Layer 5: ECDSA Test Vector Runner
; =============================================================================
; do_ecdsa_test: run RFC 6979 test vector and compare results
; Uses the known private key, k, and hash to produce (r,s)
; then compares against expected values.
;
; This is called from the menu when the user presses 'J' (or a sub-option).
; =============================================================================
do_ecdsa_test:
        lda #$0d
        jsr chrout
        lda #<ecdsa_test_hdr_msg
        ldy #>ecdsa_test_hdr_msg
        jsr print_string

        ; Initialize quarter-square table
        lda #<ecdsa_init_msg
        ldy #>ecdsa_init_msg
        jsr print_string
        jsr fp_init_sqtab

        ; === TEST 1: Basic multiply 3*5=15 ===
        lda #<ecdsa_test1_msg
        ldy #>ecdsa_test1_msg
        jsr print_string

        ; Set fp_r1 = 3
        lda #<fp_r1
        sta fp_dst
        lda #>fp_r1
        sta fp_dst+1
        jsr fp_zero
        lda #3
        sta fp_r1+31

        ; Set fp_r2 = 5
        lda #<fp_r2
        sta fp_dst
        lda #>fp_r2
        sta fp_dst+1
        jsr fp_zero
        lda #5
        sta fp_r2+31

        ; Multiply: fp_wide = fp_r1 * fp_r2
        lda #<fp_r1
        sta fp_src1
        lda #>fp_r1
        sta fp_src1+1
        lda #<fp_r2
        sta fp_src2
        lda #>fp_r2
        sta fp_src2+1
        jsr fp_mul

        ; Show last 4 bytes of fp_wide (should be 00 00 00 0F)
        lda fp_wide+60
        jsr print_hex_byte
        lda fp_wide+61
        jsr print_hex_byte
        lda fp_wide+62
        jsr print_hex_byte
        lda fp_wide+63
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        ; === TEST 2: mod_reduce (15 mod p should be 15) ===
        lda #<ecdsa_test2_msg
        ldy #>ecdsa_test2_msg
        jsr print_string
        jsr ec_set_modp
        jsr fp_mod_reduce       ; fp_r0 = fp_wide mod p
        ; Show result (should be ...0F)
        lda fp_r0+28
        jsr print_hex_byte
        lda fp_r0+29
        jsr print_hex_byte
        lda fp_r0+30
        jsr print_hex_byte
        lda fp_r0+31
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        ; === TEST 3: fp_mod_inv(7, p) ===
        lda #<ecdsa_test3_msg
        ldy #>ecdsa_test3_msg
        jsr print_string

        ; fp_r1 = 7
        lda #<fp_r1
        sta fp_dst
        lda #>fp_r1
        sta fp_dst+1
        jsr fp_zero
        lda #7
        sta fp_r1+31

        ; inverse
        lda #<fp_r1
        sta fp_src1
        lda #>fp_r1
        sta fp_src1+1
        jsr ec_set_modp
        jsr fp_mod_inv          ; fp_r0 = 7^(-1) mod p

        ; Show first 4 bytes (should be 24924924)
        lda #<ecdsa_test3r_msg
        ldy #>ecdsa_test3r_msg
        jsr print_string
        lda fp_r0
        jsr print_hex_byte
        lda fp_r0+1
        jsr print_hex_byte
        lda fp_r0+2
        jsr print_hex_byte
        lda fp_r0+3
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        ; === TEST 4: Verify 7 * inv(7) mod p == 1 ===
        lda #<ecdsa_test4_msg
        ldy #>ecdsa_test4_msg
        jsr print_string
        lda #<fp_r1
        sta fp_src1
        lda #>fp_r1
        sta fp_src1+1
        lda #<fp_r0
        sta fp_src2
        lda #>fp_r0
        sta fp_src2+1
        jsr ec_set_modp
        jsr fp_mod_mul          ; fp_r0 = 7 * inv mod p
        ; Show last 4 bytes (should be 00000001)
        lda fp_r0+28
        jsr print_hex_byte
        lda fp_r0+29
        jsr print_hex_byte
        lda fp_r0+30
        jsr print_hex_byte
        lda fp_r0+31
        jsr print_hex_byte
        lda #$0d
        jsr chrout

        lda #<ecdsa_computing_msg
        ldy #>ecdsa_computing_msg
        jsr print_string

        ; Set up pointers for signing
        lda #<ecdsa_test_hash
        sta ecdsa_hash_ptr
        lda #>ecdsa_test_hash
        sta ecdsa_hash_ptr+1
        lda #<ecdsa_test_privkey
        sta ecdsa_privkey_ptr
        lda #>ecdsa_test_privkey
        sta ecdsa_privkey_ptr+1
        lda #<ecdsa_test_k
        sta ecdsa_k_ptr
        lda #>ecdsa_test_k
        sta ecdsa_k_ptr+1

        ; Sign!
        jsr ecdsa_sign

        ; Display computed r
        lda #<ecdsa_r_label
        ldy #>ecdsa_r_label
        jsr print_string
        lda #<ecdsa_sig_r
        sta zp_ptr
        lda #>ecdsa_sig_r
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; Display computed s
        lda #<ecdsa_s_label
        ldy #>ecdsa_s_label
        jsr print_string
        lda #<ecdsa_sig_s
        sta zp_ptr
        lda #>ecdsa_sig_s
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; Compare r with expected
        lda #<ecdsa_verify_msg
        ldy #>ecdsa_verify_msg
        jsr print_string

        lda #<ecdsa_sig_r
        sta fp_src1
        lda #>ecdsa_sig_r
        sta fp_src1+1
        lda #<ecdsa_test_r
        sta fp_src2
        lda #>ecdsa_test_r
        sta fp_src2+1
        jsr fp_cmp
        bne @r_fail
        ; Compare s
        lda #<ecdsa_sig_s
        sta fp_src1
        lda #>ecdsa_sig_s
        sta fp_src1+1
        lda #<ecdsa_test_s
        sta fp_src2
        lda #>ecdsa_test_s
        sta fp_src2+1
        jsr fp_cmp
        bne @s_fail

        lda #<ecdsa_pass_msg
        ldy #>ecdsa_pass_msg
        jsr print_string
        jmp @test_done

@r_fail:
@s_fail:
        lda #<ecdsa_fail_msg
        ldy #>ecdsa_fail_msg
        jsr print_string

        ; Show expected r for comparison
        lda #<ecdsa_expr_label
        ldy #>ecdsa_expr_label
        jsr print_string
        lda #<ecdsa_test_r
        sta zp_ptr
        lda #>ecdsa_test_r
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<ecdsa_exps_label
        ldy #>ecdsa_exps_label
        jsr print_string
        lda #<ecdsa_test_s
        sta zp_ptr
        lda #>ecdsa_test_s
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

@test_done:
        rts

; --- ECDSA UI messages ---
ecdsa_test1_msg:
        !text "T1:3*5="
        !byte 0
ecdsa_test2_msg:
        !text "T2:15 MOD P="
        !byte 0
ecdsa_test3_msg:
        !text "T3:INV(7)..."
        !byte 0
ecdsa_test3r_msg:
        !text "="
        !byte 0
ecdsa_test4_msg:
        !text "T4:7*INV="
        !byte 0
ecdsa_test_hdr_msg:
        !text "=== ECDSA P-256 TEST ==="
        !byte $0d
        !text "RFC 6979 A.2.5 (SHA-256)"
        !byte $0d, 0
ecdsa_init_msg:
        !text "BUILDING MULTIPLY TABLE..."
        !byte $0d, 0
ecdsa_computing_msg:
        !text "COMPUTING ECDSA SIGNATURE..."
        !byte $0d
        !text "(THIS WILL TAKE SEVERAL MINUTES)"
        !byte $0d, 0
ecdsa_r_label:
        !text "R = "
        !byte 0
ecdsa_s_label:
        !byte $0d
        !text "S = "
        !byte 0
ecdsa_verify_msg:
        !byte $0d
        !text "VERIFYING AGAINST KNOWN VECTOR..."
        !byte $0d, 0
ecdsa_pass_msg:
        !text "*** TEST PASSED ***"
        !byte $0d, 0
ecdsa_fail_msg:
        !text "*** TEST FAILED ***"
        !byte $0d, 0
ecdsa_expr_label:
        !text "EXPECTED R = "
        !byte 0
ecdsa_exps_label:
        !byte $0d
        !text "EXPECTED S = "
        !byte 0
