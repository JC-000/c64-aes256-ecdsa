; =============================================================================
; ecdsa_curve.asm - P-256 curve parameters, test vectors, point storage, helpers
; =============================================================================

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
; Elliptic Curve Point Operations (Jacobian Coordinates)
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
