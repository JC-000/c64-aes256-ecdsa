; =============================================================================
; ecdsa_sign.asm - ECDSA signing routine
; =============================================================================

        .segment "LIB_AES256ECDSA_CODE"

.importzp ec_scalar_ptr, fp_src1, fp_src2, fp_dst
.import ec_scalar_mul, ec_jacobian_to_affine, ec_affine_x
.import fp_wide
.import ec_set_modn, ec_t1, ec_t2
.import fp_mod_reduce, fp_r0, fp_mod_mul, fp_mod_add, fp_mod_inv

; --- Full EXPORTS list per src/exports.inc's ecdsa_sign.s entry ---
.export ecdsa_hash_ptr, ecdsa_privkey_ptr, ecdsa_k_ptr, ecdsa_sig_r
.export ecdsa_sig_s, ecdsa_sign

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
ecdsa_hash_ptr:  .res 2, 0
ecdsa_privkey_ptr: .res 2, 0
ecdsa_k_ptr:     .res 2, 0

ecdsa_sig_r:     .res 32, 0
ecdsa_sig_s:     .res 32, 0

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
