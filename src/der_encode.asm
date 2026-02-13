; =============================================================================
; der_encode.asm - ASN.1/DER encoding primitives + OID constants for PKCS#10
; =============================================================================
; Writes to a sequential output buffer (der_buf) via a 16-bit write position
; (der_pos). Uses self-modifying code for buffer writes to avoid ZP conflicts.
; =============================================================================

; --- Zero-page pointer for DER source data ---
der_src_ptr     = zp_ptr2              ; $02-$03 for source data reads
der_int_ptr     = zp_ptr               ; $FB-$FC for integer encoding

; =============================================================================
; der_init - reset write position to 0
; =============================================================================
der_init:
        lda #0
        sta der_pos
        sta der_pos+1
        rts

; =============================================================================
; der_write_byte - write byte from A, advance position
; Uses self-modifying code to avoid ZP pointer conflicts.
; =============================================================================
der_write_byte:
        pha
        clc
        lda der_pos
        adc #<der_buf
        sta @store+1
        lda der_pos+1
        adc #>der_buf
        sta @store+2
        pla
@store: sta der_buf                    ; address patched above
        inc der_pos
        bne +
        inc der_pos+1
+       rts

; =============================================================================
; der_write_length - encode DER length
; A = low byte, X = high byte
; <128: 1 byte; 128-255: $81,byte; 256+: $82,hi,lo
; =============================================================================
der_write_length:
        sta der_len_lo
        stx der_len_hi
        cpx #0
        bne @long2
        cmp #128
        bcs @long1
        ; Short form: just the byte itself
        jsr der_write_byte
        rts
@long1:
        ; 128-255: write $81, then byte
        lda #$81
        jsr der_write_byte
        lda der_len_lo
        jsr der_write_byte
        rts
@long2:
        ; 256+: write $82, hi, lo
        lda #$82
        jsr der_write_byte
        lda der_len_hi
        jsr der_write_byte
        lda der_len_lo
        jsr der_write_byte
        rts

der_len_lo:     !byte 0
der_len_hi:     !byte 0

; =============================================================================
; der_write_bytes - write der_wbs_cnt bytes from address in der_src_ptr
; X = byte count on entry
; =============================================================================
der_write_bytes:
        stx der_wbs_cnt
        ldx #0
@loop:
        cpx der_wbs_cnt
        beq @done
        stx der_wbs_idx
        txa
        tay
        lda (der_src_ptr),y
        jsr der_write_byte
        ldx der_wbs_idx
        inx
        jmp @loop
@done:
        rts

der_wbs_cnt:    !byte 0
der_wbs_idx:    !byte 0

; =============================================================================
; der_write_integer_32 - write DER INTEGER from 32-byte big-endian buffer
; at der_int_ptr. Handles leading-zero skip and sign-bit padding.
; =============================================================================
der_write_integer_32:
        ; Find number of significant bytes (skip leading zeros)
        ldy #0
        ldx #32
@skip_zeros:
        cpx #1                         ; keep at least 1 byte
        beq @found_start
        lda (der_int_ptr),y
        bne @found_start
        iny
        dex
        jmp @skip_zeros

@found_start:
        ; Y = first significant byte index, X = significant byte count
        sty der_int_skip
        stx der_int_sigbytes

        ; Check if high bit is set (need $00 padding for positive INTEGER)
        lda (der_int_ptr),y
        and #$80
        sta der_int_pad

        ; Write INTEGER tag $02
        lda #$02
        jsr der_write_byte

        ; Write length: sigbytes + (pad ? 1 : 0)
        lda der_int_sigbytes
        ldy der_int_pad
        beq @no_pad_len
        clc
        adc #1
@no_pad_len:
        ldx #0
        jsr der_write_length

        ; Write padding zero if needed
        lda der_int_pad
        beq @write_value
        lda #$00
        jsr der_write_byte

@write_value:
        ; Write significant bytes from der_int_ptr + der_int_skip
        ldy der_int_skip
@val_loop:
        cpy #32
        beq @int_done
        sty der_int_save_y
        lda (der_int_ptr),y
        jsr der_write_byte
        ldy der_int_save_y
        iny
        jmp @val_loop

@int_done:
        rts

der_int_skip:    !byte 0
der_int_sigbytes: !byte 0
der_int_pad:     !byte 0
der_int_save_y:  !byte 0

; =============================================================================
; der_measure_integer_32 - return DER INTEGER TLV size for 32-byte buffer
; at der_int_ptr. Returns size in A without writing anything.
; =============================================================================
der_measure_integer_32:
        ldy #0
        ldx #32
@skip:
        cpx #1
        beq @found
        lda (der_int_ptr),y
        bne @found
        iny
        dex
        jmp @skip
@found:
        ; X = significant byte count
        lda (der_int_ptr),y
        and #$80
        beq @no_pad
        inx                            ; add 1 for padding byte
@no_pad:
        ; TLV size = 1 (tag) + 1 (length, always < 128 for 32-byte values) + X
        txa
        clc
        adc #2
        rts

; =============================================================================
; der_write_oid - write OID TLV: tag $06, length in X, bytes from der_src_ptr
; =============================================================================
der_write_oid:
        stx der_oid_len
        lda #$06
        jsr der_write_byte
        lda der_oid_len
        ldx #0
        jsr der_write_length
        ldx der_oid_len
        jsr der_write_bytes
        rts

der_oid_len:    !byte 0

; =============================================================================
; der_write_raw_string - write string TLV
; A = tag byte, X = length, der_src_ptr = string data
; =============================================================================
der_write_raw_string:
        sta der_str_tag_save
        stx der_str_len_save
        lda der_str_tag_save
        jsr der_write_byte
        lda der_str_len_save
        ldx #0
        jsr der_write_length
        ldx der_str_len_save
        jsr der_write_bytes
        rts

der_str_tag_save:  !byte 0
der_str_len_save:  !byte 0

; =============================================================================
; der_get_pos - return current position (A=lo, X=hi)
; =============================================================================
der_get_pos:
        lda der_pos
        ldx der_pos+1
        rts

; =============================================================================
; OID Constants (pre-encoded bytes)
; =============================================================================

; X.500 attribute type OIDs (2.5.4.x) - 3 bytes each
oid_country:                           ; 2.5.4.6 (C)
        !byte $55, $04, $06
oid_state:                             ; 2.5.4.8 (ST)
        !byte $55, $04, $08
oid_locality:                          ; 2.5.4.7 (L)
        !byte $55, $04, $07
oid_org:                               ; 2.5.4.10 (O)
        !byte $55, $04, $0A
oid_ou:                                ; 2.5.4.11 (OU)
        !byte $55, $04, $0B
oid_cn:                                ; 2.5.4.3 (CN)
        !byte $55, $04, $03

; emailAddress (1.2.840.113549.1.9.1) - 9 bytes
oid_email:
        !byte $2A, $86, $48, $86, $F7, $0D, $01, $09, $01

; EC public key (1.2.840.10045.2.1) - 7 bytes
oid_ec_pubkey:
        !byte $2A, $86, $48, $CE, $3D, $02, $01

; prime256v1 / P-256 (1.2.840.10045.3.1.7) - 8 bytes
oid_prime256v1:
        !byte $2A, $86, $48, $CE, $3D, $03, $01, $07

; ecdsa-with-SHA256 (1.2.840.10045.4.3.2) - 8 bytes
oid_ecdsa_sha256:
        !byte $2A, $86, $48, $CE, $3D, $04, $03, $02

; =============================================================================
; Field lookup tables (parallel arrays indexed 0-6)
; Order: C(0), ST(1), L(2), O(3), OU(4), CN(5), Email(6)
; =============================================================================

pkcs10_oid_lo:
        !byte <oid_country, <oid_state, <oid_locality
        !byte <oid_org, <oid_ou, <oid_cn, <oid_email

pkcs10_oid_hi:
        !byte >oid_country, >oid_state, >oid_locality
        !byte >oid_org, >oid_ou, >oid_cn, >oid_email

pkcs10_oid_len:
        !byte 3, 3, 3, 3, 3, 3, 9

pkcs10_fld_lo:
        !byte <csr_country, <csr_state, <csr_city
        !byte <csr_org, <csr_ou, <csr_cn, <csr_email

pkcs10_fld_hi:
        !byte >csr_country, >csr_state, >csr_city
        !byte >csr_org, >csr_ou, >csr_cn, >csr_email

pkcs10_flen_lo:
        !byte <csr_country_len, <csr_state_len, <csr_city_len
        !byte <csr_org_len, <csr_ou_len, <csr_cn_len, <csr_email_len

pkcs10_flen_hi:
        !byte >csr_country_len, >csr_state_len, >csr_city_len
        !byte >csr_org_len, >csr_ou_len, >csr_cn_len, >csr_email_len

pkcs10_str_tag:
        !byte $13, $13, $13, $13, $13, $13, $16

; =============================================================================
; Working variables
; =============================================================================
der_pos:        !word 0                ; current write position in der_buf

; =============================================================================
; DER output buffer (512 bytes)
; =============================================================================
der_buf:        !fill 512, 0
