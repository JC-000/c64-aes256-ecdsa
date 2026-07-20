; =============================================================================
; pkcs10_build.asm - PKCS#10 DER structure builder
; =============================================================================
; Builds the complete CSR DER using pre-computed lengths (no back-patching).
; Two-phase approach: measure all lengths first, then write sequentially.
; =============================================================================

        .segment "LIB_AES256ECDSA_HICODE"

.importzp der_src_ptr, der_int_ptr
.import der_buf, der_pos, pkcs10_pubkey_x, pkcs10_pubkey_y
.import ecdsa_sig_r, ecdsa_sig_s
.import oid_ec_pubkey, oid_prime256v1, oid_ecdsa_sha256
.import pkcs10_flen_lo, pkcs10_flen_hi, pkcs10_oid_len, pkcs10_oid_lo
.import pkcs10_oid_hi, pkcs10_fld_lo, pkcs10_fld_hi, pkcs10_str_tag
.import der_init, der_get_pos, der_write_byte, der_write_length
.import der_write_oid, der_write_raw_string, der_write_bytes
.import der_measure_integer_32, der_write_integer_32

; --- Full EXPORTS list per src/exports.inc's pkcs10_build.s entry
; (pkcs10_der_len is also independently needed by the Python test harness -
; see tools/run_all_tests.py ALL_REQUIRED_LABELS - already covered here) ---
.export pkcs10_der_len, pkcs10_calc_dn_len, pkcs10_calc_tbs_len
.export pkcs10_write_tbs, pkcs10_encode_sig, pkcs10_write_outer
.export pkcs10_tbs_start, pkcs10_tbs_end, pkcs10_tbs_tlv_len
.export pkcs10_copy_idx, pkcs10_tbs_copy

; =============================================================================
; Constants for fixed-size structures
; =============================================================================
; SubjectPublicKeyInfo for uncompressed P-256 point: always 91 bytes
;   SEQUENCE (2) {
;     SEQUENCE (2) {
;       OID ecPublicKey 06 07 [7 bytes]  = 9
;       OID prime256v1  06 08 [8 bytes]  = 10
;     } = 19 content -> 30 13 = 21 bytes
;     BIT STRING 03 42 00 04 [32x] [32y] = 68 bytes
;   } = 89 content -> 30 59 = 91 bytes
SPKI_SIZE       = 91

; Signature algorithm: SEQUENCE { OID ecdsa-with-SHA256 }
;   30 0A 06 08 [8 bytes] = 12 bytes
SIG_ALG_SIZE    = 12

; Version INTEGER 0: 02 01 00 = 3 bytes
VERSION_SIZE    = 3

; Attributes [0] IMPLICIT (empty): A0 00 = 2 bytes
ATTRS_SIZE      = 2

; =============================================================================
; pkcs10_calc_dn_len - calculate subject DN content length
; Iterates field table, sums SET/SEQ TLV sizes for non-empty fields
; Result in pkcs10_dn_content_len (16-bit)
; =============================================================================
pkcs10_calc_dn_len:
        lda #0
        sta pkcs10_dn_content_len
        sta pkcs10_dn_content_len+1
        sta pkcs10_field_idx

@field_loop:
        ldx pkcs10_field_idx
        cpx #7
        beq @calc_done

        ; Get field length from address in pkcs10_flen_lo/hi table
        lda pkcs10_flen_lo,x
        sta der_src_ptr
        lda pkcs10_flen_hi,x
        sta der_src_ptr+1
        ldy #0
        lda (der_src_ptr),y           ; field length
        beq @next_field                ; skip empty fields

        ; Per field: SET_TLV = 2 + 2 + (2 + oid_len) + (2 + field_len)
        ;          = 8 + oid_len + field_len
        sta pkcs10_tmp_flen            ; field_len
        ldx pkcs10_field_idx
        lda pkcs10_oid_len,x           ; oid_len
        clc
        adc pkcs10_tmp_flen
        adc #8                         ; + 8 constant overhead
        ; Add to running total (16-bit add)
        clc
        adc pkcs10_dn_content_len
        sta pkcs10_dn_content_len
        bcc @next_field
        inc pkcs10_dn_content_len+1

@next_field:
        inc pkcs10_field_idx
        jmp @field_loop

@calc_done:
        rts

; =============================================================================
; pkcs10_calc_tbs_len - compute TBS (to-be-signed) content length
; TBS content = VERSION_SIZE + subject_dn_tlv + SPKI_SIZE + ATTRS_SIZE
; subject_dn_tlv = tag(1) + length_encoding + dn_content_len
; Result in pkcs10_tbs_content_len (16-bit)
; =============================================================================
pkcs10_calc_tbs_len:
        ; Calculate subject DN TLV size = SEQUENCE tag + length + content
        ; dn_content_len is the content; need to add tag+length bytes
        lda pkcs10_dn_content_len
        ldx pkcs10_dn_content_len+1
        jsr der_calc_len_size          ; returns length encoding size in A
        clc
        adc #1                         ; +1 for SEQUENCE tag byte
        adc pkcs10_dn_content_len
        sta pkcs10_dn_tlv_len
        lda #0
        adc pkcs10_dn_content_len+1
        sta pkcs10_dn_tlv_len+1

        ; TBS content = VERSION + DN_TLV + SPKI + ATTRS
        clc
        lda #VERSION_SIZE
        adc pkcs10_dn_tlv_len
        sta pkcs10_tbs_content_len
        lda #0
        adc pkcs10_dn_tlv_len+1
        sta pkcs10_tbs_content_len+1

        clc
        lda pkcs10_tbs_content_len
        adc #SPKI_SIZE
        sta pkcs10_tbs_content_len
        bcc :+
        inc pkcs10_tbs_content_len+1
:
        clc
        lda pkcs10_tbs_content_len
        adc #ATTRS_SIZE
        sta pkcs10_tbs_content_len
        bcc :+
        inc pkcs10_tbs_content_len+1
:
        rts

; =============================================================================
; der_calc_len_size - calculate bytes needed to encode a DER length
; Input: A=lo, X=hi of the length value
; Returns: A = number of bytes for length encoding (1, 2, or 3)
; =============================================================================
der_calc_len_size:
        cpx #0
        bne @three                     ; high byte non-zero -> 3 bytes ($82,hi,lo)
        cmp #128
        bcs @two                       ; >= 128 -> 2 bytes ($81,lo)
        lda #1                         ; < 128 -> 1 byte
        rts
@two:
        lda #2
        rts
@three:
        lda #3
        rts

; =============================================================================
; pkcs10_write_tbs - write TBS SEQUENCE into der_buf
; Records TBS start/end offsets for hashing
; =============================================================================
pkcs10_write_tbs:
        jsr der_init                   ; reset buffer position

        ; Record TBS start position
        jsr der_get_pos
        sta pkcs10_tbs_start
        stx pkcs10_tbs_start+1

        ; Write TBS SEQUENCE tag + length
        lda #$30
        jsr der_write_byte
        lda pkcs10_tbs_content_len
        ldx pkcs10_tbs_content_len+1
        jsr der_write_length

        ; --- Version: INTEGER 0 ---
        lda #$02                       ; INTEGER tag
        jsr der_write_byte
        lda #$01                       ; length 1
        ldx #0
        jsr der_write_length
        lda #$00                       ; value 0
        jsr der_write_byte

        ; --- Subject DN: SEQUENCE { SET{SEQ{OID,String}} ... } ---
        lda #$30                       ; SEQUENCE tag
        jsr der_write_byte
        lda pkcs10_dn_content_len
        ldx pkcs10_dn_content_len+1
        jsr der_write_length

        ; Write each non-empty field
        lda #0
        sta pkcs10_field_idx

@dn_field_loop:
        ldx pkcs10_field_idx
        cpx #7
        bne @dn_not_done
        jmp @dn_done
@dn_not_done:

        ; Get field length
        lda pkcs10_flen_lo,x
        sta der_src_ptr
        lda pkcs10_flen_hi,x
        sta der_src_ptr+1
        ldy #0
        lda (der_src_ptr),y
        beq @dn_next_field
        sta pkcs10_tmp_flen            ; save field length

        ; Calculate inner sizes
        ldx pkcs10_field_idx
        lda pkcs10_oid_len,x
        sta pkcs10_tmp_oidlen          ; save OID length

        ; OID TLV = 2 + oid_len
        clc
        adc #2
        sta pkcs10_tmp_oid_tlv

        ; String TLV = 2 + field_len
        lda pkcs10_tmp_flen
        clc
        adc #2
        sta pkcs10_tmp_str_tlv

        ; SEQ content = OID_TLV + String_TLV
        lda pkcs10_tmp_oid_tlv
        clc
        adc pkcs10_tmp_str_tlv
        sta pkcs10_tmp_seq_content

        ; SET content = SEQ TLV = 2 + SEQ content
        lda pkcs10_tmp_seq_content
        clc
        adc #2
        sta pkcs10_tmp_set_content

        ; Write SET tag + length
        lda #$31                       ; SET tag
        jsr der_write_byte
        lda pkcs10_tmp_set_content
        ldx #0
        jsr der_write_length

        ; Write SEQUENCE tag + length
        lda #$30                       ; SEQUENCE tag
        jsr der_write_byte
        lda pkcs10_tmp_seq_content
        ldx #0
        jsr der_write_length

        ; Write OID
        ldx pkcs10_field_idx
        lda pkcs10_oid_lo,x
        sta der_src_ptr
        lda pkcs10_oid_hi,x
        sta der_src_ptr+1
        ldx pkcs10_tmp_oidlen
        jsr der_write_oid

        ; Write String (tag from table, field data)
        ldx pkcs10_field_idx
        lda pkcs10_fld_lo,x
        sta der_src_ptr
        lda pkcs10_fld_hi,x
        sta der_src_ptr+1
        lda pkcs10_str_tag,x           ; string tag ($13 or $16)
        ldx pkcs10_tmp_flen
        jsr der_write_raw_string

@dn_next_field:
        inc pkcs10_field_idx
        jmp @dn_field_loop

@dn_done:

        ; --- SubjectPublicKeyInfo ---
        ; Outer SEQUENCE: 30 59 (89 bytes content)
        lda #$30
        jsr der_write_byte
        lda #89
        ldx #0
        jsr der_write_length

        ; Inner AlgId SEQUENCE: 30 13 (19 bytes content)
        lda #$30
        jsr der_write_byte
        lda #19
        ldx #0
        jsr der_write_length

        ; OID ecPublicKey: 06 07 ...
        lda #<oid_ec_pubkey
        sta der_src_ptr
        lda #>oid_ec_pubkey
        sta der_src_ptr+1
        ldx #7
        jsr der_write_oid

        ; OID prime256v1: 06 08 ...
        lda #<oid_prime256v1
        sta der_src_ptr
        lda #>oid_prime256v1
        sta der_src_ptr+1
        ldx #8
        jsr der_write_oid

        ; BIT STRING: 03 42 00 04 [32-byte x] [32-byte y]
        lda #$03                       ; BIT STRING tag
        jsr der_write_byte
        lda #66                        ; length: 1(unused bits) + 1(04) + 32 + 32 = 66
        ldx #0
        jsr der_write_length
        lda #$00                       ; unused bits = 0
        jsr der_write_byte
        lda #$04                       ; uncompressed point indicator
        jsr der_write_byte

        ; Write public key X coordinate (32 bytes)
        lda #<pkcs10_pubkey_x
        sta der_src_ptr
        lda #>pkcs10_pubkey_x
        sta der_src_ptr+1
        ldx #32
        jsr der_write_bytes

        ; Write public key Y coordinate (32 bytes)
        lda #<pkcs10_pubkey_y
        sta der_src_ptr
        lda #>pkcs10_pubkey_y
        sta der_src_ptr+1
        ldx #32
        jsr der_write_bytes

        ; --- Attributes [0] IMPLICIT (empty) ---
        lda #$a0                       ; context tag 0, constructed
        jsr der_write_byte
        lda #$00                       ; length 0
        jsr der_write_byte

        ; Record TBS end position
        jsr der_get_pos
        sta pkcs10_tbs_end
        stx pkcs10_tbs_end+1

        rts

; =============================================================================
; pkcs10_encode_sig - encode ECDSA signature as DER
; Input: ecdsa_sig_r, ecdsa_sig_s (32 bytes each)
; Output: pkcs10_sig_buf with DER-encoded SEQUENCE { INTEGER r, INTEGER s }
;         pkcs10_sig_der_len = actual length
; =============================================================================
pkcs10_encode_sig:
        ; Save current der_pos and redirect to sig buffer
        ; We'll build the signature DER in the sig buffer using the same
        ; encoder by temporarily saving/restoring der_pos
        lda der_pos
        pha
        lda der_pos+1
        pha

        ; Measure r and s INTEGER TLV sizes
        lda #<ecdsa_sig_r
        sta der_int_ptr
        lda #>ecdsa_sig_r
        sta der_int_ptr+1
        jsr der_measure_integer_32
        sta pkcs10_r_tlv_len

        lda #<ecdsa_sig_s
        sta der_int_ptr
        lda #>ecdsa_sig_s
        sta der_int_ptr+1
        jsr der_measure_integer_32
        sta pkcs10_s_tlv_len

        ; SEQUENCE content length = r_tlv + s_tlv
        lda pkcs10_r_tlv_len
        clc
        adc pkcs10_s_tlv_len
        sta pkcs10_sig_seq_len

        ; Now encode into pkcs10_sig_buf manually
        ; We use der_init + write directly into sig_buf by copying afterward
        jsr der_init

        ; SEQUENCE tag + length
        lda #$30
        jsr der_write_byte
        lda pkcs10_sig_seq_len
        ldx #0
        jsr der_write_length

        ; INTEGER r
        lda #<ecdsa_sig_r
        sta der_int_ptr
        lda #>ecdsa_sig_r
        sta der_int_ptr+1
        jsr der_write_integer_32

        ; INTEGER s
        lda #<ecdsa_sig_s
        sta der_int_ptr
        lda #>ecdsa_sig_s
        sta der_int_ptr+1
        jsr der_write_integer_32

        ; Copy from der_buf to pkcs10_sig_buf, save length
        jsr der_get_pos
        sta pkcs10_sig_der_len

        ldx #0
@copy_sig:
        cpx pkcs10_sig_der_len
        beq @sig_copy_done
        lda der_buf,x
        sta pkcs10_sig_buf,x
        inx
        jmp @copy_sig
@sig_copy_done:

        ; Restore der_pos
        pla
        sta der_pos+1
        pla
        sta der_pos

        rts

pkcs10_r_tlv_len:   .byte 0
pkcs10_s_tlv_len:   .byte 0
pkcs10_sig_seq_len: .byte 0

; =============================================================================
; pkcs10_write_outer - write complete CSR DER
; Assumes TBS has already been written via pkcs10_write_tbs and the TBS
; data saved in pkcs10_tbs_copy. Signature DER in pkcs10_sig_buf.
; =============================================================================
pkcs10_write_outer:
        ; Calculate outer SEQUENCE content length:
        ; = TBS_TLV + SIG_ALG_TLV + BIT_STRING_TLV
        ;
        ; TBS_TLV size = tbs_end - tbs_start
        sec
        lda pkcs10_tbs_end
        sbc pkcs10_tbs_start
        sta pkcs10_tbs_tlv_len
        lda pkcs10_tbs_end+1
        sbc pkcs10_tbs_start+1
        sta pkcs10_tbs_tlv_len+1

        ; SIG_ALG_TLV = 12 bytes (constant)
        ; BIT_STRING_TLV = 1(tag) + length_encoding + 1(unused bits) + sig_der_len
        ;   sig_der_len < 128, so BIT_STRING content = 1 + sig_der_len
        ;   BIT_STRING TLV = 1 + 1 + 1 + sig_der_len = 3 + sig_der_len
        lda pkcs10_sig_der_len
        clc
        adc #3
        sta pkcs10_bitsig_tlv_len

        ; Outer content = TBS_TLV + 12 + bitsig_tlv
        clc
        lda pkcs10_tbs_tlv_len
        adc #SIG_ALG_SIZE
        sta pkcs10_outer_content_len
        lda pkcs10_tbs_tlv_len+1
        adc #0
        sta pkcs10_outer_content_len+1

        clc
        lda pkcs10_outer_content_len
        adc pkcs10_bitsig_tlv_len
        sta pkcs10_outer_content_len
        bcc :+
        inc pkcs10_outer_content_len+1
:

        ; Now write the complete CSR into der_buf
        jsr der_init

        ; Outer SEQUENCE tag + length
        lda #$30
        jsr der_write_byte
        lda pkcs10_outer_content_len
        ldx pkcs10_outer_content_len+1
        jsr der_write_length

        ; Write TBS data from pkcs10_tbs_copy
        ; Length = pkcs10_tbs_tlv_len
        lda #<pkcs10_tbs_copy
        sta der_src_ptr
        lda #>pkcs10_tbs_copy
        sta der_src_ptr+1
        ; Need to write pkcs10_tbs_tlv_len bytes (16-bit count)
        ; Use a loop since der_write_bytes only handles 8-bit count
        lda #0
        sta pkcs10_copy_idx
        sta pkcs10_copy_idx+1

@tbs_copy_loop:
        lda pkcs10_copy_idx+1
        cmp pkcs10_tbs_tlv_len+1
        bcc @tbs_do_copy
        bne @tbs_copy_done
        lda pkcs10_copy_idx
        cmp pkcs10_tbs_tlv_len
        bcs @tbs_copy_done
@tbs_do_copy:
        ; Read byte from pkcs10_tbs_copy + pkcs10_copy_idx
        clc
        lda pkcs10_copy_idx
        adc #<pkcs10_tbs_copy
        sta @cp_rd+1
        lda pkcs10_copy_idx+1
        adc #>pkcs10_tbs_copy
        sta @cp_rd+2
@cp_rd: lda pkcs10_tbs_copy            ; address patched
        jsr der_write_byte
        inc pkcs10_copy_idx
        bne :+
        inc pkcs10_copy_idx+1
:       jmp @tbs_copy_loop
@tbs_copy_done:

        ; Write signature algorithm: 30 0A 06 08 [ecdsa-sha256 OID]
        lda #$30
        jsr der_write_byte
        lda #$0a
        ldx #0
        jsr der_write_length
        lda #<oid_ecdsa_sha256
        sta der_src_ptr
        lda #>oid_ecdsa_sha256
        sta der_src_ptr+1
        ldx #8
        jsr der_write_oid

        ; Write signature BIT STRING
        lda #$03                       ; BIT STRING tag
        jsr der_write_byte
        ; Length = 1 (unused bits) + sig_der_len
        lda pkcs10_sig_der_len
        clc
        adc #1
        ldx #0
        jsr der_write_length
        lda #$00                       ; unused bits = 0
        jsr der_write_byte

        ; Write signature DER from pkcs10_sig_buf
        lda #<pkcs10_sig_buf
        sta der_src_ptr
        lda #>pkcs10_sig_buf
        sta der_src_ptr+1
        ldx pkcs10_sig_der_len
        jsr der_write_bytes

        ; Save total DER length
        jsr der_get_pos
        sta pkcs10_der_len
        stx pkcs10_der_len+1

        rts

; =============================================================================
; Working variables
; =============================================================================
pkcs10_field_idx:       .byte 0
pkcs10_tmp_flen:        .byte 0        ; current field length
pkcs10_tmp_oidlen:      .byte 0        ; current OID length
pkcs10_tmp_oid_tlv:     .byte 0        ; OID TLV size
pkcs10_tmp_str_tlv:     .byte 0        ; String TLV size
pkcs10_tmp_seq_content: .byte 0        ; inner SEQUENCE content length
pkcs10_tmp_set_content: .byte 0        ; SET content length

pkcs10_dn_content_len:  .word 0        ; subject DN content length
pkcs10_dn_tlv_len:      .word 0        ; subject DN TLV length
pkcs10_tbs_content_len: .word 0        ; TBS content length
pkcs10_tbs_start:       .word 0        ; TBS start offset in der_buf
pkcs10_tbs_end:         .word 0        ; TBS end offset in der_buf
pkcs10_tbs_tlv_len:     .word 0        ; TBS TLV length (end - start)
pkcs10_bitsig_tlv_len:  .byte 0        ; BIT STRING TLV length for signature
pkcs10_outer_content_len: .word 0      ; outer SEQUENCE content length
pkcs10_copy_idx:        .word 0        ; copy loop index
pkcs10_der_len:         .word 0        ; total DER output length

; Signature DER buffer (max 72 bytes for P-256 ECDSA)
pkcs10_sig_buf:         .res 72, 0
pkcs10_sig_der_len:     .byte 0

; TBS copy buffer (up to 400 bytes - holds TBS data while we rebuild outer)
pkcs10_tbs_copy:        .res 400, 0
