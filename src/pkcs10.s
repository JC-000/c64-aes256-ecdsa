; =============================================================================
; pkcs10.asm - Top-level PKCS#10 CSR orchestrator
; =============================================================================
; Main entry point for generating a standards-compliant PKCS#10 CSR.
; Handles key generation, multi-block SHA-256, signing, and PEM output.
; =============================================================================

; --- Exported for the Python test harness (see tools/run_all_tests.py
; ALL_REQUIRED_LABELS) ---
.export pkcs10_privkey, pkcs10_k_buf

; =============================================================================
; do_pkcs10_csr - main entry from CSR submenu option 3
; =============================================================================
do_pkcs10_csr:
        ; Print header
        lda #<pkcs10_header_msg
        ldy #>pkcs10_header_msg
        jsr print_string

        ; Collect X.509 fields (shared with text CSR)
        jsr csr_collect_fields
        bcc @fields_valid
        ; Carry set = no fields entered
        rts

@fields_valid:
        ; --- Generate ECDSA key pair ---
        lda #<pkcs10_keygen_msg
        ldy #>pkcs10_keygen_msg
        jsr print_string

        jsr pkcs10_gen_keypair

        ; Display public key
        lda #$0d
        jsr chrout
        lda #<pkcs10_pubkey_msg
        ldy #>pkcs10_pubkey_msg
        jsr print_string

        lda #<pkcs10_pubkey_x
        sta zp_ptr
        lda #>pkcs10_pubkey_x
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<pkcs10_pubkey_y
        sta zp_ptr
        lda #>pkcs10_pubkey_y
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; --- Build CSR DER ---
        lda #<pkcs10_building_msg
        ldy #>pkcs10_building_msg
        jsr print_string

        jsr pkcs10_calc_dn_len
        jsr pkcs10_calc_tbs_len
        jsr pkcs10_write_tbs

        ; Copy TBS data to tbs_copy buffer before we overwrite der_buf
        ; TBS occupies der_buf[tbs_start..tbs_end)
        sec
        lda pkcs10_tbs_end
        sbc pkcs10_tbs_start
        sta pkcs10_tbs_tlv_len
        lda pkcs10_tbs_end+1
        sbc pkcs10_tbs_start+1
        sta pkcs10_tbs_tlv_len+1

        ; Copy TBS bytes to pkcs10_tbs_copy
        lda #0
        sta pkcs10_copy_idx
        sta pkcs10_copy_idx+1
@copy_tbs:
        lda pkcs10_copy_idx+1
        cmp pkcs10_tbs_tlv_len+1
        bcc @do_copy_tbs
        bne @tbs_copied
        lda pkcs10_copy_idx
        cmp pkcs10_tbs_tlv_len
        bcs @tbs_copied
@do_copy_tbs:
        ; Read from der_buf[tbs_start + copy_idx]
        clc
        lda pkcs10_copy_idx
        adc pkcs10_tbs_start
        sta pkcs10_tmp_addr
        lda pkcs10_copy_idx+1
        adc pkcs10_tbs_start+1
        sta pkcs10_tmp_addr+1
        clc
        lda pkcs10_tmp_addr
        adc #<der_buf
        sta @tbs_rd+1
        lda pkcs10_tmp_addr+1
        adc #>der_buf
        sta @tbs_rd+2
@tbs_rd:
        lda a:der_buf                  ; address patched (forced absolute - operand bytes patched above)
        ; Write to pkcs10_tbs_copy[copy_idx]
        pha
        clc
        lda pkcs10_copy_idx
        adc #<pkcs10_tbs_copy
        sta @tbs_wr+1
        lda pkcs10_copy_idx+1
        adc #>pkcs10_tbs_copy
        sta @tbs_wr+2
        pla
@tbs_wr:
        sta a:pkcs10_tbs_copy          ; address patched (forced absolute - operand bytes patched above)

        inc pkcs10_copy_idx
        bne :+
        inc pkcs10_copy_idx+1
:       jmp @copy_tbs
@tbs_copied:

        ; --- Hash TBS data ---
        lda #<pkcs10_hashing_msg
        ldy #>pkcs10_hashing_msg
        jsr print_string

        jsr pkcs10_hash_tbs

        ; --- Sign the hash ---
        lda #<pkcs10_signing_msg
        ldy #>pkcs10_signing_msg
        jsr print_string

        ; Generate random nonce k
        jsr pkcs10_gen_k

        ; Set up ecdsa_sign parameters
        lda #<sha256_hash
        sta ecdsa_hash_ptr
        lda #>sha256_hash
        sta ecdsa_hash_ptr+1

        lda #<pkcs10_privkey
        sta ecdsa_privkey_ptr
        lda #>pkcs10_privkey
        sta ecdsa_privkey_ptr+1

        lda #<pkcs10_k_buf
        sta ecdsa_k_ptr
        lda #>pkcs10_k_buf
        sta ecdsa_k_ptr+1

        jsr ecdsa_sign

        lda #$0d
        jsr chrout

        ; --- Encode signature and build outer CSR ---
        jsr pkcs10_encode_sig
        jsr pkcs10_write_outer

        ; --- Base64 encode ---
        jsr b64_encode

        ; --- CSR Ready ---
        lda #<pkcs10_ready_msg
        ldy #>pkcs10_ready_msg
        jsr print_string

        ; Print DER size
        lda #<pkcs10_size_msg
        ldy #>pkcs10_size_msg
        jsr print_string
        lda pkcs10_der_len
        jsr print_decimal
        lda #<pkcs10_bytes_msg
        ldy #>pkcs10_bytes_msg
        jsr print_string

        ; --- Preview PEM on screen ---
        lda #$0d
        jsr chrout
        lda #1                         ; screen mode
        jsr b64_output_pem

        ; --- Prompt to save ---
        lda #$0d
        jsr chrout
        lda #<pkcs10_save_prompt
        ldy #>pkcs10_save_prompt
        jsr print_string

        jsr getin_wait
        cmp #'N'
        beq @pkcs10_exit
        cmp #'n'
        beq @pkcs10_exit

        ; --- Save to disk ---
        jsr pkcs10_save_pem

        ; Reseed DRBG with fresh entropy after RFC 6979 deterministic use
        jsr drbg_init_entropy

@pkcs10_exit:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; pkcs10_gen_keypair - generate ECDSA P-256 key pair
; Generates 32 random bytes, reduces mod n, computes Q = d*G
; =============================================================================
pkcs10_gen_keypair:
        ; Initialize quarter-square tables (needed for multiplication)
        jsr fp_init_sqtab

        ; Generate 32 random bytes for private key
        lda #<pkcs10_privkey
        sta zp_ptr
        lda #>pkcs10_privkey
        sta zp_ptr+1
        lda #32
        jsr drbg_fill_bytes

        ; Reduce mod n to get valid private key
        ; Copy privkey to fp_wide (zero-extend to 512 bits)
        ldy #63
        lda #0
@clw:   sta fp_wide,y
        dey
        bpl @clw
        ldy #31
@cpk:   lda pkcs10_privkey,y
        sta fp_wide+32,y
        dey
        bpl @cpk

        jsr ec_set_modn
        jsr fp_mod_reduce              ; fp_r0 = privkey mod n

        ; Ensure private key is not zero (astronomically unlikely, but check)
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        jsr fp_is_zero
        bne @key_nonzero
        ; Zero key: set to 1 (should never happen)
        lda #1
        sta fp_r0+31
@key_nonzero:

        ; Copy reduced key back to pkcs10_privkey
        ldy #31
@cpd:   lda fp_r0,y
        sta pkcs10_privkey,y
        dey
        bpl @cpd

        ; Compute public key Q = d * G
        lda #<pkcs10_privkey
        sta ec_scalar_ptr
        lda #>pkcs10_privkey
        sta ec_scalar_ptr+1
        jsr ec_scalar_mul              ; result in ec_p3 (Jacobian)

        ; Convert to affine
        jsr ec_jacobian_to_affine

        ; Copy affine coordinates to pubkey storage
        ldy #31
@cpx:   lda ec_affine_x,y
        sta pkcs10_pubkey_x,y
        dey
        bpl @cpx
        ldy #31
@cpy:   lda ec_affine_y,y
        sta pkcs10_pubkey_y,y
        dey
        bpl @cpy

        rts

; =============================================================================
; pkcs10_hash_tbs - multi-block SHA-256 of TBS data
; Input: pkcs10_tbs_copy with pkcs10_tbs_tlv_len bytes
; Output: sha256_hash (32 bytes)
; =============================================================================
pkcs10_hash_tbs:
        jsr sha256_init

        ; Calculate bit length (tbs_tlv_len * 8) for padding
        ; Store as 32-bit value in pkcs10_bitlen (big-endian)
        lda #0
        sta pkcs10_bitlen
        sta pkcs10_bitlen+1
        sta pkcs10_bitlen+2
        sta pkcs10_bitlen+3

        lda pkcs10_tbs_tlv_len
        sta pkcs10_bitlen+3
        lda pkcs10_tbs_tlv_len+1
        sta pkcs10_bitlen+2
        ; Multiply by 8 (shift left 3)
        asl pkcs10_bitlen+3
        rol pkcs10_bitlen+2
        rol pkcs10_bitlen+1
        asl pkcs10_bitlen+3
        rol pkcs10_bitlen+2
        rol pkcs10_bitlen+1
        asl pkcs10_bitlen+3
        rol pkcs10_bitlen+2
        rol pkcs10_bitlen+1

        ; Process full 64-byte blocks
        lda #0
        sta pkcs10_hash_pos
        sta pkcs10_hash_pos+1

@block_loop:
        ; Check if we have >= 64 bytes remaining
        sec
        lda pkcs10_tbs_tlv_len
        sbc pkcs10_hash_pos
        sta pkcs10_hash_remain
        lda pkcs10_tbs_tlv_len+1
        sbc pkcs10_hash_pos+1
        sta pkcs10_hash_remain+1

        ; If remain < 64, go to final block processing
        lda pkcs10_hash_remain+1
        bne @full_block                ; > 255 bytes remaining
        lda pkcs10_hash_remain
        cmp #64
        bcc @final_blocks

@full_block:
        ; Copy 64 bytes from pkcs10_tbs_copy[hash_pos] to sha256_block
        ldx #0
@copy_block:
        ; Read from pkcs10_tbs_copy[hash_pos + x]
        stx pkcs10_hash_tmp
        clc
        txa
        adc pkcs10_hash_pos
        sta pkcs10_tmp_addr
        lda #0
        adc pkcs10_hash_pos+1
        sta pkcs10_tmp_addr+1
        clc
        lda pkcs10_tmp_addr
        adc #<pkcs10_tbs_copy
        sta @blk_rd+1
        lda pkcs10_tmp_addr+1
        adc #>pkcs10_tbs_copy
        sta @blk_rd+2
@blk_rd:
        lda a:pkcs10_tbs_copy          ; address patched (forced absolute - operand bytes patched above)
        ldx pkcs10_hash_tmp
        sta sha256_block,x
        inx
        cpx #64
        bne @copy_block

        jsr sha256_process_block

        ; Advance hash_pos by 64
        clc
        lda pkcs10_hash_pos
        adc #64
        sta pkcs10_hash_pos
        bcc :+
        inc pkcs10_hash_pos+1
:       jmp @block_loop

@final_blocks:
        ; pkcs10_hash_remain bytes left (0-63)
        ; Clear sha256_block
        ldx #0
        lda #0
@clear_final:
        sta sha256_block,x
        inx
        cpx #64
        bne @clear_final

        ; Copy remaining bytes
        ldx #0
        lda pkcs10_hash_remain
        beq @add_pad                   ; no remaining bytes
@copy_remain:
        cpx pkcs10_hash_remain
        beq @add_pad
        stx pkcs10_hash_tmp
        clc
        txa
        adc pkcs10_hash_pos
        sta pkcs10_tmp_addr
        lda #0
        adc pkcs10_hash_pos+1
        sta pkcs10_tmp_addr+1
        clc
        lda pkcs10_tmp_addr
        adc #<pkcs10_tbs_copy
        sta @rem_rd+1
        lda pkcs10_tmp_addr+1
        adc #>pkcs10_tbs_copy
        sta @rem_rd+2
@rem_rd:
        lda a:pkcs10_tbs_copy          ; address patched (forced absolute - operand bytes patched above)
        ldx pkcs10_hash_tmp
        sta sha256_block,x
        inx
        jmp @copy_remain

@add_pad:
        ; Add $80 padding byte at position = pkcs10_hash_remain
        ldx pkcs10_hash_remain
        lda #$80
        sta sha256_block,x

        ; Check if there's room for the 8-byte length (need remain+1+8 <= 64)
        ; i.e. remain <= 55
        lda pkcs10_hash_remain
        cmp #56
        bcs @need_extra

        ; Length fits in this block
        ; Write 64-bit bit-length at bytes 56-63 (big-endian)
        ; Upper 32 bits (positions 56-59) are zero (already cleared)
        ; Lower 32 bits (positions 60-63) hold the bit count
        lda pkcs10_bitlen
        sta sha256_block+60
        lda pkcs10_bitlen+1
        sta sha256_block+61
        lda pkcs10_bitlen+2
        sta sha256_block+62
        lda pkcs10_bitlen+3
        sta sha256_block+63

        jsr sha256_process_block
        jmp @hash_done

@need_extra:
        ; Process current block (padding only, no length)
        jsr sha256_process_block

        ; Clear new block
        ldx #0
        lda #0
@clear_extra:
        sta sha256_block,x
        inx
        cpx #64
        bne @clear_extra

        ; Write bit-length (positions 60-63, upper 32 bits at 56-59 are zero)
        lda pkcs10_bitlen
        sta sha256_block+60
        lda pkcs10_bitlen+1
        sta sha256_block+61
        lda pkcs10_bitlen+2
        sta sha256_block+62
        lda pkcs10_bitlen+3
        sta sha256_block+63

        jsr sha256_process_block

@hash_done:
        jsr sha256_final
        rts

; =============================================================================
; pkcs10_gen_k - deterministic nonce k via HMAC-DRBG (RFC 6979)
; Input: pkcs10_privkey (32B), sha256_hash (32B message hash)
; Output: pkcs10_k_buf (32B nonce, reduced mod n)
; =============================================================================
pkcs10_gen_k:
        ; Build seed = privkey || message_hash
        ldy #31
@cp_priv:
        lda pkcs10_privkey,y
        sta drbg_seed,y
        dey
        bpl @cp_priv

        ldy #31
@cp_hash:
        lda sha256_hash,y
        sta drbg_seed+32,y
        dey
        bpl @cp_hash

        lda #64
        sta drbg_seed_len

        ; Instantiate DRBG and generate 32 bytes
        jsr hmac_drbg_instantiate
        jsr hmac_drbg_generate

        ; Restore sha256_hash (overwritten by HMAC-SHA256 calls inside DRBG)
        ldy #31
@restore_hash:
        lda drbg_seed+32,y
        sta sha256_hash,y
        dey
        bpl @restore_hash

        ; Copy output to k_buf
        ldy #31
@cp_out:
        lda drbg_output,y
        sta pkcs10_k_buf,y
        dey
        bpl @cp_out

        ; Reduce mod n
        ldy #63
        lda #0
@clw:   sta fp_wide,y
        dey
        bpl @clw
        ldy #31
@cpk:   lda pkcs10_k_buf,y
        sta fp_wide+32,y
        dey
        bpl @cpk

        jsr ec_set_modn
        jsr fp_mod_reduce

        ; Ensure k is not zero
        lda #<fp_r0
        sta fp_src1
        lda #>fp_r0
        sta fp_src1+1
        jsr fp_is_zero
        bne @k_nonzero
        lda #1
        sta fp_r0+31
@k_nonzero:

        ; Copy back
        ldy #31
@cpd:   lda fp_r0,y
        sta pkcs10_k_buf,y
        dey
        bpl @cpd
        rts

; =============================================================================
; pkcs10_save_pem - save PEM CSR to disk
; =============================================================================
pkcs10_save_pem:
        ; Get drive number
        lda #<csr_drive_prompt
        ldy #>csr_drive_prompt
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @default_drive
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @default_drive
        sta csr_drive_num
        jmp @got_drive

@default_drive:
        lda #8
        sta csr_drive_num

@got_drive:
        lda #<csr_using_drive_msg
        ldy #>csr_using_drive_msg
        jsr print_string
        lda csr_drive_num
        jsr print_decimal
        lda #$0d
        jsr chrout

        ; Get filename
        lda #<pkcs10_fname_prompt
        ldy #>pkcs10_fname_prompt
        jsr print_string

        jsr get_input_line
        lda input_index
        bne @user_fname

        ; Use default "P10CSR"
        ldx #0
@copy_default:
        lda pkcs10_default_fname,x
        beq @default_done
        sta actual_filename,x
        inx
        jmp @copy_default
@default_done:
        stx filename_len
        jmp @got_fname

@user_fname:
        jsr copy_input_to_filename

@got_fname:
        lda #<csr_saving_msg
        ldy #>csr_saving_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout

        ; Open file for writing
        jsr clrchn
        lda #3
        jsr close

        jsr build_write_filename

        lda write_fname_len
        ldx #<write_fname_buf
        ldy #>write_fname_buf
        jsr setnam

        lda #3
        ldx csr_drive_num
        ldy #3
        jsr setlfs

        jsr open
        bcs @save_error

        ldx #3
        jsr chkout
        bcs @save_close_error

        ; Write PEM content (chrout directed to file)
        lda #0                         ; file mode (raw ASCII bytes)
        jsr b64_output_pem

        ; Check status
        jsr readst
        and #$83
        bne @save_close_error

        jsr clrchn
        lda #3
        jsr close

        lda #<csr_save_ok_msg
        ldy #>csr_save_ok_msg
        jsr print_string
        rts

@save_close_error:
        jsr clrchn
        lda #3
        jsr close
@save_error:
        lda #<csr_save_fail_msg
        ldy #>csr_save_fail_msg
        jsr print_string
        rts

; =============================================================================
; Data storage
; =============================================================================
pkcs10_privkey:     .res 32, 0         ; EC private key d
pkcs10_pubkey_x:    .res 32, 0         ; public key Q.x
pkcs10_pubkey_y:    .res 32, 0         ; public key Q.y
pkcs10_k_buf:       .res 32, 0         ; signing nonce k

; Hash working variables
pkcs10_bitlen:      .res 4, 0          ; message length in bits (32-bit big-endian)
pkcs10_hash_pos:    .word 0            ; current position in TBS data
pkcs10_hash_remain: .word 0            ; remaining bytes
pkcs10_hash_tmp:    .byte 0            ; temp for block copy loop
pkcs10_tmp_addr:    .word 0            ; temp address computation

; Default filename
pkcs10_default_fname:
        .byte "P10CSR"
        .byte 0
