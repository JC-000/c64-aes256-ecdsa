; =============================================================================
; gcm_siv.asm - AES-256-GCM-SIV encrypt/decrypt, key derivation, CTR mode, file I/O
; Related: aes_encrypt.asm (aes_encrypt_block, aes_key_expansion), polyval.asm
; =============================================================================

        .segment "LIB_AES256ECDSA_CODE"

.importzp zp_ptr, zp_count
.importzp petscii_return
.import chrout, getin, setlfs, setnam
.import open, close, chkin, chkout, clrchn, readst
.import gcmsiv_nonce, gcmsiv_pt_buf, gcmsiv_pt_len, gcmsiv_ct_buf
.import gcmsiv_dec_buf, gcmsiv_tag, gcmsiv_tag_acc, gcmsiv_auth_key, gcmsiv_enc_key, gcmsiv_counter
.import gcmsiv_keystream, gcmsiv_block_idx, gcmsiv_ct_idx, gcmsiv_ks_idx, gcmsiv_tag_valid, gcmsiv_verify_tag
.import gcmsiv_saved_key, gcmsiv_exp_enc_key, gcmsiv_saved_exp
.import polyval_acc, polyval_h, polyval_temp
.import key_data, aes_state, expanded_key
.import drive_number, filename_buf, actual_filename, filename_len
.import using_default_name, file_exists_flag, write_fname_buf, write_fname_len, read_fname_buf
.import read_fname_len, input_index, save_byte_index, read_byte_index, read_temp_byte
.import default_gcm_filename, gcm_filename_suffix
.import bytes_msg, drive_prompt_msg, enter_new_name_msg, file_exists_msg, file_not_found_msg
.import gcm_filename_prompt_msg, gcm_load_success_msg, load_gcm_filename_prompt
.import gcmsiv_ciphertext_msg, gcmsiv_decrypt_done_msg, gcmsiv_decrypting_msg, gcmsiv_done_msg
.import gcmsiv_encrypting_msg, gcmsiv_no_data_msg, gcmsiv_nonce_msg, gcmsiv_prompt_msg
.import gcmsiv_pt_hex_msg, gcmsiv_pt_text_msg, gcmsiv_tag_fail_msg, gcmsiv_tag_msg, gcmsiv_tag_ok_msg
.import incremented_msg, instructions_msg, load_error_msg
.import loading_default_gcm_msg, loading_gcm_msg, names_exhausted_msg, no_input_msg
.import save_error_msg, save_success_msg, saving_gcm_msg, using_drive_msg
.import aes_encrypt_block, aes_key_expansion
.import polyval_init, polyval_precompute_table, polyval_update
.import drbg_random_byte
.import display_hex_block, print_string
.import get_input_line, copy_input_to_filename, print_filename
.import check_file_exists, write_hex_digit, read_hex_char
.import build_write_filename, build_read_filename, print_decimal

; --- Exported for the Python test harness (see tools/run_all_tests.py
; ALL_REQUIRED_LABELS) ---
.export gcmsiv_encrypt, gcmsiv_decrypt
; --- Rest of exports.inc's full gcm_siv.s EXPORTS list ---
.export do_gcm_siv_encrypt, do_gcm_siv_decrypt, do_save_gcm_siv, do_load_gcm_siv
.export generate_gcmsiv_nonce, gcmsiv_derive_keys
.export gcmsiv_compute_tag_base, gcmsiv_finalize_tag, gcmsiv_ctr_encrypt

; =============================================================================
; do_gcm_siv_encrypt - encrypt text using AES-256-GCM-SIV mode
; GCM-SIV is a nonce-misuse resistant AEAD mode
; Structure: nonce(12) || ciphertext || tag(16)
; =============================================================================
do_gcm_siv_encrypt:
        lda #$0d
        jsr chrout
        
        ; print prompt
        lda #<gcmsiv_prompt_msg
        ldy #>gcmsiv_prompt_msg
        jsr print_string
        
        ; get input text
        jsr get_gcmsiv_input
        
        ; check if we got any input
        lda gcmsiv_pt_len
        bne @has_input
        
        lda #<no_input_msg
        ldy #>no_input_msg
        jsr print_string
        jmp @done
        
@has_input:
        ; show plaintext length
        lda #<gcmsiv_encrypting_msg
        ldy #>gcmsiv_encrypting_msg
        jsr print_string
        lda gcmsiv_pt_len
        jsr print_decimal
        lda #<bytes_msg
        ldy #>bytes_msg
        jsr print_string
        
        ; generate random 12-byte nonce
        jsr generate_gcmsiv_nonce
        
        ; show nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; perform GCM-SIV encryption
        jsr gcmsiv_encrypt
        
        ; show ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; show authentication tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        lda #<gcmsiv_done_msg
        ldy #>gcmsiv_done_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; get_gcmsiv_input - get plaintext input for GCM-SIV encryption
; =============================================================================
get_gcmsiv_input:
        ; clear buffer
        ldx #0
        lda #0
@clear:
        sta gcmsiv_pt_buf,x
        inx
        cpx #64
        bne @clear
        
        lda #0
        sta gcmsiv_pt_len
        
@input_loop:
        jsr getin
        beq @input_loop
        
        cmp #petscii_return
        beq @input_done
        
        cmp #$14                ; delete
        beq @do_delete
        
        ; check buffer not full
        ldx gcmsiv_pt_len
        cpx #63
        bcs @input_loop
        
        ; store character
        sta gcmsiv_pt_buf,x
        inc gcmsiv_pt_len
        
        ; echo (preserving nothing - we use gcmsiv_pt_len now)
        jsr chrout
        jmp @input_loop
        
@do_delete:
        ldx gcmsiv_pt_len
        beq @input_loop
        dex
        stx gcmsiv_pt_len
        lda #0
        sta gcmsiv_pt_buf,x
        lda #$14
        jsr chrout
        jmp @input_loop
        
@input_done:
        lda #$0d
        jsr chrout
        rts

; =============================================================================
; generate_gcmsiv_nonce - generate 12-byte random nonce
; =============================================================================
generate_gcmsiv_nonce:
        ldx #0
@loop:
        jsr drbg_random_byte
        sta gcmsiv_nonce,x
        inx
        cpx #12
        bne @loop
        rts

; =============================================================================
; gcmsiv_encrypt - perform AES-256-GCM-SIV encryption
; Uses key_data as the 256-bit key
; Input: gcmsiv_pt_buf (plaintext), gcmsiv_pt_len (length), gcmsiv_nonce (12 bytes)
; Output: gcmsiv_ct_buf (ciphertext), gcmsiv_tag (16 bytes)
; =============================================================================
gcmsiv_encrypt:
        ; GCM-SIV steps:
        ; 1. Derive authentication key and encryption key from main key + nonce
        ; 2. Compute POLYVAL over AAD and plaintext
        ; 3. Derive tag from POLYVAL result
        ; 4. Encrypt plaintext using AES-CTR with tag as IV
        
        ; Step 1: Derive keys using AES
        ; For simplicity, we'll use the existing key directly
        ; and derive subkeys by encrypting nonce-based values
        
        jsr gcmsiv_derive_keys
        
        ; Step 2: Compute POLYVAL over plaintext (no AAD)
        jsr gcmsiv_compute_tag_base
        
        ; Step 3: Encrypt the tag base to get final tag
        jsr gcmsiv_finalize_tag
        
        ; Step 4: Encrypt plaintext with AES-CTR using tag as IV
        jsr gcmsiv_ctr_encrypt
        
        rts

; =============================================================================
; gcmsiv_derive_keys - derive authentication and encryption keys per RFC 8452
; For AES-256-GCM-SIV: 6 AES encryptions of (counter || nonce)
; Take first 8 bytes of each output:
;   counter=0 -> auth_key[0..7]
;   counter=1 -> auth_key[8..15]
;   counter=2 -> enc_key[0..7]
;   counter=3 -> enc_key[8..15]
;   counter=4 -> enc_key[16..23]
;   counter=5 -> enc_key[24..31]
; =============================================================================
gcmsiv_derive_keys:
        lda #0
        sta gcmsiv_derive_ctr   ; start at counter 0
        
@derive_loop:
        ; Build block: little-endian counter(4) || nonce(12)
        lda gcmsiv_derive_ctr
        sta aes_state
        lda #0
        sta aes_state+1
        sta aes_state+2
        sta aes_state+3
        
        ldx #0
@copy_nonce:
        lda gcmsiv_nonce,x
        sta aes_state+4,x
        inx
        cpx #12
        bne @copy_nonce
        
        ; Encrypt with the main key
        jsr aes_encrypt_block
        
        ; Copy first 8 bytes to appropriate destination
        lda gcmsiv_derive_ctr
        cmp #0
        beq @store_auth_lo
        cmp #1
        beq @store_auth_hi
        cmp #2
        beq @store_enc_0
        cmp #3
        beq @store_enc_1
        cmp #4
        beq @store_enc_2
        cmp #5
        beq @store_enc_3
        jmp @derive_next
        
@store_auth_lo:
        ldx #0
@sal:   lda aes_state,x
        sta gcmsiv_auth_key,x
        inx
        cpx #8
        bne @sal
        jmp @derive_next
        
@store_auth_hi:
        ldx #0
@sah:   lda aes_state,x
        sta gcmsiv_auth_key+8,x
        inx
        cpx #8
        bne @sah
        jmp @derive_next
        
@store_enc_0:
        ldx #0
@se0:   lda aes_state,x
        sta gcmsiv_enc_key,x
        inx
        cpx #8
        bne @se0
        jmp @derive_next
        
@store_enc_1:
        ldx #0
@se1:   lda aes_state,x
        sta gcmsiv_enc_key+8,x
        inx
        cpx #8
        bne @se1
        jmp @derive_next
        
@store_enc_2:
        ldx #0
@se2:   lda aes_state,x
        sta gcmsiv_enc_key+16,x
        inx
        cpx #8
        bne @se2
        jmp @derive_next
        
@store_enc_3:
        ldx #0
@se3:   lda aes_state,x
        sta gcmsiv_enc_key+24,x
        inx
        cpx #8
        bne @se3
        
@derive_next:
        inc gcmsiv_derive_ctr
        lda gcmsiv_derive_ctr
        cmp #6
        bcs @derive_done_loop
        jmp @derive_loop
@derive_done_loop:
        
        ; Now expand the derived encryption key for use in CTR and tag encryption
        ; Save original key, install derived key, expand, restore
        ; Copy current key_data to gcmsiv_saved_key
        ldx #0
@save_key:
        lda key_data,x
        sta gcmsiv_saved_key,x
        lda gcmsiv_enc_key,x
        sta key_data,x
        inx
        cpx #32
        bne @save_key
        
        ; Expand the derived encryption key
        jsr aes_key_expansion
        
        ; Copy expanded key to gcmsiv_expanded_enc_key
        ldx #0
@copy_exp:
        lda expanded_key,x
        sta gcmsiv_exp_enc_key,x
        inx
        bne @copy_exp            ; copies 256 bytes (covers 240 needed)
        
        ; Restore original key and re-expand
        ldx #0
@restore_key:
        lda gcmsiv_saved_key,x
        sta key_data,x
        inx
        cpx #32
        bne @restore_key
        
        jsr aes_key_expansion   ; restore original expanded key
        
        rts

gcmsiv_derive_ctr:
        .byte 0

; =============================================================================
; gcmsiv_compute_tag_base - compute authentication tag base using POLYVAL
; Processes plaintext blocks then a length block (AAD_len || PT_len in bits)
; =============================================================================
gcmsiv_compute_tag_base:
        ; Initialize POLYVAL with the derived auth key
        ; Copy auth key to polyval_h
        ldx #0
@copy_h:
        lda gcmsiv_auth_key,x
        sta polyval_h,x
        inx
        cpx #16
        bne @copy_h

        ; Precompute H table for fast multiplication
        jsr polyval_precompute_table

        ; Initialize accumulator to zero
        jsr polyval_init

        ; Process plaintext in 16-byte blocks
        lda #0
        sta gcmsiv_block_idx

@process_loop:
        ; Calculate remaining bytes
        lda gcmsiv_pt_len
        sec
        sbc gcmsiv_block_idx
        beq @process_done       ; no more data
        bmi @process_done

        ; Copy up to 16 bytes to polyval_temp, padded with zeros
        ldx #0
        ldy gcmsiv_block_idx

@copy_block:
        cpy gcmsiv_pt_len
        bcs @pad_block          ; past end of data

        lda gcmsiv_pt_buf,y
        sta polyval_temp,x
        iny
        inx
        cpx #16
        bne @copy_block
        jmp @update_block

@pad_block:
        lda #0
        sta polyval_temp,x
        inx
        cpx #16
        bne @pad_block

@update_block:
        ; XOR block into accumulator and multiply by H
        jsr polyval_update

        ; Move to next block
        lda gcmsiv_block_idx
        clc
        adc #16
        sta gcmsiv_block_idx

        ; Check if we've processed all data
        cmp gcmsiv_pt_len
        bcc @process_loop

@process_done:
        ; Process length block: 64-bit AAD bit length || 64-bit PT bit length
        ; AAD = 0, so first 8 bytes are zero
        ldx #0
        lda #0
@clear_len_block:
        sta polyval_temp,x
        inx
        cpx #16
        bne @clear_len_block

        ; Store PT bit length at bytes 8-15 (little-endian)
        ; pt_len * 8
        lda gcmsiv_pt_len
        asl                     ; *2
        asl                     ; *4
        asl                     ; *8
        sta polyval_temp+8
        lda gcmsiv_pt_len
        lsr
        lsr
        lsr
        lsr
        lsr                     ; high bits of *8
        sta polyval_temp+9
        ; bytes 10-15 stay zero

        ; Final POLYVAL update with length block
        jsr polyval_update

        ; Copy POLYVAL result to tag accumulator
        ldx #0
@copy_result:
        lda polyval_acc,x
        sta gcmsiv_tag_acc,x
        inx
        cpx #16
        bne @copy_result

        rts

; =============================================================================
; gcmsiv_finalize_tag - encrypt tag base with derived enc key to produce final tag
; =============================================================================
gcmsiv_finalize_tag:
        ; Copy tag accumulator to state
        ldx #0
@copy:
        lda gcmsiv_tag_acc,x
        sta aes_state,x
        inx
        cpx #16
        bne @copy
        
        ; XOR in the nonce (first 12 bytes)
        ldx #0
@xor_nonce:
        lda aes_state,x
        eor gcmsiv_nonce,x
        sta aes_state,x
        inx
        cpx #12
        bne @xor_nonce
        
        ; Clear MSB of last byte (as per GCM-SIV spec)
        lda aes_state+15
        and #$7f
        sta aes_state+15
        
        ; Install derived encryption key for this encryption
        jsr gcmsiv_install_enc_key
        
        ; Encrypt to get final tag
        jsr aes_encrypt_block
        
        ; Restore original key
        jsr gcmsiv_restore_orig_key
        
        ; Store tag
        ldx #0
@store:
        lda aes_state,x
        sta gcmsiv_tag,x
        inx
        cpx #16
        bne @store
        
        rts

; =============================================================================
; gcmsiv_install_enc_key - install derived enc key into expanded_key
; =============================================================================
gcmsiv_install_enc_key:
        ; Save original expanded key
        ldx #0
@save:
        lda expanded_key,x
        sta gcmsiv_saved_exp,x
        inx
        bne @save
        
        ; Install derived enc key expanded form
        ldx #0
@install:
        lda gcmsiv_exp_enc_key,x
        sta expanded_key,x
        inx
        bne @install
        rts

; =============================================================================
; gcmsiv_restore_orig_key - restore original expanded key
; =============================================================================
gcmsiv_restore_orig_key:
        ldx #0
@restore:
        lda gcmsiv_saved_exp,x
        sta expanded_key,x
        inx
        bne @restore
        rts

; =============================================================================
; gcmsiv_ctr_encrypt - encrypt plaintext using AES-CTR with tag as IV
; Uses derived encryption key
; =============================================================================
gcmsiv_ctr_encrypt:
        ; Install derived encryption key
        jsr gcmsiv_install_enc_key
        
        ; Copy tag to counter block
        ldx #0
@copy_tag:
        lda gcmsiv_tag,x
        sta gcmsiv_counter,x
        inx
        cpx #16
        bne @copy_tag
        
        ; Set MSB of last byte (counter mode indicator)
        lda gcmsiv_counter+15
        ora #$80
        sta gcmsiv_counter+15
        
        ; Process plaintext
        lda #0
        sta gcmsiv_ct_idx       ; ciphertext output index
        sta gcmsiv_ks_idx       ; keystream index (start at 16 to force generation)
        lda #16
        sta gcmsiv_ks_idx
        
@encrypt_loop:
        ; Check if done
        lda gcmsiv_ct_idx
        cmp gcmsiv_pt_len
        bcs @encrypt_done
        
        ; Check if we need new keystream block
        lda gcmsiv_ks_idx
        cmp #16
        bcc @have_keystream
        
        ; Generate new keystream block
        jsr gcmsiv_gen_keystream
        lda #0
        sta gcmsiv_ks_idx
        
@have_keystream:
        ; XOR plaintext with keystream
        ldx gcmsiv_ct_idx
        ldy gcmsiv_ks_idx
        lda gcmsiv_pt_buf,x
        eor gcmsiv_keystream,y
        sta gcmsiv_ct_buf,x
        
        ; Advance indices
        inc gcmsiv_ct_idx
        inc gcmsiv_ks_idx
        
        jmp @encrypt_loop
        
@encrypt_done:
        ; Restore original key
        jsr gcmsiv_restore_orig_key
        rts

; =============================================================================
; gcmsiv_gen_keystream - generate 16-byte keystream block
; =============================================================================
gcmsiv_gen_keystream:
        ; Copy counter to state
        ldx #0
@copy:
        lda gcmsiv_counter,x
        sta aes_state,x
        inx
        cpx #16
        bne @copy
        
        ; Encrypt counter
        jsr aes_encrypt_block
        
        ; Store keystream
        ldx #0
@store:
        lda aes_state,x
        sta gcmsiv_keystream,x
        inx
        cpx #16
        bne @store
        
        ; Increment counter (32-bit increment on bytes 0-3, little-endian)
        inc gcmsiv_counter
        bne @no_carry
        inc gcmsiv_counter+1
        bne @no_carry
        inc gcmsiv_counter+2
        bne @no_carry
        inc gcmsiv_counter+3
@no_carry:
        rts

; =============================================================================
; do_gcm_siv_decrypt - decrypt ciphertext using AES-256-GCM-SIV mode
; =============================================================================
do_gcm_siv_decrypt:
        lda #$0d
        jsr chrout
        
        ; check if there's ciphertext from GCM-SIV encryption
        lda gcmsiv_pt_len
        bne @has_data
        
        lda #<gcmsiv_no_data_msg
        ldy #>gcmsiv_no_data_msg
        jsr print_string
        jmp @done
        
@has_data:
        ; show what we're decrypting
        lda #<gcmsiv_decrypting_msg
        ldy #>gcmsiv_decrypting_msg
        jsr print_string
        
        ; show nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; show ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; show stored tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        ; perform GCM-SIV decryption
        jsr gcmsiv_decrypt
        
        ; Check tag verification result
        lda gcmsiv_tag_valid
        bne @tag_ok
        
        ; Tag verification failed
        lda #<gcmsiv_tag_fail_msg
        ldy #>gcmsiv_tag_fail_msg
        jsr print_string
        jmp @done
        
@tag_ok:
        ; Tag verified
        lda #<gcmsiv_tag_ok_msg
        ldy #>gcmsiv_tag_ok_msg
        jsr print_string
        
        ; show decrypted plaintext as hex
        lda #<gcmsiv_pt_hex_msg
        ldy #>gcmsiv_pt_hex_msg
        jsr print_string
        
        lda #<gcmsiv_dec_buf
        sta zp_ptr
        lda #>gcmsiv_dec_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; show decrypted plaintext as text
        lda #<gcmsiv_pt_text_msg
        ldy #>gcmsiv_pt_text_msg
        jsr print_string
        
        ; ensure uppercase mode
        lda #$8e
        jsr chrout
        
        ; print decrypted text
        ldx #0
@print_loop:
        cpx gcmsiv_pt_len
        beq @print_done
        lda gcmsiv_dec_buf,x
        beq @next_char
        
        ; only print printable characters
        cmp #$20
        bcc @next_char
        cmp #$60
        bcc @do_print
        cmp #$c0
        bcc @next_char
        cmp #$e0
        bcs @next_char
        sec
        sbc #$80
        
@do_print:
        jsr chrout
@next_char:
        inx
        cpx #64
        bcc @print_loop
        
@print_done:
        lda #$0d
        jsr chrout
        
        lda #<gcmsiv_decrypt_done_msg
        ldy #>gcmsiv_decrypt_done_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; gcmsiv_decrypt - perform AES-256-GCM-SIV decryption with tag verification
; Uses the same key derivation and CTR decryption (CTR is symmetric)
; Input: gcmsiv_ct_buf, gcmsiv_pt_len, gcmsiv_nonce, gcmsiv_tag
; Output: gcmsiv_dec_buf, gcmsiv_tag_valid (0=fail, 1=pass)
; =============================================================================
gcmsiv_decrypt:
        ; Initialize tag valid flag
        lda #0
        sta gcmsiv_tag_valid
        
        ; Step 1: Derive keys (same as encryption)
        jsr gcmsiv_derive_keys
        
        ; Step 2: Decrypt ciphertext using AES-CTR with stored tag as IV
        jsr gcmsiv_ctr_decrypt
        
        ; Step 3: Recompute tag over decrypted plaintext and verify
        ; Save the received tag
        ldx #0
@save_tag:
        lda gcmsiv_tag,x
        sta gcmsiv_verify_tag,x
        inx
        cpx #16
        bne @save_tag
        
        ; Copy decrypted data to pt_buf for tag computation
        ldx #0
@copy_dec:
        lda gcmsiv_dec_buf,x
        sta gcmsiv_pt_buf,x
        inx
        cpx gcmsiv_pt_len
        bne @copy_dec
        
        ; Recompute tag (this writes to gcmsiv_tag)
        jsr gcmsiv_compute_tag_base
        jsr gcmsiv_finalize_tag
        
        ; Compare recomputed tag with received tag
        ldx #0
@compare:
        lda gcmsiv_tag,x
        cmp gcmsiv_verify_tag,x
        bne @tag_fail
        inx
        cpx #16
        bne @compare
        
        ; Tag matches
        lda #1
        sta gcmsiv_tag_valid
        
        ; Restore the original tag (so display shows what was received)
        ldx #0
@restore_tag:
        lda gcmsiv_verify_tag,x
        sta gcmsiv_tag,x
        inx
        cpx #16
        bne @restore_tag
        
        rts
        
@tag_fail:
        ; Tag mismatch - clear decrypted data for safety
        lda #0
        sta gcmsiv_tag_valid
        ldx #0
@clear_dec:
        sta gcmsiv_dec_buf,x
        inx
        cpx #64
        bne @clear_dec
        
        ; Restore the original tag
        ldx #0
@restore_tag2:
        lda gcmsiv_verify_tag,x
        sta gcmsiv_tag,x
        inx
        cpx #16
        bne @restore_tag2
        
        rts

; =============================================================================
; gcmsiv_ctr_decrypt - decrypt ciphertext using AES-CTR with tag as IV
; Uses derived encryption key
; =============================================================================
gcmsiv_ctr_decrypt:
        ; Install derived encryption key
        jsr gcmsiv_install_enc_key
        
        ; Copy tag to counter block
        ldx #0
@copy_tag:
        lda gcmsiv_tag,x
        sta gcmsiv_counter,x
        inx
        cpx #16
        bne @copy_tag
        
        ; Set MSB of last byte (counter mode indicator)
        lda gcmsiv_counter+15
        ora #$80
        sta gcmsiv_counter+15
        
        ; Process ciphertext (CTR mode is symmetric - same operation for encrypt/decrypt)
        lda #0
        sta gcmsiv_ct_idx       ; index into ciphertext
        lda #16                 ; force keystream generation on first byte
        sta gcmsiv_ks_idx
        
@decrypt_loop:
        ; Check if done
        lda gcmsiv_ct_idx
        cmp gcmsiv_pt_len
        bcs @decrypt_done
        
        ; Check if we need new keystream block
        lda gcmsiv_ks_idx
        cmp #16
        bcc @have_keystream
        
        ; Generate new keystream block
        jsr gcmsiv_gen_keystream
        lda #0
        sta gcmsiv_ks_idx
        
@have_keystream:
        ; XOR ciphertext with keystream to get plaintext
        ldx gcmsiv_ct_idx
        ldy gcmsiv_ks_idx
        lda gcmsiv_ct_buf,x
        eor gcmsiv_keystream,y
        sta gcmsiv_dec_buf,x
        
        ; Advance indices
        inc gcmsiv_ct_idx
        inc gcmsiv_ks_idx
        
        jmp @decrypt_loop
        
@decrypt_done:
        ; Restore original key
        jsr gcmsiv_restore_orig_key
        rts

; =============================================================================
; do_save_gcm_siv - save GCM-SIV encrypted data to disk
; File format: nonce (12 bytes) || tag (16 bytes) || ciphertext length (1 byte) || ciphertext
; =============================================================================
do_save_gcm_siv:
        lda #$0d
        jsr chrout
        
        ; check if there's GCM-SIV data
        lda gcmsiv_pt_len
        bne @has_data
        
        lda #<gcmsiv_no_data_msg
        ldy #>gcmsiv_no_data_msg
        jsr print_string
        jmp @done
        
@has_data:
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<gcm_filename_prompt_msg
        ldy #>gcm_filename_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        jsr set_default_gcm_filename
        lda #1
        sta using_default_name
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        beq @do_save
        
        lda #<file_exists_msg
        ldy #>file_exists_msg
        jsr print_string
        
        lda using_default_name
        beq @prompt_new_name
        
        jsr increment_gcm_filename
        bcs @names_exhausted
        
        lda #<incremented_msg
        ldy #>incremented_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @got_filename

@names_exhausted:
        lda #<names_exhausted_msg
        ldy #>names_exhausted_msg
        jsr print_string
        jmp @done
        
@prompt_new_name:
        lda #<enter_new_name_msg
        ldy #>enter_new_name_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @do_save
        jsr copy_input_to_filename
        jmp @got_filename
        
@do_save:
        ; --- show what we're saving ---
        lda #<saving_gcm_msg
        ldy #>saving_gcm_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        ; show nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; show tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        ; show ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        ; --- save to disk ---
        jsr save_gcmsiv_to_disk
        bcs @save_error
        
        lda #<save_success_msg
        ldy #>save_success_msg
        jsr print_string
        jmp @done
        
@save_error:
        lda #<save_error_msg
        ldy #>save_error_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; do_load_gcm_siv - load GCM-SIV encrypted data from disk
; =============================================================================
do_load_gcm_siv:
        lda #$0d
        jsr chrout
        
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_drive
        
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive
        
@use_default_drive:
        lda #8
        sta drive_number
        
@got_drive:
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- get filename ---
        lda #<load_gcm_filename_prompt
        ldy #>load_gcm_filename_prompt
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @use_default_name
        
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename
        
@use_default_name:
        jsr set_default_gcm_filename
        lda #1
        sta using_default_name
        
        lda #<loading_default_gcm_msg
        ldy #>loading_default_gcm_msg
        jsr print_string
        
@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        bne @do_load
        
        lda #<file_not_found_msg
        ldy #>file_not_found_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @done
        
@do_load:
        lda #<loading_gcm_msg
        ldy #>loading_gcm_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        ; --- load from disk ---
        jsr load_gcmsiv_from_disk
        bcs @load_error
        
        ; show loaded nonce
        lda #<gcmsiv_nonce_msg
        ldy #>gcmsiv_nonce_msg
        jsr print_string
        lda #<gcmsiv_nonce
        sta zp_ptr
        lda #>gcmsiv_nonce
        sta zp_ptr+1
        lda #12
        sta zp_count
        lda #12
        jsr display_hex_block
        
        ; show loaded tag
        lda #<gcmsiv_tag_msg
        ldy #>gcmsiv_tag_msg
        jsr print_string
        lda #<gcmsiv_tag
        sta zp_ptr
        lda #>gcmsiv_tag
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block
        
        ; show loaded ciphertext
        lda #<gcmsiv_ciphertext_msg
        ldy #>gcmsiv_ciphertext_msg
        jsr print_string
        lda #<gcmsiv_ct_buf
        sta zp_ptr
        lda #>gcmsiv_ct_buf
        sta zp_ptr+1
        lda gcmsiv_pt_len
        sta zp_count
        lda #8
        jsr display_hex_block
        
        lda #<gcm_load_success_msg
        ldy #>gcm_load_success_msg
        jsr print_string
        jmp @done
        
@load_error:
        lda #<load_error_msg
        ldy #>load_error_msg
        jsr print_string
        
@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; set_default_gcm_filename - set filename to "AESGCM"
; =============================================================================
set_default_gcm_filename:
        ldx #0
@loop:
        lda default_gcm_filename,x
        sta actual_filename,x
        beq @done
        inx
        cpx #7
        bne @loop
@done:
        lda #0
        sta actual_filename,x
        lda #6
        sta filename_len
        lda #0
        sta gcm_filename_suffix
        rts

; =============================================================================
; increment_gcm_filename - increment the numeric suffix for GCM files
; returns: carry set if exhausted (reached 9)
; =============================================================================
increment_gcm_filename:
        lda gcm_filename_suffix
        cmp #10
        bcs @exhausted
        
        inc gcm_filename_suffix
        lda gcm_filename_suffix
        
        clc
        adc #$2F                ; convert to ASCII digit
        ldx #6
        sta actual_filename,x
        lda #0
        sta actual_filename+7
        lda #7
        sta filename_len
        
        clc
        rts
        
@exhausted:
        sec
        rts

; =============================================================================
; save_gcmsiv_to_disk - save nonce, tag, length, and ciphertext as hex
; =============================================================================
save_gcmsiv_to_disk:
        jsr build_write_filename
        
        lda write_fname_len
        ldx #<write_fname_buf
        ldy #>write_fname_buf
        jsr setnam
        
        lda #3
        ldx drive_number
        ldy #3
        jsr setlfs
        
        jsr open
        bcc @open_ok
        jmp @error
@open_ok:
        
        ldx #3
        jsr chkout
        bcc @chkout_ok
        jmp @close_error
@chkout_ok:
        
        ; write nonce (12 bytes as hex)
        lda #0
        sta save_byte_index
@write_nonce:
        ldx save_byte_index
        cpx #12
        beq @nonce_done
        lda gcmsiv_nonce,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$20
        jsr chrout
        inc save_byte_index
        jmp @write_nonce
@nonce_done:
        lda #$0d
        jsr chrout
        
        ; write tag (16 bytes as hex)
        lda #0
        sta save_byte_index
@write_tag:
        ldx save_byte_index
        cpx #16
        beq @tag_done
        lda gcmsiv_tag,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$20
        jsr chrout
        inc save_byte_index
        jmp @write_tag
@tag_done:
        lda #$0d
        jsr chrout
        
        ; write length (1 byte as hex)
        lda gcmsiv_pt_len
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$0d
        jsr chrout
        
        ; write ciphertext
        lda #0
        sta save_byte_index
@write_ct:
        ldx save_byte_index
        cpx gcmsiv_pt_len
        beq @ct_done
        lda gcmsiv_ct_buf,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit
        pla
        and #$0f
        jsr write_hex_digit
        lda #$20
        jsr chrout
        ; newline every 8 bytes
        lda save_byte_index
        and #$07
        cmp #$07
        bne @no_newline
        lda #$0d
        jsr chrout
@no_newline:
        inc save_byte_index
        jmp @write_ct
@ct_done:
        
        jsr readst
        bne @close_error
        
        jsr clrchn
        lda #3
        jsr close
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #3
        jsr close
@error:
        sec
        rts

; =============================================================================
; load_gcmsiv_from_disk - load nonce, tag, length, and ciphertext
; =============================================================================
load_gcmsiv_from_disk:
        jsr build_read_filename
        
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam
        
        lda #4
        ldx drive_number
        ldy #4
        jsr setlfs
        
        jsr open
        bcc @open_ok
        jmp @error
@open_ok:
        
        ldx #4
        jsr chkin
        bcc @chkin_ok
        jmp @close_error
@chkin_ok:
        
        ; read nonce (12 bytes)
        lda #0
        sta read_byte_index
@read_nonce:
        lda read_byte_index
        cmp #12
        beq @nonce_done
        jsr read_hex_char
        bcc @nonce_ok1
        jmp @close_error
@nonce_ok1:
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcc @nonce_ok2
        jmp @close_error
@nonce_ok2:
        ora read_temp_byte
        ldx read_byte_index
        sta gcmsiv_nonce,x
        inc read_byte_index
        jmp @read_nonce
@nonce_done:
        
        ; read tag (16 bytes)
        lda #0
        sta read_byte_index
@read_tag:
        lda read_byte_index
        cmp #16
        beq @tag_done
        jsr read_hex_char
        bcc @tag_ok1
        jmp @close_error
@tag_ok1:
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcc @tag_ok2
        jmp @close_error
@tag_ok2:
        ora read_temp_byte
        ldx read_byte_index
        sta gcmsiv_tag,x
        inc read_byte_index
        jmp @read_tag
@tag_done:
        
        ; read length (1 byte)
        jsr read_hex_char
        bcc @len_ok1
        jmp @close_error
@len_ok1:
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcc @len_ok2
        jmp @close_error
@len_ok2:
        ora read_temp_byte
        sta gcmsiv_pt_len
        
        ; read ciphertext
        lda #0
        sta read_byte_index
@read_ct:
        lda read_byte_index
        cmp gcmsiv_pt_len
        beq @ct_done
        jsr read_hex_char
        bcs @ct_done            ; EOF is ok here
        asl
        asl
        asl
        asl
        sta read_temp_byte
        jsr read_hex_char
        bcs @ct_done
        ora read_temp_byte
        ldx read_byte_index
        sta gcmsiv_ct_buf,x
        inc read_byte_index
        jmp @read_ct
@ct_done:
        
        jsr clrchn
        lda #4
        jsr close
        clc
        rts
        
@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec
        rts

