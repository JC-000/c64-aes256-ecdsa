; =============================================================================
; data.asm - Shared mutable buffers: IV, key, AES state, I/O buffers, SHA/GCM vars
; =============================================================================

; =============================================================================
; data section
; =============================================================================

; storage for generated values
iv_data:
        !fill 16, 0

key_data:
        !fill 32, 0

; aes working data
aes_state:
        !fill 16, 0

cbc_vector:
        !fill 16, 0

expanded_key:
        !fill 240, 0            ; 15 round keys * 16 bytes

; encryption buffers
input_buffer:
        !fill input_buf_size, 0

encrypt_buffer:
        !fill encrypt_buf_size, 0

decrypt_data:
        !fill input_buf_size, 0

input_length:
        !byte 0

encrypt_length:
        !byte 0

decrypt_length:
        !byte 0

block_count:
        !byte 0

current_block:
        !byte 0

pkcs7_pad_value:
        !byte 0

input_index:
        !byte 0

; disk save variables
drive_number:
        !byte 8

filename_buf:
        !fill 17, 0             ; input buffer for filename

actual_filename:
        !fill 17, 0             ; actual filename to use

filename_len:
        !byte 0

filename_suffix:
        !byte 0

using_default_name:
        !byte 0

file_exists_flag:
        !byte 0

cmd_buffer:
        !fill 24, 0

cmd_len:
        !byte 0

write_fname_buf:
        !fill 32, 0

write_fname_len:
        !byte 0

read_fname_buf:
        !fill 32, 0

read_fname_len:
        !byte 0

key_read_buf:
        !fill 32, 0

decimal_flag:
        !byte 0

save_byte_index:
        !byte 0

read_byte_index:
        !byte 0

read_temp_byte:
        !byte 0

disk_error_code:
        !byte 0, 0              ; two bytes for error code digits

msg_filename_suffix:
        !byte 0

enc_read_buf:
        !fill 64, 0             ; buffer for reading encrypted data back

enc_read_length:
        !byte 0

iv_read_buf:
        !fill 16, 0             ; buffer for reading IV back

; SHA-256 working variables
sha256_h0:      !fill 4, 0
sha256_h1:      !fill 4, 0
sha256_h2:      !fill 4, 0
sha256_h3:      !fill 4, 0
sha256_h4:      !fill 4, 0
sha256_h5:      !fill 4, 0
sha256_h6:      !fill 4, 0
sha256_h7:      !fill 4, 0

sha_a:          !fill 4, 0
sha_b:          !fill 4, 0
sha_c:          !fill 4, 0
sha_d:          !fill 4, 0
sha_e:          !fill 4, 0
sha_f:          !fill 4, 0
sha_g:          !fill 4, 0
sha_h:          !fill 4, 0

sha_temp3:      !fill 4, 0
sha_t1:         !fill 4, 0
sha_t2:         !fill 4, 0

sha256_block:   !fill 64, 0
sha256_w:       !fill 256, 0    ; message schedule (64 words * 4 bytes)
sha256_hash:    !fill 32, 0     ; final hash output
sha256_len:     !fill 2, 0      ; message length in bits
; sha256_round moved to ZP ($12) in constants.asm

; --- HMAC-DRBG state ---
hmac_key        !fill 32, 0     ; HMAC key / DRBG K state
hmac_val        !fill 32, 0     ; DRBG V state
hmac_opad_block !fill 64, 0     ; Scratch: K XOR opad
hmac_data_buf   !fill 97, 0     ; V(32) + 0x00/0x01(1) + seed(64)
hmac_data_len   !byte 0         ; Length of data in hmac_data_buf
hmac_result     !fill 32, 0     ; HMAC output
drbg_seed       !fill 64, 0     ; Seed material (privkey||hash)
drbg_seed_len   !byte 0         ; Length of seed
drbg_output     !fill 32, 0     ; Generate output
drbg_buf_idx    !byte 32        ; Buffer index (32 = empty, forces first generate)

; GCM-SIV variables
gcmsiv_nonce:       !fill 12, 0     ; 96-bit nonce
gcmsiv_pt_buf:      !fill 64, 0     ; plaintext buffer
gcmsiv_pt_len:      !byte 0         ; plaintext length
gcmsiv_ct_buf:      !fill 64, 0     ; ciphertext buffer
gcmsiv_dec_buf:     !fill 64, 0     ; decrypted plaintext buffer
gcmsiv_tag:         !fill 16, 0     ; authentication tag
gcmsiv_tag_acc:     !fill 16, 0     ; tag accumulator
gcmsiv_auth_key:    !fill 16, 0     ; derived auth key
gcmsiv_enc_key:     !fill 32, 0     ; derived encryption key (256-bit for AES-256)
gcmsiv_counter:     !fill 16, 0     ; CTR mode counter
gcmsiv_keystream:   !fill 16, 0     ; keystream block
gcmsiv_block_idx:   !byte 0         ; block processing index
gcmsiv_ct_idx:      !byte 0         ; ciphertext index
gcmsiv_ks_idx:      !byte 0         ; keystream index
gcmsiv_tag_valid:   !byte 0         ; tag verification: 0=fail, 1=pass
gcmsiv_verify_tag:  !fill 16, 0     ; saved received tag for verification
gcmsiv_saved_key:   !fill 32, 0     ; saved original key during derivation
gcmsiv_exp_enc_key: !fill 256, 0    ; expanded derived encryption key
gcmsiv_saved_exp:   !fill 256, 0    ; saved original expanded key

; POLYVAL variables (RFC 8452 GF(2^128) universal hash)
polyval_acc:     !fill 16, 0        ; 128-bit accumulator
polyval_h:       !fill 16, 0        ; 128-bit hash key H
polyval_temp:    !fill 16, 0        ; temp block for update
polyval_htable:  !fill 256, 0       ; precomputed 4-bit nibble table (16 entries * 16 bytes)

default_filename:
        !text "AESKEY"
        !byte 0

default_msg_filename:
        !text "AESMSG"
        !byte 0

default_gcm_filename:
        !text "AESGCM"
        !byte 0

gcm_filename_suffix:
        !byte 0

; benchmark variables
bench_iterations:   !word 0
timer_start_lo:     !byte 0
timer_start_hi:     !byte 0
timer_end_lo:       !byte 0
timer_end_hi:       !byte 0
timer_elapsed:      !word 0

; REU variables
reu_present:        !byte 0     ; 0=no REU, 1=REU detected
reu_size_kb:        !word 0     ; REU size in KB

cbc_temp:
        !fill 16, 0             ; temp storage for cbc decryption

; NIST test save/restore buffers
nist_saved_key: !fill 32, 0
nist_saved_iv:  !fill 16, 0

; mix columns temp storage
mc_a0:  !byte 0
mc_a1:  !byte 0
mc_a2:  !byte 0
mc_a3:  !byte 0
mc_b0:  !byte 0
mc_b1:  !byte 0
mc_b2:  !byte 0
mc_b3:  !byte 0

