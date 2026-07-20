; =============================================================================
; data.asm - Shared mutable buffers: IV, key, AES state, I/O buffers, SHA/GCM vars
; =============================================================================

.segment "LIB_AES256ECDSA_CODE"

; --- Exports (per src/exports.inc's full data.s EXPORTS list; supersedes
; the smaller harness-only subset this file carried before Phase 5) ---
.export iv_data, key_data, aes_state, cbc_vector, expanded_key
.export input_buffer, encrypt_buffer, decrypt_data
.export input_length, encrypt_length, decrypt_length
.export block_count, current_block, pkcs7_pad_value, input_index
.export drive_number, filename_buf, actual_filename, filename_len
.export filename_suffix, using_default_name, file_exists_flag, cmd_buffer
.export write_fname_buf, write_fname_len, read_fname_buf, read_fname_len
.export key_read_buf, decimal_flag, save_byte_index, read_byte_index
.export read_temp_byte, disk_error_code, msg_filename_suffix
.export enc_read_buf, enc_read_length, iv_read_buf
.export sha256_h0, sha256_h1, sha256_h2, sha256_h3
.export sha256_h4, sha256_h5, sha256_h6, sha256_h7
.export sha_a, sha_b, sha_c, sha_d, sha_e, sha_f, sha_g, sha_h
.export sha_temp3, sha_t1, sha_t2
.export sha256_block, sha256_w, sha256_hash, sha256_len
.export hmac_key, hmac_val, hmac_opad_block, hmac_data_buf, hmac_data_len
.export hmac_result, drbg_seed, drbg_seed_len, drbg_output, drbg_buf_idx
.export gcmsiv_nonce, gcmsiv_pt_buf, gcmsiv_pt_len, gcmsiv_ct_buf
.export gcmsiv_dec_buf, gcmsiv_tag, gcmsiv_tag_acc, gcmsiv_auth_key
.export gcmsiv_enc_key, gcmsiv_counter, gcmsiv_keystream, gcmsiv_block_idx
.export gcmsiv_ct_idx, gcmsiv_ks_idx, gcmsiv_tag_valid, gcmsiv_verify_tag
.export gcmsiv_saved_key, gcmsiv_exp_enc_key, gcmsiv_saved_exp
.export polyval_acc, polyval_h, polyval_temp, polyval_htable
.export default_filename, default_msg_filename, default_gcm_filename
.export gcm_filename_suffix
.export bench_iterations, timer_start_lo, timer_start_hi, timer_end_lo
.export timer_end_hi, timer_elapsed
.export reu_present, reu_size_kb, cbc_temp
.export nist_saved_key, nist_saved_iv
.export mc_a0, mc_a1, mc_a2, mc_a3, mc_b0, mc_b1, mc_b2, mc_b3

; NOTE: input_buf_size/encrypt_buf_size (constants.s) are NOT .import'd here
; despite exports.inc listing them as this file's only cross-module import.
; Verified directly against ca65 (2026-07-18): .res's size operand must be a
; compile-time constant expression - an .import'd symbol is only resolved at
; link time and ca65 rejects it there ("Error: Constant expression expected").
; c64-nist-curves/src/data_shared.s follows the same precedent (literal
; buffer sizes, no imported-constant .res). The two buffers below are sized
; with the literal values that must stay in sync with constants.s's
; input_buf_size (64) / encrypt_buf_size (80).

; =============================================================================
; data section
; =============================================================================

; storage for generated values
iv_data:
        .res 16, 0

key_data:
        .res 32, 0

; aes working data
aes_state:
        .res 16, 0

cbc_vector:
        .res 16, 0

expanded_key:
        .res 240, 0            ; 15 round keys * 16 bytes

; encryption buffers
input_buffer:
        .res 64, 0              ; input_buf_size (constants.s)

encrypt_buffer:
        .res 80, 0              ; encrypt_buf_size (constants.s)

decrypt_data:
        .res 64, 0              ; input_buf_size (constants.s)

input_length:
        .byte 0

encrypt_length:
        .byte 0

decrypt_length:
        .byte 0

block_count:
        .byte 0

current_block:
        .byte 0

pkcs7_pad_value:
        .byte 0

input_index:
        .byte 0

; disk save variables
drive_number:
        .byte 8

filename_buf:
        .res 17, 0             ; input buffer for filename

actual_filename:
        .res 17, 0             ; actual filename to use

filename_len:
        .byte 0

filename_suffix:
        .byte 0

using_default_name:
        .byte 0

file_exists_flag:
        .byte 0

cmd_buffer:
        .res 24, 0

cmd_len:
        .byte 0

write_fname_buf:
        .res 32, 0

write_fname_len:
        .byte 0

read_fname_buf:
        .res 32, 0

read_fname_len:
        .byte 0

key_read_buf:
        .res 32, 0

decimal_flag:
        .byte 0

save_byte_index:
        .byte 0

read_byte_index:
        .byte 0

read_temp_byte:
        .byte 0

disk_error_code:
        .byte 0, 0              ; two bytes for error code digits

msg_filename_suffix:
        .byte 0

enc_read_buf:
        .res 64, 0             ; buffer for reading encrypted data back

enc_read_length:
        .byte 0

iv_read_buf:
        .res 16, 0             ; buffer for reading IV back

; SHA-256 working variables
sha256_h0:      .res 4, 0
sha256_h1:      .res 4, 0
sha256_h2:      .res 4, 0
sha256_h3:      .res 4, 0
sha256_h4:      .res 4, 0
sha256_h5:      .res 4, 0
sha256_h6:      .res 4, 0
sha256_h7:      .res 4, 0

sha_a:          .res 4, 0
sha_b:          .res 4, 0
sha_c:          .res 4, 0
sha_d:          .res 4, 0
sha_e:          .res 4, 0
sha_f:          .res 4, 0
sha_g:          .res 4, 0
sha_h:          .res 4, 0

sha_temp3:      .res 4, 0
sha_t1:         .res 4, 0
sha_t2:         .res 4, 0

sha256_block:   .res 64, 0
sha256_w:       .res 256, 0    ; message schedule (64 words * 4 bytes)
sha256_hash:    .res 32, 0     ; final hash output
sha256_len:     .res 2, 0      ; message length in bits
; sha256_round moved to ZP ($12) in constants.asm

; --- HMAC-DRBG state ---
hmac_key:        .res 32, 0     ; HMAC key / DRBG K state
hmac_val:        .res 32, 0     ; DRBG V state
hmac_opad_block: .res 64, 0     ; Scratch: K XOR opad
hmac_data_buf:   .res 97, 0     ; V(32) + 0x00/0x01(1) + seed(64)
hmac_data_len:   .byte 0        ; Length of data in hmac_data_buf
hmac_result:     .res 32, 0     ; HMAC output
drbg_seed:       .res 64, 0     ; Seed material (privkey||hash)
drbg_seed_len:   .byte 0        ; Length of seed
drbg_output:     .res 32, 0     ; Generate output
drbg_buf_idx:    .byte 32       ; Buffer index (32 = empty, forces first generate)

; GCM-SIV variables
gcmsiv_nonce:       .res 12, 0     ; 96-bit nonce
gcmsiv_pt_buf:      .res 64, 0     ; plaintext buffer
gcmsiv_pt_len:      .byte 0        ; plaintext length
gcmsiv_ct_buf:      .res 64, 0     ; ciphertext buffer
gcmsiv_dec_buf:     .res 64, 0     ; decrypted plaintext buffer
gcmsiv_tag:         .res 16, 0     ; authentication tag
gcmsiv_tag_acc:     .res 16, 0     ; tag accumulator
gcmsiv_auth_key:    .res 16, 0     ; derived auth key
gcmsiv_enc_key:     .res 32, 0     ; derived encryption key (256-bit for AES-256)
gcmsiv_counter:     .res 16, 0     ; CTR mode counter
gcmsiv_keystream:   .res 16, 0     ; keystream block
gcmsiv_block_idx:   .byte 0        ; block processing index
gcmsiv_ct_idx:      .byte 0        ; ciphertext index
gcmsiv_ks_idx:      .byte 0        ; keystream index
gcmsiv_tag_valid:   .byte 0        ; tag verification: 0=fail, 1=pass
gcmsiv_verify_tag:  .res 16, 0     ; saved received tag for verification
gcmsiv_saved_key:   .res 32, 0     ; saved original key during derivation
gcmsiv_exp_enc_key: .res 256, 0    ; expanded derived encryption key
gcmsiv_saved_exp:   .res 256, 0    ; saved original expanded key

; POLYVAL variables (RFC 8452 GF(2^128) universal hash)
polyval_acc:     .res 16, 0        ; 128-bit accumulator
polyval_h:       .res 16, 0        ; 128-bit hash key H
polyval_temp:    .res 16, 0        ; temp block for update
polyval_htable:  .res 256, 0       ; precomputed 4-bit nibble table (16 entries * 16 bytes)

default_filename:
        .byte "AESKEY"
        .byte 0

default_msg_filename:
        .byte "AESMSG"
        .byte 0

default_gcm_filename:
        .byte "AESGCM"
        .byte 0

gcm_filename_suffix:
        .byte 0

; benchmark variables
bench_iterations:   .word 0
timer_start_lo:     .byte 0
timer_start_hi:     .byte 0
timer_end_lo:       .byte 0
timer_end_hi:       .byte 0
timer_elapsed:      .word 0

; REU variables
reu_present:        .byte 0     ; 0=no REU, 1=REU detected
reu_size_kb:        .word 0     ; REU size in KB

cbc_temp:
        .res 16, 0             ; temp storage for cbc decryption

; NIST test save/restore buffers
nist_saved_key: .res 32, 0
nist_saved_iv:  .res 16, 0

; mix columns temp storage
mc_a0:  .byte 0
mc_a1:  .byte 0
mc_a2:  .byte 0
mc_a3:  .byte 0
mc_b0:  .byte 0
mc_b1:  .byte 0
mc_b2:  .byte 0
mc_b3:  .byte 0
