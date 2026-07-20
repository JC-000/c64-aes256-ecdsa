; =============================================================================
; strings.asm - All UI message strings
; =============================================================================

.segment "CODE"

; --- Exports (167 message-string labels per src/exports.inc; the 9 dead/
; orphaned labels documented there - sid_label_main, sid_label_extra,
; stream_stats_header, stream_total_msg, stream_bytes_msg, stream_kb_msg,
; stream_rate_msg, stream_kbsec_msg, stream_stats_msg - are deliberately
; NOT exported) ---
.export title_msg, gen_iv_msg, gen_key_msg, expanding_msg, iv_header_msg, key_header_msg
.export done_msg, instructions_msg, input_prompt_msg, encrypting_msg, encrypt_done_msg, decrypting_msg
.export decrypted_header_msg, as_text_msg, no_input_msg, no_encrypted_msg, encrypted_header_msg, exit_msg
.export drive_prompt_msg, using_drive_msg, filename_prompt_msg, file_exists_msg, incremented_msg, enter_new_name_msg
.export saving_key_msg, key_value_msg, save_success_msg, save_error_msg, reading_back_msg, reading_enc_back_msg
.export key_read_msg, read_error_msg, verify_ok_msg, verify_fail_msg, names_exhausted_msg, load_filename_prompt_msg
.export loading_default_msg, file_not_found_msg, loading_key_msg, key_loaded_msg, reexpanding_msg, load_success_msg
.export load_error_msg, msg_filename_prompt_msg, saving_msg_msg, enc_value_msg, enc_read_msg, load_msg_filename_prompt
.export loading_default_msg_msg, loading_enc_msg, enc_loaded_msg, loaded_iv_msg, enc_load_success_msg, enc_load_error_msg
.export saving_iv_msg, iv_read_back_msg, no_input_hash_msg, hashing_msg, bytes_msg, calculating_msg
.export hash_result_msg, gcmsiv_prompt_msg, gcmsiv_encrypting_msg, gcmsiv_nonce_msg, gcmsiv_ciphertext_msg, gcmsiv_tag_msg
.export gcmsiv_done_msg, gcmsiv_no_data_msg, gcmsiv_decrypting_msg, gcmsiv_pt_hex_msg, gcmsiv_pt_text_msg, gcmsiv_decrypt_done_msg
.export gcmsiv_tag_ok_msg, gcmsiv_tag_fail_msg, gcm_filename_prompt_msg, saving_gcm_msg, load_gcm_filename_prompt, loading_default_gcm_msg
.export loading_gcm_msg, gcm_load_success_msg, benchmark_header_msg, bench_cbc_msg, bench_gcm_msg, bench_block_msg
.export bench_iters_msg, bench_time_msg, bench_jiffies_msg, bench_done_msg, nist_header_msg, nist_expanding_msg
.export nist_key_msg, nist_iv_msg, nist_pt_msg, nist_ct_msg, nist_verify_msg, nist_result_msg
.export nist_pass_msg, nist_fail_msg, nist_cbc_test_msg, nist_cbc_result_msg, nist_cbc_pass_msg, nist_cbc_fail_msg
.export nist_note_msg, reu_detected_msg, reu_kb_msg, reu_not_found_msg, reu_status_msg, reu_not_present_msg
.export reu_present_msg, reu_size_is_msg, reu_kb_suffix, reu_detecting_msg, reu_fill_prompt, reu_fill_type_prompt
.export reu_zeroing_msg, reu_random_msg, reu_progress_msg, reu_kb_of_msg, reu_kb_suffix2, reu_aborted_msg
.export reu_fill_done_msg, reu_save_prompt, reu_drive_prompt, reu_filename_prompt, reu_checking_disk_msg, reu_free_blocks_msg
.export reu_blocks_suffix, reu_no_space_msg, reu_disk_error_msg, reu_open_error_msg, reu_writing_msg, reu_of_msg
.export reu_write_aborted_msg, reu_write_error_msg, reu_save_done_msg, rng_file_exists_msg, rng_append_prompt, rng_refilling_msg
.export rng_pass_suffix, rng_blocks_written_msg, sid_config_header, sid_current_msg, sid_chips_msg, sid_extra_prompt
.export sid_addr_prompt, sid_configured_msg, random_stream_header, stream_sids_msg, stream_sids_suffix, stream_live_header
.export stream_sample_msg, stream_stopped_msg, stream_rate_label, stream_bps_msg, pkcs10_header_msg, pkcs10_keygen_msg
.export pkcs10_pubkey_msg, pkcs10_building_msg, pkcs10_hashing_msg, pkcs10_signing_msg, pkcs10_ready_msg, pkcs10_size_msg
.export pkcs10_bytes_msg, pkcs10_save_prompt, pkcs10_fname_prompt, pkcs10_pem_begin, pkcs10_pem_end

; =============================================================================
; messages
; =============================================================================
title_msg:
        .byte $93
        .byte "*** AES-256 ENCRYPTION DEMO ***"
        .byte $0d
        .byte "USING SID LFSR PRNG"
        .byte $0d
        .byte "FOR DEMONSTRATION ONLY"
        .byte $0d, $0d, 0

gen_iv_msg:
        .byte "GENERATING IV (16 BYTES)..."
        .byte $0d, 0

gen_key_msg:
        .byte "GENERATING KEY (32 BYTES)..."
        .byte $0d, 0

expanding_msg:
        .byte "EXPANDING KEY..."
        .byte $0d, $0d, 0

iv_header_msg:
        .byte "*** INITIALIZATION VECTOR ***"
        .byte $0d
        .byte "(16 BYTES / 128 BITS)"
        .byte $0d, $0d, 0

key_header_msg:
        .byte $0d
        .byte "*** AES-256 ENCRYPTION KEY ***"
        .byte $0d
        .byte "(32 BYTES / 256 BITS)"
        .byte $0d, $0d, 0

done_msg:
        .byte $0d
        .byte "*** READY ***"
        .byte $0d, 0

instructions_msg:
        .byte $0d
        .byte "1=KEY 2=ENC 3=SHOW 4=DEC 5=SAVE KEY"
        .byte $0d
        .byte "6=LOAD KEY 7=SAVE 8=LOAD 9=SHA256"
        .byte $0d
        .byte "A=GCM-ENC B=GCM-DEC C=GCM-SAVE"
        .byte $0d
        .byte "D=GCM-LOAD E=BENCH F=NIST G=REU"
        .byte $0d
        .byte "H=RNG STREAM I=SID CONFIG J=CSR"
        .byte $0d
        .byte "Q=QUIT"
        .byte $0d, 0

input_prompt_msg:
        .byte $0d
        .byte "ENTER TEXT TO ENCRYPT:"
        .byte $0d, 0

encrypting_msg:
        .byte $0d
        .byte "ENCRYPTING..."
        .byte $0d, 0

encrypt_done_msg:
        .byte "ENCRYPTION COMPLETE."
        .byte $0d, 0

decrypting_msg:
        .byte "DECRYPTING..."
        .byte $0d, 0

decrypted_header_msg:
        .byte $0d
        .byte "*** DECRYPTED (HEX) ***"
        .byte $0d, 0

as_text_msg:
        .byte $0d
        .byte "AS TEXT: "
        .byte 0

no_input_msg:
        .byte "NO INPUT PROVIDED."
        .byte $0d, 0

no_encrypted_msg:
        .byte "NO ENCRYPTED DATA YET."
        .byte $0d
        .byte "PRESS 2 TO ENCRYPT TEXT."
        .byte $0d, 0

encrypted_header_msg:
        .byte "*** ENCRYPTED OUTPUT ***"
        .byte $0d, $0d, 0

exit_msg:
        .byte $0d
        .byte "*** PROGRAM ENDED ***"
        .byte $0d, 0

drive_prompt_msg:
        .byte "DRIVE NUMBER (8): "
        .byte 0

using_drive_msg:
        .byte "USING DRIVE "
        .byte 0

filename_prompt_msg:
        .byte "FILENAME (AESKEY): "
        .byte 0

file_exists_msg:
        .byte $0d
        .byte "FILE ALREADY EXISTS!"
        .byte $0d, 0

incremented_msg:
        .byte "TRYING: "
        .byte 0

enter_new_name_msg:
        .byte "ENTER NEW FILENAME: "
        .byte 0

saving_key_msg:
        .byte $0d
        .byte "SAVING KEY TO: "
        .byte 0

key_value_msg:
        .byte "KEY VALUE:"
        .byte $0d, 0

save_success_msg:
        .byte "FILE SAVED SUCCESSFULLY."
        .byte $0d, 0

save_error_msg:
        .byte "ERROR SAVING FILE!"
        .byte $0d, 0

reading_back_msg:
        .byte $0d
        .byte "READING KEY BACK..."
        .byte $0d, 0

reading_enc_back_msg:
        .byte $0d
        .byte "READING DATA BACK..."
        .byte $0d, 0

key_read_msg:
        .byte "KEY READ FROM DISK:"
        .byte $0d, 0

read_error_msg:
        .byte "ERROR READING FILE!"
        .byte $0d, 0

verify_ok_msg:
        .byte "VERIFICATION OK!"
        .byte $0d, 0

verify_fail_msg:
        .byte "VERIFICATION FAILED!"
        .byte $0d, 0

names_exhausted_msg:
        .byte $0d
        .byte "ALL DEFAULT NAMES TAKEN (0-9)!"
        .byte $0d
        .byte "PLEASE SPECIFY A CUSTOM NAME."
        .byte $0d, 0

load_filename_prompt_msg:
        .byte "FILENAME TO LOAD (AESKEY): "
        .byte 0

loading_default_msg:
        .byte "USING DEFAULT FILENAME: AESKEY"
        .byte $0d, 0

file_not_found_msg:
        .byte $0d
        .byte "FILE NOT FOUND: "
        .byte 0

loading_key_msg:
        .byte $0d
        .byte "LOADING KEY FROM: "
        .byte 0

key_loaded_msg:
        .byte "KEY LOADED FROM DISK:"
        .byte $0d, 0

reexpanding_msg:
        .byte "EXPANDING KEY FOR AES..."
        .byte $0d, 0

load_success_msg:
        .byte "KEY LOADED SUCCESSFULLY!"
        .byte $0d
        .byte "READY FOR ENCRYPTION/DECRYPTION."
        .byte $0d, 0

load_error_msg:
        .byte "ERROR LOADING KEY FILE!"
        .byte $0d, 0

msg_filename_prompt_msg:
        .byte "FILENAME (AESMSG): "
        .byte 0

saving_msg_msg:
        .byte $0d
        .byte "SAVING ENCRYPTED DATA TO: "
        .byte 0

enc_value_msg:
        .byte "ENCRYPTED DATA:"
        .byte $0d, 0

enc_read_msg:
        .byte "DATA READ FROM DISK:"
        .byte $0d, 0

load_msg_filename_prompt:
        .byte "FILENAME TO LOAD (AESMSG): "
        .byte 0

loading_default_msg_msg:
        .byte "USING DEFAULT FILENAME: AESMSG"
        .byte $0d, 0

loading_enc_msg:
        .byte $0d
        .byte "LOADING ENCRYPTED DATA FROM: "
        .byte 0

enc_loaded_msg:
        .byte "ENCRYPTED DATA LOADED:"
        .byte $0d, 0

loaded_iv_msg:
        .byte "LOADED IV:"
        .byte $0d, 0

enc_load_success_msg:
        .byte "ENCRYPTED DATA LOADED SUCCESSFULLY!"
        .byte $0d
        .byte "USE OPTION 4 TO DECRYPT."
        .byte $0d, 0

enc_load_error_msg:
        .byte "ERROR LOADING ENCRYPTED FILE!"
        .byte $0d, 0

saving_iv_msg:
        .byte "IV BEING SAVED:"
        .byte $0d, 0

iv_read_back_msg:
        .byte "IV READ BACK:"
        .byte $0d, 0

no_input_hash_msg:
        .byte "NO INPUT TEXT TO HASH."
        .byte $0d
        .byte "USE OPTION 2 TO ENTER TEXT FIRST."
        .byte $0d, 0

hashing_msg:
        .byte "HASHING: "
        .byte 0

bytes_msg:
        .byte " BYTES"
        .byte $0d, 0

calculating_msg:
        .byte "CALCULATING SHA-256..."
        .byte $0d, 0

hash_result_msg:
        .byte "SHA-256 HASH:"
        .byte $0d, 0

gcmsiv_prompt_msg:
        .byte $0d
        .byte "ENTER TEXT FOR GCM-SIV ENCRYPTION:"
        .byte $0d, 0

gcmsiv_encrypting_msg:
        .byte "ENCRYPTING "
        .byte 0

gcmsiv_nonce_msg:
        .byte "NONCE (12 BYTES):"
        .byte $0d, 0

gcmsiv_ciphertext_msg:
        .byte "CIPHERTEXT:"
        .byte $0d, 0

gcmsiv_tag_msg:
        .byte "AUTH TAG (16 BYTES):"
        .byte $0d, 0

gcmsiv_done_msg:
        .byte $0d
        .byte "GCM-SIV ENCRYPTION COMPLETE."
        .byte $0d, 0

gcmsiv_no_data_msg:
        .byte "NO GCM-SIV CIPHERTEXT TO DECRYPT."
        .byte $0d
        .byte "USE OPTION A TO ENCRYPT FIRST."
        .byte $0d, 0

gcmsiv_decrypting_msg:
        .byte "DECRYPTING GCM-SIV CIPHERTEXT..."
        .byte $0d, 0

gcmsiv_pt_hex_msg:
        .byte "DECRYPTED (HEX):"
        .byte $0d, 0

gcmsiv_pt_text_msg:
        .byte "DECRYPTED (TEXT):"
        .byte $0d, 0

gcmsiv_decrypt_done_msg:
        .byte $0d
        .byte "GCM-SIV DECRYPTION COMPLETE."
        .byte $0d, 0

gcmsiv_tag_ok_msg:
        .byte "*** TAG VERIFIED OK ***"
        .byte $0d, 0

gcmsiv_tag_fail_msg:
        .byte $0d
        .byte "*** TAG VERIFICATION FAILED! ***"
        .byte $0d
        .byte "DATA MAY BE CORRUPTED/TAMPERED!"
        .byte $0d, 0

gcm_filename_prompt_msg:
        .byte "FILENAME (AESGCM): "
        .byte 0

saving_gcm_msg:
        .byte $0d
        .byte "SAVING GCM-SIV DATA TO: "
        .byte 0

load_gcm_filename_prompt:
        .byte "FILENAME TO LOAD (AESGCM): "
        .byte 0

loading_default_gcm_msg:
        .byte "USING DEFAULT FILENAME: AESGCM"
        .byte $0d, 0

loading_gcm_msg:
        .byte $0d
        .byte "LOADING GCM-SIV DATA FROM: "
        .byte 0

gcm_load_success_msg:
        .byte "GCM-SIV DATA LOADED SUCCESSFULLY!"
        .byte $0d
        .byte "USE OPTION B TO DECRYPT."
        .byte $0d, 0

benchmark_header_msg:
        .byte "=== AES BENCHMARK ==="
        .byte $0d
        .byte "ENCRYPTING 64 BYTES X 256 ITERS"
        .byte $0d, $0d, 0

bench_cbc_msg:
        .byte "AES-256-CBC (4 BLOCKS):"
        .byte $0d, 0

bench_gcm_msg:
        .byte $0d
        .byte "AES-256-GCM-SIV (64 BYTES):"
        .byte $0d, 0

bench_block_msg:
        .byte $0d
        .byte "SINGLE AES BLOCK:"
        .byte $0d, 0

bench_iters_msg:
        .byte "  ITERATIONS: $"
        .byte 0

bench_time_msg:
        .byte "  TIME: $"
        .byte 0

bench_jiffies_msg:
        .byte " JIFFIES (1/60 SEC)"
        .byte $0d, 0

bench_done_msg:
        .byte $0d
        .byte "BENCHMARK COMPLETE."
        .byte $0d, 0

nist_header_msg:
        .byte "=== NIST FIPS 197 TEST VECTORS ==="
        .byte $0d
        .byte "AES-256 APPENDIX C.3"
        .byte $0d, $0d, 0

nist_expanding_msg:
        .byte "EXPANDING KEY..."
        .byte $0d, 0

nist_key_msg:
        .byte "KEY (32 BYTES):"
        .byte $0d, 0

nist_iv_msg:
        .byte "IV (16 BYTES):"
        .byte $0d, 0

nist_pt_msg:
        .byte "EXPECTED PLAINTEXT:"
        .byte $0d, 0

nist_ct_msg:
        .byte "EXPECTED CIPHERTEXT:"
        .byte $0d, 0

nist_verify_msg:
        .byte $0d
        .byte "VERIFYING ENCRYPTION..."
        .byte $0d, 0

nist_result_msg:
        .byte "ACTUAL RESULT:"
        .byte $0d, 0

nist_pass_msg:
        .byte $0d
        .byte "*** NIST TEST PASSED! ***"
        .byte $0d, 0

nist_fail_msg:
        .byte $0d
        .byte "*** NIST TEST FAILED! ***"
        .byte $0d, 0

nist_cbc_test_msg:
        .byte $0d
        .byte "TESTING CBC MODE (ZERO IV)..."
        .byte $0d, 0

nist_cbc_result_msg:
        .byte "CBC RESULT:"
        .byte $0d, 0

nist_cbc_pass_msg:
        .byte "*** CBC TEST PASSED! ***"
        .byte $0d, 0

nist_cbc_fail_msg:
        .byte "*** CBC TEST FAILED! ***"
        .byte $0d, 0

nist_note_msg:
        .byte $0d
        .byte "NOTE: OPTION 2 ENCRYPTS ASCII TEXT,"
        .byte $0d
        .byte "NOT RAW HEX. TYPING '00' ENCRYPTS"
        .byte $0d
        .byte "$30,$30 NOT $00,$00."
        .byte $0d, 0

; REU status messages
reu_detected_msg:
        .byte "REU DETECTED: "
        .byte 0

reu_kb_msg:
        .byte " KB"
        .byte $0d, 0

reu_not_found_msg:
        .byte "NO REU DETECTED"
        .byte $0d, 0

reu_status_msg:
        .byte "=== REU STATUS ==="
        .byte $0d, 0

reu_not_present_msg:
        .byte "REU: NOT PRESENT"
        .byte $0d, 0

reu_present_msg:
        .byte "REU: PRESENT"
        .byte $0d, 0

reu_size_is_msg:
        .byte "SIZE: "
        .byte 0

reu_kb_suffix:
        .byte " KB"
        .byte $0d, 0

reu_detecting_msg:
        .byte "DETECTING REU..."
        .byte $0d, 0

reu_fill_prompt:
        .byte "FILL REU? (Y/N, ENTER=YES) "
        .byte 0

reu_fill_type_prompt:
        .byte $0d
        .byte "0=ZERO R=RANDOM (ENTER=ZERO) "
        .byte 0

reu_zeroing_msg:
        .byte "ZEROING REU (SPACE TO ABORT)..."
        .byte $0d, 0

reu_random_msg:
        .byte "RANDOM FILL (SPACE TO ABORT)..."
        .byte $0d, 0

reu_progress_msg:
        .byte "PROGRESS: "
        .byte 0

reu_kb_of_msg:
        .byte " OF "
        .byte 0

reu_kb_suffix2:
        .byte " KB"
        .byte 0

reu_aborted_msg:
        .byte "ABORTED BY USER."
        .byte $0d, 0

reu_fill_done_msg:
        .byte "REU FILL COMPLETE."
        .byte $0d, 0

reu_save_prompt:
        .byte "SAVE TO DISK? (Y/N, ENTER=YES) "
        .byte 0

reu_drive_prompt:
        .byte "DRIVE NUMBER (ENTER=8): "
        .byte 0

reu_filename_prompt:
        .byte "FILENAME (ENTER=RNGFILL): "
        .byte 0

reu_checking_disk_msg:
        .byte "CHECKING DISK..."
        .byte $0d, 0

reu_free_blocks_msg:
        .byte "FREE: "
        .byte 0

reu_blocks_suffix:
        .byte " BLOCKS"
        .byte $0d, 0

reu_no_space_msg:
        .byte "NO SPACE ON DISK!"
        .byte $0d, 0

reu_disk_error_msg:
        .byte "DISK ERROR!"
        .byte $0d, 0

reu_open_error_msg:
        .byte "CANNOT OPEN FILE!"
        .byte $0d, 0

reu_writing_msg:
        .byte "WRITING TO DISK..."
        .byte $0d, 0

reu_of_msg:
        .byte " OF "
        .byte 0

reu_write_aborted_msg:
        .byte "WRITE ABORTED."
        .byte $0d, 0

reu_write_error_msg:
        .byte "WRITE ERROR!"
        .byte $0d, 0

reu_save_done_msg:
        .byte $0d
        .byte "SAVE COMPLETE. "
        .byte 0

rng_file_exists_msg:
        .byte "FILE ALREADY EXISTS."
        .byte $0d, 0

rng_append_prompt:
        .byte "APPEND MORE DATA? (Y/N, ENTER=YES) "
        .byte 0

rng_refilling_msg:
        .byte "REFILLING REU (PASS "
        .byte 0

rng_pass_suffix:
        .byte ")..."
        .byte $0d, 0

rng_blocks_written_msg:
        .byte " BLOCKS WRITTEN."
        .byte $0d, 0

; SID configuration messages
sid_config_header:
        .byte "=== SID CONFIGURATION ==="
        .byte $0d, 0

sid_current_msg:
        .byte "CURRENT: "
        .byte 0

sid_chips_msg:
        .byte " SID CHIP(S) CONFIGURED"
        .byte $0d, 0

sid_extra_prompt:
        .byte "EXTRA SID CHIPS? (Y/N, ENTER=YES) "
        .byte 0

sid_addr_prompt:
        .byte "ENTER ADDRESSES (E.G. D420,D440):"
        .byte $0d
        .byte "(ENTER FOR DEFAULT D420) "
        .byte 0

sid_configured_msg:
        .byte "CONFIGURED: "
        .byte 0

; Random stream messages
random_stream_header:
        .byte "=== PRNG SPEED TEST ==="
        .byte $0d
        .byte "PRESS SPACE TO STOP"
        .byte $0d, $0d, 0

stream_sids_msg:
        .byte "CONFIGURED SIDS: "
        .byte 0

stream_sids_suffix:
        .byte $0d, 0

stream_live_header:
        .byte $0d
        .byte "MEASURING THROUGHPUT..."
        .byte $0d, 0

stream_sample_msg:
        .byte "SAMPLE: "
        .byte 0

stream_stopped_msg:
        .byte $0d
        .byte "STREAM STOPPED."
        .byte $0d, 0

stream_stats_header:
        .byte $0d
        .byte "STATISTICS:"
        .byte $0d, 0

stream_total_msg:
        .byte "TOTAL: "
        .byte 0

stream_bytes_msg:
        .byte " BYTES"
        .byte 0

stream_rate_label:
        .byte "RATE:  "
        .byte 0

stream_bps_msg:
        .byte " BYTES/SEC"
        .byte 0

stream_stats_msg:
        .byte "GENERATED: "
        .byte 0

stream_kb_msg:
        .byte " KB"
        .byte 0

stream_rate_msg:
        .byte "  RATE: "
        .byte 0

stream_kbsec_msg:
        .byte " KB/SEC"
        .byte 0

sid_label_main:
        .byte "SID 1 ($D400): "
        .byte 0

sid_label_extra:
        .byte "SID "
        .byte 0

; PKCS#10 CSR messages
pkcs10_header_msg:
        .byte "=== PKCS#10 CSR (ECDSA P-256) ==="
        .byte $0d
        .byte "ENTER CSR SUBJECT FIELDS."
        .byte $0d
        .byte "PRESS RETURN TO SKIP OPTIONAL FIELDS."
        .byte $0d, 0

pkcs10_keygen_msg:
        .byte $0d
        .byte "GENERATING ECDSA KEY PAIR..."
        .byte $0d, 0

pkcs10_pubkey_msg:
        .byte "PUBLIC KEY (X,Y):"
        .byte $0d, 0

pkcs10_building_msg:
        .byte "BUILDING CSR..."
        .byte $0d, 0

pkcs10_hashing_msg:
        .byte "HASHING TBS DATA..."
        .byte $0d, 0

pkcs10_signing_msg:
        .byte "SIGNING WITH ECDSA..."
        .byte $0d, 0

pkcs10_ready_msg:
        .byte $0d
        .byte "CSR READY."
        .byte $0d, 0

pkcs10_size_msg:
        .byte "DER SIZE: "
        .byte 0

pkcs10_bytes_msg:
        .byte " BYTES"
        .byte $0d, 0

pkcs10_save_prompt:
        .byte "SAVE CSR TO DISK? (Y/N, ENTER=YES) "
        .byte 0

pkcs10_fname_prompt:
        .byte "FILENAME (ENTER=P10CSR): "
        .byte 0

pkcs10_pem_begin:
        .byte "-----BEGIN CERTIFICATE REQUEST-----"
        .byte $0d, 0

pkcs10_pem_end:
        .byte "-----END CERTIFICATE REQUEST-----"
        .byte $0d, 0
