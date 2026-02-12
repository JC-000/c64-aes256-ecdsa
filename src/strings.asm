; =============================================================================
; strings.asm - All UI message strings
; =============================================================================

; =============================================================================
; messages
; =============================================================================
title_msg:
        !byte $93
        !text "*** AES-256 ENCRYPTION DEMO ***"
        !byte $0d
        !text "USING SID LFSR PRNG"
        !byte $0d
        !text "FOR DEMONSTRATION ONLY"
        !byte $0d, $0d, 0

gen_iv_msg:
        !text "GENERATING IV (16 BYTES)..."
        !byte $0d, 0

gen_key_msg:
        !text "GENERATING KEY (32 BYTES)..."
        !byte $0d, 0

expanding_msg:
        !text "EXPANDING KEY..."
        !byte $0d, $0d, 0

iv_header_msg:
        !text "*** INITIALIZATION VECTOR ***"
        !byte $0d
        !text "(16 BYTES / 128 BITS)"
        !byte $0d, $0d, 0

key_header_msg:
        !byte $0d
        !text "*** AES-256 ENCRYPTION KEY ***"
        !byte $0d
        !text "(32 BYTES / 256 BITS)"
        !byte $0d, $0d, 0

done_msg:
        !byte $0d
        !text "*** READY ***"
        !byte $0d, 0

instructions_msg:
        !byte $0d
        !text "1=KEY 2=ENC 3=SHOW 4=DEC 5=SAVE KEY"
        !byte $0d
        !text "6=LOAD KEY 7=SAVE 8=LOAD 9=SHA256"
        !byte $0d
        !text "A=GCM-ENC B=GCM-DEC C=GCM-SAVE"
        !byte $0d
        !text "D=GCM-LOAD E=BENCH F=NIST G=REU"
        !byte $0d
        !text "H=RNG STREAM I=SID CONFIG J=CSR"
        !byte $0d
        !text "Q=QUIT"
        !byte $0d, 0

input_prompt_msg:
        !byte $0d
        !text "ENTER TEXT TO ENCRYPT:"
        !byte $0d, 0

encrypting_msg:
        !byte $0d
        !text "ENCRYPTING..."
        !byte $0d, 0

encrypt_done_msg:
        !text "ENCRYPTION COMPLETE."
        !byte $0d, 0

decrypting_msg:
        !text "DECRYPTING..."
        !byte $0d, 0

decrypted_header_msg:
        !byte $0d
        !text "*** DECRYPTED (HEX) ***"
        !byte $0d, 0

as_text_msg:
        !byte $0d
        !text "AS TEXT: "
        !byte 0

no_input_msg:
        !text "NO INPUT PROVIDED."
        !byte $0d, 0

no_encrypted_msg:
        !text "NO ENCRYPTED DATA YET."
        !byte $0d
        !text "PRESS 2 TO ENCRYPT TEXT."
        !byte $0d, 0

encrypted_header_msg:
        !text "*** ENCRYPTED OUTPUT ***"
        !byte $0d, $0d, 0

exit_msg:
        !byte $0d
        !text "*** PROGRAM ENDED ***"
        !byte $0d, 0

drive_prompt_msg:
        !text "DRIVE NUMBER (8): "
        !byte 0

using_drive_msg:
        !text "USING DRIVE "
        !byte 0

filename_prompt_msg:
        !text "FILENAME (AESKEY): "
        !byte 0

file_exists_msg:
        !byte $0d
        !text "FILE ALREADY EXISTS!"
        !byte $0d, 0

incremented_msg:
        !text "TRYING: "
        !byte 0

enter_new_name_msg:
        !text "ENTER NEW FILENAME: "
        !byte 0

saving_key_msg:
        !byte $0d
        !text "SAVING KEY TO: "
        !byte 0

key_value_msg:
        !text "KEY VALUE:"
        !byte $0d, 0

save_success_msg:
        !text "FILE SAVED SUCCESSFULLY."
        !byte $0d, 0

save_error_msg:
        !text "ERROR SAVING FILE!"
        !byte $0d, 0

reading_back_msg:
        !byte $0d
        !text "READING KEY BACK..."
        !byte $0d, 0

reading_enc_back_msg:
        !byte $0d
        !text "READING DATA BACK..."
        !byte $0d, 0

key_read_msg:
        !text "KEY READ FROM DISK:"
        !byte $0d, 0

read_error_msg:
        !text "ERROR READING FILE!"
        !byte $0d, 0

verify_ok_msg:
        !text "VERIFICATION OK!"
        !byte $0d, 0

verify_fail_msg:
        !text "VERIFICATION FAILED!"
        !byte $0d, 0

names_exhausted_msg:
        !byte $0d
        !text "ALL DEFAULT NAMES TAKEN (0-9)!"
        !byte $0d
        !text "PLEASE SPECIFY A CUSTOM NAME."
        !byte $0d, 0

load_filename_prompt_msg:
        !text "FILENAME TO LOAD (AESKEY): "
        !byte 0

loading_default_msg:
        !text "USING DEFAULT FILENAME: AESKEY"
        !byte $0d, 0

file_not_found_msg:
        !byte $0d
        !text "FILE NOT FOUND: "
        !byte 0

loading_key_msg:
        !byte $0d
        !text "LOADING KEY FROM: "
        !byte 0

key_loaded_msg:
        !text "KEY LOADED FROM DISK:"
        !byte $0d, 0

reexpanding_msg:
        !text "EXPANDING KEY FOR AES..."
        !byte $0d, 0

load_success_msg:
        !text "KEY LOADED SUCCESSFULLY!"
        !byte $0d
        !text "READY FOR ENCRYPTION/DECRYPTION."
        !byte $0d, 0

load_error_msg:
        !text "ERROR LOADING KEY FILE!"
        !byte $0d, 0

msg_filename_prompt_msg:
        !text "FILENAME (AESMSG): "
        !byte 0

saving_msg_msg:
        !byte $0d
        !text "SAVING ENCRYPTED DATA TO: "
        !byte 0

enc_value_msg:
        !text "ENCRYPTED DATA:"
        !byte $0d, 0

enc_read_msg:
        !text "DATA READ FROM DISK:"
        !byte $0d, 0

load_msg_filename_prompt:
        !text "FILENAME TO LOAD (AESMSG): "
        !byte 0

loading_default_msg_msg:
        !text "USING DEFAULT FILENAME: AESMSG"
        !byte $0d, 0

loading_enc_msg:
        !byte $0d
        !text "LOADING ENCRYPTED DATA FROM: "
        !byte 0

enc_loaded_msg:
        !text "ENCRYPTED DATA LOADED:"
        !byte $0d, 0

loaded_iv_msg:
        !text "LOADED IV:"
        !byte $0d, 0

enc_load_success_msg:
        !text "ENCRYPTED DATA LOADED SUCCESSFULLY!"
        !byte $0d
        !text "USE OPTION 4 TO DECRYPT."
        !byte $0d, 0

enc_load_error_msg:
        !text "ERROR LOADING ENCRYPTED FILE!"
        !byte $0d, 0

saving_iv_msg:
        !text "IV BEING SAVED:"
        !byte $0d, 0

iv_read_back_msg:
        !text "IV READ BACK:"
        !byte $0d, 0

no_input_hash_msg:
        !text "NO INPUT TEXT TO HASH."
        !byte $0d
        !text "USE OPTION 2 TO ENTER TEXT FIRST."
        !byte $0d, 0

hashing_msg:
        !text "HASHING: "
        !byte 0

bytes_msg:
        !text " BYTES"
        !byte $0d, 0

calculating_msg:
        !text "CALCULATING SHA-256..."
        !byte $0d, 0

hash_result_msg:
        !text "SHA-256 HASH:"
        !byte $0d, 0

gcmsiv_prompt_msg:
        !byte $0d
        !text "ENTER TEXT FOR GCM-SIV ENCRYPTION:"
        !byte $0d, 0

gcmsiv_encrypting_msg:
        !text "ENCRYPTING "
        !byte 0

gcmsiv_nonce_msg:
        !text "NONCE (12 BYTES):"
        !byte $0d, 0

gcmsiv_ciphertext_msg:
        !text "CIPHERTEXT:"
        !byte $0d, 0

gcmsiv_tag_msg:
        !text "AUTH TAG (16 BYTES):"
        !byte $0d, 0

gcmsiv_done_msg:
        !byte $0d
        !text "GCM-SIV ENCRYPTION COMPLETE."
        !byte $0d, 0

gcmsiv_no_data_msg:
        !text "NO GCM-SIV CIPHERTEXT TO DECRYPT."
        !byte $0d
        !text "USE OPTION A TO ENCRYPT FIRST."
        !byte $0d, 0

gcmsiv_decrypting_msg:
        !text "DECRYPTING GCM-SIV CIPHERTEXT..."
        !byte $0d, 0

gcmsiv_pt_hex_msg:
        !text "DECRYPTED (HEX):"
        !byte $0d, 0

gcmsiv_pt_text_msg:
        !text "DECRYPTED (TEXT):"
        !byte $0d, 0

gcmsiv_decrypt_done_msg:
        !byte $0d
        !text "GCM-SIV DECRYPTION COMPLETE."
        !byte $0d, 0

gcmsiv_tag_ok_msg:
        !text "*** TAG VERIFIED OK ***"
        !byte $0d, 0

gcmsiv_tag_fail_msg:
        !byte $0d
        !text "*** TAG VERIFICATION FAILED! ***"
        !byte $0d
        !text "DATA MAY BE CORRUPTED/TAMPERED!"
        !byte $0d, 0

gcm_filename_prompt_msg:
        !text "FILENAME (AESGCM): "
        !byte 0

saving_gcm_msg:
        !byte $0d
        !text "SAVING GCM-SIV DATA TO: "
        !byte 0

load_gcm_filename_prompt:
        !text "FILENAME TO LOAD (AESGCM): "
        !byte 0

loading_default_gcm_msg:
        !text "USING DEFAULT FILENAME: AESGCM"
        !byte $0d, 0

loading_gcm_msg:
        !byte $0d
        !text "LOADING GCM-SIV DATA FROM: "
        !byte 0

gcm_load_success_msg:
        !text "GCM-SIV DATA LOADED SUCCESSFULLY!"
        !byte $0d
        !text "USE OPTION B TO DECRYPT."
        !byte $0d, 0

benchmark_header_msg:
        !text "=== AES BENCHMARK ==="
        !byte $0d
        !text "ENCRYPTING 64 BYTES X 256 ITERS"
        !byte $0d, $0d, 0

bench_cbc_msg:
        !text "AES-256-CBC (4 BLOCKS):"
        !byte $0d, 0

bench_gcm_msg:
        !byte $0d
        !text "AES-256-GCM-SIV (64 BYTES):"
        !byte $0d, 0

bench_block_msg:
        !byte $0d
        !text "SINGLE AES BLOCK:"
        !byte $0d, 0

bench_iters_msg:
        !text "  ITERATIONS: $"
        !byte 0

bench_time_msg:
        !text "  TIME: $"
        !byte 0

bench_jiffies_msg:
        !text " JIFFIES (1/60 SEC)"
        !byte $0d, 0

bench_done_msg:
        !byte $0d
        !text "BENCHMARK COMPLETE."
        !byte $0d, 0

nist_header_msg:
        !text "=== NIST FIPS 197 TEST VECTORS ==="
        !byte $0d
        !text "AES-256 APPENDIX C.3"
        !byte $0d, $0d, 0

nist_expanding_msg:
        !text "EXPANDING KEY..."
        !byte $0d, 0

nist_key_msg:
        !text "KEY (32 BYTES):"
        !byte $0d, 0

nist_iv_msg:
        !text "IV (16 BYTES):"
        !byte $0d, 0

nist_pt_msg:
        !text "EXPECTED PLAINTEXT:"
        !byte $0d, 0

nist_ct_msg:
        !text "EXPECTED CIPHERTEXT:"
        !byte $0d, 0

nist_verify_msg:
        !byte $0d
        !text "VERIFYING ENCRYPTION..."
        !byte $0d, 0

nist_result_msg:
        !text "ACTUAL RESULT:"
        !byte $0d, 0

nist_pass_msg:
        !byte $0d
        !text "*** NIST TEST PASSED! ***"
        !byte $0d, 0

nist_fail_msg:
        !byte $0d
        !text "*** NIST TEST FAILED! ***"
        !byte $0d, 0

nist_cbc_test_msg:
        !byte $0d
        !text "TESTING CBC MODE (ZERO IV)..."
        !byte $0d, 0

nist_cbc_result_msg:
        !text "CBC RESULT:"
        !byte $0d, 0

nist_cbc_pass_msg:
        !text "*** CBC TEST PASSED! ***"
        !byte $0d, 0

nist_cbc_fail_msg:
        !text "*** CBC TEST FAILED! ***"
        !byte $0d, 0

nist_note_msg:
        !byte $0d
        !text "NOTE: OPTION 2 ENCRYPTS ASCII TEXT,"
        !byte $0d
        !text "NOT RAW HEX. TYPING '00' ENCRYPTS"
        !byte $0d
        !text "$30,$30 NOT $00,$00."
        !byte $0d, 0

; REU status messages
reu_detected_msg:
        !text "REU DETECTED: "
        !byte 0

reu_kb_msg:
        !text " KB"
        !byte $0d, 0

reu_not_found_msg:
        !text "NO REU DETECTED"
        !byte $0d, 0

reu_status_msg:
        !text "=== REU STATUS ==="
        !byte $0d, 0

reu_not_present_msg:
        !text "REU: NOT PRESENT"
        !byte $0d, 0

reu_present_msg:
        !text "REU: PRESENT"
        !byte $0d, 0

reu_size_is_msg:
        !text "SIZE: "
        !byte 0

reu_kb_suffix:
        !text " KB"
        !byte $0d, 0

reu_detecting_msg:
        !text "DETECTING REU..."
        !byte $0d, 0

reu_fill_prompt:
        !text "FILL REU? (Y/N, ENTER=YES) "
        !byte 0

reu_fill_type_prompt:
        !byte $0d
        !text "0=ZERO R=RANDOM (ENTER=ZERO) "
        !byte 0

reu_zeroing_msg:
        !text "ZEROING REU (SPACE TO ABORT)..."
        !byte $0d, 0

reu_random_msg:
        !text "RANDOM FILL (SPACE TO ABORT)..."
        !byte $0d, 0

reu_progress_msg:
        !text "PROGRESS: "
        !byte 0

reu_kb_of_msg:
        !text " OF "
        !byte 0

reu_kb_suffix2:
        !text " KB"
        !byte 0

reu_aborted_msg:
        !text "ABORTED BY USER."
        !byte $0d, 0

reu_fill_done_msg:
        !text "REU FILL COMPLETE."
        !byte $0d, 0

reu_save_prompt:
        !text "SAVE TO DISK? (Y/N, ENTER=YES) "
        !byte 0

reu_drive_prompt:
        !text "DRIVE NUMBER (ENTER=8): "
        !byte 0

reu_filename_prompt:
        !text "FILENAME (ENTER=RNGFILL): "
        !byte 0

reu_checking_disk_msg:
        !text "CHECKING DISK..."
        !byte $0d, 0

reu_free_blocks_msg:
        !text "FREE: "
        !byte 0

reu_blocks_suffix:
        !text " BLOCKS"
        !byte $0d, 0

reu_no_space_msg:
        !text "NO SPACE ON DISK!"
        !byte $0d, 0

reu_disk_error_msg:
        !text "DISK ERROR!"
        !byte $0d, 0

reu_open_error_msg:
        !text "CANNOT OPEN FILE!"
        !byte $0d, 0

reu_writing_msg:
        !text "WRITING TO DISK..."
        !byte $0d, 0

reu_of_msg:
        !text " OF "
        !byte 0

reu_write_aborted_msg:
        !text "WRITE ABORTED."
        !byte $0d, 0

reu_write_error_msg:
        !text "WRITE ERROR!"
        !byte $0d, 0

reu_save_done_msg:
        !byte $0d
        !text "SAVE COMPLETE. "
        !byte 0

rng_file_exists_msg:
        !text "FILE ALREADY EXISTS."
        !byte $0d, 0

rng_append_prompt:
        !text "APPEND MORE DATA? (Y/N, ENTER=YES) "
        !byte 0

rng_refilling_msg:
        !text "REFILLING REU (PASS "
        !byte 0

rng_pass_suffix:
        !text ")..."
        !byte $0d, 0

rng_blocks_written_msg:
        !text " BLOCKS WRITTEN."
        !byte $0d, 0

; SID configuration messages
sid_config_header:
        !text "=== SID CONFIGURATION ==="
        !byte $0d, 0

sid_current_msg:
        !text "CURRENT: "
        !byte 0

sid_chips_msg:
        !text " SID CHIP(S) CONFIGURED"
        !byte $0d, 0

sid_extra_prompt:
        !text "EXTRA SID CHIPS? (Y/N, ENTER=YES) "
        !byte 0

sid_addr_prompt:
        !text "ENTER ADDRESSES (E.G. D420,D440):"
        !byte $0d
        !text "(ENTER FOR DEFAULT D420) "
        !byte 0

sid_configured_msg:
        !text "CONFIGURED: "
        !byte 0

; Random stream messages
random_stream_header:
        !text "=== PRNG SPEED TEST ==="
        !byte $0d
        !text "PRESS SPACE TO STOP"
        !byte $0d, $0d, 0

stream_sids_msg:
        !text "CONFIGURED SIDS: "
        !byte 0

stream_sids_suffix:
        !byte $0d, 0

stream_live_header:
        !byte $0d
        !text "MEASURING THROUGHPUT..."
        !byte $0d, 0

stream_sample_msg:
        !text "SAMPLE: "
        !byte 0

stream_stopped_msg:
        !byte $0d
        !text "STREAM STOPPED."
        !byte $0d, 0

stream_stats_header:
        !byte $0d
        !text "STATISTICS:"
        !byte $0d, 0

stream_total_msg:
        !text "TOTAL: "
        !byte 0

stream_bytes_msg:
        !text " BYTES"
        !byte 0

stream_rate_label:
        !text "RATE:  "
        !byte 0

stream_bps_msg:
        !text " BYTES/SEC"
        !byte 0

stream_stats_msg:
        !text "GENERATED: "
        !byte 0

stream_kb_msg:
        !text " KB"
        !byte 0

stream_rate_msg:
        !text "  RATE: "
        !byte 0

stream_kbsec_msg:
        !text " KB/SEC"
        !byte 0

sid_label_main:
        !text "SID 1 ($D400): "
        !byte 0

sid_label_extra:
        !text "SID "
        !byte 0

