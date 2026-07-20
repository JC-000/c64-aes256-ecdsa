; =============================================================================
; exports.inc - Cross-module symbol dependency map for ca65 multi-object build
;
; Each module lists what it EXPORTS (defines) and IMPORTS (uses from others).
; Converter agents: add .export/.import declarations matching these lists.
;
; This is Phase 4 of docs/modular_restructure_plan.md. It supersedes
; docs/symbol_map.md (Phase 0's deliverable) as the authoritative
; module-by-module dependency map, updated for two changes symbol_map.md
; predates:
;   - Phase 1 moved every zero-page equate out of constants.s, ecdsa_fp.s,
;     and ecdsa_points.s into src/zp_config.s. Every "ZP:" import line
;     below names zp_config.s as the source, not the original scattered
;     files. Verified against live source with `grep -rn '= \$' src/*.s`:
;     constants.s/ecdsa_fp.s/ecdsa_points.s now define zero ZP equates
;     (ecdsa_fp.s's sqtab_lo/sqtab_hi are ordinary RAM table addresses,
;     not zero page; constants.s's remaining `= $` lines are hardware/
;     KERNAL addresses and PETSCII byte constants, not ZP allocations).
;   - Phase 3 added a new leaf module, src/lib_version.s.
; Every EXPORTS/IMPORTS/routine-call fact below that is NOT about
; zero-page location was carried over unchanged from symbol_map.md's
; independently-verified per-file analysis.
;
; docs/symbol_map.md is kept as a pointer file; its prose anomaly writeups
; (sections A-D) are summarized as NOTES below but not reproduced in full.
; =============================================================================

; -----------------------------------------------------------------------------
; zp_config.s - Zero-page equates (single source of truth, was scattered
; across constants.s/ecdsa_fp.s/ecdsa_points.s prior to Phase 1)
; EXPORTS (all are ZP equates, via .exportzp):
;   kbd_buffer,
;   zp_ptr, zp_temp, zp_count, zp_ptr2,
;   zp_round, zp_col, zp_tmp1, zp_tmp2, zp_tmp3, zp_tmp4,
;   sha_temp1, sha_temp2, sha256_round,
;   fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_loop, fp_mul_i, fp_mul_j,
;   ec_scalar_ptr
; IMPORTS: (none — pure equates, zero code)
; NOTES: fp_loop is dead (zero references anywhere in src/, including
; within the field-arithmetic code that uses its neighbors) — carried
; forward from symbol_map.md's "Duplicate zero-page claims" section, not
; a new finding. zp_ptr2 ($02-$03) is re-declared as a local alias (not a
; new allocation) in base64.s (b64_ws_ptr), der_encode.s (der_src_ptr),
; csr.s (csr_wf_lo/csr_wf_hi/csr_field_ptr), and polyval.s (used
; directly) — all four transiently share the same two physical bytes and
; rely on never being re-entered mid-use by one another. zp_ptr
; ($FB-$FC) is likewise aliased as der_int_ptr (der_encode.s) and
; csr_ws_lo/csr_ws_hi (csr.s). Not bugs, just worth flagging before the
; module split moves these into separate translation units.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; lib_version.s - Library version constants (Phase 3 addition,
; c64-lib-contract SPEC.md §1 pattern, scoped down)
; EXPORTS: LIB_VERSION_MAJOR, LIB_VERSION_MINOR, LIB_VERSION_PATCH
; IMPORTS: (none)
; NOTES: Internal/forward-looking only — this repo has no external
; consumer yet, so LIB_ABI_VERSION and the SHARED_PRIMITIVES bitmask
; (c64-lib-contract SPEC §5/§8) are deliberately not defined. Starts at
; v0.1.0 (no git tags exist yet).
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/aes_decrypt.s
; EXPORTS: display_encrypted, do_decrypt_text
; IMPORTS:
;   ZP: zp_ptr, zp_count, zp_temp, zp_round, zp_col, zp_tmp1 (zp_config.s)
;   constants: chrout, input_buf_size
;   data: encrypt_length, encrypt_buffer, decrypt_data, decrypt_length, iv_data,
;         block_count, current_block, cbc_vector, aes_state, cbc_temp,
;         mc_a0, mc_a1, mc_a2, mc_a3, mc_b0, mc_b1, mc_b2, mc_b3 (data.s);
;         aes_inv_sbox (tables.s);
;         no_encrypted_msg, encrypted_header_msg, instructions_msg,
;         decrypting_msg, decrypted_header_msg, as_text_msg (strings.s);
;         debug_iv_msg, debug_len_msg, debug_blk_msg, debug_cur_msg,
;         debug_state_msg, debug_after_dec_msg, debug_cbc_msg,
;         debug_after_xor_msg, dbg_ark14_msg, dbg_mainrnd_msg (debug_strings.s)
;   display.s: print_string, display_hex_block, print_hex_byte
;   aes_encrypt.s: aes_add_round_key, gf_mul2, xor_state_with_iv
; NOTES: xor_state_with_iv was missing from this IMPORTS line prior to
; Phase 5 batch 4 — a real documentation gap found by direct standalone
; compile (aes_decrypt.s's CBC-decrypt path XORs the decrypted block with
; the saved IV using this aes_encrypt.s routine); corrected here
; 2026-07-19. `decrypt_buffer` carries .export for the Python test harness only
; (tools/run_all_tests.py) — no src/*.s caller; keep it regardless of
; in-repo importer count (anomaly A). Internal-only (not exported):
; print_state_debug, copy_cipher_to_state, save_cipher_for_cbc,
; copy_state_to_decrypt, update_cbc_from_saved, aes_decrypt_block,
; aes_inv_sub_bytes, aes_inv_shift_rows, aes_inv_mix_columns,
; gf_mul_09/0b/0d/0e. Heavily saturated with debug_strings.s tracing —
; good candidate for a release-build feature flag.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/aes_encrypt.s
; EXPORTS: clear_buffers, do_encrypt_text, copy_block_to_state,
;          xor_state_with_iv, copy_state_to_output, aes_encrypt_block,
;          aes_add_round_key, gf_mul2, aes_key_expansion
; IMPORTS:
;   ZP: zp_tmp1, zp_tmp2, zp_tmp3, zp_tmp4, zp_round, zp_col, zp_temp,
;       zp_count (zp_config.s)
;   constants: input_buf_size, petscii_return, chrout, getin
;   data: input_buffer, input_length, input_index, encrypt_buffer,
;         encrypt_length, block_count, current_block, pkcs7_pad_value,
;         iv_data, cbc_vector, aes_state, expanded_key, key_data (data.s);
;         input_prompt_msg, encrypting_msg, encrypt_done_msg,
;         instructions_msg, no_input_msg (strings.s);
;         dbg_inlen_msg, dbg_inbuf_msg, dbg_blocks_msg, dbg_enclen_msg
;         (debug_strings.s)
;   display.s: print_string, print_hex_byte
;   tables.s: aes_sbox, aes_rcon
; NOTES: `encrypt_input` carries .export for the test harness only, no
; src/*.s caller (anomaly A). gf_mul2 and aes_add_round_key, despite the
; "encrypt" filename, are genuine exports consumed by aes_decrypt.s —
; easy to misplace during the split. Not exported (internal-only):
; aes_sub_bytes, aes_shift_rows, aes_mix_columns, gf_mul3.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/base64.s
; EXPORTS: b64_encode, b64_output_pem
; IMPORTS:
;   ZP: zp_ptr2 (zp_config.s; aliased locally as b64_ws_ptr)
;   constants: chrout
;   data: der_buf (der_encode.s); pkcs10_der_len (pkcs10_build.s);
;         pkcs10_pem_begin, pkcs10_pem_end (strings.s)
;   (no jsr/jmp targets outside chrout — all internal routine calls stay
;    within base64.s)
; NOTES: Not exported (internal-only, verified zero external references):
; b64_read_src_byte, b64_output_char, b64_pem_write_str, b64_table, and
; all b64_* working-variable data labels.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/benchmark.s
; EXPORTS: do_benchmark, do_load_nist_vectors
; IMPORTS:
;   ZP: zp_ptr, zp_count (zp_config.s)
;   constants: chrout
;   data: input_buffer, gcmsiv_pt_buf, input_length, gcmsiv_pt_len, iv_data,
;         cbc_vector, key_data, aes_state, nist_saved_key, nist_saved_iv,
;         bench_iterations, current_block, block_count, timer_start_lo,
;         timer_start_hi, timer_end_lo, timer_end_hi, timer_elapsed (data.s);
;         benchmark_header_msg, bench_cbc_msg, bench_gcm_msg, bench_block_msg,
;         bench_iters_msg, bench_time_msg, bench_jiffies_msg, bench_done_msg,
;         instructions_msg, nist_header_msg, nist_expanding_msg, nist_key_msg,
;         nist_iv_msg, nist_pt_msg, nist_ct_msg, nist_verify_msg,
;         nist_result_msg, nist_pass_msg, nist_cbc_test_msg,
;         nist_cbc_result_msg, nist_cbc_pass_msg, nist_cbc_fail_msg,
;         nist_fail_msg, nist_note_msg (strings.s)
;   display.s: print_string, print_hex_byte, display_hex_block
;   aes_encrypt.s: copy_block_to_state, xor_state_with_iv, aes_encrypt_block,
;                  copy_state_to_output, aes_key_expansion
;   gcm_siv.s: generate_gcmsiv_nonce, gcmsiv_derive_keys,
;              gcmsiv_compute_tag_base, gcmsiv_finalize_tag,
;              gcmsiv_ctr_encrypt
; NOTES: nist_saved_key, nist_saved_iv, bench_iterations, timer_start_lo/hi,
; timer_end_lo/hi, timer_elapsed live in data.s but are read only by
; benchmark.s anywhere in src/ — candidates to relocate into benchmark.s's
; own data segment. timer_start/timer_stop and the nist_test_* data labels
; are defined here but have zero external callers — not exported.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/boot.s
; EXPORTS: (none — basic_stub/basic_end/start are exported only for the
;          VICE label file / test harness, never referenced by another
;          src/*.s file)
; IMPORTS:
;   ZP: zp_ptr, zp_count, kbd_buffer (zp_config.s)
;   constants: chrout, clrscr
;   data: title_msg, gen_iv_msg, gen_key_msg, expanding_msg,
;         instructions_msg (strings.s); dbg_expkey_msg (debug_strings.s);
;         iv_data, key_data, expanded_key (data.s)
;   reu_core.s: detect_reu
;   prng.s: init_sid
;   hmac_drbg.s: drbg_init_entropy, drbg_fill_bytes
;   display.s: print_string, display_hex_block, display_results
;   aes_encrypt.s: aes_key_expansion, clear_buffers
;   main_loop.s: main_loop
; NOTES: Zero genuine exports for the inter-module graph — boot.s is a
; pure consumer/entry-point. kbd_buffer was corrected 2026-07-19 (Phase 5
; final batch verification) — it's a zeropage symbol from zp_config.s
; (.exportzp), not a "constants:" import; this entry previously
; mis-classified it under constants.s.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/constants.s
; EXPORTS: chrout, getin, chrin, clrscr, setlfs, setnam, open, close, chkin,
;          chkout, clrchn, readst, load, save, sid_v3_freq_lo, sid_v3_freq_hi,
;          sid_v3_ctrl, sid_volume, sid_osc3, cia1_ta_lo, cia1_ta_hi,
;          cia1_tb_lo, cia1_tb_hi, petscii_1, petscii_2, petscii_3, petscii_4,
;          petscii_5, petscii_6, petscii_7, petscii_8, petscii_9, petscii_a,
;          petscii_b, petscii_c, petscii_d, petscii_e, petscii_f, petscii_g,
;          petscii_h, petscii_i, petscii_j, petscii_q, petscii_return,
;          input_buf_size, encrypt_buf_size
; IMPORTS: (none — pure equates, zero code, zero references to anything
;          else in src/)
; NOTES: zp_ptr, zp_temp, zp_count, zp_ptr2, zp_round, zp_col, zp_tmp1-4,
; sha_temp1, sha_temp2, sha256_round, and kbd_buffer used to be exported
; from here; Phase 1 relocated all of them to zp_config.s (see that
; module's entry above) — constants.s's live `.export`/EXPORTS list no
; longer includes them. aes_block_size/aes_key_size/aes_rounds/
; aes_expanded_key_size and the 15 REU-register/command equates
; (reu_status..reu_cmd_verify) are defined but never referenced anywhere
; else in src/ — REU code hardcodes the same addresses as raw hex
; literals instead (see reu_core.s / reu_advanced.s notes). Not included
; in exports (no genuine referencer) but flagged as a latent smell
; independent of this map.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/csr.s
; EXPORTS: do_generate_csr, csr_collect_fields, csr_drive_num,
;          csr_drive_prompt, csr_using_drive_msg, csr_saving_msg,
;          csr_save_ok_msg, csr_save_fail_msg, csr_country, csr_country_len,
;          csr_state, csr_state_len, csr_city, csr_city_len, csr_org,
;          csr_org_len, csr_ou, csr_ou_len, csr_cn, csr_cn_len, csr_email,
;          csr_email_len
; IMPORTS:
;   ZP: zp_ptr (aliased as csr_ws_lo/csr_ws_hi), zp_ptr2 (aliased as
;       csr_field_ptr / csr_wf_lo/csr_wf_hi) (zp_config.s)
;   constants: chrout, getin, open, close, chkout, clrchn, readst, setnam,
;              setlfs, petscii_return
;   data: key_data, input_index, filename_buf, actual_filename, filename_len,
;         write_fname_buf, write_fname_len (data.s); instructions_msg
;         (strings.s)
;   display.s: print_string
;   disk_io.s: get_input_line, copy_input_to_filename, print_filename,
;              print_decimal, build_write_filename
;   reu_advanced.s: getin_wait
;   ecdsa_test.s: do_ecdsa_test
;   pkcs10.s: do_pkcs10_csr
; NOTES: Member of circular dependency group 2 (csr.s <-> pkcs10.s) —
; pkcs10.s reaches back into csr.s's own save-flow state (csr_drive_num,
; csr_drive_prompt, csr_using_drive_msg, csr_saving_msg, csr_save_ok_msg,
; csr_save_fail_msg) rather than csr.s exposing a narrow save entry
; point. See "Suggested Phase 5 conversion order" below. The 7 field/len
; pairs (csr_country[_len] .. csr_email[_len]) are also consumed by
; der_encode.s's pkcs10_fld_lo/hi and pkcs10_flen_lo/hi lookup tables
; (Phase 5 batch 2 discovery — previously undocumented on der_encode.s's
; side; see that entry's IMPORTS).
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/data.s
; EXPORTS: iv_data, key_data, aes_state, cbc_vector, expanded_key,
;          input_buffer, encrypt_buffer, decrypt_data, input_length,
;          encrypt_length, decrypt_length, block_count, current_block,
;          pkcs7_pad_value, input_index, drive_number, filename_buf,
;          actual_filename, filename_len, filename_suffix,
;          using_default_name, file_exists_flag, cmd_buffer, write_fname_buf,
;          write_fname_len, read_fname_buf, read_fname_len, key_read_buf,
;          decimal_flag, save_byte_index, read_byte_index, read_temp_byte,
;          disk_error_code, msg_filename_suffix, enc_read_buf,
;          enc_read_length, iv_read_buf, sha256_h0-h7, sha_a-h, sha_temp3,
;          sha_t1, sha_t2, sha256_block, sha256_w, sha256_hash, sha256_len,
;          hmac_key, hmac_val, hmac_opad_block, hmac_data_buf, hmac_data_len,
;          hmac_result, drbg_seed, drbg_seed_len, drbg_output, drbg_buf_idx,
;          gcmsiv_nonce, gcmsiv_pt_buf, gcmsiv_pt_len, gcmsiv_ct_buf,
;          gcmsiv_dec_buf, gcmsiv_tag, gcmsiv_tag_acc, gcmsiv_auth_key,
;          gcmsiv_enc_key, gcmsiv_counter, gcmsiv_keystream, gcmsiv_block_idx,
;          gcmsiv_ct_idx, gcmsiv_ks_idx, gcmsiv_tag_valid, gcmsiv_verify_tag,
;          gcmsiv_saved_key, gcmsiv_exp_enc_key, gcmsiv_saved_exp,
;          polyval_acc, polyval_h, polyval_temp, polyval_htable,
;          default_filename, default_msg_filename, default_gcm_filename,
;          gcm_filename_suffix, bench_iterations, timer_start_lo,
;          timer_start_hi, timer_end_lo, timer_end_hi, timer_elapsed,
;          reu_present, reu_size_kb, cbc_temp, nist_saved_key, nist_saved_iv,
;          mc_a0-a3, mc_b0-b3
; IMPORTS:
;   constants: input_buf_size, encrypt_buf_size (buffer-size operands only)
; NOTES: Pure BSS/data module, zero code, zero cross-file routine
; dependency. cmd_len is defined but referenced nowhere at all (including
; within data.s) — genuinely dead, excluded from exports. Only 15 of 116
; real cross-file dependents currently have .export in the file; the rest
; rely on the single-TU .include build and will need .export added in
; Phase 5.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/debug_strings.s
; EXPORTS: debug_len_msg, debug_blk_msg, debug_cur_msg, debug_state_msg,
;          debug_after_dec_msg, debug_after_xor_msg, debug_cbc_msg,
;          debug_iv_msg, dbg_ark14_msg, dbg_mainrnd_msg, dbg_inlen_msg,
;          dbg_inbuf_msg, dbg_blocks_msg, dbg_enclen_msg, dbg_expkey_msg
; IMPORTS: (none — pure data, no code)
; NOTES: debug_blk_msg/dbg_blocks_msg and debug_len_msg/dbg_enclen_msg are
; identical-text duplicate pairs (both "BLOCKS: " and both "ENC LEN: "
; respectively), consumed by aes_decrypt.s and aes_encrypt.s respectively
; — anomaly D, a consolidation opportunity, not a broken link.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/der_encode.s
; EXPORTS: der_buf, der_init, der_write_byte, der_write_length,
;          der_write_bytes, der_write_integer_32, der_measure_integer_32,
;          der_write_oid, der_write_raw_string, der_get_pos, oid_ec_pubkey,
;          oid_prime256v1, oid_ecdsa_sha256, pkcs10_oid_lo, pkcs10_oid_hi,
;          pkcs10_oid_len, pkcs10_fld_lo, pkcs10_fld_hi, pkcs10_flen_lo,
;          pkcs10_flen_hi, pkcs10_str_tag, der_pos, der_src_ptr, der_int_ptr
; IMPORTS:
;   ZP: zp_ptr (aliased as der_int_ptr), zp_ptr2 (aliased as der_src_ptr)
;       (zp_config.s)
;   data: csr_country, csr_country_len, csr_state, csr_state_len, csr_city,
;         csr_city_len, csr_org, csr_org_len, csr_ou, csr_ou_len, csr_cn,
;         csr_cn_len, csr_email, csr_email_len (csr.s) — read by the
;         pkcs10_fld_lo/hi and pkcs10_flen_lo/hi lookup tables (Phase 5
;         batch 2 discovery: previously undocumented here)
;   (no routine imports — every jsr/jmp target resolves within
;    der_encode.s itself)
; NOTES: der_pos is directly saved/restored by pkcs10_build.s from
; outside (`sta der_pos+1` etc.) to redirect the encoder mid-stream — a
; fragile coupling, flagged as a code smell for the split since it means
; der_pos must stay a full read/write export rather than an encapsulated
; cursor. 7 of the 10 X.500 OID constants (oid_country/state/locality/
; org/ou/cn/email) are internal-only, reached only via the lookup tables;
; only oid_ec_pubkey/oid_prime256v1/oid_ecdsa_sha256 are referenced
; directly by name and exported.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/disk_io.s
; EXPORTS: do_save_key, do_load_key, do_save_encrypted, do_load_encrypted,
;          get_input_line, copy_input_to_filename, print_filename,
;          check_file_exists, write_hex_digit, read_hex_char,
;          build_write_filename, build_read_filename, print_decimal
; IMPORTS:
;   ZP: zp_ptr, zp_count (zp_config.s)
;   constants: chrout, getin, chrin, setnam, setlfs, open, chkout, chkin,
;              readst, clrchn, close, petscii_return
;   data: input_index, filename_buf, drive_number, using_default_name,
;         file_exists_flag, key_data, key_read_buf, expanded_key,
;         encrypt_length, iv_data, encrypt_buffer, iv_read_buf, enc_read_buf,
;         enc_read_length, default_msg_filename, actual_filename,
;         filename_len, msg_filename_suffix, write_fname_len, write_fname_buf,
;         save_byte_index, read_fname_len, read_fname_buf, read_byte_index,
;         read_temp_byte, default_filename, filename_suffix, disk_error_code,
;         cmd_buffer, decimal_flag (data.s); 40 message labels (strings.s;
;         corrected from a prior miscount of 39 during Phase 5 batch 3 —
;         see src/disk_io.s's real .import list for the verified set);
;         dbg_expkey_msg (debug_strings.s)
;   display.s: print_string, display_hex_block
;   aes_encrypt.s: aes_key_expansion
; NOTES: Member of circular dependency group 1 — depends on display.s and
; aes_encrypt.s, and is in turn depended upon by sid_config.s and
; reu_advanced.s (see anomaly B below). read_encrypted_from_disk appears
; dead (no jsr anywhere, including within disk_io.s) — confirm it isn't a
; harness entry point before removing. increment_filename/
; set_default_filename and increment_msg_filename/set_default_msg_filename
; are near-duplicate copy-pasted pairs.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/display.s
; EXPORTS: display_results, display_key_only, display_hex_block,
;          print_hex_byte, print_string, print_hex_digit,
;          print_decimal_word
; IMPORTS:
;   ZP: zp_ptr, zp_temp, zp_count (zp_config.s)
;   constants: chrout
;   data: iv_data, key_data (data.s); iv_header_msg, key_header_msg,
;         done_msg, instructions_msg (strings.s)
; NOTES: print_hex_digit and print_decimal_word were relocated here from
; sid_config.s (pre-Phase-5 cleanup, task #31) — this was the layering
; smell that caused circular dependency group 1 (anomaly B); resolved by
; the move, so display.s now has no outgoing edge to sid_config.s.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/ecdsa_curve.s
; EXPORTS: ec_gx, ec_gy, ecdsa_test_privkey, ecdsa_test_k, ecdsa_test_hash,
;          ecdsa_test_r, ecdsa_test_s, ec_p1, ec_p2, ec_p3, ec_t1, ec_t2,
;          ec_t3, ec_t4, ec_t5, ec_t6, ec_set_modp, ec_set_modn, ec_mulp
; IMPORTS:
;   ZP: fp_misc, fp_src1 (zp_config.s)
;   data: fp_r0 (ecdsa_mod.s)
;   ecdsa_fp.s: fp_misc, fp_src1, fp_copy
;   ecdsa_mod.s: fp_r0, fp_mod_mul
; NOTES: ec_a and ec_b (curve coefficients) and ecdsa_test_pubx/puby/
; 2gx/2gy are defined but have zero references anywhere in src/ — likely
; dead/never-wired-up test-vector data; flagged, not dropped. ec_p and
; ec_n are correctly encapsulated (only touched via ec_set_modp/
; ec_set_modn, not exported directly).
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/ecdsa_fp.s
; EXPORTS: fp_init_sqtab, fp_copy, fp_zero, fp_cmp, fp_add, fp_sub,
;          fp_is_zero, fp_rshift1, fp_mul, fp_wide
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, fp_mul_i, fp_mul_j
;       (zp_config.s — these equates lived in this file before Phase 1;
;       the file only *consumes* them now, it no longer defines them.
;       fp_mul_i/fp_mul_j were missing from this line pre-Phase-5 — a real
;       documentation gap found by direct compile during Phase 5 batch 1,
;       corrected here 2026-07-18)
;   (no routine imports from other files — true leaf module, zero jsr
;    targets outside itself)
; NOTES: fp_src1, fp_src2, fp_dst, fp_misc, fp_carry, and fp_wide are
; genuinely used by other files today but are currently missing from the
; file's own .export lists (only the 8 routine names are exported) — this
; is very likely the central gap Phase 5 needs to close for fp_wide (a
; real data export of this file); the ZP names themselves are now
; zp_config.s's .exportzp responsibility, not this file's. fp_loop is
; equated (in zp_config.s) but dead (zero references anywhere in src/).
; sqtab_lo/sqtab_hi are internal-only, ordinary (non-ZP) RAM table
; addresses defined in this file, but their address range
; ($7800-$7BFF) is an implicit cross-module constraint noted in main.s's
; segment-layout comments.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/ecdsa_mod.s
; EXPORTS: fp_mod_add, fp_mod_sub, fp_mod_reduce, fp_mod_mul, fp_mod_inv,
;          fp_r0, fp_r1, fp_r2
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, fp_misc, fp_carry (zp_config.s)
;   constants: chrout
;   data: fp_wide (ecdsa_fp.s — note: NOT data.s/tables.s, an exception to
;         the usual buffer-location pattern)
;   ecdsa_fp.s: fp_add, fp_sub, fp_cmp, fp_copy, fp_zero, fp_rshift1, fp_mul
;   display.s: print_hex_byte
; NOTES: fp_r3 is defined (.res 32) but has zero references anywhere in
; src/ including within this file — flag before dropping, may be a
; memory-layout placeholder. chrout/print_hex_byte usage is debug
; instrumentation (progress-character printing) embedded in production
; bignum-inverse code — candidate for a conditional/feature-flag strip.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/ecdsa_points.s
; EXPORTS: ec_scalar_mul, ec_jacobian_to_affine, ec_affine_x, ec_affine_y
; IMPORTS:
;   ZP: fp_src1, fp_src2, fp_dst, ec_scalar_ptr (zp_config.s — ec_scalar_ptr
;       lived in this file before Phase 1; the file only *consumes* it now)
;   constants: chrout
;   data: ec_p1, ec_p2, ec_p3, ec_t1, ec_t2, ec_t3, ec_t4, ec_t5, ec_t6,
;         ec_gx, ec_gy (ecdsa_curve.s); fp_r0 (ecdsa_mod.s)
;   ecdsa_fp.s: fp_is_zero, fp_src1, fp_src2, fp_dst
;   ecdsa_mod.s: fp_mod_sub, fp_mod_add, fp_mod_inv, fp_r0
;   ecdsa_curve.s: ec_mulp, ec_set_modp, ec_p1, ec_p2, ec_p3, ec_t1, ec_t2,
;                  ec_t3, ec_t4, ec_t5, ec_t6, ec_gx, ec_gy
;   disk_io.s: print_decimal
; NOTES: ec_point_double and ec_point_add look export-worthy but have
; zero external callers today — do not export speculatively.
; ec_scalar_ptr ($3B) is this file's own ZP equate no longer — Phase 1
; relocated it to zp_config.s (see that module's entry above); it is now
; an import here, not a same-file definition.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/ecdsa_sign.s
; EXPORTS: ecdsa_hash_ptr, ecdsa_privkey_ptr, ecdsa_k_ptr, ecdsa_sig_r,
;          ecdsa_sig_s, ecdsa_sign
; IMPORTS:
;   ZP: ec_scalar_ptr, fp_src1, fp_src2, fp_dst (zp_config.s)
;   ecdsa_points.s: ec_scalar_mul, ec_jacobian_to_affine, ec_affine_x
;   ecdsa_fp.s: fp_wide
;   ecdsa_curve.s: ec_set_modn, ec_t1, ec_t2
;   ecdsa_mod.s: fp_mod_reduce, fp_r0, fp_mod_mul, fp_mod_add, fp_mod_inv
; NOTES: No hardware/KERNAL or data.s/tables.s usage at all — purely
; internal to the ECDSA subsystem. Currently pulled in via .include from
; main.s, which becomes a real module link in Phase 5.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/ecdsa_test.s
; EXPORTS: do_ecdsa_test
; IMPORTS:
;   ZP: fp_dst, fp_src1, fp_src2, zp_ptr, zp_count (zp_config.s)
;   constants: chrout
;   data: fp_r1, fp_r2, fp_r0 (ecdsa_mod.s); fp_wide (ecdsa_fp.s);
;         ecdsa_hash_ptr, ecdsa_privkey_ptr, ecdsa_k_ptr, ecdsa_sig_r,
;         ecdsa_sig_s (ecdsa_sign.s); ecdsa_test_hash, ecdsa_test_privkey,
;         ecdsa_test_k, ecdsa_test_r, ecdsa_test_s (ecdsa_curve.s)
;   display.s: print_string, display_hex_block, print_hex_byte
;   ecdsa_fp.s: fp_init_sqtab, fp_zero, fp_mul, fp_cmp
;   ecdsa_mod.s: fp_mod_reduce, fp_mod_inv, fp_mod_mul
;   ecdsa_curve.s: ec_set_modp
;   ecdsa_sign.s: ecdsa_sign
; NOTES: anomaly C — the `data:` entries above (fp_r0-2, ecdsa_sign.s's
; pointer cells, ecdsa_curve.s's test vectors) are genuine cross-module
; dependencies verified against the target exports, just filed under
; data rather than module imports in the original per-file analysis; do
; not miss them when generating .import statements by only scanning
; routine-level imports. All 15 message-string labels defined in this
; file are internal-only (zero external references) and are not
; exported.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/gcm_siv.s
; EXPORTS: do_gcm_siv_encrypt, do_gcm_siv_decrypt, do_save_gcm_siv,
;          do_load_gcm_siv, generate_gcmsiv_nonce, gcmsiv_derive_keys,
;          gcmsiv_compute_tag_base, gcmsiv_finalize_tag, gcmsiv_ctr_encrypt,
;          gcmsiv_encrypt, gcmsiv_decrypt
; IMPORTS:
;   ZP: zp_ptr, zp_count (zp_config.s)
;   constants: chrout, getin, setlfs, setnam, open, close, chkin, chkout,
;              clrchn, readst, petscii_return
;   data: 19 gcmsiv_*/polyval_* buffers plus key_data, aes_state,
;         expanded_key (data.s); drive_number, filename_buf,
;         actual_filename, filename_len, using_default_name,
;         file_exists_flag, write_fname_buf, write_fname_len, read_fname_buf,
;         read_fname_len, input_index, save_byte_index, read_byte_index,
;         read_temp_byte, default_gcm_filename, gcm_filename_suffix
;         (data.s); ~30 gcmsiv_*/reu*/bytes_msg/no_input_msg/
;         instructions_msg-family messages including load_gcm_filename_prompt
;         (missing from this line prior to Phase 5 batch 4 — found by direct
;         standalone compile; do_load_gcm_siv's filename prompt uses it)
;         (strings.s)
;   aes_encrypt.s: aes_encrypt_block, aes_key_expansion
;   polyval.s: polyval_init, polyval_precompute_table, polyval_update
;   hmac_drbg.s: drbg_random_byte
;   display.s: display_hex_block, print_string
;   disk_io.s: get_input_line, copy_input_to_filename, print_filename,
;              check_file_exists, write_hex_digit, read_hex_char,
;              build_write_filename, build_read_filename, print_decimal
; NOTES: gcmsiv_encrypt/gcmsiv_decrypt carry .export for the test harness
; only, no src/*.s caller (anomaly A) — only do_gcm_siv_encrypt/
; do_gcm_siv_decrypt in this same file call them. This file only ever
; uses zp_ptr/zp_count from zp_config.s, no fp_*/ec_scalar_ptr ZP
; equates despite the general task hint about scattering.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/hmac_drbg.s
; EXPORTS: hmac_drbg_instantiate, hmac_drbg_generate, drbg_init_entropy,
;          drbg_random_byte, drbg_fill_bytes
; IMPORTS:
;   ZP: zp_ptr, zp_count (zp_config.s)
;   constants: sid_osc3, cia1_ta_lo
;   data: sha256_block, sha256_hash, hmac_key, hmac_val, hmac_opad_block,
;         hmac_data_buf, hmac_data_len, hmac_result, drbg_seed,
;         drbg_seed_len, drbg_output, drbg_buf_idx (data.s); extra_sid_count,
;         extra_sid_lo, extra_sid_hi (sid_config.s)
;   sha256.s: sha256_init, sha256_process_block, sha256_final
; NOTES: Member of circular dependency group 1 via
; sha256.s -> display.s -> sid_config.s -> hmac_drbg.s. hmac_sha256 and
; hmac_drbg_update are internal-only (comment-only mentions elsewhere, no
; real jsr) — not exported.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/main.s
; EXPORTS: (none)
; IMPORTS: (none — pure .include manifest, zero labels, zero instructions)
; NOTES: Will most likely collapse into linker/project configuration in
; Phase 5 rather than convert into a real module; boot.s owns the actual
; entry point (start), not main.s. Currently the single .include manifest
; that also pulls in lib_version.s and zp_config.s first, before
; constants.s — see the Phase 5 conversion order below.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/main_loop.s
; EXPORTS: main_loop
; IMPORTS:
;   ZP: kbd_buffer (zp_config.s)
;   constants: getin, sid_volume, petscii_1 through petscii_j (21 keys)
;   data: exit_msg (strings.s — not data.s/tables.s, exception to the
;         general pattern)
;   display.s: display_key_only, print_string
;   aes_encrypt.s: do_encrypt_text
;   aes_decrypt.s: display_encrypted, do_decrypt_text
;   disk_io.s: do_save_key, do_load_key, do_save_encrypted, do_load_encrypted
;   sha256.s: do_calc_sha256
;   gcm_siv.s: do_gcm_siv_encrypt, do_gcm_siv_decrypt, do_save_gcm_siv,
;              do_load_gcm_siv
;   benchmark.s: do_benchmark, do_load_nist_vectors
;   reu_advanced.s: do_show_reu_status
;   sid_config.s: do_random_stream, do_config_sid
;   csr.s: do_generate_csr
; NOTES: cleanup is defined here but only called internally (jsr cleanup
; from within main_loop.s) — not exported despite being a top-level
; label. This is the dispatcher pulled in via .include from main.s; that
; include becomes a real module link in Phase 5.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/pkcs10.s
; EXPORTS: do_pkcs10_csr, pkcs10_pubkey_x, pkcs10_pubkey_y
; IMPORTS:
;   ZP: zp_ptr, zp_count, fp_src1, ec_scalar_ptr (zp_config.s)
;   constants: chrout, clrchn, close, setnam, setlfs, open, chkout, readst
;   data: sha256_hash, sha256_block, input_index, filename_buf,
;         actual_filename, filename_len, write_fname_len, write_fname_buf,
;         drbg_seed, drbg_seed_len, drbg_output (data.s)
;   display.s: print_string, display_hex_block
;   csr.s: csr_collect_fields, csr_drive_prompt, csr_drive_num,
;          csr_using_drive_msg, csr_saving_msg, csr_save_ok_msg,
;          csr_save_fail_msg
;   pkcs10_build.s: pkcs10_calc_dn_len, pkcs10_calc_tbs_len,
;                   pkcs10_write_tbs, pkcs10_encode_sig, pkcs10_write_outer,
;                   pkcs10_tbs_start, pkcs10_tbs_end, pkcs10_tbs_tlv_len,
;                   pkcs10_copy_idx, pkcs10_der_len, pkcs10_tbs_copy
;   sha256.s: sha256_init, sha256_process_block, sha256_final
;   ecdsa_sign.s: ecdsa_sign, ecdsa_hash_ptr, ecdsa_privkey_ptr, ecdsa_k_ptr
;   base64.s: b64_encode, b64_output_pem
;   reu_advanced.s: getin_wait
;   disk_io.s: get_input_line, copy_input_to_filename, print_filename,
;              print_decimal, build_write_filename
;   ecdsa_fp.s: fp_init_sqtab, fp_is_zero, fp_wide
;   hmac_drbg.s: drbg_fill_bytes, hmac_drbg_instantiate, hmac_drbg_generate,
;                drbg_init_entropy
;   ecdsa_curve.s: ec_set_modn
;   ecdsa_mod.s: fp_mod_reduce, fp_r0
;   ecdsa_points.s: ec_scalar_mul, ec_jacobian_to_affine, ec_affine_x,
;                   ec_affine_y
;   der_encode.s: der_buf
;   strings.s: pkcs10_header_msg, pkcs10_keygen_msg, pkcs10_pubkey_msg,
;              pkcs10_building_msg, pkcs10_hashing_msg, pkcs10_signing_msg,
;              pkcs10_ready_msg, pkcs10_size_msg, pkcs10_bytes_msg,
;              pkcs10_save_prompt, pkcs10_fname_prompt, instructions_msg
; NOTES: Member of circular dependency group 2 (csr.s <-> pkcs10.s, see
; csr.s's entry above). pkcs10_privkey/pkcs10_k_buf carry .export for the
; harness only (anomaly A). Widest fan-in module in the repo (imports
; from 15 other modules) — highest-risk single file to convert in Phase
; 5, schedule accordingly.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/pkcs10_build.s
; EXPORTS: pkcs10_der_len, pkcs10_calc_dn_len, pkcs10_calc_tbs_len,
;          pkcs10_write_tbs, pkcs10_encode_sig, pkcs10_write_outer,
;          pkcs10_tbs_start, pkcs10_tbs_end, pkcs10_tbs_tlv_len,
;          pkcs10_copy_idx, pkcs10_tbs_copy
; IMPORTS:
;   ZP: der_src_ptr, der_int_ptr (aliases exported by der_encode.s, which
;       themselves alias zp_ptr2/zp_ptr from zp_config.s — not a direct
;       zp_config.s import)
;   data: der_buf, der_pos, pkcs10_pubkey_x, pkcs10_pubkey_y, ecdsa_sig_r,
;         ecdsa_sig_s, oid_ec_pubkey, oid_prime256v1, oid_ecdsa_sha256,
;         pkcs10_flen_lo, pkcs10_flen_hi, pkcs10_oid_len, pkcs10_oid_lo,
;         pkcs10_oid_hi, pkcs10_fld_lo, pkcs10_fld_hi, pkcs10_str_tag (all
;         der_encode.s except pkcs10_pubkey_x/y from pkcs10.s and
;         ecdsa_sig_r/s from ecdsa_sign.s — see anomaly C)
;   der_encode.s: der_init, der_get_pos, der_write_byte, der_write_length,
;                 der_write_oid, der_write_raw_string, der_write_bytes,
;                 der_measure_integer_32, der_write_integer_32
; NOTES: der_calc_len_size is named like a der_encode.s primitive but is
; physically defined here, called only internally — misleading for
; prefix-based splitting but not a duplicate. Zero KERNAL/hardware usage;
; zero data.s/tables.s usage (everything routes through der_encode.s or
; pkcs10.s/ecdsa_sign.s).
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/polyval.s
; EXPORTS: polyval_init, polyval_precompute_table, polyval_update
; IMPORTS:
;   ZP: zp_ptr2 (zp_config.s)
;   data: polyval_acc, polyval_h, polyval_htable, polyval_temp (data.s)
;   (no routine imports from other files — pure leaf for control flow)
; NOTES: polyval_double, polyval_right_shift_1, polyval_shift_left_4,
; polyval_multiply, polyval_xor_table_entry, pv_mul_nibble carry .export
; for the test harness only (anomaly A). polyval_finalize is dead code
; (zero references anywhere, including within this file).
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/prng.s
; EXPORTS: init_sid
; IMPORTS:
;   ZP: zp_ptr (zp_config.s)
;   constants: cia1_ta_lo, cia1_ta_hi, cia1_tb_lo, cia1_tb_hi, sid_v3_freq_lo,
;              sid_v3_freq_hi, sid_v3_ctrl, sid_volume, sid_osc3
;   data: extra_sid_count, extra_sid_lo, extra_sid_hi (sid_config.s — not
;         data.s/tables.s)
;   (no routine imports from other files)
; NOTES: init_all_sids is defined but has zero jsr callers anywhere in
; src/ (only a comment mention) — confirm before deleting; may be an
; intended-but-unwired feature.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/reu_advanced.s
; EXPORTS: do_show_reu_status, getin_wait
; IMPORTS:
;   ZP: zp_temp (zp_config.s)
;   constants: chrout, getin, chrin, setlfs, setnam, open, close, chkin,
;              chkout, clrchn, readst
;   data: reu_present, reu_size_kb (data.s); filename_buf, input_index
;         (data.s); reu_banks (reu_core.s); ~40 reu_*/rng_* message labels
;         (strings.s); instructions_msg (strings.s)
;   reu_core.s: detect_reu
;   hmac_drbg.s: drbg_random_byte
;   disk_io.s: get_input_line
;   display.s: print_string, print_decimal_word
; NOTES: Member of circular dependency group 1. reu_total_banks is
; defined but referenced nowhere at all — dead, likely superseded by
; reu_core.s's reu_banks. REU DMA registers are written via raw hex
; literals even though constants.s already defines symbolic equates for
; all of them — this file imports none of those constants today.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/reu_core.s
; EXPORTS: detect_reu, reu_banks
; IMPORTS:
;   ZP: zp_temp (zp_config.s)
;   data: reu_present, reu_size_kb (data.s); reu_detected_msg, reu_kb_msg,
;         reu_not_found_msg (strings.s)
;   display.s: print_string, print_decimal_word
; NOTES: Member of circular dependency group 1 (via other edges — the
; former dependency on sid_config.s::print_decimal_word, one of the two
; closing edges named in anomaly B below, was resolved by relocating
; print_decimal_word into display.s; see display.s's entry above). Same
; raw-hex-literal-vs-constants.s-equate pattern as reu_advanced.s for the
; REU registers.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/sha256.s
; EXPORTS: do_calc_sha256, sha256_init, sha256_final, sha256_process_block
; IMPORTS:
;   ZP: zp_ptr, zp_count, sha_temp1, sha_temp2, sha256_round (zp_config.s)
;   constants: chrout
;   data: input_length, input_buffer, sha256_hash, sha256_h0-h7, sha256_len,
;         sha256_block, sha256_w, sha_temp3, sha_a-h, sha_t1, sha_t2 (data.s)
;   display.s: display_hex_block, print_string
;   strings.s: no_input_hash_msg, hashing_msg, calculating_msg,
;              hash_result_msg, instructions_msg
; NOTES: Member of circular dependency group 1 via
; sha256.s -> display.s. sha256_update carries .export for the test
; harness only (anomaly A).
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/sid_config.s
; EXPORTS: do_config_sid, do_random_stream, extra_sid_count, extra_sid_lo,
;          extra_sid_hi
; IMPORTS:
;   ZP: zp_ptr, zp_temp (zp_config.s)
;   constants: chrout, getin
;   data: filename_buf, input_index (data.s); sid_config_header,
;         sid_current_msg, sid_chips_msg, sid_extra_prompt, sid_addr_prompt,
;         sid_configured_msg, instructions_msg, random_stream_header,
;         stream_sids_msg, stream_sids_suffix, stream_live_header,
;         stream_stopped_msg, stream_rate_label, stream_bps_msg,
;         stream_sample_msg (strings.s)
;   display.s: print_string, print_hex_byte, print_decimal_word
;   disk_io.s: get_input_line
;   hmac_drbg.s: drbg_random_byte
;   reu_advanced.s: getin_wait
; NOTES: print_hex_digit and print_decimal_word (formerly the direct
; cause of circular dependency group 1, per anomaly B) were relocated out
; of this file into display.s (pre-Phase-5 cleanup, task #31); see
; display.s's entry above. do_random_stream still calls
; display.s::print_decimal_word, but that is now a same-direction edge
; alongside this file's existing display.s imports, not a cycle-closing
; one.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/strings.s
; EXPORTS: 167 message-string labels (as_text_msg, bench_block_msg, ...
;          verify_ok_msg — full list in per-file source data; every one
;          confirmed referenced by at least one other src/*.s file)
; IMPORTS: (none — pure data, zero code)
; NOTES: 9 labels are defined but never referenced by any other file —
; dead/orphaned, NOT exported: sid_label_main, sid_label_extra,
; stream_stats_header, stream_total_msg, stream_bytes_msg, stream_kb_msg,
; stream_rate_msg, stream_kbsec_msg, stream_stats_msg. These look like an
; abandoned parallel "stream stats" string set superseded by
; stream_sample_msg/stream_sids_msg/stream_bps_msg/stream_rate_label —
; flag before Phase 5 rather than silently carrying forward.
; -----------------------------------------------------------------------------

; -----------------------------------------------------------------------------
; src/tables.s
; EXPORTS: aes_sbox, aes_inv_sbox, aes_rcon
; IMPORTS: (none — pure data, zero code, simplest module in the split)
; NOTES: aes_sbox and aes_rcon consumed only by aes_encrypt.s; aes_inv_sbox
; consumed only by aes_decrypt.s. No ambiguity.
; -----------------------------------------------------------------------------

; =============================================================================
; Anomaly summary (see docs/symbol_map.md for full prose writeups)
;
; A. Harness-only exports — .export retained purely for
;    tools/run_all_tests.py's ALL_REQUIRED_LABELS / direct jsr(labels[...])
;    calls, with zero src/*.s caller. Do not drop as "unused" in Phase 5:
;      aes_decrypt.s: decrypt_buffer
;      aes_encrypt.s: encrypt_input
;      gcm_siv.s: gcmsiv_encrypt, gcmsiv_decrypt
;      sha256.s: sha256_update
;      pkcs10.s: pkcs10_privkey, pkcs10_k_buf
;      polyval.s: polyval_double, polyval_right_shift_1,
;        polyval_shift_left_4, polyval_multiply, polyval_xor_table_entry,
;        pv_mul_nibble
;
; B. Layering smell causing circular group 1 — print_hex_digit and
;    print_decimal_word are homed in sid_config.s (SID/audio-config
;    module) instead of display.s, and this single placement decision
;    turns the dependency graph into an 8-module strongly-connected
;    component. Relocating both into display.s before Phase 5 would
;    remove display.s's only outgoing edge and is the single
;    highest-leverage cleanup available before the module split. See
;    display.s's and sid_config.s's entries above.
;
; C. Cross-file dependencies filed under data imports instead of routine
;    imports in the original per-file analysis (genuine, verified-correct
;    edges, just miscategorized) — don't miss them scanning only
;    routine-level imports:
;      ecdsa_test.s <- ecdsa_mod.s (fp_r0/fp_r1/fp_r2),
;        ecdsa_sign.s (ecdsa_hash_ptr/ecdsa_privkey_ptr/ecdsa_k_ptr/
;        ecdsa_sig_r/ecdsa_sig_s), ecdsa_curve.s (ecdsa_test_hash/
;        ecdsa_test_privkey/ecdsa_test_k/ecdsa_test_r/ecdsa_test_s),
;        ecdsa_fp.s (fp_wide)
;      pkcs10_build.s <- pkcs10.s (pkcs10_pubkey_x/pkcs10_pubkey_y),
;        ecdsa_sign.s (ecdsa_sig_r/ecdsa_sig_s)
;      reu_advanced.s <- reu_core.s (reu_banks)
;
; D. Same-content duplicate strings — debug_strings.s defines two label
;    pairs with identical text consumed by different files:
;    debug_blk_msg/dbg_blocks_msg (both "BLOCKS: ") and
;    debug_len_msg/dbg_enclen_msg (both "ENC LEN: "). Not a build-
;    breakage risk, just worth collapsing into one shared export during
;    the split.
; =============================================================================

; =============================================================================
; Suggested Phase 5 conversion order
;
; Computed (docs/symbol_map.md) by building the full cross-module
; dependency graph from every file's module-level imports and running
; Tarjan's strongly-connected-components algorithm, then depth-ordering
; the resulting condensation DAG. zp_config.s and lib_version.s are added
; at the very front here: both have zero imports, and every other module
; transitively depends on zero-page/version equates being defined before
; anything else can assemble.
;
; --- Circular dependency groups (must convert together, not sequentially) ---
;
; ca65 .export/.import alone cannot linearize these; they need to land in
; the same PR / same link step, or the layering smell in anomaly B above
; needs fixing first to shrink the big one:
;
; 1. {aes_encrypt.s, disk_io.s, display.s, hmac_drbg.s, reu_advanced.s,
;    reu_core.s, sha256.s, sid_config.s} (8 modules).
;    Closing edges: display.s -> sid_config.s (print_hex_digit) *
;    sid_config.s -> disk_io.s, hmac_drbg.s, reu_advanced.s, display.s *
;    reu_advanced.s -> reu_core.s, disk_io.s, sid_config.s, display.s,
;    hmac_drbg.s * reu_core.s -> display.s, sid_config.s
;    (print_decimal_word) * disk_io.s -> display.s, aes_encrypt.s *
;    aes_encrypt.s -> display.s * hmac_drbg.s -> sha256.s -> display.s.
;    If anomaly B is fixed first (move print_hex_digit and
;    print_decimal_word into display.s), this collapses to a much
;    smaller, likely acyclic graph — strongly recommended before Phase 5
;    starts on this group.
; 2. {csr.s, pkcs10.s} (2 modules). Closing edges: csr.s -> pkcs10.s
;    (do_pkcs10_csr) and pkcs10.s -> csr.s (csr_collect_fields,
;    csr_drive_prompt, csr_drive_num, csr_using_drive_msg, csr_saving_msg,
;    csr_save_ok_msg, csr_save_fail_msg). pkcs10.s reaching back into
;    csr.s's save-flow state (rather than csr.s owning a clean save-CSR
;    entry point pkcs10.s calls once) is the direct cause; already
;    flagged independently in csr.s's per-module notes as shared mutable
;    state.
;
; --- Full order ---
;
;  1. zp_config.s      (new leaf — Phase 1; zero imports, everything
;                        transitively needs its ZP equates)
;  2. lib_version.s     (new leaf — Phase 3; zero imports)
;  3. constants.s
;  4. data.s
;  5. debug_strings.s
;  6. der_encode.s
;  7. ecdsa_fp.s
;  8. main.s
;  9. polyval.s
; 10. prng.s
; 11. strings.s
; 12. tables.s
; 13. pkcs10_build.s
; 14. aes_encrypt.s    |
; 15. disk_io.s        |
; 16. display.s        |
; 17. hmac_drbg.s      | circular group 1 — convert together (see above)
; 18. reu_advanced.s   |
; 19. reu_core.s       |
; 20. sha256.s         |
; 21. sid_config.s     |
; 22. aes_decrypt.s
; 23. base64.s
; 24. ecdsa_mod.s
; 25. gcm_siv.s
; 26. benchmark.s
; 27. ecdsa_curve.s
; 28. ecdsa_points.s
; 29. ecdsa_sign.s
; 30. ecdsa_test.s
; 31. csr.s            | circular group 2 — convert together (see above)
; 32. pkcs10.s         |
; 33. main_loop.s
; 34. boot.s
;
; Notes on the ordering:
; - zp_config.s and lib_version.s are placed ahead of every module that
;   was already a leaf in symbol_map.md's original ordering (constants.s
;   included) because constants.s, ecdsa_fp.s, and ecdsa_points.s all now
;   *consume* ZP equates from zp_config.s rather than defining their own
;   — a dependency that didn't exist when symbol_map.md's order was
;   computed pre-Phase-1.
; - main.s is a leaf (zero real code, zero imports) but has no dependents
;   either — it will most likely be deleted in Phase 5 and replaced by
;   the linker/project file rather than converted, per its own
;   per-module note. It is also where lib_version.s and zp_config.s are
;   .include'd first today, ahead of constants.s.
; - constants.s, data.s, strings.s, debug_strings.s, der_encode.s,
;   ecdsa_fp.s, polyval.s, prng.s, tables.s are all pure leaves with zero
;   module-level imports (beyond the ZP equates zp_config.s now supplies)
;   — these are the safest, lowest-risk modules to convert first and
;   validate the .export/.import toolchain against, after the two new
;   leaves.
; - boot.s is last because it is the program's entry point and
;   transitively depends on nearly everything (reu_core.s, prng.s,
;   hmac_drbg.s, display.s, aes_encrypt.s, main_loop.s, which itself
;   depends on most of the rest of the tree).
; =============================================================================
