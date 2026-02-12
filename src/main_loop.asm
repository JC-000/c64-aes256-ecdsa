; =============================================================================
; main_loop.asm - Main menu dispatcher and cleanup
; Dispatches to functions across all modules
; =============================================================================

; =============================================================================
; main_loop - wait for keypress and handle commands
; =============================================================================
main_loop:
        ; clear keyboard buffer
        lda #0
        sta kbd_buffer
        
@wait_key:
        jsr getin               ; get key from buffer
        beq @wait_key           ; no key, keep waiting
        
        ; check for '1' - display key
        cmp #petscii_1
        beq @show_key
        
        ; check for '2' - encrypt text
        cmp #petscii_2
        beq @encrypt_text
        
        ; check for '3' - show encrypted
        cmp #petscii_3
        beq @show_encrypted
        
        ; check for '4' - decrypt and show
        cmp #petscii_4
        beq @decrypt_text
        
        ; check for '5' - save key to disk
        cmp #petscii_5
        beq @save_key
        
        ; check for '6' - load key from disk
        cmp #petscii_6
        beq @load_key
        
        ; check for '7' - save encrypted text to disk
        cmp #petscii_7
        beq @save_encrypted
        
        ; check for '8' - load encrypted text from disk
        cmp #petscii_8
        beq @load_encrypted
        
        ; check for '9' - calculate SHA-256 hash
        cmp #petscii_9
        beq @calc_hash
        
        ; check for 'A' - encrypt with GCM-SIV
        cmp #petscii_a
        beq @gcm_siv_encrypt
        
        ; check for 'B' - decrypt with GCM-SIV
        cmp #petscii_b
        beq @gcm_siv_decrypt
        
        ; check for 'C' - save GCM-SIV to disk
        cmp #petscii_c
        beq @save_gcm_siv
        
        ; check for 'D' - load GCM-SIV from disk
        cmp #petscii_d
        beq @load_gcm_siv
        
        ; check for 'E' - benchmark
        cmp #petscii_e
        beq @benchmark
        
        ; check for 'F' - load NIST test vectors
        cmp #petscii_f
        beq @load_nist
        
        ; check for 'G' - show REU status
        cmp #petscii_g
        beq @show_reu
        
        ; check for 'H' - random hex stream
        cmp #petscii_h
        beq @random_stream
        
        ; check for 'I' - configure SID chips
        cmp #petscii_i
        beq @config_sid
        
        ; check for 'J' - generate CSR
        cmp #petscii_j
        beq @generate_csr
        
        ; check for 'q' or 'Q' - quit
        cmp #petscii_q          ; uppercase Q
        beq @quit
        cmp #$71                ; lowercase q (shifted)
        beq @quit
        
        ; unknown key, keep waiting
        jmp @wait_key
        
@show_key:
        jsr display_key_only
        jmp main_loop
        
@encrypt_text:
        jsr do_encrypt_text
        jmp main_loop
        
@show_encrypted:
        jsr display_encrypted
        jmp main_loop
        
@decrypt_text:
        jsr do_decrypt_text
        jmp main_loop
        
@save_key:
        jsr do_save_key
        jmp main_loop
        
@load_key:
        jsr do_load_key
        jmp main_loop
        
@save_encrypted:
        jsr do_save_encrypted
        jmp main_loop
        
@load_encrypted:
        jsr do_load_encrypted
        jmp main_loop
        
@calc_hash:
        jsr do_calc_sha256
        jmp main_loop
        
@gcm_siv_encrypt:
        jsr do_gcm_siv_encrypt
        jmp main_loop
        
@gcm_siv_decrypt:
        jsr do_gcm_siv_decrypt
        jmp main_loop
        
@save_gcm_siv:
        jsr do_save_gcm_siv
        jmp main_loop
        
@load_gcm_siv:
        jsr do_load_gcm_siv
        jmp main_loop
        
@benchmark:
        jsr do_benchmark
        jmp main_loop
        
@load_nist:
        jsr do_load_nist_vectors
        jmp main_loop
        
@show_reu:
        jsr do_show_reu_status
        jmp main_loop
        
@random_stream:
        jsr do_random_stream
        jmp main_loop
        
@config_sid:
        jsr do_config_sid
        jmp main_loop
        
@generate_csr:
        jsr do_generate_csr
        jmp main_loop
        
@quit:
        ; cleanup and exit
        jsr cleanup
        rts                     ; return to basic

; =============================================================================
; cleanup - turn off sid and print exit message
; =============================================================================
cleanup:
        lda #0
        sta sid_volume
        
        lda #<exit_msg
        ldy #>exit_msg
        jsr print_string
        rts

