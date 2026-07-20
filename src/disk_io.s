; =============================================================================
; disk_io.s - Save/load key & ciphertext, filename mgmt, input, hex conversion
; Related: constants.s (Kernal I/O equates)
; ca65 port note: this module contained no ACME-specific directives (!byte,
; !word, !fill, !text, !pet, !source, !zone, * =) in the original source - it
; is a straight mnemonic/label port. All '@label' cheap locals are already
; ca65-compatible as-is. See docs/ca65_translation_notes.md for cross-module
; zero-page addressing concerns to verify during
; Integrate.
; =============================================================================

.segment "LIB_AES256ECDSA_CODE"

.importzp zp_ptr, zp_count
.importzp petscii_return
.import chrout, getin, chrin, setnam, setlfs, open, chkout, chkin
.import readst, clrchn, close
.import input_index, filename_buf, drive_number, using_default_name
.import file_exists_flag, key_data, key_read_buf, expanded_key
.import encrypt_length, iv_data, encrypt_buffer, iv_read_buf, enc_read_buf
.import enc_read_length, default_msg_filename, actual_filename
.import filename_len, msg_filename_suffix, write_fname_len, write_fname_buf
.import save_byte_index, read_fname_len, read_fname_buf, read_byte_index
.import read_temp_byte, default_filename, filename_suffix, disk_error_code
.import cmd_buffer, decimal_flag
.import drive_prompt_msg, enc_load_error_msg, enc_load_success_msg
.import enc_loaded_msg, enc_read_msg, enc_value_msg, enter_new_name_msg
.import file_exists_msg, file_not_found_msg, filename_prompt_msg
.import incremented_msg, instructions_msg, iv_read_back_msg
.import key_loaded_msg, key_read_msg, key_value_msg, load_error_msg
.import load_filename_prompt_msg, load_msg_filename_prompt, load_success_msg
.import loaded_iv_msg, loading_default_msg, loading_default_msg_msg
.import loading_enc_msg, loading_key_msg, msg_filename_prompt_msg
.import names_exhausted_msg, no_encrypted_msg, read_error_msg
.import reading_back_msg, reading_enc_back_msg, reexpanding_msg
.import save_error_msg, save_success_msg, saving_iv_msg, saving_key_msg
.import saving_msg_msg, using_drive_msg, verify_fail_msg, verify_ok_msg
.import dbg_expkey_msg
.import print_string, display_hex_block
.import aes_key_expansion

.export do_save_key, do_load_key, do_save_encrypted, do_load_encrypted
.export get_input_line, copy_input_to_filename, print_filename
.export check_file_exists, write_hex_digit, read_hex_char
.export build_write_filename, build_read_filename, print_decimal

; =============================================================================
; do_save_key - save the AES key to disk
; =============================================================================
do_save_key:
        lda #$0d
        jsr chrout

        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_drive

        ; parse drive number from input
        lda filename_buf
        sec
        sbc #$30                ; convert ascii to number
        cmp #10                 ; valid digit?
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive

@use_default_drive:
        lda #8
        sta drive_number

@got_drive:
        ; print selected drive
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout

        ; --- get filename ---
        lda #<filename_prompt_msg
        ldy #>filename_prompt_msg
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_name

        ; copy user filename
        jsr copy_input_to_filename
        lda #0                  ; user specified name
        sta using_default_name
        jmp @got_filename

@use_default_name:
        ; use default "AESKEY"
        jsr set_default_filename
        lda #1                  ; using default
        sta using_default_name

@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        beq @do_save            ; file doesn't exist, proceed

        ; file exists - handle it
        lda #<file_exists_msg
        ldy #>file_exists_msg
        jsr print_string

        lda using_default_name
        beq @prompt_new_name

        ; using default name, increment it
        jsr increment_filename
        bcs @names_exhausted    ; carry set = no more names to try

        lda #<incremented_msg
        ldy #>incremented_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @got_filename       ; check again

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
        beq @do_save            ; no input, overwrite
        jsr copy_input_to_filename
        jmp @got_filename       ; check again

@do_save:
        ; --- print key being saved ---
        lda #<saving_key_msg
        ldy #>saving_key_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout

        lda #<key_value_msg
        ldy #>key_value_msg
        jsr print_string

        ; display key bytes
        lda #<key_data
        sta zp_ptr
        lda #>key_data
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; --- save the key to disk ---
        jsr save_key_to_disk
        bcs @save_error

        lda #<save_success_msg
        ldy #>save_success_msg
        jsr print_string

        ; --- read key back and display ---
        lda #<reading_back_msg
        ldy #>reading_back_msg
        jsr print_string

        jsr read_key_from_disk
        bcs @read_error

        ; display read key
        lda #<key_read_msg
        ldy #>key_read_msg
        jsr print_string

        lda #<key_read_buf
        sta zp_ptr
        lda #>key_read_buf
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; verify match
        jsr verify_key_match
        bcc @verified

        lda #<verify_fail_msg
        ldy #>verify_fail_msg
        jsr print_string
        jmp @done

@verified:
        lda #<verify_ok_msg
        ldy #>verify_ok_msg
        jsr print_string
        jmp @done

@save_error:
        lda #<save_error_msg
        ldy #>save_error_msg
        jsr print_string
        jmp @done

@read_error:
        lda #<read_error_msg
        ldy #>read_error_msg
        jsr print_string

@done:
        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; do_load_key - load an AES key from disk
; =============================================================================
do_load_key:
        lda #$0d
        jsr chrout

        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_drive

        ; parse drive number from input
        lda filename_buf
        sec
        sbc #$30                ; convert ascii to number
        cmp #10                 ; valid digit?
        bcs @use_default_drive
        sta drive_number
        jmp @got_drive

@use_default_drive:
        lda #8
        sta drive_number

@got_drive:
        ; print selected drive
        lda #<using_drive_msg
        ldy #>using_drive_msg
        jsr print_string
        lda drive_number
        jsr print_decimal
        lda #$0d
        jsr chrout

        ; --- get filename ---
        lda #<load_filename_prompt_msg
        ldy #>load_filename_prompt_msg
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_name

        ; copy user filename
        jsr copy_input_to_filename
        lda #0                  ; user specified name
        sta using_default_name
        jmp @got_filename

@use_default_name:
        ; use default "AESKEY"
        jsr set_default_filename
        lda #1                  ; using default
        sta using_default_name

        ; notify user we're using default
        lda #<loading_default_msg
        ldy #>loading_default_msg
        jsr print_string

@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        bne @do_load            ; file exists, proceed

        ; file doesn't exist
        lda #<file_not_found_msg
        ldy #>file_not_found_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @done

@do_load:
        ; --- print loading message ---
        lda #<loading_key_msg
        ldy #>loading_key_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout

        ; --- read the key from disk ---
        jsr read_key_from_disk
        bcs @load_error

        ; --- display the loaded key ---
        lda #<key_loaded_msg
        ldy #>key_loaded_msg
        jsr print_string

        lda #<key_read_buf
        sta zp_ptr
        lda #>key_read_buf
        sta zp_ptr+1
        lda #32
        sta zp_count
        lda #8
        jsr display_hex_block

        ; --- copy loaded key to key_data for use ---
        ldx #0
@copy_key:
        lda key_read_buf,x
        sta key_data,x
        inx
        cpx #32
        bne @copy_key

        ; --- re-expand the key for AES ---
        lda #<reexpanding_msg
        ldy #>reexpanding_msg
        jsr print_string
        jsr aes_key_expansion

        ; DEBUG: show first 16 bytes of expanded key
        lda #<dbg_expkey_msg
        ldy #>dbg_expkey_msg
        jsr print_string
        lda #<expanded_key
        sta zp_ptr
        lda #>expanded_key
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        lda #<load_success_msg
        ldy #>load_success_msg
        jsr print_string
        jmp @done

@load_error:
        lda #<load_error_msg
        ldy #>load_error_msg
        jsr print_string

@done:
        ; print instructions
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; do_save_encrypted - save encrypted text to disk
; =============================================================================
do_save_encrypted:
        lda #$0d
        jsr chrout

        ; check if there's encrypted data
        lda encrypt_length
        bne @has_data

        lda #<no_encrypted_msg
        ldy #>no_encrypted_msg
        jsr print_string
        rts

@has_data:
        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_drive

        ; parse drive number from input
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
        lda #<msg_filename_prompt_msg
        ldy #>msg_filename_prompt_msg
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_name

        ; copy user filename
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename

@use_default_name:
        jsr set_default_msg_filename
        lda #1
        sta using_default_name

@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        beq @do_save

        ; file exists
        lda #<file_exists_msg
        ldy #>file_exists_msg
        jsr print_string

        lda using_default_name
        beq @prompt_new_name

        ; using default name, increment it
        jsr increment_msg_filename
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
        ; --- print IV being saved ---
        lda #<saving_msg_msg
        ldy #>saving_msg_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout

        lda #<saving_iv_msg
        ldy #>saving_iv_msg
        jsr print_string

        ; display IV
        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<enc_value_msg
        ldy #>enc_value_msg
        jsr print_string

        ; display encrypted bytes
        lda #<encrypt_buffer
        sta zp_ptr
        lda #>encrypt_buffer
        sta zp_ptr+1
        lda encrypt_length
        sta zp_count
        lda #8
        jsr display_hex_block

        ; --- save to disk ---
        jsr save_encrypted_to_disk
        bcs @save_error

        lda #<save_success_msg
        ldy #>save_success_msg
        jsr print_string

        ; --- read back and display ---
        lda #<reading_enc_back_msg
        ldy #>reading_enc_back_msg
        jsr print_string

        jsr read_encrypted_with_iv_from_disk
        bcs @read_error

        ; display IV read back
        lda #<iv_read_back_msg
        ldy #>iv_read_back_msg
        jsr print_string

        lda #<iv_read_buf
        sta zp_ptr
        lda #>iv_read_buf
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #8
        jsr display_hex_block

        ; display encrypted data read back
        lda #<enc_read_msg
        ldy #>enc_read_msg
        jsr print_string

        lda #<enc_read_buf
        sta zp_ptr
        lda #>enc_read_buf
        sta zp_ptr+1
        lda enc_read_length
        sta zp_count
        lda #8
        jsr display_hex_block

        jmp @done

@save_error:
        lda #<save_error_msg
        ldy #>save_error_msg
        jsr print_string
        jmp @done

@read_error:
        lda #<read_error_msg
        ldy #>read_error_msg
        jsr print_string

@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; set_default_msg_filename - set filename to "AESMSG"
; =============================================================================
set_default_msg_filename:
        ldx #0
@loop:
        lda default_msg_filename,x
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
        sta msg_filename_suffix
        rts

; =============================================================================
; increment_msg_filename - increment the numeric suffix for msg files
; returns: carry set if exhausted (reached 9)
; =============================================================================
increment_msg_filename:
        lda msg_filename_suffix
        cmp #10
        bcs @exhausted

        inc msg_filename_suffix
        lda msg_filename_suffix

        clc
        adc #$2F
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
; save_encrypted_to_disk - save encrypted buffer to disk as hex
; returns: carry clear = success, carry set = error
; =============================================================================
save_encrypted_to_disk:
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

        ; first write the IV (16 bytes) as hex
        lda #0
        sta save_byte_index

@write_iv_loop:
        ldx save_byte_index
        cpx #16
        beq @iv_done

        lda iv_data,x

        ; write high nibble
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit

        ; write low nibble
        pla
        and #$0f
        jsr write_hex_digit

        ; write space
        lda #$20
        jsr chrout

        inc save_byte_index
        jmp @write_iv_loop

@iv_done:
        ; write newline after IV
        lda #$0d
        jsr chrout

        ; now write encrypted bytes as hex
        lda #0
        sta save_byte_index

@write_loop:
        ldx save_byte_index
        cpx encrypt_length
        beq @write_done

        lda encrypt_buffer,x

        ; write high nibble
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit

        ; write low nibble
        pla
        and #$0f
        jsr write_hex_digit

        ; write space
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
        jmp @write_loop

@write_done:
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
; read_encrypted_with_iv_from_disk - read IV and encrypted data, store IV in iv_read_buf
; returns: carry clear = success, carry set = error
; =============================================================================
read_encrypted_with_iv_from_disk:
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
        bcs @error

        ldx #4
        jsr chkin
        bcs @close_error

        ; first read the IV (16 bytes) into iv_read_buf
        lda #0
        sta read_byte_index

@read_iv_loop:
        lda read_byte_index
        cmp #16
        beq @iv_done

        ; read high nibble
        jsr read_hex_char
        bcs @close_error
        asl
        asl
        asl
        asl
        sta read_temp_byte

        ; read low nibble
        jsr read_hex_char
        bcs @close_error
        ora read_temp_byte

        ; store in iv_read_buf
        ldx read_byte_index
        sta iv_read_buf,x

        inc read_byte_index
        jmp @read_iv_loop

@iv_done:
        ; now read encrypted data into enc_read_buf
        lda #0
        sta read_byte_index
        sta enc_read_length

@read_loop:
        lda read_byte_index
        cmp #64
        bcs @read_done

        jsr read_hex_char
        bcs @read_done
        asl
        asl
        asl
        asl
        sta read_temp_byte

        jsr read_hex_char
        bcs @read_done
        ora read_temp_byte

        ldx read_byte_index
        sta enc_read_buf,x

        inc read_byte_index
        inc enc_read_length
        jmp @read_loop

@read_done:
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

; =============================================================================
; read_encrypted_from_disk - read encrypted data from disk
; returns: carry clear = success, carry set = error
; =============================================================================
read_encrypted_from_disk:
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
        bcs @error

        ldx #4
        jsr chkin
        bcs @close_error

        ; first skip the IV (16 bytes = 32 hex chars + spaces)
        lda #0
        sta read_byte_index

@skip_iv_loop:
        lda read_byte_index
        cmp #16
        beq @iv_skipped

        ; read and discard high nibble
        jsr read_hex_char
        bcs @close_error

        ; read and discard low nibble
        jsr read_hex_char
        bcs @close_error

        inc read_byte_index
        jmp @skip_iv_loop

@iv_skipped:
        ; now read encrypted data
        lda #0
        sta read_byte_index
        sta enc_read_length

@read_loop:
        ; check if buffer full
        lda read_byte_index
        cmp #64                 ; max buffer size
        bcs @read_done

        ; read high nibble
        jsr read_hex_char
        bcs @read_done          ; EOF or error
        asl
        asl
        asl
        asl
        sta read_temp_byte

        ; read low nibble
        jsr read_hex_char
        bcs @read_done
        ora read_temp_byte

        ; store byte
        ldx read_byte_index
        sta enc_read_buf,x

        inc read_byte_index
        inc enc_read_length
        jmp @read_loop

@read_done:
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

; =============================================================================
; do_load_encrypted - load encrypted text from disk
; =============================================================================
do_load_encrypted:
        lda #$0d
        jsr chrout

        ; --- get drive number ---
        lda #<drive_prompt_msg
        ldy #>drive_prompt_msg
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_drive

        ; parse drive number from input
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
        lda #<load_msg_filename_prompt
        ldy #>load_msg_filename_prompt
        jsr print_string

        jsr get_input_line
        lda input_index
        beq @use_default_name

        ; copy user filename
        jsr copy_input_to_filename
        lda #0
        sta using_default_name
        jmp @got_filename

@use_default_name:
        jsr set_default_msg_filename
        lda #1
        sta using_default_name

        ; notify user we're using default
        lda #<loading_default_msg_msg
        ldy #>loading_default_msg_msg
        jsr print_string

@got_filename:
        ; --- check if file exists ---
        jsr check_file_exists
        lda file_exists_flag
        bne @do_load

        ; file doesn't exist
        lda #<file_not_found_msg
        ldy #>file_not_found_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        jmp @done

@do_load:
        ; --- print loading message ---
        lda #<loading_enc_msg
        ldy #>loading_enc_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout

        ; --- read encrypted data from disk ---
        jsr load_encrypted_from_disk
        bcs @load_error

        ; --- display the loaded IV ---
        lda #<loaded_iv_msg
        ldy #>loaded_iv_msg
        jsr print_string

        lda #<iv_data
        sta zp_ptr
        lda #>iv_data
        sta zp_ptr+1
        lda #16
        sta zp_count
        lda #16
        jsr display_hex_block

        ; --- display the loaded encrypted data ---
        lda #<enc_loaded_msg
        ldy #>enc_loaded_msg
        jsr print_string

        lda #<encrypt_buffer
        sta zp_ptr
        lda #>encrypt_buffer
        sta zp_ptr+1
        lda encrypt_length
        sta zp_count
        lda #8
        jsr display_hex_block

        lda #<enc_load_success_msg
        ldy #>enc_load_success_msg
        jsr print_string
        jmp @done

@load_error:
        lda #<enc_load_error_msg
        ldy #>enc_load_error_msg
        jsr print_string

@done:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; load_encrypted_from_disk - read encrypted data into encrypt_buffer
; returns: carry clear = success, carry set = error
; =============================================================================
load_encrypted_from_disk:
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
        bcs @error

        ldx #4
        jsr chkin
        bcs @close_error

        ; first read the IV (16 bytes)
        lda #0
        sta read_byte_index

@read_iv_loop:
        lda read_byte_index
        cmp #16
        beq @iv_done

        ; read high nibble
        jsr read_hex_char
        bcs @close_error        ; EOF or error - file format wrong
        asl
        asl
        asl
        asl
        sta read_temp_byte

        ; read low nibble
        jsr read_hex_char
        bcs @close_error
        ora read_temp_byte

        ; store byte in iv_data
        ldx read_byte_index
        sta iv_data,x

        inc read_byte_index
        jmp @read_iv_loop

@iv_done:
        ; now read encrypted data into encrypt_buffer
        lda #0
        sta read_byte_index
        sta encrypt_length

@read_loop:
        ; check if buffer full
        lda read_byte_index
        cmp #64                 ; max buffer size
        bcs @read_done

        ; read high nibble
        jsr read_hex_char
        bcs @read_done          ; EOF or error
        asl
        asl
        asl
        asl
        sta read_temp_byte

        ; read low nibble
        jsr read_hex_char
        bcs @read_done
        ora read_temp_byte

        ; store byte in encrypt_buffer
        ldx read_byte_index
        sta encrypt_buffer,x

        inc read_byte_index
        inc encrypt_length
        jmp @read_loop

@read_done:
        jsr clrchn
        lda #4
        jsr close

        ; check we got at least some data
        lda encrypt_length
        beq @error

        clc
        rts

@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec
        rts

; =============================================================================
; get_input_line - get a line of input into filename_buf
; =============================================================================
get_input_line:
        lda #0
        sta input_index

        ldx #0
@clear:
        sta filename_buf,x
        inx
        cpx #17
        bne @clear

@loop:
        jsr getin
        beq @loop

        cmp #petscii_return
        beq @done

        cmp #$14                ; delete
        beq @delete

        ldx input_index
        cpx #16                 ; max 16 chars
        bcs @loop

        sta filename_buf,x
        inc input_index
        jsr chrout
        jmp @loop

@delete:
        ldx input_index
        beq @loop
        dex
        stx input_index
        lda #0
        sta filename_buf,x
        lda #$14
        jsr chrout
        jmp @loop

@done:
        lda #$0d
        jsr chrout
        rts

; =============================================================================
; copy_input_to_filename - copy filename_buf to actual_filename
; =============================================================================
copy_input_to_filename:
        ldx #0
@loop:
        lda filename_buf,x
        beq @done
        sta actual_filename,x
        inx
        cpx #16
        bne @loop
@done:
        stx filename_len
        rts

; =============================================================================
; set_default_filename - set filename to "AESKEY"
; =============================================================================
set_default_filename:
        ; copy "AESKEY" to actual_filename
        ldx #0
@loop:
        lda default_filename,x
        sta actual_filename,x
        beq @done               ; stop at null terminator
        inx
        cpx #7
        bne @loop
@done:
        lda #0
        sta actual_filename,x   ; ensure null terminated
        lda #6
        sta filename_len
        lda #0
        sta filename_suffix     ; reset suffix counter
        rts

; =============================================================================
; increment_filename - increment the numeric suffix
; returns: carry set if we've exhausted all options (reached 9)
; =============================================================================
increment_filename:
        ; check if we've already tried 9
        lda filename_suffix
        cmp #10
        bcs @exhausted          ; already at max

        inc filename_suffix
        lda filename_suffix

        ; add digit to filename at position 6 (after "AESKEY")
        clc
        adc #$2F                ; convert 1-10 to '0'-'9' (adc #$30 - 1 since we inc'd)
        ldx #6
        sta actual_filename,x
        lda #0
        sta actual_filename+7   ; null terminate
        lda #7
        sta filename_len

        clc                     ; success, can try this name
        rts

@exhausted:
        sec                     ; no more options
        rts

; =============================================================================
; print_filename - print the current filename
; =============================================================================
print_filename:
        ldx #0
@loop:
        lda actual_filename,x
        beq @done
        jsr chrout
        inx
        cpx #16
        bne @loop
@done:
        rts

; =============================================================================
; check_file_exists - check if file already exists on disk
; sets file_exists_flag (0 = no, 1 = yes)
; uses the command channel to check for file
; =============================================================================
check_file_exists:
        lda #0
        sta file_exists_flag

        ; try to open the file for reading
        ; if it opens successfully, file exists
        ; build filename: "0:filename,s,r"
        jsr build_read_filename

        ; set filename
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam

        ; set logical file
        lda #2                  ; logical file 2
        ldx drive_number
        ldy #2                  ; secondary address 2
        jsr setlfs

        ; try to open
        jsr open
        bcs @not_found          ; open failed, file doesn't exist

        ; check the error channel
        jsr check_disk_error
        bcs @close_not_found    ; error means file not found

        ; file opened successfully, it exists
        lda #1
        sta file_exists_flag

@close_not_found:
        ; close the file
        jsr clrchn
        lda #2
        jsr close
        rts

@not_found:
        ; file doesn't exist
        lda #0
        sta file_exists_flag
        rts

; =============================================================================
; check_disk_error - read error channel, return carry set if error
; =============================================================================
check_disk_error:
        ; open command channel (15)
        lda #0                  ; no filename
        ldx #<cmd_buffer
        ldy #>cmd_buffer
        jsr setnam

        lda #15                 ; logical file 15
        ldx drive_number
        ldy #15                 ; command channel
        jsr setlfs

        jsr open
        bcs @error

        ; read from command channel
        ldx #15
        jsr chkin
        bcs @close_error

        ; read first character (error number tens digit)
        jsr chrin
        sta disk_error_code

        ; read second character (error number ones digit)
        jsr chrin
        sta disk_error_code+1

        ; clear channel and close
        jsr clrchn
        lda #15
        jsr close

        ; check if error code is "00" (no error)
        lda disk_error_code
        cmp #$30                ; '0'
        bne @is_error
        lda disk_error_code+1
        cmp #$30                ; '0'
        bne @is_error

        ; no error
        clc
        rts

@close_error:
        jsr clrchn
        lda #15
        jsr close
@error:
@is_error:
        sec
        rts

; =============================================================================
; save_key_to_disk - save 32-byte key to disk
; returns: carry clear = success, carry set = error
; =============================================================================
save_key_to_disk:
        ; build full filename with drive: "0:filename,s,w"
        jsr build_write_filename

        ; set filename
        lda write_fname_len
        ldx #<write_fname_buf
        ldy #>write_fname_buf
        jsr setnam

        ; set logical file
        lda #3                  ; logical file 3
        ldx drive_number
        ldy #3                  ; secondary address 3
        jsr setlfs

        ; open file
        jsr open
        bcs @error

        ; set output channel
        ldx #3
        jsr chkout
        bcs @close_error

        ; write 32 key bytes as hex (64 hex chars + spaces + newlines)
        lda #0
        sta save_byte_index

@write_loop:
        ldx save_byte_index
        lda key_data,x

        ; write high nibble
        pha
        lsr
        lsr
        lsr
        lsr
        jsr write_hex_digit

        ; write low nibble
        pla
        and #$0f
        jsr write_hex_digit

        ; write space
        lda #$20
        jsr chrout

        ; check for newline every 8 bytes
        lda save_byte_index
        and #$07
        cmp #$07
        bne @no_newline
        lda #$0d
        jsr chrout
@no_newline:

        inc save_byte_index
        lda save_byte_index
        cmp #32
        bne @write_loop

        ; check status
        jsr readst
        bne @close_error

        ; close file
        jsr clrchn
        lda #3
        jsr close

        clc                     ; success
        rts

@close_error:
        jsr clrchn
        lda #3
        jsr close
@error:
        sec                     ; error
        rts

; =============================================================================
; write_hex_digit - write a hex digit (0-15) to output channel
; input: A = value 0-15
; =============================================================================
write_hex_digit:
        cmp #10
        bcc @digit
        ; A-F
        clc
        adc #($41 - 10)         ; 'A' - 10
        jmp chrout
@digit:
        ; 0-9
        clc
        adc #$30                ; '0'
        jmp chrout

; =============================================================================
; read_key_from_disk - read 32-byte key from disk
; returns: carry clear = success, carry set = error
; =============================================================================
read_key_from_disk:
        ; build full filename with drive: "0:filename,s,r"
        jsr build_read_filename

        ; set filename
        lda read_fname_len
        ldx #<read_fname_buf
        ldy #>read_fname_buf
        jsr setnam

        ; set logical file
        lda #4                  ; logical file 4
        ldx drive_number
        ldy #4                  ; secondary address
        jsr setlfs

        ; open file
        jsr open
        bcs @error

        ; set input channel
        ldx #4
        jsr chkin
        bcs @close_error

        ; read hex text and convert to 32 bytes
        lda #0
        sta read_byte_index

@read_loop:
        ; read high nibble character
        jsr read_hex_char
        bcs @close_error        ; error or EOF
        asl
        asl
        asl
        asl
        sta read_temp_byte      ; store high nibble shifted

        ; read low nibble character
        jsr read_hex_char
        bcs @close_error
        ora read_temp_byte      ; combine with high nibble

        ; store the byte
        ldx read_byte_index
        sta key_read_buf,x

        inc read_byte_index
        lda read_byte_index
        cmp #32
        bne @read_loop

        ; close file
        jsr clrchn
        lda #4
        jsr close

        clc                     ; success
        rts

@close_error:
        jsr clrchn
        lda #4
        jsr close
@error:
        sec                     ; error
        rts

; =============================================================================
; read_hex_char - read next hex character, skipping spaces/newlines
; returns: A = value 0-15, carry clear on success
;          carry set on error/EOF
; =============================================================================
read_hex_char:
@skip_loop:
        jsr chrin
        pha
        jsr readst
        and #$40                ; EOF?
        bne @eof
        pla

        ; skip spaces, newlines, carriage returns
        cmp #$20                ; space
        beq @skip_loop
        cmp #$0d                ; carriage return
        beq @skip_loop
        cmp #$0a                ; line feed
        beq @skip_loop

        ; convert hex char to value
        cmp #$30                ; '0'
        bcc @invalid
        cmp #$3a                ; '9' + 1
        bcc @is_digit

        ; check for A-F (uppercase)
        cmp #$41                ; 'A'
        bcc @invalid
        cmp #$47                ; 'F' + 1
        bcc @is_upper

        ; check for a-f (lowercase)
        cmp #$61                ; 'a'
        bcc @invalid
        cmp #$67                ; 'f' + 1
        bcs @invalid

        ; lowercase a-f
        sec
        sbc #($61 - 10)         ; convert 'a'-'f' to 10-15
        clc
        rts

@is_upper:
        ; uppercase A-F
        sec
        sbc #($41 - 10)         ; convert 'A'-'F' to 10-15
        clc
        rts

@is_digit:
        ; 0-9
        sec
        sbc #$30                ; convert '0'-'9' to 0-9
        clc
        rts

@eof:
        pla
@invalid:
        sec
        rts

; =============================================================================
; build_write_filename - build "0:filename,s,w" in write_fname_buf
; =============================================================================
build_write_filename:
        lda #$30                ; '0'
        sta write_fname_buf
        lda #$3a                ; ':'
        sta write_fname_buf+1

        ldx #0
@copy:
        lda actual_filename,x
        beq @add_suffix
        sta write_fname_buf+2,x
        inx
        cpx #16
        bne @copy

@add_suffix:
        txa
        clc
        adc #2
        tay                     ; y = position after name

        lda #$2c                ; ','
        sta write_fname_buf,y
        iny
        lda #$53                ; 'S' (sequential)
        sta write_fname_buf,y
        iny
        lda #$2c                ; ','
        sta write_fname_buf,y
        iny
        lda #$57                ; 'W' (write)
        sta write_fname_buf,y
        iny

        sty write_fname_len
        rts

; =============================================================================
; build_read_filename - build "0:filename,s,r" in read_fname_buf
; =============================================================================
build_read_filename:
        lda #$30                ; '0'
        sta read_fname_buf
        lda #$3a                ; ':'
        sta read_fname_buf+1

        ldx #0
@copy:
        lda actual_filename,x
        beq @add_suffix
        sta read_fname_buf+2,x
        inx
        cpx #16
        bne @copy

@add_suffix:
        txa
        clc
        adc #2
        tay

        lda #$2c                ; ','
        sta read_fname_buf,y
        iny
        lda #$53                ; 'S'
        sta read_fname_buf,y
        iny
        lda #$2c                ; ','
        sta read_fname_buf,y
        iny
        lda #$52                ; 'R' (read)
        sta read_fname_buf,y
        iny

        sty read_fname_len
        rts

; =============================================================================
; verify_key_match - verify read key matches original
; returns: carry clear = match, carry set = mismatch
; =============================================================================
verify_key_match:
        ldx #0
@loop:
        lda key_data,x
        cmp key_read_buf,x
        bne @mismatch
        inx
        cpx #32
        bne @loop

        clc                     ; match
        rts

@mismatch:
        sec                     ; mismatch
        rts

; =============================================================================
; print_decimal - print A as decimal number
; =============================================================================
print_decimal:
        ldx #0
        stx decimal_flag

        ; hundreds
        ldx #0
@hundreds:
        cmp #100
        bcc @tens
        sbc #100
        inx
        jmp @hundreds
@tens:
        pha
        txa
        beq @skip_hundreds
        ora #$30
        jsr chrout
        inc decimal_flag
@skip_hundreds:
        pla

        ; tens
        ldx #0
@tens_loop:
        cmp #10
        bcc @ones
        sbc #10
        inx
        jmp @tens_loop
@ones:
        pha
        txa
        bne @print_tens
        lda decimal_flag
        beq @skip_tens
@print_tens:
        txa
        ora #$30
        jsr chrout
@skip_tens:
        pla

        ; ones
        ora #$30
        jsr chrout
        rts
