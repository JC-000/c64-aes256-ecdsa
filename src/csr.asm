; =============================================================================
; csr.asm - CSR submenu, field collection, format/preview, save, field buffers/labels
; Related: ecdsa_p256.asm
; =============================================================================

; =============================================================================
; CSR (Certificate Signing Request) Generation
; =============================================================================
; Generates a text-format CSR containing the AES-256 key and X.509
; subject fields entered by the user. Output is a human-readable
; sequential text file suitable for submission to a CA or for use
; with external tools that convert to PKCS#10 DER/PEM format.
;
; CSR format:
;   -----BEGIN CERTIFICATE REQUEST-----
;   Key-Type: AES-256
;   Key: <64 hex digits>
;   Subject: /C=xx/ST=xx/L=xx/O=xx/OU=xx/CN=xx
;   Email: xx
;   -----END CERTIFICATE REQUEST-----
; =============================================================================

; =============================================================================
; do_generate_csr - CSR/ECDSA sub-menu handler
; =============================================================================
do_generate_csr:
        lda #$0d
        jsr chrout
        lda #<csr_submenu_msg
        ldy #>csr_submenu_msg
        jsr print_string

        jsr getin_wait
        cmp #'1'
        beq @do_csr
        cmp #'2'
        beq @do_ecdsa_test
        ; Any other key = return
        rts

@do_ecdsa_test:
        jsr do_ecdsa_test
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

@do_csr:
        lda #<csr_header_msg
        ldy #>csr_header_msg
        jsr print_string
        
        ; --- Prompt for each CSR field ---
        
        ; Country (C) - 2 letter code
        lda #<csr_country_prompt
        ldy #>csr_country_prompt
        jsr print_string
        lda #<csr_country
        sta csr_field_ptr
        lda #>csr_country
        sta csr_field_ptr+1
        lda #2                  ; max 2 chars
        jsr csr_get_field
        sta csr_country_len
        
        ; State/Province (ST)
        lda #<csr_state_prompt
        ldy #>csr_state_prompt
        jsr print_string
        lda #<csr_state
        sta csr_field_ptr
        lda #>csr_state
        sta csr_field_ptr+1
        lda #32                 ; max 32 chars
        jsr csr_get_field
        sta csr_state_len
        
        ; Locality/City (L)
        lda #<csr_city_prompt
        ldy #>csr_city_prompt
        jsr print_string
        lda #<csr_city
        sta csr_field_ptr
        lda #>csr_city
        sta csr_field_ptr+1
        lda #32
        jsr csr_get_field
        sta csr_city_len
        
        ; Organization (O)
        lda #<csr_org_prompt
        ldy #>csr_org_prompt
        jsr print_string
        lda #<csr_org
        sta csr_field_ptr
        lda #>csr_org
        sta csr_field_ptr+1
        lda #32
        jsr csr_get_field
        sta csr_org_len
        
        ; Organizational Unit (OU)
        lda #<csr_ou_prompt
        ldy #>csr_ou_prompt
        jsr print_string
        lda #<csr_ou
        sta csr_field_ptr
        lda #>csr_ou
        sta csr_field_ptr+1
        lda #32
        jsr csr_get_field
        sta csr_ou_len
        
        ; Common Name (CN)
        lda #<csr_cn_prompt
        ldy #>csr_cn_prompt
        jsr print_string
        lda #<csr_cn
        sta csr_field_ptr
        lda #>csr_cn
        sta csr_field_ptr+1
        lda #40                 ; max 40 chars
        jsr csr_get_field
        sta csr_cn_len

        ; Email address
        lda #<csr_email_prompt
        ldy #>csr_email_prompt
        jsr print_string
        lda #<csr_email
        sta csr_field_ptr
        lda #>csr_email
        sta csr_field_ptr+1
        lda #40
        jsr csr_get_field
        sta csr_email_len

        ; Check at least one field is filled
        lda csr_country_len
        ora csr_state_len
        ora csr_city_len
        ora csr_org_len
        ora csr_ou_len
        ora csr_cn_len
        ora csr_email_len
        bne @fields_ok
        lda #<csr_empty_msg
        ldy #>csr_empty_msg
        jsr print_string
        rts
@fields_ok:
        
        ; --- Preview CSR on screen ---
        lda #$0d
        jsr chrout
        lda #<csr_preview_msg
        ldy #>csr_preview_msg
        jsr print_string
        
        jsr csr_print_content
        
        ; --- Prompt to save ---
        lda #<csr_save_prompt
        ldy #>csr_save_prompt
        jsr print_string
        
        jsr getin_wait
        cmp #'N'
        bne +
        jmp @csr_exit
+       cmp #'n'
        bne +
        jmp @csr_exit
+
        ; --- Get drive number ---
        lda #<csr_drive_prompt
        ldy #>csr_drive_prompt
        jsr print_string
        
        jsr get_input_line
        lda input_index
        beq @csr_default_drive
        lda filename_buf
        sec
        sbc #$30
        cmp #10
        bcs @csr_default_drive
        sta csr_drive_num
        jmp @csr_got_drive
        
@csr_default_drive:
        lda #8
        sta csr_drive_num
        
@csr_got_drive:
        lda #<csr_using_drive_msg
        ldy #>csr_using_drive_msg
        jsr print_string
        lda csr_drive_num
        jsr print_decimal
        lda #$0d
        jsr chrout
        
        ; --- Get filename ---
        lda #<csr_fname_prompt
        ldy #>csr_fname_prompt
        jsr print_string
        
        jsr get_input_line
        lda input_index
        bne @csr_user_fname
        
        ; Use default "MYCSR"
        ldx #0
@copy_default_csr:
        lda csr_default_fname,x
        beq @default_csr_done
        sta actual_filename,x
        inx
        jmp @copy_default_csr
@default_csr_done:
        stx filename_len
        jmp @csr_got_fname
        
@csr_user_fname:
        jsr copy_input_to_filename
        
@csr_got_fname:
        ; --- Write CSR to disk ---
        lda #<csr_saving_msg
        ldy #>csr_saving_msg
        jsr print_string
        jsr print_filename
        lda #$0d
        jsr chrout
        
        jsr csr_save_to_disk
        bcs @csr_save_error
        
        lda #<csr_save_ok_msg
        ldy #>csr_save_ok_msg
        jsr print_string
        jmp @csr_exit
        
@csr_save_error:
        lda #<csr_save_fail_msg
        ldy #>csr_save_fail_msg
        jsr print_string
        
@csr_exit:
        lda #<instructions_msg
        ldy #>instructions_msg
        jsr print_string
        rts

; =============================================================================
; csr_get_field - read user input into a CSR field buffer
; csr_field_ptr = destination pointer (set by caller)
; A = max length
; Returns: A = length of input
; =============================================================================
csr_get_field:
        sta csr_max_len
        lda #0
        sta csr_input_len
        
        ; Clear destination buffer
        ldy #0
        lda #0
@clear:
        cpy csr_max_len
        beq @input_loop
        sta (csr_field_ptr),y
        iny
        jmp @clear
        
@input_loop:
        jsr getin
        beq @input_loop
        
        cmp #petscii_return
        beq @input_done
        
        cmp #$14                ; delete
        beq @input_del
        
        ; Check max length
        ldx csr_input_len
        cpx csr_max_len
        bcs @input_loop         ; at max, ignore
        
        ; Store character
        ldy csr_input_len
        sta (csr_field_ptr),y
        inc csr_input_len
        jsr chrout              ; echo
        jmp @input_loop
        
@input_del:
        ldx csr_input_len
        beq @input_loop         ; nothing to delete
        dex
        stx csr_input_len
        txa
        tay
        lda #0
        sta (csr_field_ptr),y
        lda #$14                ; backspace on screen
        jsr chrout
        jmp @input_loop
        
@input_done:
        lda #$0d
        jsr chrout
        lda csr_input_len
        rts

; =============================================================================
; csr_print_content - output the CSR content via chrout
; Works for both screen display and file output (after chkout)
; =============================================================================
csr_print_content:
        ; -----BEGIN CERTIFICATE REQUEST-----
        lda #<csr_begin_line
        ldy #>csr_begin_line
        jsr csr_write_string
        
        ; Key-Type: AES-256
        lda #<csr_keytype_line
        ldy #>csr_keytype_line
        jsr csr_write_string
        
        ; Key: <hex>
        lda #<csr_key_label
        ldy #>csr_key_label
        jsr csr_write_string
        
        ; Write 32 key bytes as 64 hex chars (no spaces)
        lda #0
        sta csr_byte_idx
@key_loop:
        ldx csr_byte_idx
        lda key_data,x
        pha
        lsr
        lsr
        lsr
        lsr
        jsr csr_write_hex_nibble
        pla
        and #$0f
        jsr csr_write_hex_nibble
        inc csr_byte_idx
        lda csr_byte_idx
        cmp #32
        bne @key_loop
        lda #$0d
        jsr chrout
        
        ; Subject: /C=xx/ST=xx/L=xx/O=xx/OU=xx/CN=xx
        lda #<csr_subject_label
        ldy #>csr_subject_label
        jsr csr_write_string
        
        ; /C=
        lda csr_country_len
        beq @skip_c
        lda #<csr_tag_c
        ldy #>csr_tag_c
        jsr csr_write_string
        lda #<csr_country
        ldy #>csr_country
        ldx csr_country_len
        jsr csr_write_field
@skip_c:
        ; /ST=
        lda csr_state_len
        beq @skip_st
        lda #<csr_tag_st
        ldy #>csr_tag_st
        jsr csr_write_string
        lda #<csr_state
        ldy #>csr_state
        ldx csr_state_len
        jsr csr_write_field
@skip_st:
        ; /L=
        lda csr_city_len
        beq @skip_l
        lda #<csr_tag_l
        ldy #>csr_tag_l
        jsr csr_write_string
        lda #<csr_city
        ldy #>csr_city
        ldx csr_city_len
        jsr csr_write_field
@skip_l:
        ; /O=
        lda csr_org_len
        beq @skip_o
        lda #<csr_tag_o
        ldy #>csr_tag_o
        jsr csr_write_string
        lda #<csr_org
        ldy #>csr_org
        ldx csr_org_len
        jsr csr_write_field
@skip_o:
        ; /OU=
        lda csr_ou_len
        beq @skip_ou
        lda #<csr_tag_ou
        ldy #>csr_tag_ou
        jsr csr_write_string
        lda #<csr_ou
        ldy #>csr_ou
        ldx csr_ou_len
        jsr csr_write_field
@skip_ou:
        ; /CN=
        lda csr_cn_len
        beq @skip_cn
        lda #<csr_tag_cn
        ldy #>csr_tag_cn
        jsr csr_write_string
        lda #<csr_cn
        ldy #>csr_cn
        ldx csr_cn_len
        jsr csr_write_field
@skip_cn:
        
        lda #$0d
        jsr chrout
        
        ; Email: (if provided)
        lda csr_email_len
        beq @skip_email
        lda #<csr_email_label
        ldy #>csr_email_label
        jsr csr_write_string
        lda #<csr_email
        ldy #>csr_email
        ldx csr_email_len
        jsr csr_write_field
        lda #$0d
        jsr chrout
@skip_email:
        
        ; -----END CERTIFICATE REQUEST-----
        lda #<csr_end_line
        ldy #>csr_end_line
        jsr csr_write_string
        
        rts

; =============================================================================
; csr_write_string - write null-terminated string via chrout
; =============================================================================
csr_write_string:
        sta csr_ws_lo
        sty csr_ws_hi
        ldy #0
@loop:
        lda (csr_ws_lo),y
        beq @done
        jsr chrout
        iny
        bne @loop
@done:
        rts
csr_ws_lo = zp_ptr              ; reuse zp_ptr

; Alias for high byte
csr_ws_hi = zp_ptr+1

; =============================================================================
; csr_write_field - write field buffer of known length via chrout
; A/Y = buffer address low/high, X = length
; =============================================================================
csr_write_field:
        sta csr_wf_lo
        sty csr_wf_hi
        stx csr_wf_len
        ldy #0
@loop:
        cpy csr_wf_len
        beq @done
        lda (csr_wf_lo),y
        jsr chrout
        iny
        jmp @loop
@done:
        rts

csr_wf_lo = zp_ptr2            ; reuse zp_ptr2
csr_wf_hi = zp_ptr2+1
csr_wf_len:
        !byte 0

; =============================================================================
; csr_write_hex_nibble - write a single hex nibble via chrout
; A = value 0-15
; =============================================================================
csr_write_hex_nibble:
        cmp #10
        bcc @digit
        clc
        adc #($41 - 10)         ; 'A'
        jmp chrout
@digit:
        clc
        adc #$30                ; '0'
        jmp chrout

; =============================================================================
; csr_save_to_disk - write CSR content to sequential file
; Returns: carry clear = success, carry set = error
; =============================================================================
csr_save_to_disk:
        ; Ensure clean I/O state
        jsr clrchn
        lda #3
        jsr close
        
        ; Build "0:filename,s,w"
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
        bcs @error
        
        ldx #3
        jsr chkout
        bcs @close_error
        
        ; Write CSR content (chrout now directed to file)
        jsr csr_print_content
        
        ; Check status
        jsr readst
        and #$83
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

; --- CSR field pointer (reuses zp_ptr2) ---
csr_field_ptr   = zp_ptr2

; --- CSR variables ---
csr_max_len:    !byte 0
csr_input_len:  !byte 0
csr_byte_idx:   !byte 0
csr_drive_num:  !byte 8

csr_country:    !fill 3, 0
csr_country_len: !byte 0
csr_state:      !fill 33, 0
csr_state_len:  !byte 0
csr_city:       !fill 33, 0
csr_city_len:   !byte 0
csr_org:        !fill 33, 0
csr_org_len:    !byte 0
csr_ou:         !fill 33, 0
csr_ou_len:     !byte 0
csr_cn:         !fill 41, 0
csr_cn_len:     !byte 0
csr_email:      !fill 41, 0
csr_email_len:  !byte 0

csr_default_fname:
        !text "MYCSR"
        !byte 0

; --- CSR prompt messages ---
csr_submenu_msg:
        !text "J: CSR/ECDSA"
        !byte $0d
        !text "1=GENERATE CSR  2=ECDSA TEST"
        !byte $0d, 0

csr_header_msg:
        !text "=== CSR GENERATION ==="
        !byte $0d
        !text "ENTER CSR SUBJECT FIELDS."
        !byte $0d
        !text "PRESS RETURN TO SKIP OPTIONAL FIELDS."
        !byte $0d, 0

csr_country_prompt:
        !text "COUNTRY (2 LETTER CODE): "
        !byte 0

csr_state_prompt:
        !text "STATE/PROVINCE: "
        !byte 0

csr_city_prompt:
        !text "CITY/LOCALITY: "
        !byte 0

csr_org_prompt:
        !text "ORGANIZATION: "
        !byte 0

csr_ou_prompt:
        !text "ORG UNIT: "
        !byte 0

csr_cn_prompt:
        !text "COMMON NAME: "
        !byte 0

csr_email_prompt:
        !text "EMAIL ADDRESS: "
        !byte 0

csr_empty_msg:
        !text "AT LEAST ONE FIELD REQUIRED."
        !byte $0d, 0

csr_preview_msg:
        !text "--- CSR PREVIEW ---"
        !byte $0d, 0

csr_save_prompt:
        !byte $0d
        !text "SAVE CSR TO DISK? (Y/N, ENTER=YES) "
        !byte 0

csr_drive_prompt:
        !text "DRIVE NUMBER (ENTER=8): "
        !byte 0

csr_using_drive_msg:
        !text "USING DRIVE "
        !byte 0

csr_fname_prompt:
        !text "FILENAME (ENTER=MYCSR): "
        !byte 0

csr_saving_msg:
        !text "SAVING CSR TO "
        !byte 0

csr_save_ok_msg:
        !text "CSR SAVED SUCCESSFULLY."
        !byte $0d, 0

csr_save_fail_msg:
        !text "ERROR SAVING CSR!"
        !byte $0d, 0

; --- CSR file content strings ---
csr_begin_line:
        !text "-----BEGIN CERTIFICATE REQUEST-----"
        !byte $0d, 0

csr_end_line:
        !text "-----END CERTIFICATE REQUEST-----"
        !byte $0d, 0

csr_keytype_line:
        !text "KEY-TYPE: AES-256"
        !byte $0d, 0

csr_key_label:
        !text "KEY: "
        !byte 0

csr_subject_label:
        !text "SUBJECT: "
        !byte 0

csr_tag_c:
        !text "/C="
        !byte 0

csr_tag_st:
        !text "/ST="
        !byte 0

csr_tag_l:
        !text "/L="
        !byte 0

csr_tag_o:
        !text "/O="
        !byte 0

csr_tag_ou:
        !text "/OU="
        !byte 0

csr_tag_cn:
        !text "/CN="
        !byte 0

csr_email_label:
        !text "EMAIL: "
        !byte 0

