; =============================================================================
; debug_strings.asm - Debug message strings
; =============================================================================

        .segment "LIB_AES256ECDSA_HICODE"

; --- Full EXPORTS list per src/exports.inc's debug_strings.s entry ---
.export debug_len_msg, debug_blk_msg, debug_cur_msg, debug_state_msg
.export debug_after_dec_msg, debug_after_xor_msg, debug_cbc_msg, debug_iv_msg
.export dbg_ark14_msg, dbg_mainrnd_msg, dbg_inlen_msg, dbg_inbuf_msg
.export dbg_blocks_msg, dbg_enclen_msg, dbg_expkey_msg

debug_len_msg:
        .byte "ENC LEN: "
        .byte 0

debug_blk_msg:
        .byte "BLOCKS: "
        .byte 0

debug_cur_msg:
        .byte "CUR BLK: "
        .byte 0

debug_state_msg:
        .byte "STATE: "
        .byte 0

debug_after_dec_msg:
        .byte "AFTER DEC: "
        .byte 0

debug_after_xor_msg:
        .byte "AFTER XOR: "
        .byte 0

debug_cbc_msg:
        .byte "CBC VEC: "
        .byte 0

debug_iv_msg:
        .byte "IV DATA: "
        .byte 0

dbg_ark14_msg:
        .byte "ARK14: "
        .byte 0

dbg_mainrnd_msg:
        .byte "MAINRND: "
        .byte 0

dbg_inlen_msg:
        .byte "IN LEN: "
        .byte 0

dbg_inbuf_msg:
        .byte "IN BUF: "
        .byte 0

dbg_blocks_msg:
        .byte "BLOCKS: "
        .byte 0

dbg_enclen_msg:
        .byte "ENC LEN: "
        .byte 0

dbg_expkey_msg:
        .byte "EXP KEY: "
        .byte 0
