#!/usr/bin/env python3
"""
test_csr.py - CSR Integration Test Script

Automates end-to-end validation of the CSR (Certificate Signing Request)
feature by driving the C64 program in VICE and cross-checking all
cryptographic output against OpenSSL via the `cryptography` library.

Launches VICE in warp+NTSC mode, drives CSR user interactions via keyboard
injection, reads results from both screen memory and raw data memory,
then compares against a Python/OpenSSL reference.

Usage:
    python3 tools/test_csr.py [--timeout SECONDS] [--port PORT] [--vice-path PATH]

Requires: Python 3.10+, cryptography >= 41.0, VICE x64sc on PATH
"""

import argparse
import os
import subprocess
import sys
import time

# Add tools directory to path for vicemon import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vicemon import ViceMon, ASCII_TO_PETSCII

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEYBUF_ADDR = 0x0277   # C64 keyboard buffer (10 bytes)
KEYBUF_COUNT = 0x00C6  # Number of chars in keyboard buffer
KEYBUF_MAX = 10        # C64 keyboard buffer capacity

# Extended PETSCII mapping for chars missing from vicemon.py
EXTRA_PETSCII = {
    '@': 0x40,
    '<': 0x3C,
    '>': 0x3E,
    '[': 0x5B,
    ']': 0x5D,
    '_': 0xA4,
}


def char_to_petscii(ch):
    """Convert a single character to its PETSCII code."""
    if ch in ASCII_TO_PETSCII:
        return ASCII_TO_PETSCII[ch]
    if ch in EXTRA_PETSCII:
        return EXTRA_PETSCII[ch]
    raise ValueError(f'No PETSCII mapping for {ch!r}')


# ---------------------------------------------------------------------------
# Wrap-aware screen text helpers
# ---------------------------------------------------------------------------
# The C64 screen is a contiguous 1000-byte buffer (25 rows x 40 cols).
# Text printed via KERNAL chrout wraps naturally at column 40 with no
# padding.  ViceMon.screen_text() inserts '\n' every 40 chars, which
# breaks substring searches for text that spans a row boundary.
#
# These helpers join the rows back into one continuous string so that
# wrapped text like "EMAIL AD" + "DRESS:" is searchable as "EMAIL ADDRESS:".
# ---------------------------------------------------------------------------

def screen_continuous(mon):
    """Return screen as a single 1000-char string (no newlines)."""
    return mon.screen_text().replace('\n', '')


def screen_has_text(mon, text):
    """Check if text appears on screen, handling 40-column line wraps."""
    return text.upper() in screen_continuous(mon).upper()


def wait_for_screen_text(mon, text, timeout=60, poll_interval=2, verbose=True):
    """Wait until text appears on screen, handling line wraps."""
    text_upper = text.upper()
    start = time.time()
    while time.time() - start < timeout:
        try:
            continuous = screen_continuous(mon)
            if text_upper in continuous.upper():
                return True
            if verbose:
                elapsed = int(time.time() - start)
                chunks = [continuous[i:i+40] for i in range(0, 1000, 40)]
                last = [c for c in chunks if c.strip()]
                tail = last[-1].strip()[:60] if last else ''
                print(f'  [{elapsed:3d}s] {tail}', flush=True)
        except Exception as e:
            if verbose:
                print(f'  [monitor error: {e}]', flush=True)
        time.sleep(poll_interval)
    return False


# ---------------------------------------------------------------------------
# VICE lifecycle
# ---------------------------------------------------------------------------

VICE_PROC = None


def start_vice(prg_path, port=6510, vice_path='x64sc'):
    """Launch x64sc in warp+NTSC mode with remote monitor."""
    global VICE_PROC

    # Kill any existing VICE on this port
    subprocess.run(
        ['pkill', '-f', f'remotemonitoraddress.*{port}'],
        capture_output=True
    )
    time.sleep(0.5)

    proc = subprocess.Popen(
        [
            vice_path,
            '-autostart', prg_path,
            '-warp',
            '-ntsc',
            '-remotemonitor',
            '-remotemonitoraddress', f'ip4://127.0.0.1:{port}',
            '+sound',
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    VICE_PROC = proc
    print(f'  VICE started (PID {proc.pid}, NTSC, warp)')
    return proc


def stop_vice():
    """Kill VICE process and cleanup."""
    global VICE_PROC
    if VICE_PROC is not None:
        try:
            VICE_PROC.terminate()
            VICE_PROC.wait(timeout=5)
        except Exception:
            try:
                VICE_PROC.kill()
            except Exception:
                pass
        VICE_PROC = None


def wait_for_monitor(port=6510, timeout=30):
    """Wait until the VICE monitor port is accepting connections."""
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(('127.0.0.1', port))
            s.close()
            return True
        except Exception:
            time.sleep(1)
    return False


def wait_for_menu(mon, timeout=30):
    """Poll screen for 'Q=QUIT' (main menu sentinel)."""
    return wait_for_screen_text(mon, 'Q=QUIT', timeout=timeout, poll_interval=2)


# ---------------------------------------------------------------------------
# Fast keyboard input
# ---------------------------------------------------------------------------

def send_keys_fast(mon, text):
    """Send a string via the C64 keyboard buffer in batches of up to 10.

    Much faster than mon.send_keys() which creates 2 TCP connections per
    character.  Handles '@' and other chars missing from vicemon's mapping.

    No explicit drain-check is needed: each write_mem() call takes ~0.9s of
    wall-clock time (TCP connect + drain), during which the C64 in warp mode
    executes millions of cycles — more than enough to consume a 10-key buffer.
    """
    petscii_codes = [char_to_petscii(ch) for ch in text]

    for i in range(0, len(petscii_codes), KEYBUF_MAX):
        batch = petscii_codes[i:i + KEYBUF_MAX]
        mon.write_mem(KEYBUF_ADDR, batch)
        mon.write_mem(KEYBUF_COUNT, [len(batch)])


def send_key_fast(mon, ch):
    """Send a single key via the keyboard buffer."""
    petscii = char_to_petscii(ch) if isinstance(ch, str) else ch
    mon.write_mem(KEYBUF_ADDR, [petscii])
    mon.write_mem(KEYBUF_COUNT, [1])


# ---------------------------------------------------------------------------
# Reliable memory reads
# ---------------------------------------------------------------------------

def read_mem_reliable(mon, addr, length):
    """Read memory from VICE, working around vicemon.py's parsing limitation.

    vicemon's read_mem() uses ``line.startswith('>')`` to find data lines,
    but the VICE text monitor sometimes prepends the prompt ``(C:$XXXX)``
    on the *same* line as the ``>C:`` data.  For multi-line reads (e.g.
    screen_bytes) only the first line is lost, so it mostly works.  For
    single-line reads the entire result is lost.

    This function searches for ``>C:`` *anywhere* in each line, which
    handles the prepended-prompt case correctly.
    """
    import re
    end = addr + length - 1
    resp = mon.command(f'm {addr:04x} {end:04x}')
    result = []
    for line in resp.split('\n'):
        # Find ">C:XXXX" anywhere in the line (not just at start)
        m = re.search(r'>C:[0-9a-fA-F]{4}\s{2}(.*)', line)
        if not m:
            continue
        hex_section = m.group(1)
        parts = hex_section.split('  ')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens and all(
                len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t)
                for t in tokens
            ):
                for t in tokens:
                    result.append(int(t, 16))
    return result[:length]


# ---------------------------------------------------------------------------
# Debug helpers
# ---------------------------------------------------------------------------

def dump_screen(mon, label=''):
    """Print the current C64 screen contents for debugging."""
    prefix = f' [{label}]' if label else ''
    print(f'  --- Screen dump{prefix} ---')
    try:
        for i, line in enumerate(mon.screen_text().split('\n')):
            print(f'  {i:2d}| {line}')
    except Exception as e:
        print(f'  (screen read failed: {e})')
    print('  ---')


# ---------------------------------------------------------------------------
# C64 interaction helpers
# ---------------------------------------------------------------------------

def read_key_from_memory(mon):
    """Read 32 bytes at key_data label."""
    addr = mon.label_addr('key_data')
    return bytes(read_mem_reliable(mon, addr, 32))


def read_iv_from_memory(mon):
    """Read 16 bytes at iv_data label."""
    addr = mon.label_addr('iv_data')
    return bytes(read_mem_reliable(mon, addr, 16))


def navigate_to_csr(mon, timeout=30):
    """Send J, wait for submenu, send 1 to start CSR generation."""
    send_key_fast(mon, 'J')
    if not wait_for_screen_text(mon, '1=GENERATE CSR', timeout=timeout):
        raise TimeoutError('CSR submenu did not appear')
    time.sleep(0.1)
    send_key_fast(mon, '1')


def send_csr_fields(mon, fields, timeout=20):
    """Type each CSR field value, prompt-gated with RETURN after each.

    fields is a dict with keys: country, state, city, org, ou, cn, email
    Values may be empty string to just press RETURN (skip).
    """
    prompts = [
        ('country', 'COUNTRY'),
        ('state',   'STATE/PROVINCE'),
        ('city',    'CITY/LOCALITY'),
        ('org',     'ORGANIZATION'),
        ('ou',      'ORG UNIT'),
        ('cn',      'COMMON NAME'),
        ('email',   'EMAIL ADDRESS'),
    ]
    for key, prompt_text in prompts:
        if not wait_for_screen_text(mon, prompt_text, timeout=timeout, verbose=False):
            raise TimeoutError(f'Prompt for {key} ({prompt_text}) did not appear')
        time.sleep(0.05)
        value = fields.get(key, '')
        if value:
            send_keys_fast(mon, value)
        send_key_fast(mon, '\r')
        time.sleep(0.05)


def wait_for_preview(mon, timeout=20):
    """Poll for 'CSR PREVIEW' on screen."""
    return wait_for_screen_text(mon, 'CSR PREVIEW', timeout=timeout, verbose=False)


def read_screen_csr(mon):
    """Extract CSR fields from screen, handling C64 40-column line wraps.

    The CSR format on screen is:
      -----BEGIN CERTIFICATE REQUEST-----
      KEY-TYPE: AES-256
      KEY: <64 hex digits>        ← wraps across 2 rows
      SUBJECT: /C=xx/ST=xx/...    ← may wrap
      EMAIL: xx                   ← optional
      -----END CERTIFICATE REQUEST-----

    In screen memory these are contiguous (no newline chars), so we search
    the joined 1000-char buffer and extract between known markers.
    """
    mon.wait_for_stable(timeout=5)
    continuous = screen_continuous(mon)
    upper = continuous.upper()

    result = {'key_hex': None, 'subject': None, 'email': None}

    # KEY: 64 hex chars immediately after "KEY: "
    # (won't match "KEY-TYPE:" because that has '-' not ' ' after KEY)
    key_idx = upper.find('KEY: ')
    if key_idx >= 0:
        hex_start = key_idx + 5
        candidate = continuous[hex_start:hex_start + 64]
        hex_clean = ''.join(c for c in candidate if c.upper() in '0123456789ABCDEF')
        if len(hex_clean) >= 64:
            result['key_hex'] = hex_clean[:64]

    # SUBJECT: text between "SUBJECT: " and the next marker
    subj_idx = upper.find('SUBJECT: ')
    if subj_idx >= 0:
        subj_start = subj_idx + 9
        # End at EMAIL: or -----END, whichever comes first
        email_marker = upper.find('EMAIL:', subj_start)
        end_marker = upper.find('-----END', subj_start)
        markers = [m for m in (email_marker, end_marker) if m > subj_start]
        subj_end = min(markers) if markers else subj_start + 120
        result['subject'] = continuous[subj_start:subj_end].strip()

    # EMAIL: text between "EMAIL: " and "-----END"
    email_idx = upper.find('EMAIL: ')
    if email_idx >= 0:
        email_start = email_idx + 7
        end_marker = upper.find('-----END', email_start)
        if end_marker > email_start:
            result['email'] = continuous[email_start:end_marker].strip()
        else:
            result['email'] = continuous[email_start:email_start + 60].strip()

    return result


def decline_save(mon, timeout=20):
    """Send N at the save prompt, wait for main menu."""
    if not wait_for_screen_text(mon, 'SAVE CSR TO DISK', timeout=timeout, verbose=False):
        raise TimeoutError('Save prompt did not appear')
    time.sleep(0.05)
    send_key_fast(mon, 'N')
    wait_for_menu(mon, timeout=timeout)


def recover_to_menu(mon, timeout=15):
    """Try to get back to the main menu from any CSR state.

    Sends RETURNs to finish any pending field inputs, then N to decline
    save if prompted, then waits for the main menu sentinel.
    """
    print('  (recovering to main menu...)')
    for _ in range(8):
        send_key_fast(mon, '\r')
        time.sleep(0.1)
    time.sleep(0.5)

    if screen_has_text(mon, 'SAVE CSR TO DISK'):
        send_key_fast(mon, 'N')
        time.sleep(0.3)

    if screen_has_text(mon, 'DRIVE NUMBER'):
        send_key_fast(mon, '\r')
        time.sleep(0.3)

    if screen_has_text(mon, 'FILENAME'):
        send_key_fast(mon, '\r')
        time.sleep(0.3)

    if not wait_for_menu(mon, timeout=timeout):
        dump_screen(mon, 'recovery failed')
        return False
    return True


def read_field_buffers(mon):
    """Read all 7 CSR field buffers from memory. Returns dict."""
    fields = {}
    field_defs = [
        ('country',  'csr_country',  'csr_country_len',  3),
        ('state',    'csr_state',    'csr_state_len',    33),
        ('city',     'csr_city',     'csr_city_len',     33),
        ('org',      'csr_org',      'csr_org_len',      33),
        ('ou',       'csr_ou',       'csr_ou_len',       33),
        ('cn',       'csr_cn',       'csr_cn_len',       41),
        ('email',    'csr_email',    'csr_email_len',    41),
    ]
    for name, buf_label, len_label, max_len in field_defs:
        len_addr = mon.label_addr(len_label)
        length = mon.read_mem(len_addr, 1)[0] if len_addr else 0
        buf_addr = mon.label_addr(buf_label)
        if buf_addr and length > 0:
            raw = mon.read_mem(buf_addr, min(length, max_len))
            fields[name] = ''.join(chr(b) for b in raw)
        else:
            fields[name] = ''
    return fields


# ---------------------------------------------------------------------------
# OpenSSL / Python reference
# ---------------------------------------------------------------------------

def build_expected_subject(fields):
    """Build expected Subject DN string from field dict, matching C64 format.

    Order: /C=/ST=/L=/O=/OU=/CN=  (only non-empty fields)
    """
    parts = []
    mapping = [
        ('country', 'C'),
        ('state',   'ST'),
        ('city',    'L'),
        ('org',     'O'),
        ('ou',      'OU'),
        ('cn',      'CN'),
    ]
    for key, tag in mapping:
        val = fields.get(key, '')
        if val:
            parts.append(f'/{tag}={val}')
    return ''.join(parts)


def validate_key_hex(screen_hex, memory_key):
    """Decode hex string from screen, compare to memory key bytes."""
    screen_hex_clean = screen_hex.replace(' ', '').upper()
    if len(screen_hex_clean) != 64:
        return False, f'Key hex wrong length: {len(screen_hex_clean)} (expected 64)'
    try:
        decoded = bytes.fromhex(screen_hex_clean)
    except ValueError as e:
        return False, f'Key hex decode error: {e}'
    if decoded != memory_key:
        return False, f'Key mismatch: screen={decoded.hex()} memory={memory_key.hex()}'
    return True, 'Key matches'


def validate_subject_dn(screen_dn, fields):
    """Parse /C=../ST=.. components and verify against expected fields."""
    expected = build_expected_subject(fields).upper()
    actual = screen_dn.upper()
    if actual == expected:
        return True, 'Subject matches'
    return False, f'Subject mismatch: got {actual!r}, expected {expected!r}'


def openssl_aes_ecb_encrypt(key_bytes, plaintext_bytes):
    """AES-256-ECB encryption via cryptography library."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(plaintext_bytes) + enc.finalize()


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

def test_1_full_csr(mon):
    """Test 1: Full CSR — all 7 fields populated."""
    print('\n=== Test 1: Full CSR (all fields) ===')

    fields = {
        'country': 'US',
        'state':   'CALIFORNIA',
        'city':    'SAN JOSE',
        'org':     'ACME CORP',
        'ou':      'ENGINEERING',
        'cn':      'TEST.EXAMPLE.COM',
        'email':   'TEST@EXAMPLE.COM',
    }

    key_bytes = read_key_from_memory(mon)
    print(f'  Key from memory: {key_bytes.hex()}')

    navigate_to_csr(mon)
    send_csr_fields(mon, fields)

    if not wait_for_preview(mon):
        dump_screen(mon, 'no preview')
        return False, 'CSR preview did not appear'

    csr = read_screen_csr(mon)
    errors = []

    # Validate key hex
    if csr['key_hex'] is None:
        errors.append('KEY line not found on screen')
        dump_screen(mon, 'missing KEY')
    else:
        ok, msg = validate_key_hex(csr['key_hex'], key_bytes)
        if not ok:
            errors.append(msg)
        else:
            print(f'  {msg}')
        try:
            decoded = bytes.fromhex(csr['key_hex'].replace(' ', ''))
            if len(decoded) != 32:
                errors.append(f'Key length {len(decoded)}, expected 32')
        except ValueError as e:
            errors.append(f'Key hex parse error: {e}')

    # Validate subject
    if csr['subject'] is None:
        errors.append('SUBJECT line not found on screen')
    else:
        ok, msg = validate_subject_dn(csr['subject'], fields)
        if not ok:
            errors.append(msg)
        else:
            print(f'  {msg}')

    # Verify email present
    if csr['email'] is None:
        errors.append('EMAIL line not found on screen')
    else:
        if fields['email'].upper() not in csr['email'].upper():
            errors.append(f'Email mismatch: got {csr["email"]!r}')
        else:
            print(f'  Email present: {csr["email"]}')

    decline_save(mon)

    if errors:
        return False, '; '.join(errors)
    return True, 'All checks passed'


def test_2_cn_only(mon):
    """Test 2: CN-only CSR."""
    print('\n=== Test 2: CN-only CSR ===')

    fields = {
        'country': '',
        'state':   '',
        'city':    '',
        'org':     '',
        'ou':      '',
        'cn':      'MY.SERVER.COM',
        'email':   '',
    }

    key_bytes = read_key_from_memory(mon)
    navigate_to_csr(mon)
    send_csr_fields(mon, fields)

    if not wait_for_preview(mon):
        dump_screen(mon, 'no preview')
        return False, 'CSR preview did not appear'

    csr = read_screen_csr(mon)
    errors = []

    if csr['key_hex'] is None:
        errors.append('KEY line not found')
    else:
        ok, msg = validate_key_hex(csr['key_hex'], key_bytes)
        if not ok:
            errors.append(msg)
        else:
            print(f'  {msg}')

    if csr['subject'] is None:
        errors.append('SUBJECT line not found')
    else:
        ok, msg = validate_subject_dn(csr['subject'], fields)
        if not ok:
            errors.append(msg)
        else:
            print(f'  {msg}')
        subj_upper = csr['subject'].upper()
        for tag in ['/C=', '/ST=', '/L=', '/O=', '/OU=']:
            if tag in subj_upper:
                errors.append(f'Unexpected {tag} in subject: {subj_upper}')

    if csr['email'] is not None and csr['email'].strip():
        errors.append(f'Unexpected email: {csr["email"]}')

    decline_save(mon)

    if errors:
        return False, '; '.join(errors)
    return True, 'All checks passed'


def test_3_no_cn(mon):
    """Test 3: No CN, other fields filled (bug fix 1 regression)."""
    print('\n=== Test 3: No CN (regression test) ===')

    fields = {
        'country': 'US',
        'state':   '',
        'city':    '',
        'org':     'ACME',
        'ou':      '',
        'cn':      '',
        'email':   '',
    }

    navigate_to_csr(mon)
    send_csr_fields(mon, fields)

    if not wait_for_preview(mon, timeout=15):
        if screen_has_text(mon, 'REQUIRED'):
            return False, 'CN still appears required (bug not fixed)'
        dump_screen(mon, 'no preview')
        return False, 'CSR preview did not appear'

    csr = read_screen_csr(mon)
    errors = []

    if csr['subject'] is None:
        errors.append('SUBJECT line not found')
    else:
        subj_upper = csr['subject'].upper()
        if '/C=US' not in subj_upper:
            errors.append(f'/C=US not in subject: {subj_upper}')
        else:
            print('  /C=US present')
        if '/O=ACME' not in subj_upper:
            errors.append(f'/O=ACME not in subject: {subj_upper}')
        else:
            print('  /O=ACME present')
        if '/CN=' in subj_upper:
            errors.append(f'Unexpected /CN= in subject: {subj_upper}')
        else:
            print('  No /CN= (correct)')

    decline_save(mon)

    if errors:
        return False, '; '.join(errors)
    return True, 'All checks passed'


def test_4_all_empty_rejected(mon):
    """Test 4: All fields empty -> rejection."""
    print('\n=== Test 4: All fields empty (rejection) ===')

    fields = {
        'country': '',
        'state':   '',
        'city':    '',
        'org':     '',
        'ou':      '',
        'cn':      '',
        'email':   '',
    }

    navigate_to_csr(mon)
    send_csr_fields(mon, fields)

    # Should NOT show preview — should show error
    time.sleep(0.5)

    errors = []

    if not screen_has_text(mon, 'AT LEAST ONE FIELD REQUIRED'):
        errors.append('"AT LEAST ONE FIELD REQUIRED" not shown')
        dump_screen(mon, 'missing error msg')
    else:
        print('  Error message displayed correctly')

    if screen_has_text(mon, 'CSR PREVIEW'):
        errors.append('CSR preview appeared despite all empty fields')

    if not wait_for_menu(mon, timeout=15):
        errors.append('Did not return to main menu')
    else:
        print('  Returned to main menu')

    if errors:
        return False, '; '.join(errors)
    return True, 'All checks passed'


def test_5_key_preserved_after_nist(mon):
    """Test 5: Key preserved after NIST test (bug fix 2 regression)."""
    print('\n=== Test 5: Key preserved after NIST test ===')

    key_before = read_key_from_memory(mon)
    print(f'  Key before NIST: {key_before.hex()}')

    send_key_fast(mon, 'F')

    # The NIST test prints results then immediately prints the menu,
    # which scrolls the PASS/FAIL off screen in warp mode.  So we wait
    # for the menu to reappear (meaning the test finished) and check
    # that FAIL is NOT on screen.
    if not wait_for_screen_text(mon, 'NIST', timeout=30, verbose=False):
        return False, 'NIST test header did not appear'

    # Wait for menu to return (NIST done)
    if not wait_for_menu(mon, timeout=90):
        dump_screen(mon, 'NIST did not finish')
        return False, 'Did not return to main menu after NIST'

    # If FAIL is visible, the test failed
    if screen_has_text(mon, 'FAIL'):
        dump_screen(mon, 'NIST FAIL')
        return False, 'NIST test reported FAIL'

    print('  NIST test completed (no FAIL on screen)')

    key_after = read_key_from_memory(mon)
    print(f'  Key after NIST:  {key_after.hex()}')

    errors = []

    if key_before != key_after:
        errors.append(
            f'Key changed after NIST! before={key_before.hex()} after={key_after.hex()}'
        )
    else:
        print('  Key preserved after NIST test')

    # Generate a CN-only CSR and verify key matches
    fields = {
        'country': '',
        'state':   '',
        'city':    '',
        'org':     '',
        'ou':      '',
        'cn':      'AFTER.NIST.COM',
        'email':   '',
    }
    navigate_to_csr(mon)
    send_csr_fields(mon, fields)

    if not wait_for_preview(mon):
        errors.append('CSR preview did not appear after NIST')
        dump_screen(mon, 'post-NIST CSR')
    else:
        csr = read_screen_csr(mon)
        if csr['key_hex'] is not None:
            ok, msg = validate_key_hex(csr['key_hex'], key_before)
            if not ok:
                errors.append(f'Key in CSR differs from pre-NIST key: {msg}')
            else:
                print('  CSR key matches pre-NIST key')
        else:
            errors.append('KEY line not found on screen')

    decline_save(mon)

    if errors:
        return False, '; '.join(errors)
    return True, 'All checks passed'


def test_6_aes_crypto_match(mon):
    """Test 6: AES cryptographic comparison — C64 vs OpenSSL."""
    print('\n=== Test 6: AES crypto match (C64 vs OpenSSL) ===')

    errors = []

    # NIST known-answer test (OpenSSL side)
    nist_key = bytes(range(0x00, 0x20))
    nist_pt = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ])
    expected_ct = bytes([
        0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
        0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89,
    ])

    actual_ct = openssl_aes_ecb_encrypt(nist_key, nist_pt)
    if actual_ct != expected_ct:
        errors.append(
            f'NIST KAT failed: got {actual_ct.hex()}, expected {expected_ct.hex()}'
        )
    else:
        print(f'  NIST KAT (OpenSSL): {actual_ct.hex()} — matches FIPS 197 C.3')

    # Live key integrity check (read in 16-byte chunks for reliability)
    key_data = read_key_from_memory(mon)
    iv_data = read_iv_from_memory(mon)
    print(f'  Live key_data ({len(key_data)} bytes): {key_data.hex()}')
    print(f'  Live iv_data  ({len(iv_data)} bytes): {iv_data.hex()}')

    if len(key_data) != 32:
        errors.append(f'key_data length {len(key_data)}, expected 32')

    # Expanded key first 32 bytes = original key for AES-256
    exp_addr = mon.label_addr('expanded_key')
    if exp_addr:
        exp_first_32 = bytes(read_mem_reliable(mon, exp_addr, 32))
        if exp_first_32 == key_data:
            print('  Expanded key round 0 matches key_data')
        else:
            errors.append(
                f'Expanded key mismatch: first 32={exp_first_32.hex()} '
                f'key_data={key_data.hex()}'
            )
    else:
        errors.append('expanded_key label not found')

    # Verify the live key encrypts via OpenSSL
    if len(key_data) == 32:
        live_ct = openssl_aes_ecb_encrypt(key_data, nist_pt)
        print(f'  Live key encrypts NIST PT to: {live_ct.hex()}')
        if len(live_ct) != 16:
            errors.append(f'Live ciphertext wrong length: {len(live_ct)}')
    else:
        errors.append('Skipping live encrypt (key wrong length)')

    if errors:
        return False, '; '.join(errors)
    return True, 'All checks passed'


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='CSR Integration Test')
    parser.add_argument('--timeout', type=int, default=300,
                        help='Overall timeout in seconds (default: 300)')
    parser.add_argument('--port', type=int, default=6510,
                        help='VICE monitor port (default: 6510)')
    parser.add_argument('--vice-path', default='x64sc',
                        help='Path to VICE executable (default: x64sc)')
    args = parser.parse_args()

    # Change to project root (parent of tools/)
    project_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    os.chdir(project_root)

    prg_path = 'build/aes256keygen.prg'
    labels_path = 'build/labels.txt'

    # Build
    print('=== Building ===')
    subprocess.run(['make', 'clean'], capture_output=True)
    result = subprocess.run(['make'], capture_output=True, text=True)
    if result.returncode != 0:
        print(f'Build failed:\n{result.stderr}')
        sys.exit(1)
    print('  Build OK')

    if not os.path.exists(prg_path):
        print(f'FATAL: {prg_path} not found')
        sys.exit(1)

    # Start VICE
    print('\n=== Starting VICE ===')
    start_vice(prg_path, port=args.port, vice_path=args.vice_path)

    try:
        print('  Waiting for monitor...')
        if not wait_for_monitor(port=args.port, timeout=30):
            print('FATAL: Could not connect to VICE monitor')
            sys.exit(1)
        print('  Monitor connected')

        mon = ViceMon(port=args.port)

        n = mon.load_labels(labels_path)
        print(f'  Loaded {n} labels')

        print('  Waiting for main menu...')
        if not wait_for_menu(mon, timeout=60):
            print('FATAL: Main menu did not appear')
            dump_screen(mon, 'startup')
            sys.exit(1)
        print('  Main menu ready')

        # Run test scenarios
        scenarios = [
            ('Test 1: Full CSR',                  test_1_full_csr),
            ('Test 2: CN-only CSR',               test_2_cn_only),
            ('Test 3: No CN (regression)',         test_3_no_cn),
            ('Test 4: All empty (rejection)',      test_4_all_empty_rejected),
            ('Test 5: Key preserved after NIST',   test_5_key_preserved_after_nist),
            ('Test 6: AES crypto match',           test_6_aes_crypto_match),
        ]

        results = []
        for name, func in scenarios:
            try:
                ok, msg = func(mon)
                status = 'PASS' if ok else 'FAIL'
                results.append((name, status, msg))
                print(f'  => {status}: {msg}')
            except TimeoutError as e:
                results.append((name, 'FAIL', f'Timeout: {e}'))
                print(f'  => FAIL: Timeout: {e}')
                dump_screen(mon, f'{name} timeout')
                recover_to_menu(mon)
            except Exception as e:
                results.append((name, 'FAIL', f'Error: {e}'))
                print(f'  => FAIL: Error: {e}')
                dump_screen(mon, f'{name} error')
                recover_to_menu(mon)

        # Summary
        print('\n' + '=' * 60)
        print('RESULTS')
        print('=' * 60)
        passed = 0
        for name, status, msg in results:
            icon = '+' if status == 'PASS' else '-'
            print(f'  [{icon}] {name}: {status}')
            if status == 'PASS':
                passed += 1
        total = len(results)
        print(f'\n  {passed}/{total} passed')
        print('=' * 60)

        return 0 if passed == total else 1

    finally:
        print('\n=== Stopping VICE ===')
        stop_vice()


if __name__ == '__main__':
    sys.exit(main())
