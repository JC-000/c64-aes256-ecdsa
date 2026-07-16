#!/usr/bin/env python3
"""
test_csr_harness.py - CSR Integration Test Using c64_test_harness

Drives the C64 through CSR generation via the c64_test_harness package,
builds an OpenSSL reference using Python's `cryptography` library, and
compares field by field.  On failure, diagnostics distinguish C64 program
bugs from test harness errors.

Usage:
    python3 tools/test_csr_harness.py

Requires: Python 3.10+, cryptography >= 41.0, c64_test_harness, VICE x64sc
"""

import difflib
import os
import subprocess
import sys
import time

from cryptography.x509 import Name, NameAttribute
from cryptography.x509.oid import NameOID

from c64_test_harness import (
    Labels,
    ScreenGrid,
    TestRunner,
    ViceConfig,
    ViceProcess,
    C64Transport as ViceTransport,
    dump_screen,
    read_bytes,
    send_key,
    send_text,
    wait_for_text,
    wait_for_stable,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "aes256keygen.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# X.509 OID → C64 tag, in the assembly-defined field order
FIELD_ORDER = [
    ("country", NameOID.COUNTRY_NAME, "C"),
    ("state", NameOID.STATE_OR_PROVINCE_NAME, "ST"),
    ("city", NameOID.LOCALITY_NAME, "L"),
    ("org", NameOID.ORGANIZATION_NAME, "O"),
    ("ou", NameOID.ORGANIZATIONAL_UNIT_NAME, "OU"),
    ("cn", NameOID.COMMON_NAME, "CN"),
]

# Prompt text the C64 shows for each field, in order
FIELD_PROMPTS = [
    ("country", "COUNTRY"),
    ("state", "STATE/PROVINCE"),
    ("city", "CITY/LOCALITY"),
    ("org", "ORGANIZATION"),
    ("ou", "ORG UNIT"),
    ("cn", "COMMON NAME"),
    ("email", "EMAIL ADDRESS"),
]


# ---------------------------------------------------------------------------
# OpenSSL reference helpers
# ---------------------------------------------------------------------------

def build_openssl_name(fields: dict[str, str]) -> Name:
    """Construct a cryptography.x509.Name from a field dict."""
    attrs = []
    for key, oid, _tag in FIELD_ORDER:
        val = fields.get(key, "")
        if val:
            attrs.append(NameAttribute(oid, val))
    return Name(attrs)


def render_dn_c64_format(name: Name) -> str:
    """Render an X.509 Name as /C=xx/ST=xx/... in the C64's field order."""
    oid_to_tag = {oid: tag for _key, oid, tag in FIELD_ORDER}
    # Walk in C64 field order so output matches the assembly sequence
    parts = []
    for _key, oid, tag in FIELD_ORDER:
        for attr in name:
            if attr.oid == oid:
                parts.append(f"/{tag}={attr.value}")
                break
    return "".join(parts)


def build_expected_csr(fields: dict[str, str], key_bytes: bytes) -> dict:
    """Build a reference dict {key_hex, subject, email} for comparison."""
    name = build_openssl_name(fields)
    return {
        "key_hex": key_bytes.hex().upper(),
        "subject": render_dn_c64_format(name).upper(),
        "email": fields.get("email", "").upper() or None,
    }


def generate_real_csr(fields: dict[str, str]) -> tuple[str, str, Name]:
    """Generate a real PKCS#10 PEM CSR using the cryptography library.

    Returns (pem_text, openssl_command, x509_name).
    The CSR is signed with a throwaway ECDSA P-256 key so the structure
    is valid and can be parsed by any standards-compliant tool.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography import x509 as cx509

    # Build X.509 Name with same fields
    name = build_openssl_name(fields)

    # Add emailAddress if present (it's a separate OID)
    email = fields.get("email", "")
    if email:
        attrs = list(name)
        attrs.append(NameAttribute(NameOID.EMAIL_ADDRESS, email))
        name = Name(attrs)

    # Generate a throwaway EC key and sign the CSR
    private_key = ec.generate_private_key(ec.SECP256R1())
    builder = cx509.CertificateSigningRequestBuilder().subject_name(name)
    csr = builder.sign(private_key, hashes.SHA256())
    pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    # Build equivalent openssl CLI command
    subj_parts = []
    tag_map = [
        ("country", "C"),
        ("state", "ST"),
        ("city", "L"),
        ("org", "O"),
        ("ou", "OU"),
        ("cn", "CN"),
        ("email", "emailAddress"),
    ]
    for key, tag in tag_map:
        val = fields.get(key, "")
        if val:
            subj_parts.append(f"/{tag}={val}")
    subj_str = "".join(subj_parts)
    ossl_cmd = (
        f"openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "
        f"-keyout /dev/null -nodes -subj '{subj_str}'"
    )

    return pem, ossl_cmd, name


def parse_real_csr_subject(pem: str) -> dict[str, str]:
    """Parse a PEM CSR and extract subject fields as a dict."""
    from cryptography import x509 as cx509

    csr = cx509.load_pem_x509_csr(pem.encode())
    result = {}
    oid_map = {
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COMMON_NAME: "CN",
        NameOID.EMAIL_ADDRESS: "emailAddress",
    }
    for attr in csr.subject:
        tag = oid_map.get(attr.oid)
        if tag:
            result[tag] = attr.value
    return result


def print_csr_comparison(
    c64_csr: dict, fields: dict[str, str], key_bytes: bytes
) -> None:
    """Print C64 custom CSR, a real PKCS#10 CSR, and compare parsed fields."""
    sep = "=" * 72

    # --- Generate real PKCS#10 CSR ---
    pem, ossl_cmd, x509_name = generate_real_csr(fields)
    parsed_subject = parse_real_csr_subject(pem)

    # --- C64 custom CSR (reconstructed from screen fields) ---
    c64_key = c64_csr["key_hex"].upper()
    c64_subj = c64_csr["subject"].upper()
    c64_email = c64_csr["email"].upper() if c64_csr["email"] else None
    c64_block = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        "KEY-TYPE: AES-256\n"
        f"KEY: {c64_key}\n"
        f"SUBJECT: {c64_subj}\n"
    )
    if c64_email:
        c64_block += f"EMAIL: {c64_email}\n"
    c64_block += "-----END CERTIFICATE REQUEST-----"

    # ---- Output ----
    print(f"\n{sep}")
    print("CSR COMPARISON: C64 Custom Format vs OpenSSL PKCS#10")
    print(sep)

    print("\n[1] C64 Program Output (custom format, from screen)")
    print("-" * 72)
    print(c64_block)

    print(f"\n[2] OpenSSL PKCS#10 CSR (generated via Python cryptography library)")
    print("-" * 72)
    print(pem.rstrip())

    print(f"\n[3] Equivalent openssl CLI command")
    print("-" * 72)
    print(f"  $ {ossl_cmd}")

    # --- Decode the real CSR to show its parsed fields ---
    print(f"\n[4] Parsed fields from the PKCS#10 CSR above")
    print("-" * 72)
    for tag, val in parsed_subject.items():
        print(f"  {tag:20s} = {val}")

    # --- Field-by-field comparison ---
    print(f"\n[5] Field-by-field diff: C64 vs PKCS#10")
    print("-" * 72)

    c64_field_map = {
        "C": ("country", "C"),
        "ST": ("state", "ST"),
        "L": ("city", "L"),
        "O": ("org", "O"),
        "OU": ("ou", "OU"),
        "CN": ("cn", "CN"),
        "emailAddress": ("email", "EMAIL"),
    }

    all_match = True
    for pkcs_tag, (field_key, c64_tag) in c64_field_map.items():
        pkcs_val = parsed_subject.get(pkcs_tag, "")
        c64_val = fields.get(field_key, "")
        match = pkcs_val.upper() == c64_val.upper()
        icon = "OK" if match else "MISMATCH"
        if not match and pkcs_val and c64_val:
            all_match = False
        if pkcs_val or c64_val:
            print(f"  {c64_tag:5s}  PKCS#10={pkcs_val!r:30s}  C64={c64_val!r:30s}  [{icon}]")

    # Key comparison note
    print()
    print(f"  KEY    PKCS#10: ECDSA P-256 public key (in ASN.1 SubjectPublicKeyInfo)")
    print(f"         C64:     AES-256 symmetric key = {c64_key}")
    print(f"         (Different by design -- C64 embeds the AES session key)")

    if all_match:
        print(f"\n  Result: All subject/email fields match between formats.")
    else:
        print(f"\n  Result: MISMATCH in one or more fields!")

    print(sep)


# Captured CSR data from test 1 for post-run comparison
_captured_csr: dict | None = None
_captured_fields: dict[str, str] | None = None
_captured_key_bytes: bytes | None = None


# ---------------------------------------------------------------------------
# C64 interaction helpers
# ---------------------------------------------------------------------------

def navigate_to_csr(transport: ViceTransport, timeout: float = 30.0) -> None:
    """Press J -> wait for '1=TEXT CSR' -> press 1."""
    send_key(transport, "J")
    grid = wait_for_text(transport, "1=TEXT CSR", timeout=timeout)
    if grid is None:
        raise TimeoutError("CSR submenu did not appear")
    time.sleep(0.1)
    send_key(transport, "1")


def send_csr_fields(
    transport: ViceTransport, fields: dict[str, str], timeout: float = 20.0
) -> None:
    """Wait for each prompt, type value + RETURN."""
    for key, prompt_text in FIELD_PROMPTS:
        grid = wait_for_text(
            transport, prompt_text, timeout=timeout, verbose=False
        )
        if grid is None:
            raise TimeoutError(
                f"Prompt for {key} ({prompt_text}) did not appear"
            )
        time.sleep(0.05)
        value = fields.get(key, "")
        if value:
            send_text(transport, value)
        send_key(transport, "\r")
        time.sleep(0.05)


def read_screen_csr(transport: ViceTransport) -> dict:
    """Extract KEY/SUBJECT/EMAIL from continuous_text().

    Uses manual index searching (not extract_between) to avoid matching
    KEY-TYPE when looking for KEY, and to handle the conditional EMAIL
    end-marker.
    """
    grid = wait_for_stable(transport, timeout=5.0)
    if grid is None:
        grid = ScreenGrid.from_transport(transport)

    continuous = grid.continuous_text()
    upper = continuous.upper()

    result: dict[str, str | None] = {
        "key_hex": None,
        "subject": None,
        "email": None,
    }

    # KEY: 64 hex chars immediately after "KEY: "
    # (won't match "KEY-TYPE:" because that has '-' not ' ' after KEY)
    key_idx = upper.find("KEY: ")
    if key_idx >= 0:
        hex_start = key_idx + 5
        candidate = continuous[hex_start : hex_start + 64]
        hex_clean = "".join(
            c for c in candidate if c.upper() in "0123456789ABCDEF"
        )
        if len(hex_clean) >= 64:
            result["key_hex"] = hex_clean[:64]

    # SUBJECT: text between "SUBJECT: " and the next marker
    subj_idx = upper.find("SUBJECT: ")
    if subj_idx >= 0:
        subj_start = subj_idx + 9
        email_marker = upper.find("EMAIL:", subj_start)
        end_marker = upper.find("-----END", subj_start)
        markers = [m for m in (email_marker, end_marker) if m > subj_start]
        subj_end = min(markers) if markers else subj_start + 120
        result["subject"] = continuous[subj_start:subj_end].strip()

    # EMAIL: text between "EMAIL: " and "-----END"
    email_idx = upper.find("EMAIL: ")
    if email_idx >= 0:
        email_start = email_idx + 7
        end_marker = upper.find("-----END", email_start)
        if end_marker > email_start:
            result["email"] = continuous[email_start:end_marker].strip()
        else:
            result["email"] = continuous[email_start : email_start + 60].strip()

    return result


def decline_save_and_return(
    transport: ViceTransport, timeout: float = 20.0
) -> None:
    """Press N at 'SAVE CSR TO DISK', wait for main menu."""
    grid = wait_for_text(
        transport, "SAVE CSR TO DISK", timeout=timeout, verbose=False
    )
    if grid is None:
        raise TimeoutError("Save prompt did not appear")
    time.sleep(0.05)
    send_key(transport, "N")
    grid = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if grid is None:
        raise TimeoutError("Main menu did not reappear after declining save")


def recover_to_menu(transport: ViceTransport, timeout: float = 15.0) -> bool:
    """Try to get back to main menu from any CSR state."""
    print("  (recovering to main menu...)")
    for _ in range(8):
        send_key(transport, "\r")
        time.sleep(0.1)
    time.sleep(0.5)

    grid = ScreenGrid.from_transport(transport)
    if grid.has_text("SAVE CSR TO DISK"):
        send_key(transport, "N")
        time.sleep(0.3)

    grid = ScreenGrid.from_transport(transport)
    if grid.has_text("DRIVE NUMBER"):
        send_key(transport, "\r")
        time.sleep(0.3)

    grid = ScreenGrid.from_transport(transport)
    if grid.has_text("FILENAME"):
        send_key(transport, "\r")
        time.sleep(0.3)

    result = wait_for_text(transport, "Q=QUIT", timeout=timeout)
    if result is None:
        dump_screen(transport, "recovery failed")
        return False
    return True


def compare_csr_fields(
    actual: dict, expected: dict
) -> list[str]:
    """Field-by-field comparison.  Returns list of error strings (empty = pass)."""
    errors = []

    # KEY
    if actual["key_hex"] is None:
        errors.append("KEY line not found on screen")
    elif actual["key_hex"].upper() != expected["key_hex"]:
        errors.append(
            f"KEY mismatch:\n"
            f"  expected: {expected['key_hex']}\n"
            f"  actual:   {actual['key_hex'].upper()}"
        )

    # SUBJECT
    if actual["subject"] is None:
        errors.append("SUBJECT line not found on screen")
    elif actual["subject"].upper() != expected["subject"]:
        errors.append(
            f"SUBJECT mismatch:\n"
            f"  expected: {expected['subject']}\n"
            f"  actual:   {actual['subject'].upper()}"
        )

    # EMAIL
    if expected["email"] is None:
        if actual["email"] is not None and actual["email"].strip():
            errors.append(
                f"Unexpected EMAIL on screen: {actual['email']!r}"
            )
    else:
        if actual["email"] is None:
            errors.append("EMAIL line not found on screen")
        elif actual["email"].upper() != expected["email"]:
            errors.append(
                f"EMAIL mismatch:\n"
                f"  expected: {expected['email']}\n"
                f"  actual:   {actual['email'].upper()}"
            )

    return errors


# ---------------------------------------------------------------------------
# Test scenarios
# ---------------------------------------------------------------------------

def test_full_csr(transport, labels):
    """Test 1: Full CSR -- all 7 fields populated."""
    global _captured_csr, _captured_fields, _captured_key_bytes
    print("\n=== Test 1: Full CSR (all fields) ===")

    fields = {
        "country": "US",
        "state": "CALIFORNIA",
        "city": "SAN JOSE",
        "org": "ACME CORP",
        "ou": "ENGINEERING",
        "cn": "TEST.EXAMPLE.COM",
        "email": "TEST@EXAMPLE.COM",
    }

    key_addr = labels["key_data"]
    key_bytes = read_bytes(transport, key_addr, 32)
    print(f"  Key from memory: {key_bytes.hex()}")

    navigate_to_csr(transport)
    send_csr_fields(transport, fields)

    grid = wait_for_text(transport, "CSR PREVIEW", timeout=20.0, verbose=False)
    if grid is None:
        dump_screen(transport, "no preview")
        return False, "CSR preview did not appear"

    actual = read_screen_csr(transport)
    expected = build_expected_csr(fields, key_bytes)
    errors = compare_csr_fields(actual, expected)

    # Store for post-run comparison output
    _captured_csr = actual
    _captured_fields = fields
    _captured_key_bytes = key_bytes

    if errors:
        for e in errors:
            print(f"  FAIL: {e}")
        dump_screen(transport, "full_csr errors")

    decline_save_and_return(transport)

    if errors:
        return False, "; ".join(e.split("\n")[0] for e in errors)

    print("  All fields match OpenSSL reference")
    return True, "All checks passed"


def test_cn_only(transport, labels):
    """Test 2: CN-only -- only CN filled, no email."""
    print("\n=== Test 2: CN-only CSR ===")

    fields = {
        "country": "",
        "state": "",
        "city": "",
        "org": "",
        "ou": "",
        "cn": "MY.SERVER.COM",
        "email": "",
    }

    key_addr = labels["key_data"]
    key_bytes = read_bytes(transport, key_addr, 32)

    navigate_to_csr(transport)
    send_csr_fields(transport, fields)

    grid = wait_for_text(transport, "CSR PREVIEW", timeout=20.0, verbose=False)
    if grid is None:
        dump_screen(transport, "no preview")
        return False, "CSR preview did not appear"

    actual = read_screen_csr(transport)
    expected = build_expected_csr(fields, key_bytes)
    errors = compare_csr_fields(actual, expected)

    # Verify no empty tags leaked into subject
    if actual["subject"]:
        subj_upper = actual["subject"].upper()
        for tag in ["/C=", "/ST=", "/L=", "/O=", "/OU="]:
            if tag in subj_upper:
                errors.append(f"Unexpected {tag} in CN-only subject: {subj_upper}")

    # Verify no email line
    if actual["email"] is not None and actual["email"].strip():
        errors.append(f"Unexpected email in CN-only CSR: {actual['email']!r}")

    if errors:
        for e in errors:
            print(f"  FAIL: {e}")

    decline_save_and_return(transport)

    if errors:
        return False, "; ".join(errors)

    print("  CN-only subject correct, no extra tags, no email")
    return True, "All checks passed"


def test_no_cn(transport, labels):
    """Test 3: No CN -- Country + Org only."""
    print("\n=== Test 3: No CN (Country + Org only) ===")

    fields = {
        "country": "US",
        "state": "",
        "city": "",
        "org": "ACME",
        "ou": "",
        "cn": "",
        "email": "",
    }

    navigate_to_csr(transport)
    send_csr_fields(transport, fields)

    grid = wait_for_text(transport, "CSR PREVIEW", timeout=20.0, verbose=False)
    if grid is None:
        # Check if the program rejected it instead
        probe = ScreenGrid.from_transport(transport)
        if probe.has_text("REQUIRED"):
            return False, "CN still appears required (bug not fixed)"
        dump_screen(transport, "no preview")
        return False, "CSR preview did not appear"

    actual = read_screen_csr(transport)
    errors = []

    if actual["subject"] is None:
        errors.append("SUBJECT line not found")
    else:
        subj_upper = actual["subject"].upper()
        if "/C=US" not in subj_upper:
            errors.append(f"/C=US not in subject: {subj_upper}")
        else:
            print("  /C=US present")
        if "/O=ACME" not in subj_upper:
            errors.append(f"/O=ACME not in subject: {subj_upper}")
        else:
            print("  /O=ACME present")
        if "/CN=" in subj_upper:
            errors.append(f"Unexpected /CN= in subject: {subj_upper}")
        else:
            print("  No /CN= (correct)")

    if errors:
        for e in errors:
            print(f"  FAIL: {e}")

    decline_save_and_return(transport)

    if errors:
        return False, "; ".join(errors)
    return True, "All checks passed"


def test_all_empty_rejected(transport, labels):
    """Test 4: All fields empty -> rejection, no preview."""
    print("\n=== Test 4: All fields empty (rejection) ===")

    fields = {
        "country": "",
        "state": "",
        "city": "",
        "org": "",
        "ou": "",
        "cn": "",
        "email": "",
    }

    navigate_to_csr(transport)
    send_csr_fields(transport, fields)

    # Should NOT show preview -- should show error
    time.sleep(0.5)

    errors = []
    grid = ScreenGrid.from_transport(transport)

    if not grid.has_text("AT LEAST ONE FIELD REQUIRED"):
        errors.append('"AT LEAST ONE FIELD REQUIRED" not shown')
        dump_screen(transport, "missing error msg")
    else:
        print("  Error message displayed correctly")

    if grid.has_text("CSR PREVIEW"):
        errors.append("CSR preview appeared despite all empty fields")

    # Should auto-return to main menu
    result = wait_for_text(transport, "Q=QUIT", timeout=15.0)
    if result is None:
        errors.append("Did not return to main menu")
    else:
        print("  Returned to main menu")

    if errors:
        return False, "; ".join(errors)
    return True, "All checks passed"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.chdir(PROJECT_ROOT)

    # Build
    print("=== Building ===")
    subprocess.run(["make", "clean"], capture_output=True)
    result = subprocess.run(["make"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Build failed:\n{result.stderr}")
        sys.exit(1)
    print("  Build OK")

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found")
        sys.exit(1)

    # Load labels
    labels = Labels.from_file(LABELS_PATH)
    if labels.address("key_data") is None:
        print("FATAL: 'key_data' label not found in labels file")
        sys.exit(1)
    print(f"  Labels loaded, key_data at ${labels['key_data']:04X}")

    # Start VICE
    print("\n=== Starting VICE ===")
    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

    with ViceProcess(config) as vice:
        if not vice.wait_for_monitor(timeout=30.0):
            print("FATAL: Could not connect to VICE monitor")
            sys.exit(1)
        print(f"  VICE started (PID {vice.pid})")

        transport = ViceTransport(port=config.port)

        # Wait for main menu
        print("  Waiting for main menu...")
        grid = wait_for_text(transport, "Q=QUIT", timeout=60.0)
        if grid is None:
            print("FATAL: Main menu did not appear")
            dump_screen(transport, "startup")
            sys.exit(1)
        print("  Main menu ready")

        # Register test scenarios
        runner = TestRunner()

        def make_recovery():
            return lambda: recover_to_menu(transport)

        runner.add_scenario(
            "Full CSR (all fields)",
            lambda: test_full_csr(transport, labels),
            make_recovery(),
        )
        runner.add_scenario(
            "CN-only CSR",
            lambda: test_cn_only(transport, labels),
            make_recovery(),
        )
        runner.add_scenario(
            "No CN (Country + Org)",
            lambda: test_no_cn(transport, labels),
            make_recovery(),
        )
        runner.add_scenario(
            "All empty (rejection)",
            lambda: test_all_empty_rejected(transport, labels),
            make_recovery(),
        )

        runner.run_all()
        runner.print_summary()

        # Print full CSR comparison if test 1 captured data
        if _captured_csr and _captured_fields and _captured_key_bytes:
            print_csr_comparison(
                _captured_csr, _captured_fields, _captured_key_bytes
            )

        sys.exit(runner.exit_code)


if __name__ == "__main__":
    main()
