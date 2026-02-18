"""Shared utilities for C64 direct-memory test suites."""

import random
import time

from c64_test_harness import jsr

SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def robust_jsr(transport, addr, timeout=10.0, retries=3, verbose=False):
    """jsr() with retry for transient VICE connection failures."""
    for attempt in range(retries):
        try:
            return jsr(transport, addr, timeout=timeout)
        except Exception as e:
            if attempt < retries - 1:
                if verbose:
                    print(f"  [retry {attempt+1}/{retries}] jsr(${addr:04X}) failed: {e}")
                time.sleep(0.3)
                continue
            raise


def generate_random_string(min_len=1, max_len=63, rng=None):
    """Generate a random string of safe characters with random length."""
    r = rng or random
    length = r.randint(min_len, max_len)
    return "".join(r.choice(SAFE_CHARS) for _ in range(length))


def generate_random_bytes(length, rng=None):
    """Generate random bytes of the given length."""
    r = rng or random
    return bytes(r.randint(0, 255) for _ in range(length))
