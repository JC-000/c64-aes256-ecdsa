#!/usr/bin/env python3
"""
vicemon.py - VICE Remote Monitor Client for C64 Test Automation

Connects to a running VICE instance via its remote text monitor and provides
high-level operations for testing C64 programs:

  - Read/decode screen memory to text
  - Send keystrokes via the keyboard buffer
  - Read/write arbitrary memory
  - Pause/continue execution
  - Wait for specific screen content
  - Dump memory regions in hex

Usage as library:
    from vicemon import ViceMon
    mon = ViceMon()  # connects to localhost:6510
    print(mon.screen_text())
    mon.send_key('J')
    mon.wait_for_text('PASS', timeout=300)

Usage from command line:
    python3 vicemon.py screen          # Show current screen
    python3 vicemon.py send KEY        # Send a keypress
    python3 vicemon.py wait TEXT [SEC] # Wait for text on screen
    python3 vicemon.py mem ADDR LEN    # Hex dump memory
    python3 vicemon.py regs            # Show CPU registers
    python3 vicemon.py resume          # Continue execution
    python3 vicemon.py labels FILE     # Load VICE label file
"""

import socket
import sys
import time
import re

# C64 screen code to ASCII mapping
# Screen codes 0-31 = @,A-Z,[,\,],^,_ (uppercase)
# 32 = space, 33-63 = !,",...
SCREEN_TO_ASCII = {}
for i in range(0, 27):
    SCREEN_TO_ASCII[i] = chr(ord('@') + i)  # @, A-Z
SCREEN_TO_ASCII[0] = '@'
for i in range(1, 27):
    SCREEN_TO_ASCII[i] = chr(ord('A') + i - 1)
SCREEN_TO_ASCII[27] = '['
SCREEN_TO_ASCII[28] = '\\'
SCREEN_TO_ASCII[29] = ']'
SCREEN_TO_ASCII[30] = '^'
SCREEN_TO_ASCII[31] = '_'
SCREEN_TO_ASCII[32] = ' '
for i in range(33, 64):
    SCREEN_TO_ASCII[i] = chr(i)  # !"#$%&'()*+,-./0-9:;<=>?
# 64-95 repeat 0-31 (with high bit patterns)
for i in range(64, 96):
    SCREEN_TO_ASCII[i] = SCREEN_TO_ASCII[i - 64]
# 96-127: horizontal line and graphics chars -> use placeholder
for i in range(96, 128):
    SCREEN_TO_ASCII[i] = '.'
# 128-255: reverse video versions
for i in range(128, 256):
    SCREEN_TO_ASCII[i] = SCREEN_TO_ASCII.get(i - 128, '?')

# PETSCII to screen code mapping for sending keys
ASCII_TO_PETSCII = {}
for i in range(ord('A'), ord('Z') + 1):
    ASCII_TO_PETSCII[chr(i)] = i  # uppercase stays same in PETSCII
for i in range(ord('a'), ord('z') + 1):
    ASCII_TO_PETSCII[chr(i)] = i - 32  # lowercase -> uppercase PETSCII
for i in range(ord('0'), ord('9') + 1):
    ASCII_TO_PETSCII[chr(i)] = i
ASCII_TO_PETSCII[' '] = 0x20
ASCII_TO_PETSCII['\r'] = 0x0D
ASCII_TO_PETSCII['\n'] = 0x0D
ASCII_TO_PETSCII['!'] = 0x21
ASCII_TO_PETSCII['"'] = 0x22
ASCII_TO_PETSCII['#'] = 0x23
ASCII_TO_PETSCII['$'] = 0x24
ASCII_TO_PETSCII['%'] = 0x25
ASCII_TO_PETSCII['&'] = 0x26
ASCII_TO_PETSCII["'"] = 0x27
ASCII_TO_PETSCII['('] = 0x28
ASCII_TO_PETSCII[')'] = 0x29
ASCII_TO_PETSCII['*'] = 0x2A
ASCII_TO_PETSCII['+'] = 0x2B
ASCII_TO_PETSCII[','] = 0x2C
ASCII_TO_PETSCII['-'] = 0x2D
ASCII_TO_PETSCII['.'] = 0x2E
ASCII_TO_PETSCII['/'] = 0x2F
ASCII_TO_PETSCII[':'] = 0x3A
ASCII_TO_PETSCII[';'] = 0x3B
ASCII_TO_PETSCII['='] = 0x3D
ASCII_TO_PETSCII['?'] = 0x3F


class ViceMon:
    """Client for VICE's remote text monitor."""

    SCREEN_BASE = 0x0400
    SCREEN_COLS = 40
    SCREEN_ROWS = 25
    KEYBUF_ADDR = 0x0277
    KEYBUF_COUNT = 0x00C6

    def __init__(self, host='127.0.0.1', port=6510, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.labels = {}
        self._sock = None

    def _connect(self):
        """Create a fresh connection for a command."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        # Read the initial prompt
        self._drain(s, 0.3)
        return s

    def _drain(self, sock, wait=0.3):
        """Read all available data from socket."""
        data = b''
        sock.setblocking(False)
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
                if chunk:
                    data += chunk
                    deadline = time.time() + 0.1  # extend if still receiving
                else:
                    break
            except BlockingIOError:
                time.sleep(0.02)
        sock.setblocking(True)
        sock.settimeout(self.timeout)
        return data.decode('latin-1', errors='replace')

    def command(self, cmd):
        """Send a monitor command and return the response."""
        s = self._connect()
        try:
            s.sendall((cmd + '\n').encode())
            time.sleep(0.1)
            resp = self._drain(s, 0.5)
            return resp.strip()
        finally:
            s.close()

    def read_mem(self, addr, length):
        """Read memory bytes, returns list of ints."""
        end = addr + length - 1
        resp = self.command(f'm {addr:04x} {end:04x}')
        # Parse hex bytes from monitor output lines like:
        # >C:0400  05 18 10 20  0b 05 19 3a  20 37 03 20  06 04 20 03   ...
        result = []
        for line in resp.split('\n'):
            line = line.strip()
            if not line.startswith('>'):
                continue
            # Extract hex portion between address and ASCII dump
            # Format: >C:ADDR  XX XX XX XX  XX XX XX XX  ...  ASCII
            parts = line.split('  ')
            # parts[0] = ">C:ADDR", parts[1..N-1] = hex groups, parts[N] = ASCII
            for part in parts[1:]:
                part = part.strip()
                if not part:
                    continue
                # Check if this looks like hex bytes (not ASCII dump)
                tokens = part.split()
                if all(len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t) for t in tokens):
                    for t in tokens:
                        result.append(int(t, 16))
        return result[:length]

    def write_mem(self, addr, data):
        """Write bytes to memory. data is list of ints or bytes."""
        hex_str = ' '.join(f'{b:02x}' for b in data)
        self.command(f'>C:{addr:04x} {hex_str}')

    def screen_bytes(self):
        """Read all 1000 bytes of screen memory."""
        return self.read_mem(self.SCREEN_BASE, self.SCREEN_COLS * self.SCREEN_ROWS)

    def screen_text(self):
        """Read screen memory and return as 25-line text string."""
        raw = self.screen_bytes()
        lines = []
        for row in range(self.SCREEN_ROWS):
            start = row * self.SCREEN_COLS
            end = start + self.SCREEN_COLS
            chars = raw[start:end]
            line = ''.join(SCREEN_TO_ASCII.get(b, '?') for b in chars)
            lines.append(line)
        return '\n'.join(lines)

    def screen_lines(self):
        """Return screen as list of 25 strings (stripped)."""
        return self.screen_text().split('\n')

    def screen_has(self, text):
        """Check if text appears anywhere on screen."""
        return text.upper() in self.screen_text().upper()

    def send_key(self, char):
        """Send a single keypress by writing to the C64 keyboard buffer."""
        if char in ASCII_TO_PETSCII:
            petscii = ASCII_TO_PETSCII[char]
        elif isinstance(char, int):
            petscii = char
        else:
            raise ValueError(f"Unknown character: {char!r}")
        self.write_mem(self.KEYBUF_ADDR, [petscii])
        self.write_mem(self.KEYBUF_COUNT, [1])

    def send_keys(self, text, delay=0.05):
        """Send a string of keystrokes one at a time."""
        for ch in text:
            self.send_key(ch)
            time.sleep(delay)

    def resume(self):
        """Continue execution (exit monitor)."""
        s = self._connect()
        try:
            s.sendall(b'x\n')
            time.sleep(0.1)
        finally:
            s.close()

    def registers(self):
        """Read CPU registers, return as dict."""
        resp = self.command('r')
        regs = {}
        # Parse: .;XXXX AA XX YY SP ...
        for line in resp.split('\n'):
            m = re.match(r'\.;([0-9a-fA-F]{4})\s+([0-9a-fA-F]{2})\s+([0-9a-fA-F]{2})\s+([0-9a-fA-F]{2})\s+([0-9a-fA-F]{2})', line)
            if m:
                regs['PC'] = int(m.group(1), 16)
                regs['A'] = int(m.group(2), 16)
                regs['X'] = int(m.group(3), 16)
                regs['Y'] = int(m.group(4), 16)
                regs['SP'] = int(m.group(5), 16)
        return regs

    def load_labels(self, path):
        """Load VICE format label file."""
        self.labels = {}
        with open(path) as f:
            for line in f:
                line = line.strip()
                m = re.match(r'al\s+C:([0-9a-fA-F]+)\s+\.(\S+)', line)
                if m:
                    addr = int(m.group(1), 16)
                    name = m.group(2)
                    self.labels[name] = addr
        return len(self.labels)

    def label_addr(self, name):
        """Get address for a label name."""
        return self.labels.get(name)

    def hex_dump(self, addr, length):
        """Return hex dump string of memory region."""
        data = self.read_mem(addr, length)
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            lines.append(f'${addr+i:04X}: {hex_part}')
        return '\n'.join(lines)

    def wait_for_text(self, text, timeout=60, poll_interval=2, verbose=True):
        """Wait until text appears on screen. Returns True if found."""
        text_upper = text.upper()
        start = time.time()
        while time.time() - start < timeout:
            try:
                screen = self.screen_text()
                if text_upper in screen.upper():
                    return True
                if verbose:
                    elapsed = int(time.time() - start)
                    # Show last non-blank screen line as progress
                    lines = [l for l in screen.split('\n') if l.strip()]
                    last = lines[-1].strip() if lines else ''
                    print(f'  [{elapsed:3d}s] {last[:60]}', flush=True)
            except Exception as e:
                if verbose:
                    print(f'  [monitor error: {e}]', flush=True)
            time.sleep(poll_interval)
        return False

    def wait_for_stable(self, timeout=10, poll_interval=0.5):
        """Wait until screen content stops changing."""
        prev = None
        stable_count = 0
        start = time.time()
        while time.time() - start < timeout:
            try:
                current = self.screen_text()
                if current == prev:
                    stable_count += 1
                    if stable_count >= 3:
                        return current
                else:
                    stable_count = 0
                    prev = current
            except Exception:
                pass
            time.sleep(poll_interval)
        return prev


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()
    mon = ViceMon()

    if cmd == 'screen':
        text = mon.screen_text()
        for i, line in enumerate(text.split('\n')):
            print(f'{i:2d}| {line}')

    elif cmd == 'send':
        if len(sys.argv) < 3:
            print("Usage: vicemon.py send KEY")
            sys.exit(1)
        key = sys.argv[2]
        if key == 'RETURN':
            key = '\r'
        mon.send_key(key)
        print(f"Sent key: {sys.argv[2]!r}")

    elif cmd == 'wait':
        text = sys.argv[2] if len(sys.argv) > 2 else 'PASS'
        timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 60
        found = mon.wait_for_text(text, timeout=timeout)
        print(f"{'FOUND' if found else 'NOT FOUND'}: {text!r}")
        sys.exit(0 if found else 1)

    elif cmd == 'mem':
        addr = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x0400
        length = int(sys.argv[3], 0) if len(sys.argv) > 3 else 32
        print(mon.hex_dump(addr, length))

    elif cmd == 'regs':
        regs = mon.registers()
        for k, v in regs.items():
            print(f'  {k}: ${v:04X}' if k == 'PC' else f'  {k}: ${v:02X}')

    elif cmd == 'resume':
        mon.resume()
        print("Resumed execution")

    elif cmd == 'labels':
        path = sys.argv[2] if len(sys.argv) > 2 else 'build/labels.txt'
        n = mon.load_labels(path)
        print(f"Loaded {n} labels")
        if len(sys.argv) > 3:
            name = sys.argv[3]
            addr = mon.label_addr(name)
            print(f"  {name} = ${addr:04X}" if addr else f"  {name} not found")

    elif cmd == 'stable':
        text = mon.wait_for_stable()
        if text:
            for i, line in enumerate(text.split('\n')):
                print(f'{i:2d}| {line}')

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == '__main__':
    main()
