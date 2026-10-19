#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check publication files for credentials, runtime artifacts and real IPs."""
import ipaddress
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SKIP = {'.git', '.test-tmp', '__pycache__', '.venv', '.pytest_cache'}
ALLOWED_IPS = tuple(ipaddress.ip_network(n) for n in (
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24',
    '198.18.0.0/15', '127.0.0.0/8', '0.0.0.0/32'))
TOKEN = re.compile(rb'\b[0-9]{6,12}:[A-Za-z0-9_-]{25,}\b')
IP = re.compile(rb'(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])')
PRIVATE = re.compile(b'-----BEGIN '+rb'(?:OPENSSH |RSA |EC )?PRIVATE KEY-----')


def files():
    for path in sorted(ROOT.rglob('*')):
        if path.is_file() and not any(part in SKIP for part in path.relative_to(ROOT).parts):
            yield path


def check():
    errors = []
    paths = list(files())
    for path in paths:
        relative = str(path.relative_to(ROOT))
        if path.name == 'config.json' or path.suffix in ('.sqlite3', '.db', '.log', '.key', '.pem', '.pub'):
            errors.append(relative+': runtime or credential file')
        if path.name.endswith(('.sqlite3-wal','.sqlite3-shm')) or path.name.startswith(('id_rsa','id_ed25519')):
            errors.append(relative+': private runtime artifact')
        data = path.read_bytes()
        if TOKEN.search(data) or PRIVATE.search(data):
            errors.append(relative+': possible credential (contents intentionally hidden)')
        if path.suffix.lower() in ('.jpg','.jpeg','.png'):
            continue
        for found in IP.finditer(data):
            try:
                ip = ipaddress.ip_address(found[0].decode())
            except ValueError:
                continue
            if not any(ip in network for network in ALLOWED_IPS):
                errors.append(relative+': non-documentation IPv4 address (value intentionally hidden)')
    return paths, errors


if __name__ == '__main__':
    paths, errors = check()
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        raise SystemExit(1)
    print(f'Publication scan passed: {len(paths)} files; no candidate tokens, private keys, runtime artifacts or real IPv4 addresses.')
