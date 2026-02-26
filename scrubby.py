#!/usr/bin/env python3
"""
scrubby.py - Sanitize tool output for safe sharing.

Deterministically replaces IPv4 addresses, MAC addresses, hostnames,
and domain names using fixed-offset or codename substitution. Fully
reversible via a JSON mapping file.

Usage:
  # Sanitize (auto-produces .map.json alongside output)
  python3 scrubby.py -i scan.txt -o sanitized.txt
  cat scan.txt | python3 scrubby.py -m my.map.json > sanitized.txt

  # Reverse (requires the mapping file)
  python3 scrubby.py --reverse -m sanitized.txt.map.json -i sanitized.txt -o original.txt

  # Dump human-readable table to stderr
  python3 scrubby.py -i scan.txt -o sanitized.txt --dump-map
"""

import re
import sys
import json
import argparse
from collections import OrderedDict

# Offset configuration
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
IP_OFFSETS  = (0, 10, 12, 0)
MAC_OFFSETS = (0x1A, 0x1A, 0x1A, 0x2C, 0x2C, 0x2C)

# Hostname / domain config
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
KNOWN_TLDS = {
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'us',
    'uk', 'de', 'fr', 'es', 'pt', 'nl', 'be', 'it', 'ru', 'cn', 'jp',
    'au', 'ca', 'br', 'in', 'info', 'biz', 'dev', 'app', 'cloud',
    'local', 'internal', 'corp', 'lan', 'home', 'localdomain', 'test',
    'example', 'invalid', 'localhost', 'arpa',
}

#| Domains we never sanitize (tool infra, public services, known vendors) ----
SAFE_DOMAINS = {
    'nmap.org', 'nmap.com',
    'cve.mitre.org', 'nvd.nist.gov',
    'exploit-db.com', 'github.com',
    'mozilla.org', 'apache.org', 'openssl.org',
    'ubuntu.com', 'debian.org', 'redhat.com', 'centos.org',
    'microsoft.com', 'google.com', 'cloudflare.com',
    'letsencrypt.org', 'digicert.com',
    'w3.org', 'iana.org', 'ietf.org',
}

REDACTED_DOMAIN = 'redacted.local'
HOST_PREFIX     = 'host'

#| Always skip our own substitution domain ----
SAFE_DOMAINS.add(REDACTED_DOMAIN)

# Tracking dicts (original -> sanitized)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
ip_map:   OrderedDict[str, str] = OrderedDict()
mac_map:  OrderedDict[str, str] = OrderedDict()
host_map: OrderedDict[str, str] = OrderedDict()      # original_case -> alias
_host_seen: dict[str, str]     = {}                  # lowercase -> alias (dedup)

_host_counter = 0

# Core substitution helpers
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def _wrap_octet(value: int, offset: int) -> int:
    if offset == 0:
        return value
    return (value - 1 + offset) % 254 + 1


def _next_host_alias(is_fqdn: bool) -> str:
    global _host_counter
    _host_counter += 1
    base = f'{HOST_PREFIX}-{_host_counter:04d}'
    return f'{base}.{REDACTED_DOMAIN}' if is_fqdn else base


def sanitize_ip(match: re.Match) -> str:
    original = match.group(0)
    octets = list(map(int, original.split('.')))
    if any(o > 255 for o in octets):
        return original

    if original in ip_map:
        return ip_map[original]

    sanitized_octets = [_wrap_octet(o, off) for o, off in zip(octets, IP_OFFSETS)]
    sanitized = '.'.join(str(o) for o in sanitized_octets)
    ip_map[original] = sanitized
    return sanitized


def sanitize_mac(match: re.Match) -> str:
    original = match.group(0)
    sep = ':' if ':' in original else '-'
    key = original.upper()

    if key in mac_map:
        stored = mac_map[key]
        return stored.replace(':', sep).replace('-', sep)

    bytes_ = [int(b, 16) for b in re.split(r'[:\-]', original)]
    sanitized_bytes = [(b + off) % 256 for b, off in zip(bytes_, MAC_OFFSETS)]
    sanitized = sep.join(f'{b:02X}' for b in sanitized_bytes)
    mac_map[key] = sanitized
    return sanitized


def _is_safe_domain(domain: str) -> bool:
    dl = domain.lower()
    for safe in SAFE_DOMAINS:
        if dl == safe or dl.endswith('.' + safe):
            return True
    return False


def _has_known_tld(domain: str) -> bool:
    parts = domain.lower().rsplit('.', 1)
    return len(parts) == 2 and parts[1] in KNOWN_TLDS


def sanitize_fqdn(match: re.Match) -> str:
    original = match.group(0)

    if _is_safe_domain(original):
        return original

    key = original.lower()
    if key in _host_seen:
        return _host_seen[key]

    alias = _next_host_alias(is_fqdn=True)
    _host_seen[key] = alias
    host_map[original] = alias
    return alias


# Regex patterns 
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b'
)

MAC_RE = re.compile(
    r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'
)

_tld_alt = '|'.join(sorted(KNOWN_TLDS, key=len, reverse=True))
FQDN_RE = re.compile(
    r'(?<![/@\w])'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}'
    r'(?:' + _tld_alt + r')'
    r'\b',
    re.IGNORECASE
)

# | Contextual short hostnames - after keywords that signal a hostname. 
# | Hostname must look hostname-like: contain a hyphen, digit, or dot. ----

HOST_CONTEXT_RE = re.compile(
    r'((?:for|hostname|server|target|rdns|PTR\s+record'
    r'|NetBIOS\s+name|Computer\s+name|DNS\s+name|FQDN)[:\s]+)'
    r'([a-zA-Z][a-zA-Z0-9\-_.]{2,40})',
    re.IGNORECASE
)


def _ctx_host_replace(m: re.Match) -> str:
    prefix   = m.group(1)
    hostname = m.group(2)
    hl       = hostname.lower()

    #| Already handled, safe, or looks like an IP / version string ----
    if hl in _host_seen or _is_safe_domain(hl):
        if hl in _host_seen:
            return prefix + _host_seen[hl]
        return m.group(0)
    if IP_RE.fullmatch(hostname):
        return m.group(0)
    if re.fullmatch(r'[\d.]+[a-z]?\d*', hostname):
        return m.group(0)
    #| Must look like a hostname: contain a hyphen, digit, dot, or underscore ----
    if not re.search(r'[\-\d._]', hostname):
        return m.group(0)

    is_fqdn = '.' in hostname and _has_known_tld(hostname)
    alias = _next_host_alias(is_fqdn=is_fqdn)
    _host_seen[hl] = alias
    host_map[hostname] = alias
    return prefix + alias


def sanitize_line(line: str) -> str:
    """Apply all sanitization passes to a single line."""
    line = MAC_RE.sub(sanitize_mac, line)
    line = IP_RE.sub(sanitize_ip, line)
    line = FQDN_RE.sub(sanitize_fqdn, line)
    line = HOST_CONTEXT_RE.sub(_ctx_host_replace, line)
    return line


# Mapping file I/O
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def save_mapping(path: str):
    data = {
        'version': 2,
        'note': 'KEEP PRIVATE. Required for --reverse.',
        'ip_map':   dict(ip_map),
        'mac_map':  dict(mac_map),
        'host_map': dict(host_map),
    }
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def load_mapping(path: str) -> dict:
    with open(path, 'r') as f:
        return json.load(f)


def build_reverse_map(data: dict) -> list[tuple[str, str]]:
    """Build sanitized->original pairs, sorted longest-key-first."""
    pairs: list[tuple[str, str]] = []
    for orig, san in data.get('ip_map', {}).items():
        pairs.append((san, orig))
    for orig, san in data.get('mac_map', {}).items():
        pairs.append((san, orig))
    for orig, san in data.get('host_map', {}).items():
        pairs.append((san, orig))
    #| Longest first prevents partial substring matches ----
    pairs.sort(key=lambda kv: len(kv[0]), reverse=True)
    return pairs


def reverse_line(line: str, rev_pairs: list[tuple[str, str]]) -> str:
    for sanitized, original in rev_pairs:
        line = line.replace(sanitized, original)
    return line


# Human-readable mapping dump
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def dump_mapping_table(stream=sys.stderr):
    if not (ip_map or mac_map or host_map):
        return

    stream.write('\n' + '=' * 68 + '\n')
    stream.write('  SANITIZATION MAP  (keep private — needed for --reverse)\n')
    stream.write('=' * 68 + '\n')

    if ip_map:
        stream.write('\n  IPv4 Addresses:\n')
        stream.write('  ' + '-' * 56 + '\n')
        for orig, san in ip_map.items():
            stream.write(f'  {orig:<20s}  ->  {san}\n')

    if mac_map:
        stream.write('\n  MAC Addresses:\n')
        stream.write('  ' + '-' * 56 + '\n')
        for orig, san in mac_map.items():
            stream.write(f'  {orig:<20s}  ->  {san}\n')

    if host_map:
        stream.write('\n  Hostnames / Domains:\n')
        stream.write('  ' + '-' * 56 + '\n')
        for orig, san in host_map.items():
            stream.write(f'  {orig:<40s}  ->  {san}\n')

    stream.write('=' * 68 + '\n')


# CLI
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Sanitize pentest output (IPs, MACs, hostnames). Reversible.'
    )
    parser.add_argument('-i', '--input',  help='Input file (default: stdin)')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument(
        '-m', '--map-file',
        help='Path for JSON mapping file. '
             'Default on sanitize: <output>.map.json. Required on --reverse.'
    )
    parser.add_argument(
        '--reverse', action='store_true',
        help='Reverse mode: restore originals using a mapping file.'
    )
    parser.add_argument(
        '--dump-map', action='store_true',
        help='Print human-readable mapping table to stderr.'
    )
    args = parser.parse_args()

    # ---- REVERSE MODE ----
    if args.reverse:
        if not args.map_file:
            parser.error('--reverse requires -m <mapping.json>')

        data = load_mapping(args.map_file)
        rev_pairs = build_reverse_map(data)

        if args.input:
            with open(args.input, 'r', errors='replace') as f:
                lines = f.readlines()
        else:
            lines = sys.stdin.readlines()

        restored = [reverse_line(line, rev_pairs) for line in lines]

        if args.output:
            with open(args.output, 'w') as f:
                f.writelines(restored)
            sys.stderr.write(f'[*] Restored output written to: {args.output}\n')
        else:
            sys.stdout.writelines(restored)

        return

    #| SANITIZE MODE ----
  
    if args.input:
        with open(args.input, 'r', errors='replace') as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()

    sanitized = [sanitize_line(line) for line in lines]

  #| Write sanitized output ----
  
  if args.output:
        with open(args.output, 'w') as f:
            f.writelines(sanitized)
        map_path = args.map_file or (args.output + '.map.json')
        save_mapping(map_path)
        sys.stderr.write(f'[*] Sanitized output : {args.output}\n')
        sys.stderr.write(f'[*] Mapping saved to : {map_path}\n')
    else:
        sys.stdout.writelines(sanitized)
        if args.map_file:
            save_mapping(args.map_file)
            sys.stderr.write(f'[*] Mapping saved to: {args.map_file}\n')
        else:
            sys.stderr.write(
                '[!] No -o or -m specified — mapping NOT saved. '
                'Use -m <file> to enable --reverse later.\n'
            )

    if args.dump_map:
        dump_mapping_table()


if __name__ == '__main__':
    main()
