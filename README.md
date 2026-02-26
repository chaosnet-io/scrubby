# scrubby

tldr; Sanitizes tool output for safe sharing. Can also revert back to original values if needed :)

Deterministically replaces IPv4 addresses, MAC addresses, hostnames, and domain names using fixed-offset or codename substitution. Fully reversible via a JSON mapping file.

The description below details the obfuscation logic of the script as it sits on the repo, not only the values are easily changed on the script's first few lines (~27-32), I **strongly recommend** you change them to something else to add entropy to your own file sanitization.

## IP Logic:
  - 1st octet: preserved (keeps network context)
  - 2nd octet: +10 (wrapped to 1-254)
  - 3rd octet: +12 (wrapped to 1-254)
  - 4th octet: preserved (keeps host differentiation)

## MAC Logic:
  - Bytes 0-2 (OUI): each byte +0x1A (wrapped to 00-FF)
  - Bytes 3-5 (NIC): each byte +0x2C (wrapped to 00-FF)

## Hostname/Domain Logic:
  - FQDNs   -> host-NNNN.redacted.local
  - Short   -> host-NNNN

Usage:
  # Sanitize (auto-produces .map.json alongside output)
  python3 scrubby.py -i scan.txt -o sanitized.txt
  cat scan.txt | python3 scrubby.py -m my.map.json > sanitized.txt

  # Reverse (requires the mapping file)
  python3 scrubby.py --reverse -m sanitized.txt.map.json -i sanitized.txt -o original.txt

  # Dump human-readable table to stderr
  python3 scrubby.py -i scan.txt -o sanitized.txt --dump-map
