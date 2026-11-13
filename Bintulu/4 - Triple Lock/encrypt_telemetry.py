#!/usr/bin/env python3
"""
PETRONAS Bintulu MLNG — SCADA Telemetry Encryption Module

Recovered from compromised historian server HST-BIN-03.
This script was used to encrypt exfiltrated production telemetry
before transmission to external C2 infrastructure.

Three cryptographic keys were generated from hardware entropy
on the historian server. Each key is a 128-bit prime. Their
product serves as the composite encryption modulus.

The encryption uses a four-stage pipeline:

  Stage 1 — Raw reading compressed with exponent e1
             (three LNG train groups: Satu, Dua, Tiga)
  Stage 2 — Two of the three key fragments added as offset
  Stage 3 — Result sealed with exponent e2
             (nine LNG production trains)
  Stage 4 — Integrity tag XOR from SHA-256 of sealed block

Partial key material was recovered from a RAM dump of HST-BIN-03
before the attacker wiped the disk. The output files are in the
telemetry_output/ directory.
"""

import hashlib
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


KEY_BITS = 128

key_alpha = getPrime(KEY_BITS)
key_beta  = getPrime(KEY_BITS)
key_gamma = getPrime(KEY_BITS)

composite_key = key_alpha * key_beta * key_gamma

e1 = 3
e2 = 5


def encrypt_block(data, e1, e2, modulus):
    m = bytes_to_long(data)

    raw_reading = pow(m, e1, modulus)

    two_fragments = key_alpha + key_beta
    compressed = (raw_reading + two_fragments) % modulus

    sealed = pow(compressed, e2, modulus)

    tag = int(
        hashlib.sha256(
            str(modulus).encode()
        ).hexdigest()[:8],
        16
    )

    return sealed ^ tag


telemetry = b"PETRONAS{????????????????????????????????}"

assert bytes_to_long(telemetry) < composite_key, \
    "telemetry block exceeds modulus capacity"


encrypted = encrypt_block(
    telemetry,
    e1,
    e2,
    composite_key
)


FRAGMENT_BITS = 64

fragment_alpha = bin(key_alpha)[-FRAGMENT_BITS:]
fragment_beta  = bin(key_beta)[-FRAGMENT_BITS:]

sequence_number = (key_alpha + key_beta) % 100000


with open("telemetry_header.txt", "w") as f:
    f.write("PETRONAS BINTULU MLNG — SCADA TELEMETRY INTERCEPT\n")
    f.write("Classification : CONFIDENTIAL — XENOTIME INVESTIGATION\n")
    f.write("Source         : Historian Server HST-BIN-03, Train 9\n")
    f.write("Status         : Encrypted, partial key material recovered from RAM dump\n\n")
    f.write(f"Composite key    = {composite_key}\n")
    f.write(f"Fragment alpha   = {fragment_alpha}\n")
    f.write(f"Fragment beta    = {fragment_beta}\n")
    f.write(f"Sequence number  = {sequence_number}\n")


with open("encrypted_telemetry.enc", "w") as f:
    f.write(str(encrypted))


print("Telemetry encrypted and stored.")
