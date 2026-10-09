# ecdsa-secp256k1

Pure-Python ECDSA signing and verification on the **secp256k1** curve —
the elliptic curve behind Bitcoin and Ethereum signatures. Zero dependencies,
standard library only (`hashlib`, `hmac`).

## What's inside

- `ecdsa.py` — the whole implementation in one file:
  - secp256k1 field/group arithmetic (affine double-and-add)
  - **RFC 6979** deterministic nonce generation (HMAC-SHA256) — no weak RNG,
    the same message + key always yields the same signature
  - `sign()` / `verify()` per SEC 1
  - **low-S** normalization (Bitcoin's malleability fix convention)
  - DER signature encoding/decoding (BIP 66 style)
  - compressed / uncompressed public-key serialization

## Usage

```python
import hashlib
from ecdsa import sign, verify, pubkey_from_priv, serialize_pubkey, der_encode

priv = 0x1                                    # private key
pub = pubkey_from_priv(priv)                  # (x, y)

digest = hashlib.sha256(b"hello").digest()
r, s = sign(digest, priv)

assert verify(digest, (r, s), pub)             # True
assert verify(digest, der_decode(der_encode((r, s))), pub)

print(serialize_pubkey(pub).hex())            # compressed pubkey
```

## Verified

- Generator point matches the SEC 2 known vector:
  `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`
- Built-in known-answer test: signing `SHA256("Satoshi Nakamoto")` with
  private key `1` is deterministic (RFC 6979) and asserted in `__main__`.
- Cross-checked against OpenSSL in both directions: OpenSSL-produced
  signatures verify with this code, and signatures produced by this code
  verify with `openssl dgst -verify`.

Run `python3 ecdsa.py` for the self-test demo.

## Note

Educational code — not audited. Do not use it to guard real funds.
