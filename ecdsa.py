"""Pure-Python ECDSA on the secp256k1 curve (Bitcoin/Ethereum's curve).

Zero dependencies — standard library only (hashlib, hmac).

Implements:
  * secp256k1 field and group arithmetic (affine double-and-add)
  * RFC 6979 deterministic nonce generation (HMAC-SHA256)
  * sign() / verify() per SEC 1, with low-S normalization (Bitcoin convention)
  * DER signature encoding / decoding (BIP 66 style)
  * compressed / uncompressed public key serialization

Educational code — not audited, do not use to guard real funds.
"""

import hashlib
import hmac

# ---------------------------------------------------------------------------
# secp256k1 domain parameters (SEC 2)
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # field prime
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
INF = None  # point at infinity


# ---------------------------------------------------------------------------
# curve arithmetic
# ---------------------------------------------------------------------------
def _inv(a, p=P):
    """Modular inverse via Fermat's little theorem."""
    return pow(a % p, p - 2, p)


def point_add(p1, p2):
    """Add two affine curve points (INF-safe)."""
    if p1 is INF:
        return p2
    if p2 is INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return INF
        slope = (3 * x1 * x1 + A) * _inv(2 * y1) % P  # point doubling
    else:
        slope = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, point=G):
    """Scalar multiplication via double-and-add."""
    k %= N
    result = INF
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# RFC 6979 deterministic nonces (HMAC-SHA256)
# ---------------------------------------------------------------------------
def _bits2int(b):
    """RFC 6979 §2.3.2: bit string -> integer, truncated to qlen bits."""
    i = int.from_bytes(b, "big")
    blen = len(b) * 8
    qlen = N.bit_length()
    if blen > qlen:
        i >>= blen - qlen
    return i


def _bits2octets(b):
    """RFC 6979 §2.3.4: bit string -> qlen-octet string, reduced mod N."""
    z = _bits2int(b)
    if z >= N:
        z -= N
    return z.to_bytes(32, "big")


def rfc6979_nonce(priv, msg_hash):
    """RFC 6979 §3.2: deterministic nonce k in [1, N-1]."""
    x = priv.to_bytes(32, "big")
    h1 = _bits2octets(msg_hash)
    v = b"\x01" * 32
    k = b"\x00" * 32

    def hmac_k(data):
        return hmac.new(k, data, hashlib.sha256).digest()

    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        t = b""
        while len(t) < 32:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        cand = _bits2int(t)
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# signing / verification (SEC 1 §4.1.3 / §4.1.4)
# ---------------------------------------------------------------------------
def _hash_to_int(msg_hash):
    return _bits2int(msg_hash)


def sign(msg_hash, priv, low_s=True):
    """Sign a 32-byte message digest. Returns (r, s)."""
    if not (1 <= priv < N):
        raise ValueError("private key out of range")
    e = _hash_to_int(msg_hash)
    while True:
        k = rfc6979_nonce(priv, msg_hash)
        r_point = point_mul(k)
        r = r_point[0] % N
        if r == 0:
            continue
        s = (_inv(k, N) * (e + r * priv)) % N
        if s == 0:
            continue
        if low_s and s > N // 2:  # BIP 62 low-S normalization
            s = N - s
        return (r, s)


def verify(msg_hash, sig, pub):
    """Verify an (r, s) signature against a public point. Returns bool."""
    r, s = sig
    if not (1 <= r < N and 1 <= s < N):
        return False
    if pub is INF or not _on_curve(pub):
        return False
    e = _hash_to_int(msg_hash)
    w = _inv(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N
    x = point_add(point_mul(u1), point_mul(u2, pub))
    if x is INF:
        return False
    return (x[0] % N) == r


def _on_curve(point):
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


# ---------------------------------------------------------------------------
# DER encoding (BIP 66)
# ---------------------------------------------------------------------------
def _der_int(x):
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der_encode(sig):
    """Encode (r, s) as a DER SEQUENCE."""
    r, s = sig
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def der_decode(der):
    """Decode a DER signature back to (r, s)."""
    if der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("bad DER prefix")
    pos = 2
    if der[pos] != 0x02:
        raise ValueError("bad DER integer marker")
    rlen = der[pos + 1]
    r = int.from_bytes(der[pos + 2:pos + 2 + rlen], "big")
    pos += 2 + rlen
    if der[pos] != 0x02:
        raise ValueError("bad DER integer marker")
    slen = der[pos + 1]
    s = int.from_bytes(der[pos + 2:pos + 2 + slen], "big")
    if pos + 2 + slen != len(der):
        raise ValueError("trailing DER bytes")
    return (r, s)


# ---------------------------------------------------------------------------
# key serialization
# ---------------------------------------------------------------------------
def pubkey_from_priv(priv):
    return point_mul(priv)


def serialize_pubkey(pub, compressed=True):
    x, y = pub
    if compressed:
        return bytes([0x02 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# demo / self-test
# ---------------------------------------------------------------------------
def _demo():
    priv = 1
    pub = pubkey_from_priv(priv)
    # known-answer: G in compressed form (SEC 2)
    assert serialize_pubkey(pub).hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ), "generator point mismatch"

    msg = b"Satoshi Nakamoto"
    digest = hashlib.sha256(msg).digest()
    r, s = sign(digest, priv)

    # known-answer test: RFC 6979 is deterministic, so this never changes.
    # (vector produced by this implementation; cross-checked with OpenSSL)
    assert r == 0x934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8, "KAT r"
    assert s == 0x2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5, "KAT s"

    assert verify(digest, (r, s), pub)
    assert verify(digest, der_decode(der_encode((r, s))), pub)
    assert not verify(hashlib.sha256(b"tampered").digest(), (r, s), pub)
    assert not verify(digest, (r, N), pub)  # out-of-range s

    print("msg      :", msg.decode())
    print("digest   : 0x" + digest.hex())
    print("priv     : 0x%064x" % priv)
    print("pubkey   :", serialize_pubkey(pub).hex())
    print("r        : 0x%064x" % r)
    print("s        : 0x%064x" % s)
    print("DER      :", der_encode((r, s)).hex())
    print("verified : OK (round-trip, DER, tamper rejection all pass)")


if __name__ == "__main__":
    _demo()
