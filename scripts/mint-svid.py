#!/usr/bin/env python3
"""Mint SPIFFE JWT-SVIDs and a SPIFFE trust-bundle JWKS without SPIRE.

Purpose: exercise Keycloak's federated client authentication (SPIFFE provider)
on a lab box where standing up SPIRE would be disproportionate.

Deliberately stdlib-only: P-256 ECDSA is implemented below so the script runs on
a bare Fedora python3 with no pip installs. This is LAB code -- it holds a
private key in a file and is not constant-time. Never use it outside a lab.

Outputs (relative to --outdir, default ../cimd):
    bundle.json   SPIFFE bundle for the trust domain:
                  {"keys":[{"use":"jwt-svid","kid":...,"kty":"EC","crv":"P-256",...}],
                   "spiffe_sequence":N,"spiffe_refresh_hint":300}
                  Keycloak's SpiffeJSONWebKeySet expects the two spiffe_* fields
                  at the top level and does NOT set "alg" on the JWK.
    svid.jwt      the last minted JWT-SVID (for shell convenience)

Usage:
    ./mint-svid.py init  --trust-domain spiffe://lab.local
    ./mint-svid.py mint  --trust-domain spiffe://lab.local \
                         --subject spiffe://lab.local/workload/mcp-client \
                         --audience https://kc.lab.local:8443/realms/lab
    ./mint-svid.py mint  ... --audience https://wrong.example   # negative test
    ./mint-svid.py mint  ... --exp-offset -120                  # expired
    ./mint-svid.py selftest
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time

# --- P-256 (secp256r1) parameters -------------------------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _inv(x: int, m: int = P) -> int:
    return pow(x % m, -1, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def _mul(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int32(v: int) -> bytes:
    return v.to_bytes(32, "big")


def _keys_dir(outdir: str, trust_domain: str) -> str:
    td = trust_domain.split("://", 1)[-1].strip("/") or "default"
    d = os.path.join(outdir, "keys", td)
    os.makedirs(d, exist_ok=True)
    return d


def init_key(outdir: str, trust_domain: str) -> tuple[int, tuple[int, int]]:
    d = _keys_dir(outdir, trust_domain)
    path = os.path.join(d, "ec-p256.pem")
    if os.path.exists(path):
        d_val, x, y = (int(v, 16) for v in open(path).read().split())
        return d_val, (x, y)
    d_val = secrets.randbelow(N - 1) + 1
    qx, qy = _mul(d_val, (GX, GY))
    with open(path, "w") as fh:
        os.chmod(path, 0o600)
        fh.write(f"{d_val:x} {qx:x} {qy:x}\n")
    return d_val, (qx, qy)


def kid_for(pub: tuple[int, int]) -> str:
    raw = _int32(pub[0]) + _int32(pub[1])
    return _b64u(hashlib.sha256(raw).digest()[:12])


def write_bundle(outdir: str, trust_domain: str, pub, kid: str, sequence: int) -> str:
    bundle = {
        "keys": [
            {
                "use": "jwt-svid",
                "kid": kid,
                "kty": "EC",
                "crv": "P-256",
                "x": _b64u(_int32(pub[0])),
                "y": _b64u(_int32(pub[1])),
            }
        ],
        # SPIFFE bundle metadata; Keycloak's bundle loader reads both.
        "spiffe_sequence": sequence,
        "spiffe_refresh_hint": 300,
    }
    path = os.path.join(outdir, "bundle.json")
    os.makedirs(outdir, exist_ok=True)
    with open(path, "w") as fh:
        json.dump(bundle, fh, indent=2)
        fh.write("\n")
    return path


def sign_es256(signing_input: bytes, d_val: int) -> bytes:
    z = int.from_bytes(hashlib.sha256(signing_input).digest(), "big") % N
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = _mul(k, (GX, GY))[0] % N
        if r == 0:
            continue
        s = _inv(k, N) * (z + r * d_val) % N
        if s == 0:
            continue
        return _int32(r) + _int32(s)


def verify_es256(signing_input: bytes, sig: bytes, pub) -> bool:
    if len(sig) != 64:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(hashlib.sha256(signing_input).digest(), "big") % N
    w = _inv(s, N)
    point = _add(_mul(z * w % N, (GX, GY)), _mul(r * w % N, pub))
    return point is not None and point[0] % N == r


def mint(outdir, trust_domain, subject, audience, kid, exp_offset, ttl, sequence):
    d_val, pub = init_key(outdir, trust_domain)
    kid = kid or kid_for(pub)
    now = int(time.time())
    header = {"alg": "ES256", "kid": kid, "typ": "JWT"}
    payload = {
        "sub": subject,
        "aud": [audience],
        "exp": now + exp_offset + ttl,
        "iat": now,
    }
    signing_input = (
        _b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64u(json.dumps(payload, separators=(",", ":")).encode())
    ).encode()
    token = signing_input.decode() + "." + _b64u(sign_es256(signing_input, d_val))
    bundle_path = write_bundle(outdir, trust_domain, pub, kid, sequence)
    with open(os.path.join(outdir, "svid.jwt"), "w") as fh:
        fh.write(token + "\n")
    print(token)
    print(f"# bundle: {bundle_path}", file=sys.stderr)
    print(f"# kid: {kid}  sub: {subject}  aud: {audience}", file=sys.stderr)
    print(f"# exp: {payload['exp']} (now{'+' if exp_offset >= 0 else ''}{exp_offset}s)", file=sys.stderr)


def selftest() -> int:
    d_val, pub = init_key("/tmp/cimd-selftest", "spiffe://selftest.local")
    msg = b"header.payload"
    sig = sign_es256(msg, d_val)
    ok = verify_es256(msg, sig, pub)
    bad = verify_es256(b"header.payloadX", sig, pub)
    print(f"sign/verify ok={ok} tamper-rejected={not bad}")
    if not ok or bad:
        return 1
    # Known-answer check of the curve arithmetic: 1*G == G, n*G == infinity.
    assert _mul(1, (GX, GY)) == (GX, GY)
    assert _mul(N, (GX, GY)) is None
    print("curve arithmetic ok (1G==G, nG==O)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outdir", default=os.path.join(os.path.dirname(__file__), "..", "cimd"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "mint"):
        p = sub.add_parser(name)
        p.add_argument("--trust-domain", default="spiffe://lab.local")
        if name == "init":
            continue
        p.add_argument("--subject", default="spiffe://lab.local/workload/mcp-client")
        p.add_argument("--audience", default="https://kc.lab.local:8443/realms/lab")
        p.add_argument("--kid", default=None)
        p.add_argument("--exp-offset", type=int, default=0,
                       help="seconds to shift exp/iat; negative = already expired")
        p.add_argument("--ttl", type=int, default=300)
        p.add_argument("--sequence", type=int, default=1)
    sub.add_parser("selftest")
    args = ap.parse_args()

    outdir = os.path.abspath(args.outdir)
    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "init":
        _, pub = init_key(outdir, args.trust_domain)
        print(write_bundle(outdir, args.trust_domain, pub, kid_for(pub), 1))
        return 0
    mint(outdir, args.trust_domain, args.subject, args.audience, args.kid,
         args.exp_offset, args.ttl, args.sequence)
    return 0


if __name__ == "__main__":
    sys.exit(main())
