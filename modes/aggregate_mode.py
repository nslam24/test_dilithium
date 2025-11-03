#!/usr/bin/env python3
"""Aggregate multi-signature (simple Rahmati-style demo).

This module implements a simple aggregation scheme for demonstration purposes.
Each participant produces a partial signature (their usual signature). The
aggregator computes per-partial digests h_i = H(partial_i) (sha3_512), then
computes:

  c = H(h_1 || h_2 || ... || h_n)
  z = (SUM_i int(h_i)) mod 2**512    # fixed-size 512-bit accumulator

The aggregate signature is (c, z). Verification will:
 - verify each partial signature individually against its public key
 - recompute h_i and check that c and z match the aggregate

This is a pedagogical implementation and not a production secure aggregate
scheme. It demonstrates combining partials and verifying an aggregated value.

Vietnamese comments included.
"""
from typing import List, Tuple, Dict
import hashlib
import time
import base64

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend


def _sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def sign_partials(message: bytes, key_pairs: List[Tuple[bytes, bytes]], level: str, sig_type: str) -> Tuple[List[bytes], List[float]]:
    """Each signer returns a partial signature (their normal signature).

    Returns (partials, sign_times)
    """
    partials: List[bytes] = []
    sign_times: List[float] = []
    for pub, priv in key_pairs:
        t0 = time.time()
        if sig_type == "dilithium":
            with oqs.Signature(level, priv) as signer:
                sig = signer.sign(message)
        elif sig_type == "rsa":
            sk = serialization.load_der_private_key(priv, password=None, backend=default_backend())
            sig = sk.sign(message, padding.PKCS1v15(), hashes.SHA256())
        else:
            sk = serialization.load_der_private_key(priv, password=None, backend=default_backend())
            sig = sk.sign(message, ec.ECDSA(hashes.SHA256()))
        t1 = time.time()
        partials.append(sig)
        sign_times.append(t1 - t0)
    return partials, sign_times


def aggregate_partials(partials: List[bytes]) -> Dict[str, str]:
    """Aggregate partial signatures into an aggregate signature dict.

    Returns a dict { 'c': base64, 'z': base64 }
    """
    # compute h_i = H(partial_i)
    hs = [_sha3_512(p) for p in partials]
    # c = H(h1 || h2 || ...)
    c = _sha3_512(b"".join(hs))
    # z = SUM(int(h_i)) mod 2**512, returned as 64-byte big-endian
    total = 0
    for h in hs:
        total = (total + int.from_bytes(h, "big")) & ((1 << 512) - 1)
    z_bytes = total.to_bytes(64, "big")
    return {"c": base64.b64encode(c).decode(), "z": base64.b64encode(z_bytes).decode()}


def verify_aggregate(message: bytes, aggregate: Dict[str, str], public_keys: List[bytes], partials: List[bytes], level: str, sig_type: str) -> Tuple[bool, List[bool], List[float]]:
    """Verify an aggregate signature by verifying partials and matching c,z.

    Returns (overall_ok, per_partial_results, per_partial_verify_times)
    """
    # First verify partials individually
    results: List[bool] = []
    verify_times: List[float] = []
    for sig, pub in zip(partials, public_keys):
        t0 = time.time()
        if sig_type == "dilithium":
            with oqs.Signature(level) as verifier:
                ok = verifier.verify(message, sig, pub)
        elif sig_type == "rsa":
            pk = serialization.load_der_public_key(pub, backend=default_backend())
            try:
                pk.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
                ok = True
            except Exception:
                ok = False
        else:
            pk = serialization.load_der_public_key(pub, backend=default_backend())
            try:
                pk.verify(sig, message, ec.ECDSA(hashes.SHA256()))
                ok = True
            except Exception:
                ok = False
        t1 = time.time()
        results.append(ok)
        verify_times.append(t1 - t0)

    # If any partial didn't verify, overall fails
    if not all(results):
        return False, results, verify_times

    # Recompute aggregate values from partials and compare
    hs = [_sha3_512(p) for p in partials]
    c_calc = _sha3_512(b"".join(hs))
    total = 0
    for h in hs:
        total = (total + int.from_bytes(h, "big")) & ((1 << 512) - 1)
    z_calc = total.to_bytes(64, "big")

    c_b = base64.b64decode(aggregate["c"]) if isinstance(aggregate.get("c"), str) else aggregate.get("c")
    z_b = base64.b64decode(aggregate["z"]) if isinstance(aggregate.get("z"), str) else aggregate.get("z")

    c_ok = c_b == c_calc
    z_ok = z_b == z_calc

    return (c_ok and z_ok), results, verify_times


if __name__ == "__main__":
    # Simple smoke-test: sign partials, aggregate, verify
    import argparse, json, os

    parser = argparse.ArgumentParser(description="Aggregate multisig smoke test")
    parser.add_argument("--level", default="Dilithium3")
    parser.add_argument("--users", default=",".join([f"user{i+1}" for i in range(3)]))
    parser.add_argument("--message", default="Aggregate demo")
    parser.add_argument("--keys-dir", default="keys")
    args = parser.parse_args()

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    pairs = []
    pubs = []
    for u in users:
        pub_path = os.path.join(args.keys_dir, u, args.level, "public.key")
        priv_path = os.path.join(args.keys_dir, u, args.level, "private.key")
        with open(pub_path, "rb") as f:
            pub = f.read()
        with open(priv_path, "rb") as f:
            priv = f.read()
        pairs.append((pub, priv))
        pubs.append(pub)

    partials, st = sign_partials(args.message.encode(), pairs, args.level, "dilithium")
    agg = aggregate_partials(partials)
    ok, results, vt = verify_aggregate(args.message.encode(), agg, pubs, partials, args.level, "dilithium")
    print("Partial sign times:", st)
    print("Partial verify results:", results)
    print("Partial verify times:", vt)
    print("Aggregate:", json.dumps(agg))
    print("Aggregate verified:", ok)
