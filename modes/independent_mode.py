#!/usr/bin/env python3
"""Independent multi-signature helpers.

Each signer independently signs the same message M. This produces N
separate signatures that can be verified individually.

This module provides:
- sign_independent(message, key_pairs, level, sig_type) -> (signatures, sign_times)
- verify_independent(message, signatures, public_keys, level, sig_type) -> (ok, results, verify_times)

Vietnamese comments are added to explain steps.
"""
from typing import List, Tuple
import time
import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend


def sign_independent(message: bytes, key_pairs: List[Tuple[bytes, bytes]], level: str, sig_type: str) -> Tuple[List[bytes], List[float]]:
    """Each signer signs the same message independently.

    Args:
      message: bytes to sign
      key_pairs: list of (pub_bytes, priv_bytes)
      level: label for Dilithium (e.g. 'Dilithium3')
      sig_type: 'dilithium' | 'rsa' | 'ecc'

    Returns (signatures, sign_times)
    """
    sigs: List[bytes] = []
    times: List[float] = []
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
        sigs.append(sig)
        times.append(t1 - t0)
    return sigs, times


def verify_independent(message: bytes, signatures: List[bytes], public_keys: List[bytes], level: str, sig_type: str) -> Tuple[bool, List[bool], List[float]]:
    """Verify each signature against the corresponding public key.

    Returns (overall_ok, per_signature_results, per_signature_verify_times)
    """
    results: List[bool] = []
    verify_times: List[float] = []
    for sig, pub in zip(signatures, public_keys):
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
    return all(results), results, verify_times


if __name__ == "__main__":
    # Simple smoke-test when run directly
    import argparse, base64, os

    parser = argparse.ArgumentParser(description="Independent multisig smoke test")
    parser.add_argument("--level", default="Dilithium3")
    parser.add_argument("--users", default=",".join([f"user{i+1}" for i in range(3)]))
    parser.add_argument("--message", default="Independent demo")
    parser.add_argument("--keys-dir", default="keys")
    args = parser.parse_args()

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    pairs = []
    for u in users:
        pub_path = os.path.join(args.keys_dir, u, args.level, "public.key")
        priv_path = os.path.join(args.keys_dir, u, args.level, "private.key")
        with open(pub_path, "rb") as f:
            pub = f.read()
        with open(priv_path, "rb") as f:
            priv = f.read()
        pairs.append((pub, priv))

    sigs, st = sign_independent(args.message.encode(), pairs, args.level, "dilithium")
    print("Sign times:", st)
    pubs = [p for p, _ in pairs]
    ok, res, vt = verify_independent(args.message.encode(), sigs, pubs, args.level, "dilithium")
    print("Verify results:", res)
    print("Verify times:", vt)
    print("First sig b64:", base64.b64encode(sigs[0])[:60])
