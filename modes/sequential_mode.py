#!/usr/bin/env python3
"""Sequential multi-signature helpers.

Each signer signs a message that includes the message and all previous
signatures hashed with sha3_512, as described in the project instructions:

  msg1 = M
  msg2 = H(M || sig1)
  msg3 = H(M || sig1 || sig2)
  ...

This file exposes two functions:
- sign_sequential(message, key_pairs, level, sig_type) -> (signatures, sign_times)
- verify_sequential(message, signatures, public_keys, level, sig_type) -> (ok, results, verify_times)

Supports Dilithium (liboqs) and fallback RSA/ECC via cryptography for parity
with the rest of the repo.

Vietnamese comments are included to explain steps.
"""
from typing import List, Tuple
import hashlib
import time

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend


def _sha3_512(data: bytes) -> bytes:
    """Return sha3_512 digest of data (raw bytes)."""
    return hashlib.sha3_512(data).digest()


def sign_sequential(message: bytes, key_pairs: List[Tuple[bytes, bytes]], level: str, sig_type: str) -> Tuple[List[bytes], List[float]]:
    """Perform sequential signing over key_pairs.

    Args:
      message: original message bytes M
      key_pairs: list of (public_bytes, private_bytes) in signer order
      level: algorithm level label (e.g., "Dilithium3") for liboqs
      sig_type: "dilithium" | "rsa" | "ecc"

    Returns: (signatures, sign_times) both lists aligned with key_pairs order.
    """
    signatures: List[bytes] = []
    sign_times: List[float] = []

    # Accumulate previous signatures for constructing next message digest
    prev_sigs = b""

    for pub, priv in key_pairs:
        # For signer i: message_to_sign = M if first, else H(M || sig1 || ... || sig_{i-1})
        if len(signatures) == 0:
            msg_to_sign = message
        else:
            msg_to_sign = _sha3_512(message + prev_sigs)

        t0 = time.time()
        if sig_type == "dilithium":
            with oqs.Signature(level, priv) as signer:
                sig = signer.sign(msg_to_sign)
        elif sig_type == "rsa":
            sk = serialization.load_der_private_key(priv, password=None, backend=default_backend())
            sig = sk.sign(msg_to_sign, padding.PKCS1v15(), hashes.SHA256())
        else:  # ecc
            sk = serialization.load_der_private_key(priv, password=None, backend=default_backend())
            sig = sk.sign(msg_to_sign, ec.ECDSA(hashes.SHA256()))
        t1 = time.time()

        signatures.append(sig)
        sign_times.append(t1 - t0)

        # update previous signatures accumulator
        prev_sigs += sig

    return signatures, sign_times


def verify_sequential(message: bytes, signatures: List[bytes], public_keys: List[bytes], level: str, sig_type: str) -> Tuple[bool, List[bool], List[float]]:
    """Verify a sequential signature chain.

    For each i, rebuild the expected message (M for i==0, else H(M || sig1 || ... || sig_{i-1}))
    and verify signatures[i] against public_keys[i].

    Returns: (overall_ok, per_signature_results, per_signature_verify_times)
    """
    results: List[bool] = []
    verify_times: List[float] = []

    prev_sigs = b""

    for i, (sig, pub) in enumerate(zip(signatures, public_keys)):
        if i == 0:
            msg_to_verify = message
        else:
            msg_to_verify = _sha3_512(message + prev_sigs)

        t0 = time.time()
        if sig_type == "dilithium":
            with oqs.Signature(level) as verifier:
                ok = verifier.verify(msg_to_verify, sig, pub)
        elif sig_type == "rsa":
            pk = serialization.load_der_public_key(pub, backend=default_backend())
            try:
                pk.verify(sig, msg_to_verify, padding.PKCS1v15(), hashes.SHA256())
                ok = True
            except Exception:
                ok = False
        else:  # ecc
            pk = serialization.load_der_public_key(pub, backend=default_backend())
            try:
                pk.verify(sig, msg_to_verify, ec.ECDSA(hashes.SHA256()))
                ok = True
            except Exception:
                ok = False
        t1 = time.time()

        results.append(ok)
        verify_times.append(t1 - t0)

        # append this signature to prev_sigs whether ok or not, because chain depends on raw bytes
        prev_sigs += sig

    return all(results), results, verify_times


if __name__ == "__main__":
    # Small self-test when run directly (expects keys in keys/userX/Dilithium3)
    import argparse
    import base64

    parser = argparse.ArgumentParser(description="Quick sequential multisig demo (requires keys/ layout)")
    parser.add_argument("--level", default="Dilithium3")
    parser.add_argument("--users", default=",".join([f"user{i+1}" for i in range(5)]))
    parser.add_argument("--message", default="Sequential demo")
    parser.add_argument("--keys-dir", default="keys")
    args = parser.parse_args()

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    # load key pairs (simple loader here to avoid circular import)
    pairs = []
    for u in users:
        pub_path = f"{args.keys_dir}/{u}/{args.level}/public.key"
        priv_path = f"{args.keys_dir}/{u}/{args.level}/private.key"
        with open(pub_path, "rb") as f:
            pub = f.read()
        with open(priv_path, "rb") as f:
            priv = f.read()
        pairs.append((pub, priv))

    sigs, stimes = sign_sequential(args.message.encode(), pairs, args.level, "dilithium")
    print("Sign times:", stimes)
    pubs = [p for p, _ in pairs]
    ok, results, vtimes = verify_sequential(args.message.encode(), sigs, pubs, args.level, "dilithium")
    print("Verify results:", results)
    print("Verify times:", vtimes)
    print("Bundle sample (first sig b64):", base64.b64encode(sigs[0])[:60])
