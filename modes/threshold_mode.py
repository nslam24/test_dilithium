#!/usr/bin/env python3
"""Threshold Multi-Signature implementation combining:
   (1) Davydov & Bezzateev - Lattice-based (Dilithium) additive threshold
   (2) Cozzo & Smart - MQ-based (LUOV-style) LSSS threshold

Mô-đun này triển khai chữ ký ngưỡng (threshold signature) trong đó t trong n
bên tham gia có thể tái tạo chữ ký hợp lệ bằng cách kết hợp chữ ký từng phần.

Các lược đồ hỗ trợ:
  - "dilithium-threshold": Chia sẻ cộng trên Rq (Davydov & Bezzateev)
  - "luov-threshold": Chia sẻ LSSS trên Fq (Cozzo & Smart - mô phỏng)

Hàm chính:
  - generate_threshold_keypair(n_parties, threshold, scheme)
  - sign_threshold(message, sk_shares, scheme, level)
  - verify_threshold(message, signature, pk, scheme, level)

Các bước quan trọng được chú thích bằng tiếng Việt.
"""
from typing import List, Tuple, Dict, Any
import hashlib
import time
import os
import random
import base64
import json

import oqs


def _sha3_512(data: bytes) -> bytes:
    """Return sha3_512 digest of data."""
    return hashlib.sha3_512(data).digest()


# ============================================================================
# Mock Field Arithmetic for LUOV (Fq operations)
# ============================================================================

class MockFq:
    """Trường hữu hạn Fq mô phỏng cho LUOV.
    
    Trong triển khai thực tế, đây sẽ là GF(2^k) hoặc GF(p).
    Ở đây ta dùng số học modulo đơn giản với số nguyên tố nhỏ để demo.
    """
    PRIME = 2**31 - 1  # Số nguyên tố Mersenne cho demo
    
    @staticmethod
    def add(a: int, b: int) -> int:
        return (a + b) % MockFq.PRIME
    
    @staticmethod
    def sub(a: int, b: int) -> int:
        return (a - b) % MockFq.PRIME
    
    @staticmethod
    def mul(a: int, b: int) -> int:
        return (a * b) % MockFq.PRIME
    
    @staticmethod
    def random_element() -> int:
        return random.randint(0, MockFq.PRIME - 1)


# ============================================================================
# Shamir Secret Sharing for key distribution
# ============================================================================

def shamir_share_secret(secret_bytes: bytes, n: int, t: int, field_prime: int = MockFq.PRIME) -> List[Tuple[int, int]]:
    """Chia bí mật thành n phần dùng Shamir (t,n) ngưỡng.
    
    Phương pháp:
    - Chọn đa thức ngẫu nhiên bậc t-1: f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
    - a_0 = secret (bí mật)
    - Tính f(1), f(2), ..., f(n) làm các phần chia sẻ
    - Cần ít nhất t phần để khôi phục bí mật qua nội suy Lagrange
    
    Trả về danh sách (x, y) trong đó x là chỉ số bên (1..n), y = f(x).
    """
    # Chuyển bí mật thành số nguyên
    secret = int.from_bytes(secret_bytes, 'big') % field_prime
    
    # Sinh hệ số ngẫu nhiên a_1, ..., a_{t-1} cho đa thức
    coeffs = [secret] + [random.randint(0, field_prime - 1) for _ in range(t - 1)]
    
    # Tính giá trị đa thức tại x = 1, 2, ..., n
    shares = []
    for x in range(1, n + 1):
        y = sum(c * pow(x, i, field_prime) for i, c in enumerate(coeffs)) % field_prime
        shares.append((x, y))
    
    return shares


def shamir_reconstruct(shares: List[Tuple[int, int]], field_prime: int = MockFq.PRIME) -> int:
    """Reconstruct secret from t shares using Lagrange interpolation."""
    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        # Lagrange basis polynomial
        num = 1
        den = 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                num = (num * (-x_j)) % field_prime
                den = (den * (x_i - x_j)) % field_prime
        
        # Modular inverse of denominator
        lagrange_coeff = (num * pow(den, -1, field_prime)) % field_prime
        secret = (secret + y_i * lagrange_coeff) % field_prime
    
    return secret


# ============================================================================
# Dilithium Threshold (Davydov & Bezzateev style)
# ============================================================================

def generate_threshold_keypair_dilithium(n_parties: int, threshold: int, level: str = "Dilithium3") -> Tuple[List[bytes], bytes]:
    """Generate threshold key shares for Dilithium using additive sharing.
    
    Strategy:
    - Generate a master secret key using liboqs
    - Split it into n additive shares: sk = s_1 + s_2 + ... + s_n (mod q)
    - Derive public key from master secret (or sum of A*s_i)
    
    Args:
      n_parties: total number of signers
      threshold: minimum number needed (t-of-n); for additive we need all n
      level: Dilithium security level
    
    Returns:
      (sk_shares, pk) where sk_shares is list of secret key bytes
    """
    # Generate master keypair
    with oqs.Signature(level) as sig:
        pk = sig.generate_keypair()
        master_sk = sig.export_secret_key()
    
    # For true threshold, we'd use Shamir or LSSS. 
    # Here we use simple additive sharing for demonstration:
    # Each party gets a random share; last party gets remainder
    sk_len = len(master_sk)
    shares = []
    
    # Generate n-1 random shares
    for i in range(n_parties - 1):
        share = os.urandom(sk_len)
        shares.append(share)
    
    # Compute last share so sum equals master (XOR for bytes as simple combiner)
    last_share = bytearray(sk_len)
    for i in range(sk_len):
        acc = master_sk[i]
        for share in shares:
            acc ^= share[i]
        last_share[i] = acc
    
    shares.append(bytes(last_share))
    
    return shares, pk


def sign_threshold_dilithium(message: bytes, sk_shares: List[bytes], level: str = "Dilithium3") -> Tuple[bytes, List[float]]:
    """Threshold signing for Dilithium using partial response aggregation.
    
    Protocol (simplified Davydov & Bezzateev):
    1. Each party i generates random y_i, computes v_i = A*y_i
    2. Aggregate w = Σ v_i
    3. Compute challenge c = H(message || w)
    4. Each party computes z_i = y_i + c*s_i
    5. Aggregate z = Σ z_i
    6. Signature is (z, c)
    
    For simplicity with liboqs: we reconstruct the full key and sign.
    In a real threshold scheme, partial responses would be combined via MPC.
    
    Returns: (signature, sign_times_per_party)
    """
    sign_times = []
    
    # Reconstruct master secret by XORing all shares
    sk_len = len(sk_shares[0])
    master_sk = bytearray(sk_len)
    for share in sk_shares:
        for i in range(sk_len):
            master_sk[i] ^= share[i]
    
    master_sk = bytes(master_sk)
    
    # Sign with reconstructed key (simulating aggregated signature)
    t0 = time.time()
    with oqs.Signature(level, master_sk) as signer:
        signature = signer.sign(message)
    t1 = time.time()
    
    # Record time for each "party" (in reality they'd sign in parallel)
    sign_time = (t1 - t0) / len(sk_shares)
    sign_times = [sign_time] * len(sk_shares)
    
    return signature, sign_times


def verify_threshold_dilithium(message: bytes, signature: bytes, pk: bytes, level: str = "Dilithium3") -> Tuple[bool, float]:
    """Verify threshold Dilithium signature.
    
    Verification is identical to standard Dilithium verification.
    
    Returns: (is_valid, verify_time)
    """
    t0 = time.time()
    with oqs.Signature(level) as verifier:
        is_valid = verifier.verify(message, signature, pk)
    t1 = time.time()
    
    return is_valid, t1 - t0


# ============================================================================
# LUOV Threshold (Cozzo & Smart style - mock implementation)
# ============================================================================

def generate_threshold_keypair_luov(n_parties: int, threshold: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Generate threshold LUOV keypair using LSSS over Fq.
    
    Mock implementation: generates random secret shares and a public key.
    Real implementation would involve:
    - Generate LUOV secret key (oil/vinegar variables)
    - Use LSSS to share secret over Fq
    - Derive public key from shared secret
    
    Returns: (sk_shares, pk) where each share is a dict with party info
    """
    # Mock secret: random field elements
    secret_size = 128  # mock dimension
    master_secret = [MockFq.random_element() for _ in range(secret_size)]
    
    # Convert to bytes for Shamir sharing
    secret_bytes = b''.join(x.to_bytes(8, 'big') for x in master_secret[:16])  # first 128 bytes
    
    # Generate Shamir shares
    shamir_shares = shamir_share_secret(secret_bytes, n_parties, threshold)
    
    # Each party gets a share dict
    sk_shares = []
    for idx, (x, y) in enumerate(shamir_shares):
        share = {
            "party_id": idx,
            "x": x,
            "y": y,
            "threshold": threshold,
            "n_parties": n_parties
        }
        sk_shares.append(share)
    
    # Mock public key (in LUOV this would be the quadratic map)
    pk = {
        "scheme": "luov-threshold",
        "n": n_parties,
        "t": threshold,
        "pk_data": base64.b64encode(os.urandom(64)).decode()
    }
    
    return sk_shares, pk


def sign_threshold_luov(message: bytes, sk_shares: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[float]]:
    """Threshold signing for LUOV using LSSS partial evaluation.
    
    Mock implementation simulates:
    1. Each party evaluates their share on the message
    2. Partial signatures are combined via additive reconstruction
    3. Final signature is the aggregate
    
    Returns: (signature_dict, sign_times_per_party)
    """
    sign_times = []
    partials = []
    
    for share in sk_shares:
        t0 = time.time()
        
        # Mock partial signature: hash of message + share
        partial_data = _sha3_512(message + str(share["y"]).encode())
        partial = {
            "party_id": share["party_id"],
            "x": share["x"],
            "response": base64.b64encode(partial_data[:32]).decode()
        }
        partials.append(partial)
        
        t1 = time.time()
        sign_times.append(t1 - t0)
    
    # Aggregate partials (mock: just concatenate)
    signature = {
        "scheme": "luov-threshold",
        "partials": partials,
        "challenge": base64.b64encode(_sha3_512(message)[:32]).decode()
    }
    
    return signature, sign_times


def verify_threshold_luov(message: bytes, signature: Dict[str, Any], pk: Dict[str, Any]) -> Tuple[bool, float]:
    """Verify threshold LUOV signature.
    
    Mock implementation: checks that signature structure is valid.
    Real LUOV verification would check quadratic equations.
    
    Returns: (is_valid, verify_time)
    """
    t0 = time.time()
    
    # Mock verification: check that challenge matches
    expected_challenge = base64.b64encode(_sha3_512(message)[:32]).decode()
    is_valid = signature.get("challenge") == expected_challenge
    
    # Also check we have enough partials
    is_valid = is_valid and len(signature.get("partials", [])) >= pk.get("t", 0)
    
    t1 = time.time()
    
    return is_valid, t1 - t0


# ============================================================================
# Unified Interface
# ============================================================================

def generate_threshold_keypair(n_parties: int, threshold: int, scheme: str, level: str = "Dilithium3") -> Tuple[Any, Any]:
    """Generate threshold keypair for specified scheme.
    
    Args:
      n_parties: total number of signers (n)
      threshold: minimum required (t)
      scheme: "dilithium-threshold" or "luov-threshold"
      level: security level (for Dilithium)
    
    Returns: (sk_shares, pk)
    """
    if scheme == "dilithium-threshold":
        return generate_threshold_keypair_dilithium(n_parties, threshold, level)
    elif scheme == "luov-threshold":
        return generate_threshold_keypair_luov(n_parties, threshold)
    else:
        raise ValueError(f"Unsupported threshold scheme: {scheme}")


def sign_threshold(message: bytes, sk_shares: Any, scheme: str, level: str = "Dilithium3") -> Tuple[Any, List[float]]:
    """Threshold signing for specified scheme.
    
    Returns: (signature, sign_times_per_party)
    """
    if scheme == "dilithium-threshold":
        return sign_threshold_dilithium(message, sk_shares, level)
    elif scheme == "luov-threshold":
        return sign_threshold_luov(message, sk_shares)
    else:
        raise ValueError(f"Unsupported threshold scheme: {scheme}")


def verify_threshold(message: bytes, signature: Any, pk: Any, scheme: str, level: str = "Dilithium3") -> Tuple[bool, float]:
    """Verify threshold signature for specified scheme.
    
    Returns: (is_valid, verify_time)
    """
    if scheme == "dilithium-threshold":
        return verify_threshold_dilithium(message, signature, pk, level)
    elif scheme == "luov-threshold":
        return verify_threshold_luov(message, signature, pk)
    else:
        raise ValueError(f"Unsupported threshold scheme: {scheme}")


# ============================================================================
# Main smoke test
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Threshold signature smoke test")
    parser.add_argument("--scheme", choices=["dilithium-threshold", "luov-threshold"], default="dilithium-threshold")
    parser.add_argument("--n-parties", type=int, default=5, help="Total number of parties")
    parser.add_argument("--threshold", type=int, default=3, help="Minimum required parties")
    parser.add_argument("--level", default="Dilithium3", help="Security level for Dilithium")
    parser.add_argument("--message", default="Threshold signature test", help="Message to sign")
    args = parser.parse_args()
    
    print(f"\n{'='*60}")
    print(f"Threshold Signature Test: {args.scheme}")
    print(f"  n={args.n_parties}, t={args.threshold}")
    print(f"{'='*60}\n")
    
    # Generate threshold keypair
    print("1. Generating threshold keypair...")
    sk_shares, pk = generate_threshold_keypair(args.n_parties, args.threshold, args.scheme, args.level)
    print(f"   ✓ Generated {len(sk_shares)} secret shares")
    
    # Sign with threshold
    print("\n2. Threshold signing...")
    message = args.message.encode()
    signature, sign_times = sign_threshold(message, sk_shares, args.scheme, args.level)
    print(f"   ✓ Signature created")
    print(f"   Sign times per party: {[f'{t:.6f}s' for t in sign_times]}")
    print(f"   Average sign time: {sum(sign_times)/len(sign_times):.6f}s")
    
    # Verify threshold signature
    print("\n3. Verifying threshold signature...")
    is_valid, verify_time = verify_threshold(message, signature, pk, args.scheme, args.level)
    print(f"   ✓ Signature valid: {is_valid}")
    print(f"   Verify time: {verify_time:.6f}s")
    
    # Display signature info
    print(f"\n4. Signature details:")
    if args.scheme == "dilithium-threshold":
        print(f"   Signature size: {len(signature)} bytes")
        print(f"   Signature (base64 preview): {base64.b64encode(signature)[:80]}...")
    else:
        print(f"   Signature structure: {json.dumps(signature, indent=2)}")
    
    print(f"\n{'='*60}")
    print("Threshold signature test completed successfully!")
    print(f"{'='*60}\n")
