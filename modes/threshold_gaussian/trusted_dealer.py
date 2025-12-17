#!/usr/bin/env python3
"""
trusted_dealer.py - Trusted Dealer setup with Shamir Secret Sharing

Implements key generation following the paper's Trusted Dealer model:
- Dealer generates master secret key s
- Distributes shares using polynomial-based Shamir sharing (cite: 207)
- Each participant receives share of each coefficient
"""

import random
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from core.dilithium_math import (
    Poly, DILITHIUM_Q, DILITHIUM_N,
    _matvec_mul, expand_a, _serialize_poly_vec
)
from .gaussian_primitives import gaussian_sample_vector, SIGMA
import base64
import hashlib
import json


# ============================================================================
# SHAMIR SECRET SHARING UTILITIES
# ============================================================================

def eval_poly_at(coeffs, x: int, q: int) -> int:
    """
    Evaluate polynomial f(x) = c0 + c1*x + c2*x^2 + ... at point x (mod q).
    
    Used in Shamir sharing to compute f(uid) for each participant.
    
    Args:
        coeffs: polynomial coefficients [c0, c1, ..., c_{t-1}]
        x: evaluation point (user ID)
        q: modulus
        
    Returns:
        f(x) mod q
    """
    result = 0
    x_power = 1
    for c in coeffs:
        result = (result + c * x_power) % q
        x_power = (x_power * x) % q
    return result


def compute_lagrange_coeff(uid: int, participant_uids, q: int = DILITHIUM_Q) -> int:
    """
    Compute Lagrange coefficient l_i for participant i at point 0.
    
    Formula: l_i = ∏_{j≠i} (0 - x_j) / (x_i - x_j) mod q
             = ∏_{j≠i} (-x_j) / (x_i - x_j) mod q
    
    Used in signing phase to combine shares: s = Σ l_i · s_i
    
    Args:
        uid: user ID of current participant (x_i)
        participant_uids: list of all participating user IDs
        q: modulus
        
    Returns:
        Lagrange coefficient l_i mod q
    """
    numerator = 1
    denominator = 1
    
    for other_uid in participant_uids:
        if other_uid == uid:
            continue
        
        # Numerator: ∏ (0 - x_j) = ∏ (-x_j)
        numerator = (numerator * (-other_uid % q)) % q
        
        # Denominator: ∏ (x_i - x_j)
        denominator = (denominator * ((uid - other_uid) % q)) % q
    
    # Compute inverse of denominator
    denom_inv = pow(denominator, -1, q)
    
    # l_i = numerator / denominator mod q
    lagrange = (numerator * denom_inv) % q
    
    return lagrange


# ============================================================================
# TRUSTED DEALER KEY GENERATION
# ============================================================================

def trusted_dealer_setup(n_parties: int, threshold: int, *,
                        q: int = DILITHIUM_Q, 
                        N: int = DILITHIUM_N,
                        K: int = 1, 
                        L: int = 1,
                        seed: bytes = None):
    """
    Trusted Dealer key generation with Shamir Secret Sharing.
    
    Protocol:
    1. Dealer samples master secret s = (s1, s2) from Gaussian
       - s1: vector of L polynomials (secret part)
       - s2: vector of K polynomials (error part, for Module-LWE)
    
    2. For each coefficient of each polynomial in s:
       - Create Shamir polynomial f(x) = coeff + a1*x + ... + a_{t-1}*x^{t-1}
       - Compute f(uid) for each participant uid ∈ [1, n_parties]
    
    3. Compute public key: t = A·s1 + s2
    
    4. Distribute shares to participants
    
    Args:
        n_parties: total number of participants (n)
        threshold: minimum signers required (t)
        q, N: Dilithium parameters
        K, L: matrix dimensions (K rows, L columns)
        seed: optional seed for reproducibility
        
    Returns:
        (shares_list, public_key) where:
        - shares_list: list of dicts, one per participant
        - public_key: dict with A (as seed), t, and parameters
    """
    if not (1 <= threshold <= n_parties):
        raise ValueError(f"Invalid threshold: {threshold} not in [1, {n_parties}]")
    
    if seed is not None:
        random.seed(seed)
        import numpy as np
        np.random.seed(int.from_bytes(seed[:4], 'big'))
    
    print(f"\n[DEALER] Setting up {threshold}-of-{n_parties} threshold scheme", 
          file=sys.stderr)
    print(f"[DEALER] Parameters: K={K}, L={L}, q={q}, N={N}, σ={SIGMA}", 
          file=sys.stderr)
    
    # ========================================================================
    # STEP 1: Generate master secret key with Gaussian sampling
    # ========================================================================
    
    # s1: secret vector (L polynomials)
    s1_master = gaussian_sample_vector(L, q, N, SIGMA)
    
    # s2: error vector (K polynomials, for Module-LWE)
    s2_master = gaussian_sample_vector(K, q, N, SIGMA)
    
    print(f"[DEALER] Generated master secret s = (s1, s2)", file=sys.stderr)
    
    # ========================================================================
    # STEP 2: Generate public matrix A from seed ρ
    # ========================================================================
    
    rho = random.randbytes(32) if seed is None else seed[:32]
    A = expand_a(rho, K, L, q, N)
    
    print(f"[DEALER] Generated public matrix A from seed ρ", file=sys.stderr)
    
    # ========================================================================
    # STEP 3: Compute public key t = A·s1 (SIS-based, no error)
    # ========================================================================
    
    # For threshold signatures, we use SIS-based scheme (no error term)
    # This avoids the issue with error accumulation in Fiat-Shamir
    # t = A·s1 (no "+s2" term)
    t_vec = _matvec_mul(A, s1_master)
    
    print(f"[DEALER] Computed public key t = A·s1 (SIS-based)", file=sys.stderr)
    
    # ========================================================================
    # STEP 4: Generate individual secrets s_i for rejection sampling
    # ========================================================================
    # 
    # CRITICAL FOR REJECTION SAMPLING:
    # Each participant needs a SMALL secret s_i (from S_η, η ∈ [2,4]) 
    # for rejection sampling in Step 4(f).
    # 
    # This is DIFFERENT from Shamir shares x_i which have ||x_i|| ~ q/2.
    # The small s_i ensures c·s_i remains small, making Gaussian rejection
    # sampling work without "compromise".
    #
    # In full distributed protocol: each user generates own s_i
    # In trusted dealer model: dealer generates and distributes s_i
    
    individual_secrets_s1 = {}
    for uid in range(1, n_parties + 1):
        # Generate small Gaussian secret for this user (for rejection sampling only)
        # NOTE: This is independent of Shamir sharing
        s_i = gaussian_sample_vector(L, q, N, SIGMA)
        individual_secrets_s1[uid] = s_i
    
    print(f"[DEALER] Generated individual secrets s_i for rejection sampling", 
          file=sys.stderr)
    
    # ========================================================================
    # STEP 5: Shamir sharing of MASTER SECRET (for signing)
    # ========================================================================
    
    # Storage for shares: shares[uid][poly_index][coeff_index]
    s1_shares = {uid: [[] for _ in range(L)] for uid in range(1, n_parties + 1)}
    s2_shares = {uid: [[] for _ in range(K)] for uid in range(1, n_parties + 1)}
    
    # Share s1 (L polynomials)
    for l in range(L):
        poly = s1_master[l]
        for coeff_idx in range(N):
            coeff = poly.coeffs[coeff_idx]
            
            # Create Shamir polynomial: f(x) = coeff + a1*x + ... + a_{t-1}*x^{t-1}
            shamir_coeffs = [coeff] + [random.randint(0, q-1) for _ in range(threshold - 1)]
            
            # Evaluate f(uid) for each participant
            for uid in range(1, n_parties + 1):
                share_value = eval_poly_at(shamir_coeffs, uid, q)
                s1_shares[uid][l].append(share_value)
    
    print(f"[DEALER] Completed Shamir sharing for s1 ({L} polynomials)", file=sys.stderr)
    
    # Share s2 (K polynomials)
    for k in range(K):
        poly = s2_master[k]
        for coeff_idx in range(N):
            coeff = poly.coeffs[coeff_idx]
            
            # Create Shamir polynomial
            shamir_coeffs = [coeff] + [random.randint(0, q-1) for _ in range(threshold - 1)]
            
            # Evaluate for each participant
            for uid in range(1, n_parties + 1):
                share_value = eval_poly_at(shamir_coeffs, uid, q)
                s2_shares[uid][k].append(share_value)
    
    print(f"[DEALER] Completed Shamir sharing for s2 ({K} polynomials)", file=sys.stderr)
    
    # ========================================================================
    # STEP 5: Package public key
    # ========================================================================
    
    pk = {
        "scheme": "threshold-gaussian-dealer",
        "q": q,
        "N": N,
        "K": K,
        "L": L,
        "rho": base64.b64encode(rho).decode(),  # Seed for A (32 bytes)
        "t": _serialize_poly_vec(t_vec),
        "n_parties": n_parties,
        "threshold": threshold,
        "sigma": SIGMA,
    }
    
    # Compute hash for verification
    pk_bytes = json.dumps(pk, sort_keys=True).encode('utf-8')
    pk_hash = hashlib.sha3_256(pk_bytes).hexdigest()[:16]
    
    # ========================================================================
    # STEP 6: Package shares for each participant
    # ========================================================================
    
    shares_list = []
    for uid in range(1, n_parties + 1):
        # Serialize individual secret s_i for rejection sampling
        s_i_serialized = [[poly.coeffs[idx] for idx in range(N)] 
                          for poly in individual_secrets_s1[uid]]
        
        share_data = {
            "uid": uid,
            "s1_share": s1_shares[uid],  # Shamir share (for signing): List[List[int]], shape [L][N]
            "s2_share": s2_shares[uid],  # Shamir share: List[List[int]], shape [K][N]
            "s1_original": s_i_serialized,  # SMALL secret (for rejection sampling): List[List[int]], shape [L][N]
            "q": q,
            "N": N,
            "K": K,
            "L": L,
            "threshold": threshold,
            "n_parties": n_parties,
            "pk_hash": pk_hash,
        }
        shares_list.append(share_data)
    
    print(f"[DEALER] Generated {n_parties} shares successfully", file=sys.stderr)
    print(f"[DEALER] Public key hash: {pk_hash}", file=sys.stderr)
    
    return shares_list, pk


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    print("\n[TEST] Trusted Dealer Setup")
    print("=" * 60)
    
    # Test 1: Basic setup (5-of-3)
    print("\n1. Generate 3-of-5 threshold scheme:")
    shares, pk = trusted_dealer_setup(
        n_parties=5, 
        threshold=3,
        K=1, 
        L=1,
        seed=b"test_seed_12345" + b"\x00" * 17
    )
    
    print(f"\n   ✓ Generated {len(shares)} shares")
    print(f"   ✓ Public key scheme: {pk['scheme']}")
    print(f"   ✓ Threshold: {pk['threshold']}-of-{pk['n_parties']}")
    
    # Test 2: Verify share structure
    print("\n2. Verify share structure:")
    share = shares[0]
    print(f"   - Share UID: {share['uid']}")
    print(f"   - s1_share shape: {len(share['s1_share'])} x {len(share['s1_share'][0])}")
    print(f"   - s2_share shape: {len(share['s2_share'])} x {len(share['s2_share'][0])}")
    print(f"   - Hash matches: {share['pk_hash'] == shares[1]['pk_hash']}")
    
    # Test 3: Lagrange coefficient computation
    print("\n3. Test Lagrange coefficients:")
    participant_uids = [1, 2, 3]  # First 3 participants sign
    lagrange_coeffs = [compute_lagrange_coeff(uid, participant_uids) for uid in participant_uids]
    print(f"   - Lagrange coeffs for UIDs {participant_uids}:")
    for uid, lam in zip(participant_uids, lagrange_coeffs):
        print(f"     l_{uid} = {lam}")
    
    # Verify: sum of Lagrange coefficients at reconstruction should give correct value
    # (This is a property of Lagrange interpolation at x=0)
    
    print("\n" + "=" * 60)
    print("✓ Trusted Dealer setup completed successfully")
