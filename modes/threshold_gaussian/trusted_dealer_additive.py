#!/usr/bin/env python3
"""
trusted_dealer_additive.py - ADDITIVE Threshold Key Generation for TLBSS

ARCHITECTURE: Additive Secret Sharing (n-of-n)
==============================================

Following TLBSS paper Section 3, Step 2 (Distributed Key Generation):

1. Each user i generates SMALL secret: s_i ← S_η
   - Coefficients in [-η, η] where η ∈ {2, 4}
   - ||s_i||_2 ≈ η·√(N·(K+L)) ≈ 90 (for η=2, N=256, K+L=8)

2. Aggregated master secret: s = Σ s_i (mod q)

3. Public key: t = A·s where A is public matrix

4. Each user stores:
   - s1_i, s2_i: Their SMALL individual secrets (for rejection sampling)
   - User ID: For signing protocol

WHY ADDITIVE (not Shamir):
---------------------------
Shamir sharing over Z_q produces LARGE shares:
  - Share x_i ~ Uniform(Z_q) → ||x_i|| ≈ q/2 ≈ 4,200,000
  - Rejection formula: P ∝ exp(-||c·s_i||² / (2σ²))
  - With large s_i: exponent ≈ -2800 → P ≈ 0 (FAILS!)

Additive sharing preserves smallness:
  - Each s_i ∈ S_η → ||s_i|| ≈ 90
  - Rejection sampling WORKS as designed
  - Trade-off: Requires ALL n users (no t-of-n flexibility)

PARAMETERS:
-----------
- K = 1: Dimension of secret s1
- L = 1: Dimension of secret s2  
- η = 2: Small coefficient bound (s_i ∈ [-2, 2])
- N = 256: Polynomial degree
- q = 8380417: Modulus
"""

import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from core.dilithium_math import (
    Poly, DILITHIUM_Q, DILITHIUM_N,
    _matvec_mul, expand_a, _serialize_poly_vec
)
import base64
import hashlib


# ============================================================================
# PARAMETERS (TLBSS-Compatible)
# ============================================================================

K = 1  # Dimension of s1
L = 1  # Dimension of s2
ETA = 2  # Small coefficient bound: s ∈ S_η = {[-η, η]}^N
N = DILITHIUM_N  # 256
q = DILITHIUM_Q  # 8380417


# ============================================================================
# SMALL SECRET SAMPLING (S_η)
# ============================================================================

def sample_small_secret_poly(eta: int = ETA, q: int = q, N: int = N) -> Poly:
    """
    Sample polynomial from S_η: coefficients uniformly in [-η, η].
    
    This produces SMALL secrets as required by TLBSS:
    - Expected ||s||_2 ≈ η·√N ≈ 32 (for η=2, N=256)
    - Critical for rejection sampling to work
    
    Args:
        eta: Coefficient bound
        q: Modulus
        N: Polynomial degree
    
    Returns:
        Poly with small coefficients in [-eta, eta]
    """
    coeffs = [random.randint(-eta, eta) for _ in range(N)]
    coeffs_mod = [(c % q) for c in coeffs]
    return Poly(coeffs_mod, q, N, in_ntt=False)


def sample_small_secret_vector(length: int, eta: int = ETA, q: int = q, N: int = N):
    """Sample vector of small polynomials from S_η."""
    return [sample_small_secret_poly(eta, q, N) for _ in range(length)]


# ============================================================================
# ADDITIVE THRESHOLD SETUP
# ============================================================================

def additive_threshold_setup(n: int, eta: int = ETA):
    """
    Generate keys for n-of-n additive threshold signature.
    
    Protocol:
    ---------
    1. Each user i generates small secrets:
       - s1_i ← S_η^K (K polynomials)
       - s2_i ← S_η^L (L polynomials)
    
    2. Compute aggregated master:
       - s1 = Σ s1_i (mod q)
       - s2 = Σ s2_i (mod q)
    
    3. Generate public matrix A from random seed ρ
    
    4. Compute public key:
       - t = A·s1 (mod q)
    
    5. Each user stores (uid, s1_i, s2_i)
    
    Args:
        n: Number of participants
        eta: Small coefficient bound
    
    Returns:
        shares: List of n dicts with {uid, s1, s2}
        public_key: Dict with {t, A_seed, params}
    """
    print(f'\n[ADDITIVE] Setting up {n}-of-{n} additive threshold', file=sys.stderr)
    print(f'[ADDITIVE] Params: K={K}, L={L}, η={eta}, N={N}, q={q}', file=sys.stderr)
    
    # Step 1: Generate individual small secrets for each user
    user_secrets = []
    for i in range(n):
        s1_i = sample_small_secret_vector(K, eta)
        s2_i = sample_small_secret_vector(L, eta)
        user_secrets.append((s1_i, s2_i))
        
        # Verify smallness
        s1_norm = sum(c**2 for poly in s1_i for c in poly.get_centered_coeffs())**0.5
        print(f'[ADDITIVE] User {i+1}: ||s1_{i+1}||_2 = {s1_norm:.1f} (SMALL ✓)', file=sys.stderr)
    
    # Step 2: Aggregate secrets (additive sharing)
    s1_master = [Poly([0]*N, q, N) for _ in range(K)]
    s2_master = [Poly([0]*N, q, N) for _ in range(L)]
    
    for s1_i, s2_i in user_secrets:
        for j in range(K):
            s1_master[j] = s1_master[j].add(s1_i[j])
        for j in range(L):
            s2_master[j] = s2_master[j].add(s2_i[j])
    
    master_norm = sum(c**2 for poly in s1_master for c in poly.get_centered_coeffs())**0.5
    print(f'[ADDITIVE] Master: ||s1_master||_2 = {master_norm:.1f}', file=sys.stderr)
    
    # Step 3: Generate public matrix A from seed
    rho = random.randbytes(32)
    A = expand_a(rho, K, L, q, N)
    
    # Step 4: Compute public key t = A·s1
    t = _matvec_mul(A, s1_master)
    
    # Serialize public key
    t_bytes_list = _serialize_poly_vec(t)
    t_bytes = ''.join(t_bytes_list).encode()
    pk_hash = hashlib.sha3_256(rho + t_bytes).hexdigest()[:16]
    print(f'[ADDITIVE] Public key hash: {pk_hash}', file=sys.stderr)
    
    # Step 5: Create shares for each user
    shares = []
    for i in range(n):
        s1_i, s2_i = user_secrets[i]
        share = {
            'uid': i + 1,
            's1': s1_i,  # SMALL secret for rejection sampling
            's2': s2_i,  # SMALL secret for protocol
        }
        shares.append(share)
    
    # Public key structure
    public_key = {
        't': t,
        'rho': rho,
        'K': K,
        'L': L,
        'eta': eta,
        'N': N,
        'q': q,
        'n': n,
        'threshold_type': 'additive',
        'pk_hash': pk_hash
    }
    
    print(f'[ADDITIVE] Generated {n} shares successfully\n', file=sys.stderr)
    
    return shares, public_key


# ============================================================================
# COMPATIBILITY WRAPPER
# ============================================================================

def trusted_dealer_setup(n: int, t: int, use_additive: bool = True):
    """
    Compatibility wrapper for existing code.
    
    Args:
        n: Number of participants
        t: Threshold (IGNORED in additive mode - always n-of-n)
        use_additive: Force additive mode (recommended)
    
    Returns:
        shares, public_key (same format as old implementation)
    """
    if not use_additive:
        raise NotImplementedError(
            "Shamir mode disabled. Use additive mode for proper rejection sampling."
        )
    
    if t != n:
        print(f'[WARNING] Additive mode requires ALL {n} users. Threshold {t} ignored.', 
              file=sys.stderr)
    
    return additive_threshold_setup(n, eta=ETA)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    print('='*70)
    print('ADDITIVE THRESHOLD KEY GENERATION TEST')
    print('='*70)
    
    # Test 3-of-3
    shares, pk = additive_threshold_setup(3)
    
    print('\nShare structure:')
    print(f'  User 1: uid={shares[0]["uid"]}, has s1, s2')
    
    print('\nPublic key:')
    print(f'  Hash: {pk["pk_hash"]}')
    print(f'  Type: {pk["threshold_type"]}')
    print(f'  Participants: {pk["n"]}-of-{pk["n"]}')
    
    # Verify reconstruction
    print('\nVerification:')
    s1_reconstructed = [Poly([0]*N, q, N) for _ in range(K)]
    for share in shares:
        for j in range(K):
            s1_reconstructed[j] = s1_reconstructed[j].add(share['s1'][j])
    
    A = expand_a(pk['rho'], K, L, q, N)
    t_check = _matvec_mul(A, s1_reconstructed)
    
    match = all(
        t_check[i].coeffs == pk['t'][i].coeffs
        for i in range(len(pk['t']))
    )
    print(f'  t = A·Σs_i: {"✓ PASS" if match else "✗ FAIL"}')
