#!/usr/bin/env python3
"""
shamir_utils.py - Shamir Secret Sharing Utilities for TLBSS

Implements coefficient-wise Shamir sharing for Dilithium polynomial vectors.

Following Leevik et al. paper:
- Secret sharing: x_i = f(uid_i) where f(x) = s + a₁·x + ... + a_{t-1}·x^{t-1}
- Lagrange interpolation: s = Σ (x_i · λ_i) where λ_i = Π_{j≠i} uid_j/(uid_j - uid_i)
- Weighted noise: ȳ_i = y_i · λ_i^{-1} to cancel out during aggregation
"""

import random
from typing import List, Dict


# ============================================================================
# MODULAR ARITHMETIC
# ============================================================================

def mod_inverse(a: int, m: int) -> int:
    """
    Compute modular multiplicative inverse: a^{-1} mod m
    Using Extended Euclidean Algorithm.
    
    Args:
        a: Number to invert
        m: Modulus
    
    Returns:
        x such that (a * x) % m == 1
    
    Raises:
        ValueError: If gcd(a, m) != 1 (no inverse exists)
    """
    if a < 0:
        a = (a % m + m) % m
    
    # Extended Euclidean Algorithm
    g, x, _ = extended_gcd(a, m)
    
    if g != 1:
        raise ValueError(f'Modular inverse does not exist for {a} mod {m}')
    
    return (x % m + m) % m


def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


# ============================================================================
# POLYNOMIAL EVALUATION
# ============================================================================

def eval_poly(coeffs: List[int], x: int, q: int) -> int:
    """
    Evaluate polynomial at point x in Z_q.
    
    P(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
    
    Uses Horner's method for efficiency:
    P(x) = coeffs[0] + x*(coeffs[1] + x*(coeffs[2] + ...))
    
    Args:
        coeffs: Polynomial coefficients [c0, c1, c2, ...]
        x: Evaluation point
        q: Modulus
    
    Returns:
        P(x) mod q
    """
    if not coeffs:
        return 0
    
    # Horner's method
    result = coeffs[-1] % q
    for i in range(len(coeffs) - 2, -1, -1):
        result = (result * x + coeffs[i]) % q
    
    return result


# ============================================================================
# LAGRANGE COEFFICIENTS
# ============================================================================

def compute_lagrange_coefficient(uid: int, all_uids: List[int], q: int) -> int:
    """
    Compute Lagrange coefficient λ_i for user uid.
    
    λ_i = Π_{j≠i} (uid_j / (uid_j - uid_i)) mod q
    
    This allows interpolation: f(0) = Σ (f(uid_i) · λ_i)
    
    Args:
        uid: User ID for which to compute coefficient
        all_uids: List of ALL participating user IDs
        q: Modulus
    
    Returns:
        λ_uid mod q
    """
    lambda_i = 1
    
    for uid_j in all_uids:
        if uid_j == uid:
            continue
        
        # Numerator: uid_j
        numerator = uid_j % q
        
        # Denominator: (uid_j - uid_i)
        denominator = (uid_j - uid) % q
        
        # Compute uid_j / (uid_j - uid_i) mod q
        # = uid_j * (uid_j - uid_i)^{-1} mod q
        denom_inv = mod_inverse(denominator, q)
        term = (numerator * denom_inv) % q
        
        lambda_i = (lambda_i * term) % q
    
    return lambda_i


def compute_all_lagrange_coefficients(uids: List[int], q: int) -> Dict[int, int]:
    """
    Compute Lagrange coefficients for all participating users.
    
    Args:
        uids: List of participating user IDs
        q: Modulus
    
    Returns:
        Dict mapping uid -> λ_uid
    """
    coeffs = {}
    for uid in uids:
        coeffs[uid] = compute_lagrange_coefficient(uid, uids, q)
    
    return coeffs


# ============================================================================
# SHAMIR SECRET SHARING (Coefficient-wise for Polynomial Vectors)
# ============================================================================

def create_shamir_polynomial(secret: int, t: int, q: int) -> List[int]:
    """
    Create random polynomial f(x) = secret + a₁·x + ... + a_{t-1}·x^{t-1}
    
    Args:
        secret: Constant term (the secret to share)
        t: Threshold (degree = t-1)
        q: Modulus
    
    Returns:
        List of coefficients [secret, a₁, a₂, ..., a_{t-1}]
    """
    coeffs = [secret]
    for _ in range(t - 1):
        coeffs.append(random.randint(0, q - 1))
    
    return coeffs


def share_coefficient(coeff: int, n: int, t: int, q: int) -> Dict[int, int]:
    """
    Share a single coefficient using Shamir scheme.
    
    Args:
        coeff: Secret coefficient to share
        n: Total number of users
        t: Threshold
        q: Modulus
    
    Returns:
        Dict mapping uid -> share_value
    """
    # Create polynomial f(x) = coeff + a₁·x + ... + a_{t-1}·x^{t-1}
    poly_coeffs = create_shamir_polynomial(coeff, t, q)
    
    # Evaluate at each user ID (1, 2, ..., n)
    shares = {}
    for uid in range(1, n + 1):
        shares[uid] = eval_poly(poly_coeffs, uid, q)
    
    return shares


def share_polynomial_vector(poly_vector, n: int, t: int, q: int, N: int):
    """
    Share entire polynomial vector using coefficient-wise Shamir sharing.
    
    For each polynomial in the vector:
    - For each coefficient of that polynomial:
      - Create Shamir polynomial and evaluate at all UIDs
    
    Args:
        poly_vector: List of Poly objects (e.g., s1_master or s2_master)
        n: Total number of users
        t: Threshold
        q: Modulus
        N: Polynomial degree (number of coefficients)
    
    Returns:
        Dict mapping uid -> List[Poly] (shared polynomial vector for each user)
    """
    from core.dilithium_math import Poly
    
    num_polys = len(poly_vector)
    
    # Initialize shares structure: {uid: [Poly, Poly, ...]}
    shares = {uid: [] for uid in range(1, n + 1)}
    
    # For each polynomial in the vector
    for poly_idx, poly in enumerate(poly_vector):
        # Get coefficients of this polynomial
        coeffs = poly.coeffs
        
        # Share each coefficient
        coeff_shares = {uid: [] for uid in range(1, n + 1)}
        
        for coeff in coeffs:
            # Create Shamir shares for this coefficient
            coeff_share_dict = share_coefficient(coeff, n, t, q)
            
            # Distribute to each user
            for uid in range(1, n + 1):
                coeff_shares[uid].append(coeff_share_dict[uid])
        
        # Convert coefficient lists back to Poly objects
        for uid in range(1, n + 1):
            shared_poly = Poly(coeff_shares[uid], q, N, in_ntt=False)
            shares[uid].append(shared_poly)
    
    return shares


# ============================================================================
# LAGRANGE INTERPOLATION (Reconstruction)
# ============================================================================

def reconstruct_secret(shares: Dict[int, int], q: int) -> int:
    """
    Reconstruct secret from Shamir shares using Lagrange interpolation.
    
    f(0) = Σ (f(uid_i) · λ_i) where λ_i evaluated at x=0
    
    Args:
        shares: Dict mapping uid -> share_value
        q: Modulus
    
    Returns:
        Reconstructed secret f(0) mod q
    """
    uids = list(shares.keys())
    
    # Compute Lagrange coefficients (evaluated at x=0)
    lambda_coeffs = compute_all_lagrange_coefficients(uids, q)
    
    # Interpolate: secret = Σ (share_i · λ_i)
    secret = 0
    for uid in uids:
        term = (shares[uid] * lambda_coeffs[uid]) % q
        secret = (secret + term) % q
    
    return secret


def reconstruct_polynomial_vector(shares_dict: Dict[int, list], q: int, N: int):
    """
    Reconstruct polynomial vector from shares using Lagrange interpolation.
    
    Args:
        shares_dict: Dict mapping uid -> List[Poly] (shares for each user)
        q: Modulus
        N: Polynomial degree
    
    Returns:
        List[Poly] (reconstructed polynomial vector)
    """
    from core.dilithium_math import Poly
    
    uids = list(shares_dict.keys())
    num_polys = len(shares_dict[uids[0]])
    
    reconstructed = []
    
    # For each polynomial position in the vector
    for poly_idx in range(num_polys):
        reconstructed_coeffs = []
        
        # For each coefficient position
        for coeff_idx in range(N):
            # Collect shares for this coefficient
            coeff_shares = {}
            for uid in uids:
                poly_share = shares_dict[uid][poly_idx]
                coeff_shares[uid] = poly_share.coeffs[coeff_idx]
            
            # Reconstruct this coefficient
            reconstructed_coeff = reconstruct_secret(coeff_shares, q)
            reconstructed_coeffs.append(reconstructed_coeff)
        
        # Create Poly from reconstructed coefficients
        reconstructed.append(Poly(reconstructed_coeffs, q, N, in_ntt=False))
    
    return reconstructed


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    # Test modular inverse
    q = 8380417
    a = 12345
    a_inv = mod_inverse(a, q)
    assert (a * a_inv) % q == 1, "Modular inverse failed"
    print(f"✓ Modular inverse: {a} * {a_inv} ≡ 1 (mod {q})")
    
    # Test Lagrange coefficients
    uids = [1, 3, 5]  # t=3 users
    lambdas = compute_all_lagrange_coefficients(uids, q)
    print(f"✓ Lagrange coefficients for UIDs {uids}:")
    for uid, lam in lambdas.items():
        print(f"  λ_{uid} = {lam}")
    
    # Test Shamir sharing
    secret = 42
    n, t = 5, 3
    shares = share_coefficient(secret, n, t, q)
    print(f"\n✓ Shamir shares for secret={secret}, n={n}, t={t}:")
    for uid, share in shares.items():
        print(f"  Share[{uid}] = {share}")
    
    # Test reconstruction with t shares
    subset_shares = {1: shares[1], 2: shares[2], 3: shares[3]}
    reconstructed = reconstruct_secret(subset_shares, q)
    assert reconstructed == secret, f"Reconstruction failed: {reconstructed} != {secret}"
    print(f"✓ Reconstructed secret from UIDs {list(subset_shares.keys())}: {reconstructed}")
    
    # Test with different subset
    subset_shares2 = {2: shares[2], 4: shares[4], 5: shares[5]}
    reconstructed2 = reconstruct_secret(subset_shares2, q)
    assert reconstructed2 == secret, f"Reconstruction failed: {reconstructed2} != {secret}"
    print(f"✓ Reconstructed secret from UIDs {list(subset_shares2.keys())}: {reconstructed2}")
    
    print("\n✅ All Shamir utilities tests passed!")
