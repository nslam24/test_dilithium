#!/usr/bin/env python3
"""
commitment_scheme.py - Lattice-based Commitment Scheme for TLBSS

Implements Baum et al.'s commitment scheme (Definition 4) used in TLBSS paper.

COMMITMENT SCHEME STRUCTURE (Definition 4, cite: 130-135):
- Setup: Generate commitment key ck = Â ∈ Z_q^{m'×n'}
- Commit: com = Commit_ck(x, r) = Â·r + [0, x]
- Open: Open_ck(com, r, x) = 1 iff:
    1. ||r|| ≤ B_commit (norm bound)
    2. com = Â·r + [0, x] (structural equation)

SECURITY PROPERTIES:
- Binding: Cannot open same com to two different x (based on M-SIS hardness)
- Hiding: com reveals no information about x (statistical hiding)

IMPLEMENTATION NOTES:
- Matrix Â is generated uniformly from seed
- Dimension: m' = k (message dimension), n' = k + λ (randomness dimension)
- Bound B_commit chosen for M-SIS security parameter λ
"""

import sys
import os
import hashlib
import numpy as np

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from core.dilithium_math import (
    Poly, DILITHIUM_Q, DILITHIUM_N,
    expand_a, vec_add, vec_zeros,
)

# ============================================================================
# COMMITMENT PARAMETERS (Following TLBSS Definition 4)
# ============================================================================

# Commitment security parameter λ (lambda)
# - Controls hiding property and M-SIS hardness
# - Paper recommendation: λ ≥ 128 for 128-bit security
# - Larger λ → stronger hiding but larger randomness r
LAMBDA_COMMIT = 128

# Commitment norm bound B_commit
# - Used in Open_ck to check ||r|| ≤ B_commit
# - Must be large enough to allow valid randomness
# - But small enough to ensure M-SIS hardness
# - Paper guidance: B_commit ≈ σ_r · √(n'·N) where σ_r is randomness std dev
# - For simplicity: Use same bound as signature randomness
# Import will be done later to avoid circular dependency
B_COMMIT = 900000  # Same as B_BOUND in gaussian_primitives


# ============================================================================
# COMMITMENT KEY GENERATION (DYNAMIC DERIVATION)
# ============================================================================

def derive_commitment_key_from_message(message: bytes, pk_bytes: bytes, K: int,
                                      q: int = DILITHIUM_Q, 
                                      N: int = DILITHIUM_N):
    """
    Derive commitment key ck = Â dynamically from message and public key.
    
    TLBSS Protocol (CRITICAL):
    The commitment key is NOT static! It must be derived fresh for each message
    using the formula: ck = H₃(μ || pk) → Expand → Â
    
    WHY THIS IS CRITICAL:
    - Binds commitment to specific message μ (prevents commitment reuse)
    - Prevents forgery attacks using old commitments
    - Ensures fresh randomness for each signing session
    - Both signer and verifier can compute locally (no transmission)
    
    Formula [cite: TLBSS Protocol]:
        seed = H₃(message || pk)
        ck = Expand(seed) → Â ∈ Z_q^{K×(K+λ)}
    
    Args:
        message: The message μ being signed (bytes)
        pk_bytes: Public key representation (e.g., serialized (ρ, t))
        K: message dimension (public key vector size)
        q: modulus
        N: polynomial degree
        
    Returns:
        ck_matrix: commitment key Â as list of K rows, each with (K+λ) columns
                   Format: [[Â_{0,0}, ..., Â_{0,n'-1}], ..., [Â_{m'-1,0}, ...]]
    """
    m_prime = K  # Message dimension
    n_prime = K + (LAMBDA_COMMIT // 8)  # Randomness dimension (λ in bytes → polynomials)
    
    # CRITICAL: Hash message || pk to get commitment key seed
    # This binds ck to the specific message being signed
    h = hashlib.sha3_256()
    h.update(b"TLBSS_CK|")  # Domain separator
    h.update(message)       # Message μ
    h.update(pk_bytes)      # Public key
    ck_seed = h.digest()
    
    # Expand seed to matrix Â using SHAKE (same as Dilithium's A expansion)
    # expand_a expects (rows, cols, q, N) and returns matrix[rows][cols]
    ck_matrix = expand_a(ck_seed, m_prime, n_prime, q, N)
    
    return ck_matrix


def generate_commitment_key(K: int, seed: bytes, 
                           q: int = DILITHIUM_Q, 
                           N: int = DILITHIUM_N):
    """
    DEPRECATED: Use derive_commitment_key_from_message() instead.
    
    This function generates ck from a static seed, which is INCORRECT
    for TLBSS protocol. Kept for backward compatibility with tests only.
    
    For actual signing/verification, use derive_commitment_key_from_message()
    which properly binds ck to the message being signed.
    """
    m_prime = K
    n_prime = K + (LAMBDA_COMMIT // 8)
    
    ck_seed = hashlib.sha3_256(b"TLBSS_CK|" + seed).digest()
    ck_matrix = expand_a(ck_seed, m_prime, n_prime, q, N)
    
    return ck_matrix


# ============================================================================
# COMMITMENT OPERATIONS
# ============================================================================

def commit(ck_matrix, x_vec, r_vec, 
          q: int = DILITHIUM_Q, 
          N: int = DILITHIUM_N):
    """
    Create commitment: com = Commit_ck(x, r) = Â·r + [0, x]
    
    Following Definition 4 (cite: 133):
    - Input: x ∈ Z_q^{m'×N} (message, K polynomials)
    - Input: r ∈ Z_q^{n'×N} (randomness, (K+λ) polynomials)
    - Output: com ∈ Z_q^{m'×N} (commitment, K polynomials)
    
    Computation:
    1. Compute Â·r (matrix-vector multiplication)
    2. Create padded vector [0, x] = [0, ..., 0, x_0, x_1, ..., x_{m'-1}]
       (But since matrix multiplication already gives right size, just add x)
    3. Return com = Â·r + [0, x]
    
    CRITICAL DETAIL: The [0, x] notation means:
    - Randomness r has dimension n' = K + λ
    - Matrix Â has shape (K × (K+λ))
    - Product Â·r has dimension K (matches x)
    - So we simply add x to Â·r
    
    Args:
        ck_matrix: commitment key Â (K × (K+λ) matrix)
        x_vec: message vector (K polynomials)
        r_vec: randomness vector ((K+λ) polynomials)
        q, N: Dilithium parameters
        
    Returns:
        com_vec: commitment vector (K polynomials)
    """
    K = len(x_vec)
    
    # Check dimensions
    if len(ck_matrix) != K:
        raise ValueError(f"ck_matrix rows {len(ck_matrix)} != K {K}")
    if len(r_vec) != len(ck_matrix[0]):
        raise ValueError(f"r_vec size {len(r_vec)} != ck_matrix cols {len(ck_matrix[0])}")
    
    # Step 1: Compute Â·r
    # Matrix multiplication: (K × n') × (n' × 1) = (K × 1)
    A_r = vec_zeros(K, q, N)
    for i in range(K):  # For each row of Â
        row_sum = Poly([0] * N, q, N)
        for j in range(len(r_vec)):  # For each column
            # Polynomial multiplication in NTT domain
            term = ck_matrix[i][j].to_ntt().mul(r_vec[j].to_ntt()).from_ntt()
            row_sum = row_sum.add(term)
        A_r[i] = row_sum
    
    # Step 2: Add [0, x] = x (since dimensions already match)
    com_vec = vec_add(A_r, x_vec)
    
    return com_vec


def open_commitment(ck_matrix, com_vec, r_vec, x_vec,
                   bound: int = B_COMMIT,
                   q: int = DILITHIUM_Q,
                   N: int = DILITHIUM_N) -> bool:
    """
    Verify commitment opening: Open_ck(com, r, x) ∈ {0, 1}
    
    Following Definition 4 (cite: 135):
    Returns 1 (True) if and only if:
    1. ||r|| ≤ B_commit (norm bound check)
    2. com = Â·r + [0, x] (structural equation check)
    
    This is the CRITICAL function for TLBSS verification (cite: 346):
    - Used in signing phase to validate aggregated signature
    - Used in verification phase to ensure commitment binding
    
    Args:
        ck_matrix: commitment key Â
        com_vec: claimed commitment (K polynomials)
        r_vec: randomness opening ((K+λ) polynomials)
        x_vec: message opening (K polynomials)
        bound: norm bound B_commit
        q, N: parameters
        
    Returns:
        True if commitment opens correctly, False otherwise
    """
    # Import here to avoid circular dependency
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
    from modes.threshold_gaussian.gaussian_primitives import norm_infinity
    
    # CHECK 1: Norm Bound ||r|| ≤ B_commit
    r_norm = norm_infinity(r_vec)
    if r_norm > bound:
        print(f"[OPEN] REJECT - Randomness norm: ||r||={r_norm} > B={bound}", 
              file=sys.stderr)
        return False
    
    # CHECK 2: Structural Equation com = Â·r + [0, x]
    # Recompute commitment with given (r, x)
    com_recomputed = commit(ck_matrix, x_vec, r_vec, q, N)
    
    # Compare all K polynomials coefficient-by-coefficient
    for i in range(len(com_vec)):
        # Compare coefficient arrays using numpy
        com_coeffs = np.array(com_vec[i].coeffs)
        recomp_coeffs = np.array(com_recomputed[i].coeffs)
        
        if not np.array_equal(com_coeffs, recomp_coeffs):
            print(f"[OPEN] REJECT - Equation check failed at polynomial {i}", 
                  file=sys.stderr)
            print(f"[OPEN]   Expected: {com_coeffs[:4]}...", 
                  file=sys.stderr)
            print(f"[OPEN]   Got:      {recomp_coeffs[:4]}...", 
                  file=sys.stderr)
            return False
    
    # Both checks passed
    return True


# ============================================================================
# HELPER: Sample randomness for commitment
# ============================================================================

def sample_commitment_randomness(K: int, q: int = DILITHIUM_Q, N: int = DILITHIUM_N):
    """
    Sample randomness r for commitment scheme.
    
    Following TLBSS protocol:
    - Dimension: n' = K + λ (includes security parameter)
    - Distribution: Discrete Gaussian D_σ (same as signature noise)
    
    Args:
        K: message dimension
        q, N: parameters
        
    Returns:
        r_vec: randomness vector ((K+λ) polynomials)
    """
    # Import here to avoid circular dependency
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
    from modes.threshold_gaussian.gaussian_primitives import gaussian_sample_vector, SIGMA
    
    n_prime = K + (LAMBDA_COMMIT // 8)
    return gaussian_sample_vector(n_prime, q, N, SIGMA)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
    from modes.threshold_gaussian.gaussian_primitives import gaussian_sample_vector, SIGMA
    
    print("\n[TEST] TLBSS Commitment Scheme (Baum et al.)")
    print("=" * 60)
    
    K = 4  # Dilithium2 dimension
    q = DILITHIUM_Q
    N = DILITHIUM_N
    
    print(f"\nParameters:")
    print(f"  K = {K} (message dimension)")
    print(f"  λ = {LAMBDA_COMMIT} (security parameter)")
    print(f"  n' = {K + LAMBDA_COMMIT//8} (randomness dimension)")
    print(f"  B_commit = {B_COMMIT}")
    
    # 1. Generate commitment key
    print(f"\n1. Generate commitment key ck = Â:")
    seed = b"test_commitment" + b"\x00" * 18
    ck = generate_commitment_key(K, seed)
    print(f"   ✓ ck matrix shape: {len(ck)} × {len(ck[0])}")
    
    # 2. Create commitment
    print(f"\n2. Create commitment com = Commit_ck(x, r):")
    
    x = gaussian_sample_vector(K, q, N, SIGMA)  # Message
    r = sample_commitment_randomness(K, q, N)   # Randomness
    
    com = commit(ck, x, r)
    print(f"   ✓ Commitment created (K={len(com)} polynomials)")
    
    # 3. Open commitment (valid)
    print(f"\n3. Open commitment with correct (r, x):")
    valid = open_commitment(ck, com, r, x)
    print(f"   Result: {valid} (expected: True)")
    
    # 4. Open with wrong message (should fail)
    print(f"\n4. Open commitment with wrong message:")
    x_wrong = gaussian_sample_vector(K, q, N, SIGMA)
    valid = open_commitment(ck, com, r, x_wrong)
    print(f"   Result: {valid} (expected: False)")
    
    # 5. Open with wrong randomness (should fail)
    print(f"\n5. Open commitment with wrong randomness:")
    r_wrong = sample_commitment_randomness(K, q, N)
    valid = open_commitment(ck, com, r_wrong, x)
    print(f"   Result: {valid} (expected: False)")
    
    print("\n" + "=" * 60)
    print("✓ Commitment scheme test completed")
