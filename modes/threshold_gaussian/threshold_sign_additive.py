#!/usr/bin/env python3
"""
threshold_sign_additive.py - ADDITIVE Threshold Signing for TLBSS

ARCHITECTURE: Additive Reconstruction (n-of-n)
==============================================

CORRECTED PROTOCOL (Following Paper Exactly):
- Additive sharing: x_i = s_i (share equals secret component)
- Lagrange coefficients: l_i = 1 for all i (n-of-n case)
- Each user uses their SMALL secret s_i (||s_i|| ≈ 23, from S_η)
- Rejection sampling WORKS because s_i is small!

SIGNING PROTOCOL (TLBSS Section 3, Step 4 - CORRECTED):
========================================================

ROUND 1 - COMMITMENT:
(a) Each signer i samples y_i ← D_σ^{L} (Gaussian noise, NOT weighted)
(b) Computes w_i = A·y_i (using ORIGINAL y_i, not ȳ_i)
(c) Samples randomness r_i
(d) Computes commitment: com_i = Commit_ck(w_i, r_i)
(e) Sends com_i

ROUND 2 - CHALLENGE:
(f) Aggregate commitments (homomorphic): com = Σ com_i
(g) Challenge: c = H₀(com, μ, pk)

ROUND 3 - RESPONSE & REJECTION:
(h) Compute weighted noise: ȳ_i = y_i · l_i^(-1) mod q
    (In additive: l_i = 1, so ȳ_i = y_i)
(i) Compute partial signature (TO SEND): z_i = c·x_i + ȳ_i
    (In additive: x_i = s_i, so z_i = c·s_i + y_i)
(j) Compute check vector (FOR REJECTION): z'_i = c·s_i + y_i
    (In additive: z'_i = z_i, same as above)
(k) Rejection Sampling on z'_i (NOT z_i!):
    - Hard bound: ||z'_i|| < B
    - Probabilistic: P ∝ exp((||y_i||² - ||z'_i||²)/(2σ²))
(l) If REJECT → send RESTART, else send (z_i, r_i)

AGGREGATION (Combiner):
(m) Lagrange interpolation: z = Σ(z_i · l_i)
    (In additive: l_i = 1, so z = Σ z_i)
(n) Aggregate randomness: r = Σ r_i
(o) Global bound check: ||z|| ≤ t·B (t = n for additive)
(p) Reconstruct w: w = A·z - c·t
(q) Verify commitment: Open_ck(com, r, w) = 1
(r) Output signature: σ = (com, z, r)

KEY INSIGHT: In additive mode, protocol simplifies because:
  - l_i = 1 (no weighting needed)
  - x_i = s_i (shares are original secrets)
  - z_i = z'_i (response equals check vector)
"""

import sys
import os
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from core.dilithium_math import (
    Poly, DILITHIUM_Q, DILITHIUM_N,
    _matvec_mul, expand_a, _serialize_poly_vec,
    _hash_to_challenge_poly, vec_add, vec_zeros,
)

from .gaussian_primitives import (
    gaussian_sample_vector, 
    norm_infinity, 
    rejection_sample_check,
    SIGMA, 
    B_BOUND,
)

from .commitment_scheme import (
    derive_commitment_key_from_message,
    commit,
    open_commitment,
    sample_commitment_randomness,
)


# ============================================================================
# ADDITIVE THRESHOLD SIGNING
# ============================================================================

def sign_threshold_additive(message: bytes, shares, pk, max_attempts: int = 5000):
    """
    Sign message using additive threshold (requires ALL n users).
    
    Args:
        message: Message to sign
        shares: List of ALL n user shares (n-of-n required!)
        pk: Public key from additive_threshold_setup
        max_attempts: Max rejection sampling attempts
    
    Returns:
        (signature, metadata) or (None, error_meta)
    """
    q = pk['q']
    N = pk['N']
    K = pk['K']
    L = pk['L']
    n = pk['n']
    tau = pk.get('tau', 49)  # Challenge Hamming weight (default: Dilithium3)
    
    if len(shares) != n:
        raise ValueError(f'Additive mode requires ALL {n} users, got {len(shares)}')
    
    print(f'\n[SIGN-ADD] Starting additive signing', file=sys.stderr)
    print(f'[SIGN-ADD] Participants: {n}-of-{n}', file=sys.stderr)
    
    # Load public matrix A
    rho = pk['rho']
    A = expand_a(rho, K, L, q, N)
    t = pk['t']
    
    # Message hash
    mu = hashlib.sha3_512(message).digest()
    
    # Derive commitment key ck from message (dynamic, not static!)
    pk_bytes_list = _serialize_poly_vec(t)
    pk_bytes = ''.join(pk_bytes_list).encode()
    ck_matrix = derive_commitment_key_from_message(mu, pk_bytes, K)
    
    # Rejection sampling loop
    for attempt in range(1, max_attempts + 1):
        # ====================================================================
        # ROUND 1 - COMMITMENT
        # ====================================================================
        user_data = []
        
        for i, share in enumerate(shares):
            uid = share['uid']
            x_i = share['s1']  # In additive: x_i = s_i (share = secret component)
            s_i = share['s1']  # s_i: original secret (same as x_i in additive)
            s2_i = share['s2']
            
            # (a) Sample Gaussian noise y_i ← D_σ^L (NOT weighted yet!)
            y_i = gaussian_sample_vector(L, q, N, SIGMA)
            
            # (b) Compute w_i = A·y_i (using ORIGINAL y_i, not ȳ_i)
            w_i = _matvec_mul(A, y_i)
            
            # (c) Sample randomness r_i for commitment
            r_i = sample_commitment_randomness(K)
            
            # (d) Lattice commitment: com_i = Commit_ck(w_i, r_i)
            com_i = commit(ck_matrix, w_i, r_i, q, N)
            
            user_data.append({
                'uid': uid,
                'x_i': x_i,     # Share (for computing z_i)
                's_i': s_i,     # Original secret (for rejection check)
                's2': s2_i,
                'y_i': y_i,     # Original noise (NOT weighted)
                'w_i': w_i,
                'r_i': r_i,
                'com_i': com_i
            })
        
        # ====================================================================
        # ROUND 2 - CHALLENGE
        # ====================================================================
        
        # (f) Aggregate commitments (homomorphic addition)
        com = user_data[0]['com_i']
        for data in user_data[1:]:
            com = vec_add(com, data['com_i'])
        
        # Serialize commitment for challenge
        com_bytes_list = _serialize_poly_vec(com)
        com_bytes = ''.join(com_bytes_list).encode()
        
        # (g) Challenge: c = H₀(com, μ, pk)
        challenge_input = com_bytes + mu + pk_bytes
        c = _hash_to_challenge_poly(mu, challenge_input, tau=tau, q=q, N=N)
        
        # ====================================================================
        # ROUND 3 - RESPONSE & REJECTION SAMPLING
        # ====================================================================
        
        z_parts = []  # Partial signatures to send
        r_parts = []  # Randomness to send
        all_accepted = True
        
        for data in user_data:
            x_i = data['x_i']   # Share (in additive: = s_i)
            s_i = data['s_i']   # Original secret
            y_i = data['y_i']   # Original noise
            
            # (h) Compute weighted noise: ȳ_i = y_i · l_i^(-1)
            # In additive: l_i = 1, so ȳ_i = y_i (no change)
            y_bar_i = y_i  # No weighting in additive mode
            
            # (i) Compute partial signature (TO SEND): z_i = c·x_i + ȳ_i
            # In additive: x_i = s_i and ȳ_i = y_i, so z_i = c·s_i + y_i
            c_times_x_i = [c.mul(x_poly).from_ntt() for x_poly in x_i]
            z_i = vec_add(c_times_x_i, y_bar_i)
            
            # (j) Compute check vector (FOR REJECTION): z'_i = c·s_i + y_i
            # In additive: z'_i = z_i (same as above since x_i = s_i)
            c_times_s_i = [c.mul(s_poly).from_ntt() for s_poly in s_i]
            z_prime_i = vec_add(c_times_s_i, y_i)
            
            # (k) Rejection Sampling on z'_i (NOT z_i!)
            # NOTE: In additive mode, z_i = z'_i, but we follow protocol strictly
            accepted = rejection_sample_check(
                z_prime=z_prime_i,  # Check vector (c·s_i + y_i)
                y=y_i,              # Original noise
                c_times_s=c_times_s_i,  # For probabilistic check
                sigma=SIGMA,
                bound=B_BOUND
            )
            
            # (l) If REJECT → restart entire protocol
            if not accepted:
                all_accepted = False
                break
            
            # Accept: store z_i and r_i to send
            z_parts.append(z_i)
            r_parts.append(data['r_i'])
        
        if not all_accepted:
            continue  # Restart from Round 1
        
        # ====================================================================
        # AGGREGATION (Combiner)
        # ====================================================================
        
        # (m) Lagrange interpolation: z = Σ(z_i · l_i)
        # In additive: l_i = 1 for all i, so z = Σ z_i (simple sum)
        z = vec_zeros(L, q, N)
        for z_i in z_parts:
            # l_i = 1 in additive mode, so just add
            z = vec_add(z, z_i)
        
        # (n) Aggregate randomness: r = Σ r_i
        r = r_parts[0]
        for r_i in r_parts[1:]:
            r = vec_add(r, r_i)
        
        # (o) Global bound check: ||z|| ≤ t·B (t = n for additive)
        z_norm_inf = norm_infinity(z)
        bound_limit = n * B_BOUND
        
        if z_norm_inf >= bound_limit:
            print(f'[COMBINER] (o) REJECT - Global bound: ||z||={z_norm_inf} >= {n}·B={bound_limit}', 
                  file=sys.stderr)
            continue
        
        # (p) Reconstruct w: w = A·z - c·t
        Az = _matvec_mul(A, z)
        ct = [c.mul(t_poly).from_ntt() for t_poly in t]
        w_reconstructed = vec_add(Az, [poly.scalar_mul(-1) for poly in ct])
        
        # (q) Verify commitment: Open_ck(com, r, w) = 1
        # ⚡ CRITICAL SECURITY CHECK (TLBSS Step 4h)
        # Prevents malicious signers from producing invalid responses
        commitment_valid = open_commitment(
            ck_matrix=ck_matrix,
            com_vec=com,
            r_vec=r,
            x_vec=w_reconstructed,
            q=q,
            N=N
        )
        
        if not commitment_valid:
            print(f'[COMBINER] (q) REJECT - Open_ck failed (fraud detected!)', 
                  file=sys.stderr)
            continue
        
        # ====================================================================
        # (r) SUCCESS - Output signature σ = (com, z, r)
        # ====================================================================
        
        signature = {
            'com': com,     # Aggregated commitment
            'z': z,         # Aggregated response (Lagrange-interpolated)
            'r': r,         # Aggregated randomness
            'c': c          # Challenge (for debugging)
        }
        
        metadata = {
            'attempts': attempt,
            'acceptance_rate': 1.0 / attempt,
            'z_norm_inf': z_norm_inf
        }
        
        print(f'[SIGN-ADD] ✓ Success in {attempt} attempts', file=sys.stderr)
        
        return signature, metadata
    
    # Max attempts exceeded
    print(f'[SIGN-ADD] ERROR: Max attempts ({max_attempts}) exceeded', 
          file=sys.stderr)
    return None, {'attempts': max_attempts, 'error': 'max_attempts_exceeded'}


# ============================================================================
# VERIFICATION
# ============================================================================

def verify_threshold_additive(message: bytes, signature, pk) -> tuple:
    """
    Verify TLBSS signature with additive threshold.
    
    Verification (TLBSS Section 3, Step 5):
    1. Parse σ = (com, z, r)
    2. Check ||z|| ≤ n·B (bound scaled by n)
    3. Derive ck = H₃(μ || pk) (dynamic!)
    4. Recompute c = H₀(com, μ, pk)
    5. Compute w = A·z - c·t
    6. Verify Open_ck(com, r, w) = 1 ✓ LATTICE-BASED
    
    Args:
        message: Original message
        signature: Dict with {com, z, r}
        pk: Public key
    
    Returns:
        (valid: bool, details: dict)
    """
    q = pk['q']
    N = pk['N']
    K = pk['K']
    L = pk['L']
    n = pk['n']
    tau = pk.get('tau', 49)  # Challenge Hamming weight
    
    com = signature['com']
    z = signature['z']
    r = signature['r']
    
    # Step 1: Parse (already done)
    
    # Step 2: Bound check ||z||_∞ ≤ n·B
    z_norm_inf = norm_infinity(z)
    bound_limit = n * B_BOUND
    
    if z_norm_inf >= bound_limit:
        return False, {'error': 'bound_check_failed', 'norm': z_norm_inf}
    
    # Step 3: Derive commitment key ck from message (SAME as signing!)
    mu = hashlib.sha3_512(message).digest()
    t = pk['t']
    pk_bytes_list = _serialize_poly_vec(t)
    pk_bytes = ''.join(pk_bytes_list).encode()
    ck_matrix = derive_commitment_key_from_message(mu, pk_bytes, K)
    
    # Step 4: Recompute challenge c = H₀(com, μ, pk)
    com_bytes_list = _serialize_poly_vec(com)
    com_bytes = ''.join(com_bytes_list).encode()
    challenge_input = com_bytes + mu + pk_bytes
    c = _hash_to_challenge_poly(mu, challenge_input, tau=tau, q=q, N=N)
    
    # Step 5: Compute w = A·z - c·t
    rho = pk['rho']
    A = expand_a(rho, K, L, q, N)
    
    Az = _matvec_mul(A, z)
    ct = [c.mul(t_poly).from_ntt() for t_poly in t]
    w = vec_add(Az, [poly.scalar_mul(-1) for poly in ct])
    
    # Step 6: Verify Open_ck(com, r, w) = 1 (LATTICE-BASED!)
    commitment_valid = open_commitment(
        ck_matrix=ck_matrix,
        com_vec=com,
        r_vec=r,
        x_vec=w,
        q=q,
        N=N
    )
    
    if not commitment_valid:
        return False, {'error': 'open_commitment_failed'}
    
    return True, {'z_norm_inf': z_norm_inf, 'bound_limit': bound_limit}
