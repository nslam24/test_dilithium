#!/usr/bin/env python3
"""
threshold_sign_additive.py - ADDITIVE Threshold Signing for TLBSS

ARCHITECTURE: Additive Reconstruction (n-of-n)
==============================================

KEY DIFFERENCE from Shamir mode:
- NO Lagrange interpolation (ȳ_i = y_i, NOT y_i·l_i^{-1})
- Direct summation: z = Σ z_i where z_i = c·s_i + y_i
- Each user uses their SMALL secret s_i (||s_i|| ~ 90)
- Rejection sampling WORKS because s_i is small!

SIGNING PROTOCOL (TLBSS Section 3, Step 4):
===========================================

ROUND 1 - COMMITMENT:
(a) Each signer i samples y_i ← D_σ^{K+L}
(b) Computes w_i = A·y_i
(c) Samples randomness r_i
(d) Sends com_i = Hash(w_i || r_i)

ROUND 2 - CHALLENGE:
(e) Aggregate: com = Σ com_i (simple XOR/addition)
(f) Challenge: c = H₀(com, μ, pk)

ROUND 3 - RESPONSE & REJECTION:
(g) Compute response: z_i = c·s_i + y_i (NO WEIGHTING!)
(h) Rejection check on z_i:
    - Hard bound: ||z_i|| < B
    - Probabilistic: P = (1/M)·exp((||y_i||² - ||z_i||²)/(2σ²))
(i) If reject → RESTART, else send (z_i, r_i)

AGGREGATION:
(j) Reconstruct: z = Σ z_i (simple addition!)
(k) Opening: r = Σ r_i
(l) Verify bounds and commitment
(m) Output: σ = (com, z, r)
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
    
    # Rejection sampling loop
    for attempt in range(1, max_attempts + 1):
        # ROUND 1: Each user generates noise and commitment
        user_data = []
        w_total = vec_zeros(K, q, N)
        com_parts = []
        
        for i, share in enumerate(shares):
            uid = share['uid']
            s1_i = share['s1']
            s2_i = share['s2']
            
            # (a) Sample Gaussian noise y_i (NO WEIGHTING!)
            y_i = gaussian_sample_vector(L, q, N, SIGMA)
            
            # (b) Compute w_i = A·y_i
            w_i = _matvec_mul(A, y_i)
            w_total = vec_add(w_total, w_i)
            
            # (c) Sample randomness for commitment
            r_i = hashlib.sha3_256(f'r_{uid}_{attempt}'.encode()).digest()
            
            # (d) Commitment: Hash(w_i || r_i)
            w_i_bytes_list = _serialize_poly_vec(w_i)
            w_i_bytes = ''.join(w_i_bytes_list).encode()
            com_i_bytes = hashlib.sha3_256(w_i_bytes + r_i).digest()
            com_parts.append(com_i_bytes)
            
            user_data.append({
                'uid': uid,
                's1': s1_i,
                's2': s2_i,
                'y': y_i,
                'w': w_i,
                'r': r_i,
                'com': com_i_bytes
            })
        
        # ROUND 2: Aggregate commitment and compute challenge
        # (e) Aggregate randomness: r_agg = XOR(r_i)
        r_agg = user_data[0]['r']
        for data in user_data[1:]:
            r_i = data['r']
            r_agg = bytes(a ^ b for a, b in zip(r_agg, r_i))
        
        # Commitment: Hash(w_total || r_agg)
        w_total_bytes_list = _serialize_poly_vec(w_total)
        w_total_bytes = ''.join(w_total_bytes_list).encode()
        com_aggregated = hashlib.sha3_256(w_total_bytes + r_agg).digest()
        
        # (f) Challenge: c = H₀(com, μ, pk)
        pk_bytes_list = _serialize_poly_vec(t)
        pk_bytes = ''.join(pk_bytes_list).encode()
        challenge_input = com_aggregated + mu + pk_bytes
        # _hash_to_challenge_poly expects (message, w_bytes, tau, q, N)
        c = _hash_to_challenge_poly(mu, challenge_input, tau=49, q=q, N=N)
        
        # ROUND 3: Compute responses and check rejection
        z_parts = []
        all_accepted = True
        
        for data in user_data:
            s1_i = data['s1']
            y_i = data['y']
            
            # (g) Response: z_i = c·s_i + y_i (NO LAGRANGE!)
            c_times_s1_i = [c.mul(s1).from_ntt() for s1 in s1_i]
            z_i = vec_add(c_times_s1_i, y_i)
            
            # (h) Rejection check
            accepted = rejection_sample_check(
                z_prime=z_i,
                y=y_i,
                c_times_s=c_times_s1_i,
                sigma=SIGMA,
                bound=B_BOUND
            )
            
            if not accepted:
                all_accepted = False
                break
            
            z_parts.append(z_i)
        
        if not all_accepted:
            continue  # Restart
        
        # AGGREGATION: Direct summation (no Lagrange!)
        # (j) z = Σ z_i
        z = vec_zeros(L, q, N)
        for z_i in z_parts:
            z = vec_add(z, z_i)
        
        # (k) r_agg already computed above
        
        # (l) Verify: w = A·z - c·t
        Az = _matvec_mul(A, z)
        ct = [c.mul(t_poly).from_ntt() for t_poly in t]
        w_reconstructed = vec_add(Az, [poly.scalar_mul(-1) for poly in ct])
        
        # Check bound
        z_norm_inf = norm_infinity(z)
        if z_norm_inf >= n * B_BOUND:
            print(f'[SIGN-ADD] Bound check failed: ||z||_∞ = {z_norm_inf}', 
                  file=sys.stderr)
            continue
        
        # (m) Verify commitment opening: Hash(w || r) == com
        w_bytes_list = _serialize_poly_vec(w_reconstructed)
        w_bytes = ''.join(w_bytes_list).encode()
        com_check = hashlib.sha3_256(w_bytes + r_agg).digest()
        
        if com_check != com_aggregated:
            print(f'[SIGN-ADD] Commitment opening failed', file=sys.stderr)
            continue
        
        # SUCCESS!
        signature = {
            'com': com_aggregated,
            'z': z,
            'r': r_agg,
            'c': c  # Include for debugging
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
    3. Recompute c = H₀(com, μ, pk)
    4. Compute w = A·z - c·t
    5. Verify Open_ck(com, r, w) = 1
    
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
    
    com = signature['com']
    z = signature['z']
    r = signature['r']
    
    # Step 1: Parse (already done)
    
    # Step 2: Bound check ||z||_∞ ≤ n·B
    z_norm_inf = norm_infinity(z)
    bound_limit = n * B_BOUND
    
    if z_norm_inf >= bound_limit:
        return False, {'error': 'bound_check_failed', 'norm': z_norm_inf}
    
    # Step 3: Recompute challenge c = H₀(com, μ, pk)
    mu = hashlib.sha3_512(message).digest()
    t = pk['t']
    pk_bytes_list = _serialize_poly_vec(t)
    pk_bytes = ''.join(pk_bytes_list).encode()
    challenge_input = com + mu + pk_bytes
    c = _hash_to_challenge_poly(mu, challenge_input, tau=49, q=q, N=N)
    
    # Step 4: Compute w = A·z - c·t
    rho = pk['rho']
    A = expand_a(rho, K, L, q, N)
    
    Az = _matvec_mul(A, z)
    ct = [c.mul(t_poly).from_ntt() for t_poly in t]
    w = vec_add(Az, [poly.scalar_mul(-1) for poly in ct])
    
    # Step 5: Verify Open_ck(com, r, w) = 1
    w_bytes_list = _serialize_poly_vec(w)
    w_bytes = ''.join(w_bytes_list).encode()
    com_check = hashlib.sha3_256(w_bytes + r).digest()
    
    if com_check != com:
        return False, {'error': 'commitment_opening_failed'}
    
    return True, {'z_norm_inf': z_norm_inf, 'bound_limit': bound_limit}
