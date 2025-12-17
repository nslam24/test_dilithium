#!/usr/bin/env python3
"""
threshold_sign.py - Threshold signing with Gaussian noise and rejection sampling

Implements the signing protocol following the paper's specification:
- Round 1: Commitment with weighted Gaussian noise ȳ_i = y_i / l_i
- Round 2: Challenge generation c = H(w || m)
- Round 3: Response with rejection sampling
  * z' = c·s_i + y_i (using original y_i, not weighted)
  * Check ||z'|| < B (hard bound)
  * Probabilistic Gaussian ratio test
"""

import random
import time
import sys
import os
import base64
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from core.dilithium_math import (
    Poly, DILITHIUM_Q, DILITHIUM_N,
    _matvec_mul, expand_a, _deserialize_poly_vec, _serialize_poly_vec,
    _hash_to_challenge_poly, vec_add, vec_zeros,
)

from .gaussian_primitives import (
    gaussian_sample_vector, 
    norm_infinity, 
    rejection_sample_check,
    SIGMA, 
    B_BOUND,
)

from .trusted_dealer import compute_lagrange_coeff


# ============================================================================
# THRESHOLD SIGNING PROTOCOL
# ============================================================================

def sign_threshold_gaussian(message: bytes, shares_subset, pk) -> tuple:
    """
    Threshold signing with Gaussian sampling and weighted noise.
    
    Protocol (following paper):
    
    ROUND 1 - COMMITMENT:
    (a) Each signer i samples y_i ← D_σ (Gaussian)
    (d) Computes weighted noise: ȳ_i = y_i · l_i^{-1} where l_i is Lagrange coeff
    (b) Computes w_i = A·ȳ_i
    (c) Sends commitment com_i = Com(w_i, r_i)
    
    ROUND 2 - CHALLENGE:
    - Aggregate: w = Σ w_i
    - Compute challenge: c = H(w || message)
    
    ROUND 3 - RESPONSE:
    (e) Each signer computes z'_i = c·s_i + y_i  (NOTE: use original y_i!)
    (f) Rejection sampling:
        - Check ||z'_i|| < B (hard bound, cite: 334)
        - Probabilistic check (cite: 336)
        - If reject => RESTART from Round 1
    (g) Send z_i = z'_i (if accepted)
    
    AGGREGATION:
    (h) Combiner computes z = Σ z_i
        - Verify ||z|| ≤ t·B
        - Output signature (z, c)
    
    Args:
        message: message to sign
        shares_subset: list of share dicts from participants
        pk: public key dict
        
    Returns:
        (signature, metadata) or (None, None) if max attempts exceeded
    """
    if not shares_subset:
        raise ValueError("Need at least 1 share")
    
    q = pk["q"]
    N = pk["N"]
    K = pk["K"]
    L = pk["L"]
    threshold = pk["threshold"]
    
    if len(shares_subset) < threshold:
        raise ValueError(
            f"Insufficient shares: got {len(shares_subset)}, need {threshold}"
        )
    
    # Deserialize public key
    rho = base64.b64decode(pk["rho"])
    A = expand_a(rho, K, L, q, N)
    t_vec = _deserialize_poly_vec(pk["t"], q, N)
    
    # Extract participant UIDs
    participant_uids = [share["uid"] for share in shares_subset]
    
    # Compute Lagrange coefficients for this signing set
    lagrange_coeffs = {
        uid: compute_lagrange_coeff(uid, participant_uids, q)
        for uid in participant_uids
    }
    
    print(f"\n[SIGN] Starting threshold signing", file=sys.stderr)
    print(f"[SIGN] Participants: {participant_uids}", file=sys.stderr)
    print(f"[SIGN] Lagrange coeffs: {list(lagrange_coeffs.values())[:3]}...", 
          file=sys.stderr)
    
    # Signing loop with rejection sampling
    attempts = 0
    MAX_ATTEMPTS = 5000
    
    all_attempt_times = []
    
    while attempts < MAX_ATTEMPTS:
        attempts += 1
        t_start = time.perf_counter()
        
        # ====================================================================
        # ROUND 1: COMMITMENT PHASE
        # ====================================================================
        
        y_list = []        # Gaussian noise samples (additive model)
        
        for share in shares_subset:
            uid = share["uid"]
            l_i = lagrange_coeffs[uid]
            
            # (a) Sample Gaussian noise y_i from discrete distribution D_σ
            y_i = gaussian_sample_vector(L, q, N, SIGMA)
            
            # NOTE: Using additive noise model (not weighted)
            # Response will be z_i = y_i + c·λ_i·s_i
            # Aggregate: Σz_i = Σy_i + c·s (via Lagrange interpolation)
            
            y_list.append(y_i)
        
        # ====================================================================
        # ROUND 2: CHALLENGE GENERATION
        # ====================================================================
        
        # Aggregate commitments from ORIGINAL y (not weighted!)
        # This is crucial for Fiat-Shamir: verifier will compute w' = A·z - c·t
        # Let's derive why:
        #
        # During signing:
        # - Each participant i samples y_i
        # - Computes partial response: z_i = y_i + c·λ_i·s_i
        # - Aggregate: z = Σ z_i = Σ(y_i + c·λ_i·s_i) = Σy_i + c·Σ(λ_i·s_i) = Σy_i + c·s
        #   (because Lagrange interpolation: Σλ_i·s_i = s)
        #
        # During verification:
        # - w' = A·z - c·t = A·(Σy_i + c·s) - c·(A·s) = A·Σy_i + A·c·s - c·A·s = A·Σy_i
        # - So challenge MUST be computed from w = A·Σy_i
        #
        # NOTE: Weighted noise ȳ_i = y_i/λ_i was used in the paper for internal
        # commitment to prevent cheating, but for Fiat-Shamir we MUST use original y!
        
        w_total = vec_zeros(K, q, N)
        for y_i in y_list:
            # Compute w_i = A·y_i (using ORIGINAL y_i, not weighted)
            w_i = _matvec_mul(A, y_i)
            w_total = vec_add(w_total, w_i)
        
        # Hash to get challenge polynomial c = H(w || message)
        # This is the Fiat-Shamir transform: challenge derived from commitment
        w_bytes = b"".join(p.to_bytes() for p in w_total)
        c_poly = _hash_to_challenge_poly(message, w_bytes, tau=49, q=q, N=N)
        
        # ====================================================================
        # ROUND 3: RESPONSE PHASE (with rejection sampling)
        # ====================================================================
        
        z_list = []
        all_accepted = True
        
        for idx, share in enumerate(shares_subset):
            uid = share["uid"]
            
            # Reconstruct secret share s_i from Shamir shares
            s1_i = [Poly(share["s1_share"][l], q, N) for l in range(L)]
            # s2_i not needed for signing (only used in keygen for t = A·s1 + s2)
            
            # (e) Compute z'_i = y_i + c·λ_i·s_i
            # NOTE: In Shamir threshold, we MUST multiply by Lagrange coefficient
            # because shares don't sum directly: Σ s_i ≠ s
            # Instead: Σ λ_i · s_i = s (Lagrange reconstruction)
            
            y_i = y_list[idx]
            l_i = lagrange_coeffs[uid]
            
            # c·λ_i·s_i (polynomial multiplication)
            c_ntt = c_poly.to_ntt()
            c_times_lambda_i = c_poly.scalar_mul(l_i)  # c·λ_i
            c_lambda_ntt = c_times_lambda_i.to_ntt()
            
            c_lambda_times_s_i = [
                s1_i[l].to_ntt().mul(c_lambda_ntt).from_ntt()
                for l in range(L)
            ]
            
            # z'_i = y_i + c·λ_i·s_i
            z_prime_i = [y_i[l].add(c_lambda_times_s_i[l]) for l in range(L)]
            
            # (f) & (g) Rejection sampling check
            z_norm_local = norm_infinity(z_prime_i)
            accept = rejection_sample_check(
                z_prime_i, 
                y_i, 
                c_lambda_times_s_i,  # Use c·λ·s for rejection check
                sigma=SIGMA,
                bound=B_BOUND
            )
            
            # Debug: log first rejection
            if attempts == 1 and idx == 0 and not accept:
                print(f"[DEBUG] First attempt rejection: ||z'||={z_norm_local}, B={B_BOUND}", 
                      file=sys.stderr)
            
            if not accept:
                all_accepted = False
                break  # RESTART entire signing round
            
            z_list.append(z_prime_i)
        
        # If any participant rejected, restart
        if not all_accepted:
            t_end = time.perf_counter()
            all_attempt_times.append(t_end - t_start)
            continue  # Go to next attempt
        
        # ====================================================================
        # AGGREGATION
        # ====================================================================
        
        # (h) Combine responses: z = Σ z_i
        z_total = vec_zeros(L, q, N)
        for z_i in z_list:
            z_total = vec_add(z_total, z_i)
        
        # Global rejection check: ||z|| ≤ t·B
        t_signers = len(shares_subset)
        global_bound = t_signers * B_BOUND
        
        z_norm = norm_infinity(z_total)
        
        if z_norm > global_bound:
            # Global rejection
            t_end = time.perf_counter()
            all_attempt_times.append(t_end - t_start)
            print(f"[SIGN] Attempt {attempts}: REJECT (global) - "
                  f"||z||={z_norm} > {global_bound}", file=sys.stderr)
            continue
        
        # SUCCESS!
        t_end = time.perf_counter()
        all_attempt_times.append(t_end - t_start)
        
        print(f"[SIGN] Attempt {attempts}: ACCEPT - "
              f"||z||={z_norm} ≤ {global_bound}", file=sys.stderr)
        
        # Package signature: σ = (z, c) following Dilithium/FIPS 204 standard
        # NOTE: 'com' (w) is NOT included - verifier reconstructs it via w' = A·z - c·t
        # This prevents forgery: attacker cannot pick arbitrary (w, z, c)
        # because c MUST satisfy c = H(w' || message)
        signature = {
            "scheme": "threshold-gaussian",
            "q": q,
            "N": N,
            "K": K,
            "L": L,
            "z": _serialize_poly_vec(z_total),
            "c": base64.b64encode(c_poly.to_bytes()).decode(),  # c_poly is already in coeff domain
            "participants": participant_uids,
            "norm": z_norm,
            "bound": global_bound,
        }
        
        metadata = {
            "attempts": attempts,
            "total_time": sum(all_attempt_times),
            "avg_attempt_time": sum(all_attempt_times) / len(all_attempt_times),
            "final_norm": z_norm,
            "bound": global_bound,
            "norm_ratio": z_norm / global_bound,
        }
        
        return signature, metadata
    
    # Max attempts exceeded
    print(f"[SIGN] ERROR: Max attempts ({MAX_ATTEMPTS}) exceeded", file=sys.stderr)
    return None, None


# ============================================================================
# THRESHOLD VERIFICATION
# ============================================================================

def verify_threshold_gaussian(message: bytes, signature, pk) -> tuple:
    """
    Verify threshold signature using Fiat-Shamir transform.
    
    SECURITY FIX: Check Hash(w') == c instead of comparing w' to stored commitment.
    This prevents forgery where attacker picks arbitrary (z, c) and computes fake w.
    
    Verification steps (Fiat-Shamir protocol):
    1. Check norm bound: ||z|| ≤ t·B
    2. Reconstruct commitment: w' = A·z - c·t
    3. Recompute challenge: c' = H(w' || message)
    4. Verify challenge consistency: c' == c (CRITICAL)
    
    Args:
        message: original message
        signature: signature dict with (z, c) - NO 'com' field
        pk: public key dict
        
    Returns:
        (is_valid, verify_time)
    """
    t0 = time.perf_counter()
    
    q = pk["q"]
    N = pk["N"]
    K = pk["K"]
    L = pk["L"]
    
    # Deserialize signature components
    z_vec = _deserialize_poly_vec(signature["z"], q, N)
    c_bytes = base64.b64decode(signature["c"])
    c_poly_from_sig = Poly.from_bytes(c_bytes, q, N)
    
    # Check 1: Norm bound ||z|| ≤ t·B
    t_signers = len(signature["participants"])
    verify_bound = t_signers * B_BOUND
    
    z_norm = norm_infinity(z_vec)
    if z_norm > verify_bound:
        print(f"[VERIFY] REJECT - norm check: {z_norm} > {verify_bound}",
              file=sys.stderr)
        t1 = time.perf_counter()
        return False, (t1 - t0)
    
    # Deserialize public key
    rho = base64.b64decode(pk["rho"])
    A = expand_a(rho, K, L, q, N)
    t_vec = _deserialize_poly_vec(pk["t"], q, N)
    
    # Check 2: Reconstruct commitment w' = A·z - c·t
    # Mathematical proof:
    # During signing: z = Σy_i + c·s (via Lagrange interpolation)
    # So: A·z = A·Σy_i + A·c·s = A·Σy_i + c·(A·s) = A·Σy_i + c·t
    # Therefore: A·z - c·t = A·Σy_i = w (original commitment)
    
    Az = _matvec_mul(A, z_vec)
    
    c_ntt = c_poly_from_sig.to_ntt()
    ct = [t_vec[k].to_ntt().mul(c_ntt).from_ntt() for k in range(K)]
    
    w_prime = [Az[k].sub(ct[k]) for k in range(K)]
    
    # Check 3: Verify Fiat-Shamir challenge consistency (CRITICAL SECURITY CHECK)
    # Recompute: c' = H(w' || message)
    # The challenge MUST be derived from the reconstructed commitment
    # This prevents forgery: attacker cannot pick arbitrary (z, c) because
    # c must satisfy the hash equation c = H(A·z - c·t || message)
    
    w_prime_bytes = b"".join(p.to_bytes() for p in w_prime)
    c_computed = _hash_to_challenge_poly(message, w_prime_bytes, tau=49, q=q, N=N)
    
    # Compare challenge polynomials coefficient-wise
    import numpy as np
    c_computed_coeffs = c_computed.coeffs  # Already in coeff domain
    c_sig_coeffs = c_poly_from_sig.coeffs  # Deserialized in coeff domain
    
    if not np.array_equal(c_computed_coeffs, c_sig_coeffs):
        print(f"[VERIFY] REJECT - Fiat-Shamir check failed: Hash(w') ≠ c",
              file=sys.stderr)
        print(f"[VERIFY]   c_computed[:5] = {c_computed_coeffs[:5]}", file=sys.stderr)
        print(f"[VERIFY]   c_from_sig[:5] = {c_sig_coeffs[:5]}", file=sys.stderr)
        t1 = time.perf_counter()
        return False, (t1 - t0)
    
    # All checks passed
    print(f"[VERIFY] ACCEPT - ||z||={z_norm} ≤ {verify_bound}, Hash(w')=c ✓", 
          file=sys.stderr)
    t1 = time.perf_counter()
    return True, (t1 - t0)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    from .trusted_dealer import trusted_dealer_setup
    
    print("\n[TEST] Threshold Signing with Gaussian Noise")
    print("=" * 60)
    
    # Setup
    print("\n1. Setup 3-of-5 scheme:")
    shares, pk = trusted_dealer_setup(
        n_parties=5,
        threshold=3,
        K=1,
        L=1,
        seed=b"test_sign_123" + b"\x00" * 19
    )
    print(f"   ✓ Generated {len(shares)} shares")
    
    # Sign
    print("\n2. Sign with first 3 participants:")
    signing_shares = shares[:3]  # UIDs 1, 2, 3
    
    message = b"Test message for threshold Gaussian signing"
    sig, meta = sign_threshold_gaussian(message, signing_shares, pk)
    
    if sig is None:
        print("   ✗ Signing failed (max attempts exceeded)")
    else:
        print(f"   ✓ Signature generated successfully")
        print(f"   - Attempts: {meta['attempts']}")
        print(f"   - Total time: {meta['total_time']:.4f}s")
        print(f"   - Final norm: {meta['final_norm']}")
        print(f"   - Norm ratio: {meta['norm_ratio']:.3f}")
    
    # Verify
    if sig is not None:
        print("\n3. Verify signature:")
        valid, vtime = verify_threshold_gaussian(message, sig, pk)
        print(f"   - Valid: {valid}")
        print(f"   - Verify time: {vtime:.6f}s")
    
    print("\n" + "=" * 60)
    print("✓ Threshold signing test completed")
