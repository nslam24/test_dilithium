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
    Threshold signing following TLBSS paper protocol.
    
    CRITICAL DIFFERENCES from Dilithium:
    - Signature format: σ = (com, z, r)  [TLBSS includes commitment!]
    - Challenge: c = H₀(com, μ, pk)  [NOT H(w, μ) like Dilithium]
    - Verification: Open_ck(com, r, w) = 1  [Requires commitment opening]
    
    ROUND 1 - COMMITMENT:
    (a) Each signer i samples y_i ← D_σ^{l+k} (Gaussian noise)
    (b) Computes w_i = A·y_i  (using ORIGINAL y_i, NOT weighted!)
    (c) Samples randomness r_i and sends com_i = Commit_ck(w_i, r_i)
    
    ROUND 2 - CHALLENGE:
    - Aggregate commitments: com = Σ com_i  (homomorphic addition)
    - Compute challenge: c = H₀(com, μ, pk)  [Paper Eq, cite: 333]
    
    ROUND 3 - RESPONSE:
    (d) Compute weighted noise: ȳ_i = y_i · l_i^{-1} mod q
    (e) Compute partial signature (to send): z_i = c·x_i + ȳ_i
        - x_i: Shamir share
        - ȳ_i: weighted noise
    (f) Compute check vector (for rejection): z'_i = c·s_i + y_i
        - s_i: original secret component  
        - y_i: original noise (NOT weighted!)
    (g) Rejection sampling on z'_i:
        - Hard bound: ||z'_i|| < B  [cite: 334]
        - Probabilistic: min(1, D_s(z'_i) / (M·D_{cs_i,s}(z'_i)))  [cite: 336]
        - If reject => RESTART
    (h) If accept, send (z_i, r_i)
    
    AGGREGATION:
    (i) Combiner verifies Hash(z_i, r_i) == g''_i
    (j) Reconstruct via Lagrange: z = Σ(z_i · l_i)  [multiply by Lagrange!]
    (k) Aggregate opening: r = Σ r_i
    (l) Recover w: w = A·z - c·t
    (m) Verify: ||z|| ≤ t·B and Open_ck(com, r, w) == 1  [cite: 346]
    (n) Output σ = (com, z, r)  [TLBSS signature format]
    
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
        # ROUND 1: COMMITMENT PHASE (TLBSS Protocol)
        # ====================================================================
        
        y_list = []        # Original Gaussian noise: y_i ← D_σ^{l+k}
        w_list = []        # Commitments: w_i = A·y_i
        r_list = []        # Commitment randomness: r_i
        
        for share in shares_subset:
            uid = share["uid"]
            
            # (a) Sample Gaussian noise y_i from discrete distribution D_σ
            y_i = gaussian_sample_vector(L, q, N, SIGMA)
            
            # (b) Compute w_i = A·y_i using ORIGINAL y_i (NOT weighted!)
            # This is critical: weighting happens later in Round 3
            w_i = _matvec_mul(A, y_i)
            
            # (c) Sample commitment randomness r_i
            # In full protocol: r_i is random bytes for Commit_ck(w_i, r_i)
            # For simplicity: r_i = random 32-byte string
            r_i = os.urandom(32)
            
            y_list.append(y_i)
            w_list.append(w_i)
            r_list.append(r_i)
        
        # ====================================================================
        # ROUND 2: CHALLENGE GENERATION (TLBSS Protocol)
        # ====================================================================
        
        # Aggregate commitments: w = Σ w_i = Σ A·y_i = A·Σy_i
        w_total = vec_zeros(K, q, N)
        for w_i in w_list:
            w_total = vec_add(w_total, w_i)
        
        # Aggregate randomness: r = Σ r_i (for commitment opening)
        r_total = b"".join(r_list)
        
        # Compute commitment: com = Commit_ck(w, r)
        # In paper: com_i = Commit_ck(w_i, r_i), then com = Σ com_i (homomorphic)
        # For simplicity: com = Hash(w || r)
        w_bytes = b"".join(p.to_bytes() for p in w_total)
        com = hashlib.sha3_256(w_bytes + r_total).digest()
        
        # CRITICAL: Challenge c = H₀(com, μ, pk)  [TLBSS Eq, cite: 333]
        # This is DIFFERENT from Dilithium: c = H(w, μ)
        pk_bytes = rho  # Use public seed as pk representation
        challenge_input = com + message + pk_bytes
        
        c_poly = _hash_to_challenge_poly(
            challenge_input,
            b"",  # No additional w_bytes (already in com)
            tau=49,
            q=q,
            N=N
        )
        
        # ====================================================================
        # ROUND 3: RESPONSE PHASE (CORRECTED PROTOCOL)
        # ====================================================================
        
        z_list = []  # Partial signatures to send: z_i = c·x_i + ȳ_i
        all_accepted = True
        
        for idx, share in enumerate(shares_subset):
            uid = share["uid"]
            l_i = lagrange_coeffs[uid]
            y_i = y_list[idx]
            
            # Reconstruct shares
            # x_i: Shamir share (LARGE, used for signing z_i = c·x_i + ȳ_i)
            # s_i: Original SMALL secret (used for rejection z'_i = c·s_i + y_i)
            x_i = [Poly(share["s1_share"][l], q, N) for l in range(L)]
            s_i = [Poly(share["s1_original"][l], q, N) for l in range(L)]  # CRITICAL FIX!
            
            # (d) Compute weighted noise: ȳ_i = y_i · l_i^{-1} mod q
            # Need modular inverse of Lagrange coefficient
            try:
                l_i_inv = pow(int(l_i), -1, q)  # Modular inverse
            except ValueError:
                print(f"[ERROR] Lagrange coeff {l_i} not invertible mod {q}", 
                      file=sys.stderr)
                all_accepted = False
                break
            
            y_bar_i = [y_i[l].scalar_mul(l_i_inv) for l in range(L)]
            
            # (e) Compute partial signature (TO SEND): z_i = c·x_i + ȳ_i
            c_ntt = c_poly.to_ntt()
            c_times_x_i = [
                x_i[l].to_ntt().mul(c_ntt).from_ntt()
                for l in range(L)
            ]
            
            z_i = [c_times_x_i[l].add(y_bar_i[l]) for l in range(L)]
            
            # (f) Compute check vector (FOR REJECTION): z'_i = c·s_i + y_i
            # CRITICAL: Use ORIGINAL s_i and y_i (NOT weighted!)
            c_times_s_i = [
                s_i[l].to_ntt().mul(c_ntt).from_ntt()
                for l in range(L)
            ]
            
            z_prime_i = [c_times_s_i[l].add(y_i[l]) for l in range(L)]
            
            # (g) Rejection sampling on z'_i (NOT z_i!)
            accept = rejection_sample_check(
                z_prime_i,
                y_i,
                c_times_s_i,
                bound=B_BOUND
            )
            
            if not accept:
                all_accepted = False
                break  # RESTART
            
            # (h) If accepted, store z_i (the one to send, not z'_i!)
            z_list.append(z_i)
        
        # If any participant rejected, restart
        if not all_accepted:
            t_end = time.perf_counter()
            all_attempt_times.append(t_end - t_start)
            continue  # Go to next attempt
        
        # ====================================================================
        # AGGREGATION (CORRECTED WITH LAGRANGE)
        # ====================================================================
        
        # (j) Reconstruct signature via Lagrange interpolation:
        # z = Σ(z_i · l_i)
        # 
        # Why multiply by l_i again?
        # - In Round 3, we sent z_i = c·x_i + ȳ_i where ȳ_i = y_i · l_i^{-1}
        # - So: z_i = c·x_i + y_i·l_i^{-1}
        # - Multiply by l_i: z_i·l_i = c·x_i·l_i + y_i
        # - Sum: Σ(z_i·l_i) = Σ(c·x_i·l_i + y_i) = c·Σ(x_i·l_i) + Σy_i
        # - By Lagrange: Σ(x_i·l_i) = s (reconstructed secret)
        # - Result: z = c·s + Σy_i (standard signature form!)
        
        z_total = vec_zeros(L, q, N)
        for idx, z_i in enumerate(z_list):
            uid = shares_subset[idx]["uid"]
            l_i = lagrange_coeffs[uid]
            
            # Multiply z_i by Lagrange coefficient l_i
            z_i_times_l_i = [z_i[l].scalar_mul(int(l_i) % q) for l in range(L)]
            z_total = vec_add(z_total, z_i_times_l_i)
        
        # (m) Global rejection check: ||z|| ≤ t·B
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
        
        # Package signature: σ = (com, z, r) following TLBSS paper
        # CRITICAL: TLBSS includes commitment com (different from Dilithium!)
        # Verification requires: Open_ck(com, r, w) = 1 where w = A·z - c·t
        # Note: c is NOT included (verifier recomputes c = H₀(com, μ, pk))
        signature = {
            "scheme": "threshold-gaussian-tlbss",
            "q": q,
            "N": N,
            "K": K,
            "L": L,
            "com": base64.b64encode(com).decode(),  # TLBSS commitment
            "z": _serialize_poly_vec(z_total),
            "r": base64.b64encode(r_total).decode(),  # Opening randomness
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
    Verify threshold signature following TLBSS paper protocol.
    
    TLBSS Verification (DIFFERENT from Dilithium):
    - Input: σ = (com, z, r), message μ, public key pk
    - Challenge derived from COMMITMENT: c = H₀(com, μ, pk)
    - Commitment opening: Open_ck(com, r, w) where w = A·z - c·t
    
    Verification steps [cite: 346]:
    1. Parse signature: (com, z, r)
    2. Recompute challenge: c = H₀(com, μ, pk)  [from commitment!]
    3. Check norm bound: ||z|| ≤ t·B
    4. Reconstruct w: w = A·z - c·t
    5. Verify commitment opening: Open_ck(com, r, w) = 1  [CRITICAL]
    
    Args:
        message: original message μ
        signature: signature dict σ = (com, z, r)  [TLBSS format]
        pk: public key dict
        
    Returns:
        (is_valid, verify_time)
    """
    t0 = time.perf_counter()
    
    q = pk["q"]
    N = pk["N"]
    K = pk["K"]
    L = pk["L"]
    
    # Step 1: Parse signature σ = (com, z, r)
    com = base64.b64decode(signature["com"])
    z_vec = _deserialize_poly_vec(signature["z"], q, N)
    r = base64.b64decode(signature["r"])
    
    # Deserialize public key
    rho = base64.b64decode(pk["rho"])
    A = expand_a(rho, K, L, q, N)
    t_vec = _deserialize_poly_vec(pk["t"], q, N)
    pk_bytes = rho
    
    # Step 2: Recompute challenge c = H₀(com, μ, pk)  [TLBSS Protocol]
    # CRITICAL: Challenge depends on COMMITMENT (not w directly)
    # This binds the challenge to the commitment without revealing w
    challenge_input = com + message + pk_bytes
    c_computed = _hash_to_challenge_poly(
        challenge_input,
        b"",
        tau=49,
        q=q,
        N=N
    )
    
    # Step 3: Check norm bound ||z|| ≤ t·B
    t_signers = len(signature["participants"])
    verify_bound = t_signers * B_BOUND
    
    z_norm = norm_infinity(z_vec)
    if z_norm > verify_bound:
        print(f"[VERIFY] REJECT - norm check: ||z||={z_norm} > {verify_bound}",
              file=sys.stderr)
        t1 = time.perf_counter()
        return False, (t1 - t0)
    
    # Step 4: Reconstruct w = A·z - c·t
    # Mathematical proof:
    # During signing: z = Σy_i + c·s (via Lagrange interpolation)
    # So: A·z = A·Σy_i + A·c·s = A·Σy_i + c·(A·s) = A·Σy_i + c·t
    # Therefore: A·z - c·t = A·Σy_i = w (original commitment)
    
    Az = _matvec_mul(A, z_vec)
    
    c_ntt = c_computed.to_ntt()
    ct = [t_vec[k].to_ntt().mul(c_ntt).from_ntt() for k in range(K)]
    
    w_reconstructed = [Az[k].sub(ct[k]) for k in range(K)]
    
    # Step 5: Verify commitment opening Open_ck(com, r, w) = 1  [TLBSS cite: 346]
    # Check: com == Commit_ck(w, r) = Hash(w || r)
    # This ensures:
    # - Signer committed to w before seeing challenge c
    # - Cannot modify w after challenge (binding property)
    # - w hides the noise y_i (hiding property)
    w_bytes = b"".join(p.to_bytes() for p in w_reconstructed)
    com_check = hashlib.sha3_256(w_bytes + r).digest()
    
    if com != com_check:
        print(f"[VERIFY] REJECT - Commitment opening failed: Open_ck(com, r, w) ≠ 1",
              file=sys.stderr)
        print(f"[VERIFY]   Expected: {com[:8].hex()}...", file=sys.stderr)
        print(f"[VERIFY]   Got:      {com_check[:8].hex()}...", file=sys.stderr)
        t1 = time.perf_counter()
        return False, (t1 - t0)
    
    # All checks passed
    print(f"[VERIFY] ACCEPT - ||z||={z_norm} ≤ {verify_bound}, Open_ck(com,r,w)=1 ✓", 
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
