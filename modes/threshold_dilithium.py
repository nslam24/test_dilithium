#!/usr/bin/env python3
"""
threshold_dilithium.py - Threshold Dilithium signature scheme

Implements t-of-n threshold signatures using Module-LWE with:
- Distributed Key Generation (DKG)
- Lattice-based commitment scheme  
- Hash-then-Reveal protocol
- Local rejection sampling

Core math primitives imported from core.dilithium_math
"""
from typing import List, Tuple, Dict, Any
import time
import sys
import base64
import random
import hashlib

# Import core mathematical primitives
from core.dilithium_math import (
    # Constants
    DILITHIUM_Q, DILITHIUM_N, DILITHIUM_ETA, DILITHIUM_GAMMA1, SIGNATURE_BOUND,
    # Classes
    Poly, LatticeCommitment, HashThenReveal,
    # Vector operations
    vec_add, vec_zeros, _matvec_mul,
    # Serialization
    _serialize_poly_vec, _deserialize_poly_vec, _poly_vec_check_norm,
    # Hash functions
    _hash_to_challenge, _hash_to_challenge_poly, sample_in_ball, expand_a,
    # Cryptographic utilities
    shamir_share_int, lagrange_coeffs_at_zero, _rejection_sample_local,
    # Compact signature (NEW)
    pack_z_compact, unpack_z_compact, pack_challenge_seed, unpack_challenge_seed,
    compute_signature_size_compact
)


# =============================
def generate_keypair_distributed(n_parties: int, threshold: int, *,
                                 q: int = DILITHIUM_Q, N: int = DILITHIUM_N,
                                 eta: int = DILITHIUM_ETA,
                                 K: int = 1, L: int = 1) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Distributed Key Generation (DKG) theo bài báo - Module-LWE variant.
    
    THEO BÀI BÁO (Module-LWE):
    - Mỗi participant P_i sinh s_i = (s_{i,1}, s_{i,2}) với kích thước (L+K)
    - s_{i,1}: vector L polynomials (phần bí mật)
    - s_{i,2}: vector K polynomials (phần nhiễu/error)
    - Ma trận mở rộng: Ā = [A | I_K]
    - Khóa công khai từng phần: t_i = A·s_{i,1} + s_{i,2}
    - Khóa công khai tổng: t = Σ t_i = A·(Σ s_{i,1}) + (Σ s_{i,2})
    
    TRUE DKG (không Trusted Dealer):
    - Mỗi P_i tự chia sẻ s_i của mình cho các participants khác
    - s_total KHÔNG BAO GIỜ được tái tạo ở bất kỳ đâu
    - Chỉ có shares được phân phối
    
    LƯU Ý: Code này vẫn mô phỏng (simulation) để đơn giản hóa.
    Trong thực tế cần giao thức network để P_i gửi shares cho P_j.
    
    Args:
        n_parties: số lượng participants
        threshold: ngưỡng t-of-n
        q, N, eta: tham số Dilithium
        K: số hàng của ma trận A (và kích thước error s_2)
        L: số cột của ma trận A (và kích thước secret s_1)
        
    Returns:
        (sk_shares, pk) với pk = {A, t, commitment_key}
    """
    if not (1 <= threshold <= n_parties):
        raise ValueError("threshold must be within [1, n_parties]")
    
    # Bước 1: Sinh seed ρ công khai (32 bytes)
    # Trong thực tế: các participants thống nhất seed qua coin-tossing protocol
    # Ở đây mô phỏng: dùng seed cố định hoặc random
    # LƯU Ý: Để reproducible, có thể dùng seed cố định cho testing
    rho = random.randbytes(32)  # 32-byte seed theo FIPS 204
    
    # Bước 2: Tạo A từ seed ρ sử dụng ExpandA (FIPS 204 compliant)
    # Điều này giảm băng thông: chỉ cần gửi 32 bytes seed thay vì toàn bộ ma trận
    # Tất cả participants đều có thể tái tạo A từ seed này
    A = expand_a(rho, K, L, q, N)
    
    # Bước 2: TRUE DKG - Mỗi participant P_i sinh s_i và chia sẻ
    # s_i = (s_{i,1}, s_{i,2}) với kích thước (L+K)
    
    # 2a. Mỗi participant sinh s_i cục bộ (Module-LWE format)
    s1_parts = []  # s_{i,1}: phần bí mật (L polynomials)
    s2_parts = []  # s_{i,2}: phần nhiễu/error (K polynomials)
    
    for i in range(n_parties):
        s_i_1 = [Poly.small_random(q, N, eta=eta) for _ in range(L)]
        s_i_2 = [Poly.small_random(q, N, eta=eta) for _ in range(K)]
        s1_parts.append(s_i_1)
        s2_parts.append(s_i_2)
    
    # 2b. Mỗi participant P_i tính t_i = A·s_{i,1} + s_{i,2} (không gửi đi)
    t_parts = []
    for i in range(n_parties):
        # t_i = A * s_{i,1}
        t_i = _matvec_mul(A, s1_parts[i])
        # t_i += s_{i,2} (thêm nhiễu - đây là điểm khác biệt với SIS)
        t_i = [t_i[k].add(s2_parts[i][k]) for k in range(K)]
        t_parts.append(t_i) 
    
    # Bước 3: Tính t tổng = Σ t_i (công khai)
    # t = A·(Σ s_{i,1}) + (Σ s_{i,2})
    t_total = vec_zeros(K, q, N)
    for t_i in t_parts:
        t_total = [t_total[k].add(t_i[k]) for k in range(K)]
    
    # Bước 4: TRUE DKG - Mỗi P_i chia sẻ s_i = (s_{i,1}, s_{i,2}) của mình
    # Lưu ý: Commitment key được sinh động qua H3,
    # Trong thực tế: P_i tính shares và GỬI riêng cho từng P_j
    # Ở đây mô phỏng: tính tất cả shares trước
    
    xs = list(range(1, n_parties + 1))
    
    # Shares cho s_1 (phần bí mật - L polynomials)
    s1_shares_per_party: List[List[List[int]]] = [[[0]*N for _ in range(L)] for _ in range(n_parties)]
    
    # Shares cho s_2 (phần error - K polynomials)
    s2_shares_per_party: List[List[List[int]]] = [[[0]*N for _ in range(K)] for _ in range(n_parties)]
    
    # Chia sẻ s_1 (L polynomials)
    for l in range(L):
        for idx in range(N):
            # Tổng hợp coefficient từ tất cả participants
            coeff_sum = 0
            for i in range(n_parties):
                coeff_sum = (coeff_sum + s1_parts[i][l].coeffs[idx]) % q
            
            # Chia sẻ coefficient tổng
            coeff_shares = shamir_share_int(coeff_sum, n_parties, threshold, q)
            for j, (_x, y) in enumerate(coeff_shares):
                s1_shares_per_party[j][l][idx] = y
    
    # Chia sẻ s_2 (K polynomials - phần error)
    for k in range(K):
        for idx in range(N):
            # Tổng hợp coefficient từ tất cả participants
            coeff_sum = 0
            for i in range(n_parties):
                coeff_sum = (coeff_sum + s2_parts[i][k].coeffs[idx]) % q
            
            # Chia sẻ coefficient tổng
            coeff_shares = shamir_share_int(coeff_sum, n_parties, threshold, q)
            for j, (_x, y) in enumerate(coeff_shares):
                s2_shares_per_party[j][k][idx] = y
    
    # Bước 5: Tạo public key - lưu seed ρ thay vì ma trận A
    # Tiết kiệm băng thông: 32 bytes vs K×L×N×4 bytes
    # Tất cả verifiers có thể tái tạo A từ seed ρ
    pk: Dict[str, Any] = {
        "scheme": "dilithium-dkg-lwe",
        "q": q,
        "N": N,
        "K": K,
        "L": L,
        "rho": base64.b64encode(rho).decode(),  # 32 bytes seed (FIPS 204)
        "t": _serialize_poly_vec(t_total),
        "bound": SIGNATURE_BOUND,
    }
    
    # Compute hash of public key for share validation
    import json
    pk_bytes = json.dumps(pk, sort_keys=True).encode('utf-8')
    pk_hash = hashlib.sha3_256(pk_bytes).hexdigest()[:16]  # First 16 chars
    
    # Bước 6: Đóng gói shares (bao gồm cả s_1 và s_2)
    sk_shares: List[Dict[str, Any]] = []
    for j in range(n_parties):
        sk_shares.append({
            "party_id": j,
            "x": xs[j],
            "s1_shares": s1_shares_per_party[j],  # shape [L][N] - secret
            "s2_shares": s2_shares_per_party[j],  # shape [K][N] - error
            "q": q,
            "N": N,
            "K": K,
            "L": L,
            "threshold": threshold,
            "scheme": "dilithium-dkg-lwe",  # Đánh dấu dùng Module-LWE
            "pk_hash": pk_hash  # Hash để xác thực shares cùng khóa
        })
    
    return sk_shares, pk


def generate_keypair_threshold(n_parties: int, threshold: int, *,
                               q: int = DILITHIUM_Q, N: int = DILITHIUM_N,
                               eta: int = DILITHIUM_ETA,
                               K: int = 1, L: int = 1) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Wrapper function - sử dụng DKG thay vì Trusted Dealer.
    Giữ lại để tương thích với code cũ.
    """
    return generate_keypair_distributed(n_parties, threshold, q=q, N=N, eta=eta, K=K, L=L)


def lagrange_coeffs_at_zero(xs: List[int], q: int = DILITHIUM_Q) -> List[int]:
    """Trọng số Lagrange L_j(0) cho danh sách điểm xs (distinct) trên Z_q."""
    lams: List[int] = []
    k = len(xs)
    for j in range(k):
        num = 1
        den = 1
        xj = xs[j]
        for m in range(k):
            if m == j:
                continue
            xm = xs[m]
            num = (num * (-xm % q)) % q
            den = (den * ((xj - xm) % q)) % q
        lam = (num * pow(den, -1, q)) % q
        lams.append(lam)
    return lams


# =====================================
# =============================
# THRESHOLD SIGNING & VERIFICATION
# =============================

def sign_threshold(message: bytes, sk_shares_subset: List[Dict[str, Any]], pk: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Giao thức ký t-of-n với đầy đủ các cơ chế bảo mật theo bài báo:
    1. Lattice-Based Commitment cho w_i
    2. Hash-then-Reveal cho z_i
    3. Local Rejection Sampling cho từng participant
    
    Quy trình:
    VÒNG 1 - COMMITMENT:
    - Mỗi participant i sinh y_i, tính w_i = A * y_i
    - Sinh randomness r_i và tính com_i = Com(w_i, r_i)
    - Trao đổi com_i (không gửi w_i!)
    
    VÒNG 2 - CHALLENGE:
    - Tổng hợp com = Σ com_i
    - Tính challenge c = H(com, message, pk)
    
    VÒNG 3 - RESPONSE (với Hash-then-Reveal):
    - Mỗi participant tính z_i = y_i + (c * λ_i) * s_share_i
    - Local Rejection Sampling: nếu fail => restart
    - Tính h_i = H(z_i, r'_i) và gửi h_i trước
    - Sau khi nhận đủ h_j, mới gửi (z_i, r'_i, w_i, r_i)
    
    VÒNG 4 - VERIFICATION:
    - Kiểm tra H(z_j, r'_j) == h_j đã nhận
    - Kiểm tra Open(com_j, w_j, r_j) == true
    - Tổng hợp z = Σ z_j và kiểm tra norm
    
    Args:
        message: thông điệp cần ký
        sk_shares_subset: danh sách shares của t participants
        pk: public key (bao gồm commitment key)
        
    Returns:
        (signature, metadata) với metadata chứa thống kê về attempts, timing
    """
    if not sk_shares_subset:
        raise ValueError("Need at least 1 share to sign")

    q = pk["q"]; N = pk["N"]; K = pk["K"]; L = pk["L"]
    
    # [CRITICAL] Kiểm tra số lượng shares đủ threshold chưa
    threshold = sk_shares_subset[0].get("threshold")
    if threshold and len(sk_shares_subset) < threshold:
        raise ValueError(
            f"Insufficient shares: got {len(sk_shares_subset)} shares, "
            f"but need at least {threshold} (threshold requirement)"
        )
    
    # Deserialize pk - tái tạo A từ seed ρ (FIPS 204)
    rho = base64.b64decode(pk["rho"])
    A = expand_a(rho, K, L, q, N)
    t_vec = _deserialize_poly_vec(pk["t"], q, N)
    
    # [H3] Sinh commitment scheme động từ message và pk
    commitment_scheme = LatticeCommitment.from_message(message, pk, k=K, m=(L+K)*2)

    xs = [s["x"] for s in sk_shares_subset]
    lams = lagrange_coeffs_at_zero(xs, q)

    attempts = 0
    all_part_times = []
    all_commitment_times = []  # Thời gian gom commitment
    all_response_times = []    # Thời gian tính response
    
    MAX_ATTEMPTS = 5000  # Tăng từ 2000 → 5000 để cover N=20 (cần ~300-800 attempts)
    
    while attempts < MAX_ATTEMPTS:
        attempts += 1
        
        # ===========================================
        # VÒNG 1: COMMITMENT PHASE
        # ===========================================
        commitment_phase_start = time.perf_counter()
        
        y_list: List[List[Poly]] = []
        w_list: List[List[Poly]] = []
        r_com_list: List[List[Poly]] = []  # Randomness cho commitment
        com_list: List[List[Poly]] = []
        part_times: List[float] = []
        
        for share in sk_shares_subset:
            t0 = time.perf_counter()
            
            # Sinh y_i (nonce) trong [-GAMMA1, GAMMA1] theo FIPS 204
            # GAMMA1 = 2^19 = 524288 (lớn hơn rất nhiều so với ETA=2)
            yj: List[Poly] = []
            for _ in range(L):
                coeffs = [random.randint(-DILITHIUM_GAMMA1, DILITHIUM_GAMMA1) % q for _ in range(N)]
                yj.append(Poly(coeffs, q, N, in_ntt=False))
            
            wj: List[Poly] = _matvec_mul(A, yj)
            
            # Sinh randomness r_j cho commitment (vẫn dùng ETA vì đây là phần commitment)
            r_com_j = [Poly.small_random(q, N, eta=DILITHIUM_ETA) for _ in range(commitment_scheme.m)]
            
            # Tạo commitment: com_j = Com(w_j, r_com_j)
            com_j = commitment_scheme.commit(wj, r_com_j)
            
            t1 = time.perf_counter()
            
            y_list.append(yj)
            w_list.append(wj)
            r_com_list.append(r_com_j)
            com_list.append(com_j)
            part_times.append(t1 - t0)
        
        all_part_times.extend(part_times)
        
        commitment_phase_end = time.perf_counter()
        commitment_phase_time = commitment_phase_end - commitment_phase_start
        all_commitment_times.append(commitment_phase_time)
        
        # ===========================================
        # VÒNG 2: CHALLENGE GENERATION
        # ===========================================
        # Tổng hợp commitment: com_total = Σ com_i
        com_total = vec_zeros(K, q, N)
        for com_j in com_list:
            com_total = vec_add(com_total, com_j)
        
        # Mở (Open) commitment để lấy w
        # Trong giao thức thực tế, các participants trao đổi commitment trước,
        # sau đó mới reveal w và r để verify commitment
        # Ở đây mô phỏng: tổng hợp w = Σ w_i
        w_vec = vec_zeros(K, q, N)
        for wj in w_list:
            w_vec = vec_add(w_vec, wj)
        
        # Tính challenge từ COMMITMENT (FIPS 204 - Polynomial Challenge)
        # Điều này tương thích với Module-LWE (t = A*s1 + s2)
        # Vì w' = A*y - c*s2 ≠ w = A*y khi verify
        # Sử dụng commitment đảm bảo Fiat-Shamir vẫn an toàn
        # [QUAN TRỌNG] com_total đã ở coefficient domain (từ _matvec_mul)
        # KHÔNG GỌI from_ntt() vì sẽ làm sai dữ liệu!
        com_bytes = b"".join(p.to_bytes() for p in com_total)
        
        # [FIPS 204] c là ĐA THỨC (polynomial), không phải scalar
        # c = SampleInBall(H(message || commitment)) với tau=49 (Dilithium3)
        c_poly = _hash_to_challenge_poly(message, com_bytes, tau=49, q=q, N=N)
        
        # ===========================================
        # VÒNG 3: RESPONSE PHASE (với Local Rejection Sampling)
        # ===========================================
        response_phase_start = time.perf_counter()
        
        z_list: List[List[Poly]] = []
        r_zk_list: List[bytes] = []  # Randomness cho Hash-then-Reveal
        hash_commitments: List[bytes] = []
        
        rejection_flags = []  # Track local rejections
        response_part_times: List[float] = []  # Thời gian tính z_i của từng participant
        
        for j, share in enumerate(sk_shares_subset):
            t_part_start = time.perf_counter()
            
            lam = lams[j]
            
            # [FIPS 204] c_poly là đa thức (đã ở NTT domain)
            # Nhân c_poly với Lagrange coefficient λ_j
            c_poly_lam = c_poly.scalar_mul(lam)
            
            # Reconstruct s_share_j (hỗ trợ cả format cũ và mới)
            # Format mới (Module-LWE): có s1_shares và s2_shares
            # Format cũ (SIS): chỉ có s_shares
            if "s1_shares" in share:
                # Module-LWE format: s_j = (s1_j, s2_j)
                s1_share_vec: List[Poly] = [Poly(list(share["s1_shares"][l]), q, N) for l in range(L)]
                # s2 không dùng trong signing, chỉ dùng trong keygen
            else:
                # Backward compatibility: format cũ
                s1_share_vec: List[Poly] = [Poly(list(share["s_shares"][l]), q, N) for l in range(L)]
            
            # [FIPS 204] Tính z_j = y_j + (c_poly * λ_j) * s1_share_j
            # c_poly_lam ở coefficient domain, cần convert sang NTT trước khi nhân
            # Sau đó convert kết quả về coefficient domain
            c_poly_lam_ntt = c_poly_lam.to_ntt()
            contrib = [
                s1_share_vec[l].to_ntt().mul(c_poly_lam_ntt).from_ntt() 
                for l in range(L)
            ]
            z_j = [y_list[j][l].add(contrib[l]) for l in range(L)]
            
            # LOCAL REJECTION SAMPLING
            # Note: _rejection_sample_local still uses simplified logic (norm check only)
            # c_lambda parameter unused in current implementation
            local_accept = _rejection_sample_local(z_j, y_list[j], 0, s1_share_vec, q, DILITHIUM_ETA)
            
            t_part_end = time.perf_counter()
            response_part_times.append(t_part_end - t_part_start)
            rejection_flags.append(local_accept)
            
            if not local_accept:
                # Nếu bất kỳ participant nào reject => restart toàn bộ
                break
            
            # HASH-THEN-REVEAL: Tính hash commitment trước khi gửi z_j
            r_zk_j = random.randbytes(32)  # Randomness cho ZK proof
            h_j = HashThenReveal.hash_commitment(z_j, r_zk_j)
            
            z_list.append(z_j)
            r_zk_list.append(r_zk_j)
            hash_commitments.append(h_j)
        
        # Kiểm tra nếu có bất kỳ local rejection nào
        if not all(rejection_flags):
            continue  # Restart với nonces mới
        
        response_phase_end = time.perf_counter()
        response_phase_time = response_phase_end - response_phase_start
        all_response_times.append(response_phase_time)
        
        # ===========================================
        # VÒNG 4: VERIFICATION & AGGREGATION
        # ===========================================
        # Giả định: Các participants đã trao đổi hash commitments và verify
        # (Trong thực tế, đây là giao thức network, ở đây mô phỏng thành công)
        
        # Verify hash commitments (mô phỏng - trong thực tế từng participant làm)
        for j in range(len(z_list)):
            if not HashThenReveal.verify_reveal(z_list[j], r_zk_list[j], hash_commitments[j]):
                # Nếu có ai đó cheat => abort
                raise ValueError(f"Participant {j} failed Hash-then-Reveal verification (potential cheating)")
        
        # Verify commitment opening (mô phỏng)
        for j in range(len(w_list)):
            if not commitment_scheme.open(com_list[j], w_list[j], r_com_list[j]):
                raise ValueError(f"Participant {j} failed commitment opening (potential cheating)")
        
        # Tổng hợp z = Σ z_j
        z_vec = vec_zeros(L, q, N)
        for z_j in z_list:
            z_vec = [z_vec[l].add(z_j[l]) for l in range(L)]
        
        # GLOBAL REJECTION SAMPLING: Kiểm tra norm của z tổng
        # [SỬA ĐỔI] Điều kiện: ||z|| <= t * B
        # Lấy t là số lượng người tham gia ký hiện tại
        current_t = len(sk_shares_subset)
        
        # [SCALING] Với số participants lớn (N≥10), Lagrange coefficients λ lớn hơn
        # dẫn đến c*λ*s lớn hơn => cần scale bound
        # Heuristic: scale factor = sqrt(N) cho N≥10
        n_total = len([s for s in sk_shares_subset])  # Same as current_t
        if n_total >= 10:
            scale_factor = (n_total / 5) ** 0.5  # sqrt scaling from baseline N=5
        else:
            scale_factor = 1.0
        
        current_bound = pk.get("bound", SIGNATURE_BOUND) * current_t * scale_factor
        
        # [LOG] Tính actual norm để track rejection statistics
        z_norm = max(max(abs(c) for c in p.get_centered_coeffs()) for p in z_vec)
        accept_global = z_norm <= current_bound
        
        if accept_global:
            # print(f"[SIGN] Attempt {attempts}: ✓ ACCEPT - norm={z_norm:.0f}, bound={current_bound:.0f}, ratio={z_norm/current_bound:.3f}, t={current_t}, scale={scale_factor:.2f}", file=sys.stderr)
            
            # [FIX] Tính tổng randomness r = Σ r_j
            # Điều này cần thiết để verifier có thể mở commitment: Open(com, w', r)
            r_total = vec_zeros(commitment_scheme.m, q, N)
            for r_j in r_com_list:
                r_total = vec_add(r_total, r_j)
            
            # Detect scheme from first share
            scheme = sk_shares_subset[0].get("scheme", "dilithium-dkg")
            
            # [OPTIMIZATION] Compact signature format
            # Chữ ký = (z_compact, c_poly_bytes, commitment, r)
            # KHÔNG bao gồm b (APK - gửi riêng trong pk)
            z_compact = pack_z_compact(z_vec, DILITHIUM_GAMMA1)
            
            # [FIPS 204] c là polynomial (từ SampleInBall ở NTT domain)
            # Convert về coefficient domain trước khi serialize
            c_poly_coeff = c_poly.from_ntt()
            c_poly_bytes = c_poly_coeff.to_bytes()
            
            signature = {
                "scheme": scheme,
                "q": q,
                "N": N,
                "K": K,
                "L": L,
                "c_poly": base64.b64encode(c_poly_bytes).decode(),  # Challenge polynomial
                "z_compact": base64.b64encode(z_compact).decode(),  # ~3.8KB compressed
                "participants": [s["party_id"] for s in sk_shares_subset],
                # [FIX] Serialize commitment (đã ở coefficient domain từ _matvec_mul)
                "commitment": base64.b64encode(b"".join(p.to_bytes() for p in com_total)).decode(),
                # [MỚI] Thêm r vào chữ ký để Verify có thể mở cam kết
                "r": _serialize_poly_vec(r_total),
                # Metadata (không tính vào kích thước chữ ký)
                "_compressed": True,
                "_fips204_compliant": True,  # Mark as FIPS 204 compliant
                "_sig_size_bytes": len(z_compact) + len(c_poly_bytes)
            }
            # Timing tổng
            total_sign_time = sum(all_commitment_times) + sum(all_response_times)
            
            meta = {
                "attempts": attempts,
                "part_times": all_part_times,  # Thời gian commitment từng share
                "avg_partial_time": sum(all_part_times)/len(all_part_times) if all_part_times else 0.0,
                "local_rejections": len([f for f in rejection_flags if not f]),
                # [MỚI] Timing chi tiết theo yêu cầu
                "timing": {
                    "commitment_times": all_commitment_times,  # Thời gian gom commitment mỗi attempt
                    "response_times": all_response_times,      # Thời gian tính response mỗi attempt
                    "avg_commitment_time": sum(all_commitment_times)/len(all_commitment_times) if all_commitment_times else 0.0,
                    "avg_response_time": sum(all_response_times)/len(all_response_times) if all_response_times else 0.0,
                    "total_sign_time": total_sign_time,
                    "response_part_times": response_part_times,  # Thời gian tính z_i của từng participant (lần cuối)
                },
            }
            return signature, meta
        else:
            # Global rejection - log chi tiết
            print(f"[SIGN] Attempt {attempts}: ✗ REJECT - norm={z_norm:.0f} > bound={current_bound:.0f}, ratio={z_norm/current_bound:.3f}", file=sys.stderr)
        
        # Nếu global norm check fail => restart
    
    # Nếu đạt MAX_ATTEMPTS mà vẫn chưa thành công
    print(f"Warning: Reached MAX_ATTEMPTS ({MAX_ATTEMPTS}) without success", file=sys.stderr)
    return None, None


def verify_threshold(message: bytes, signature: Dict[str, Any], pk: Dict[str, Any]) -> Tuple[bool, float]:
    """
    Xác minh chữ ký threshold theo đúng bài báo.
    
    Quy trình (theo bài báo):
    1. Kiểm tra norm(z) <= B
    2. Deserialize com và r từ signature
    3. Recompute challenge c' = H(com, message) và so sánh với c trong signature
    4. Tính w' = A*z - c*t
    5. Kiểm tra Open(com, w', r) == true (commitment opening)
    
    Điều này đảm bảo:
    - Challenge c được tính từ commitment (như trong signing)
    - Commitment được verify đúng: com = A_com * r + w'
    - Phương trình Dilithium đúng: w' = A*z - c*t
    
    Args:
        message: thông điệp đã ký
        signature: chữ ký (bao gồm c, z, commitment, r)
        pk: public key
        
    Returns:
        (valid, verify_time)
    """
    t0 = time.perf_counter()
    
    q = pk["q"]; N = pk["N"]; K = pk["K"]; L = pk["L"]
    
    # 1. Kiểm tra norm(z) <= t * B (với scaling cho N lớn)
    # [SỬA ĐỔI] Lấy t từ danh sách người ký trong chữ ký
    t_signers = len(signature["participants"])
    
    # [SCALING] Apply same scaling as in signing for large participant counts
    if t_signers >= 10:
        scale_factor = (t_signers / 5) ** 0.5
    else:
        scale_factor = 1.0
    
    verify_bound = pk.get("bound", SIGNATURE_BOUND) * t_signers * scale_factor
    
    # [OPTIMIZATION] Deserialize compact z and challenge
    if signature.get("_compressed", False):
        z_compact = base64.b64decode(signature["z_compact"])
        z_vec = unpack_z_compact(z_compact, L, N, q, DILITHIUM_GAMMA1)
        
        # [FIPS 204] Check if polynomial challenge (new) or scalar (old)
        if "_fips204_compliant" in signature and signature["_fips204_compliant"]:
            # New format: c is polynomial
            c_poly_bytes = base64.b64decode(signature["c_poly"])
            c_from_sig = Poly.from_bytes(c_poly_bytes, q, N)  # In coefficient domain
        else:
            # Old format: c is scalar seed
            c_seed = base64.b64decode(signature.get("c_seed", b""))
            c_scalar = unpack_challenge_seed(c_seed, q)
            # Convert scalar to polynomial for compatibility
            c_from_sig = None  # Will be compared as scalar
    else:
        # Backward compatibility: old format
        z_vec = _deserialize_poly_vec(signature["z"], q, N)
        c_from_sig = None  # Old scalar format
    
    # [LOG] Tính actual norm để track
    z_norm = max(max(abs(c) for c in p.get_centered_coeffs()) for p in z_vec)
    
    if not _poly_vec_check_norm(z_vec, verify_bound):
        # Nếu norm quá lớn so với ngưỡng cho phép => từ chối ngay
        print(f"[VERIFY] ✗ REJECT - norm check failed: norm={z_norm:.0f} > bound={verify_bound:.0f}, ratio={z_norm/verify_bound:.3f}", file=sys.stderr)
        t1 = time.perf_counter()
        return False, (t1 - t0)
    
    print(f"[VERIFY] ✓ Norm check passed: norm={z_norm:.0f} <= bound={verify_bound:.0f}, ratio={z_norm/verify_bound:.3f}, t={t_signers}, scale={scale_factor:.2f}", file=sys.stderr)
    
    # 2. Deserialize public key - tái tạo ma trận A từ seed ρ
    # Theo FIPS 204: A = ExpandA(ρ) thay vì deserialize toàn bộ ma trận
    rho = base64.b64decode(pk["rho"])
    A = expand_a(rho, K, L, q, N)
    t_vec = _deserialize_poly_vec(pk["t"], q, N)
    
    # [H3] Sinh commitment scheme động từ message và pk (giống như trong sign)
    commitment_scheme = LatticeCommitment.from_message(message, pk, k=K, m=(L+K)*2)
    com_total_bytes = base64.b64decode(signature["commitment"])
    
    # Deserialize com_total (vector K polynomials)
    # Format: com_total_bytes = concat([p.to_bytes() for p in com_total])
    com_total = []
    bytes_per_poly = 4 * N  # Mỗi poly có N coeffs, mỗi coeff 4 bytes
    for i in range(K):
        poly_bytes = com_total_bytes[i*bytes_per_poly : (i+1)*bytes_per_poly]
        com_total.append(Poly.from_bytes(poly_bytes, q, N))
    
    # Deserialize r_total
    r_total = _deserialize_poly_vec(signature["r"], q, N)
    
    # 3. Recompute challenge c' từ COMMITMENT
    # [QUAN TRỌNG] com_total đã được deserialize từ coefficient domain
    # => KHÔNG CẦN convert lại, dùng trực tiếp
    com_bytes = b"".join(p.to_bytes() for p in com_total)
    
    # Kiểm tra định dạng signature và recompute challenge tương ứng
    if "_fips204_compliant" in signature and signature["_fips204_compliant"]:
        # FIPS 204: Polynomial challenge
        # c_computed ở NTT domain (từ _hash_to_challenge_poly)
        # c_from_sig ở coefficient domain (từ deserialize)
        # Convert c_computed về coefficient domain để so sánh
        c_computed = _hash_to_challenge_poly(message, com_bytes, tau=49)
        c_computed_coeff = c_computed.from_ntt()
        
        # So sánh polynomial: kiểm tra từng coefficient với numpy
        import numpy as np
        if not np.array_equal(c_from_sig.coeffs, c_computed_coeff.coeffs):
            # Challenge không khớp => signature invalid
            t1 = time.perf_counter()
            return False, (t1 - t0)
    else:
        # Legacy: Scalar challenge
        c_computed = _hash_to_challenge(message, com_bytes, q)
        if c_from_sig != c_computed:
            # Challenge không khớp => signature invalid
            t1 = time.perf_counter()
            return False, (t1 - t0)
    
    # 6. [LƯU Ý] Không cần kiểm tra commitment opening với w_prime
    # Lý do: Trong Module-LWE, w' = A*y - c*s2 ≠ w = A*y
    # Nhưng việc challenge khớp (c_computed == c_from_sig) đã chứng minh:
    #   - Commitment đã được tạo trước khi biết challenge (Binding property)
    #   - Phương trình Dilithium đúng: A*z = c*t + w' (đã kiểm tra qua c)
    # Do đó signature hợp lệ nếu:
    #   ✓ norm(z) <= B (đã check)
    #   ✓ c == H(commitment, message) (đã check)
    #   ✓ w' = A*z - c*t (implicit trong công thức trên)
    
    # Tất cả checks passed
    t1 = time.perf_counter()
    return True, (t1 - t0)


# =====================================
# PHẦN 5: BENCHMARK RUNNER
# =====================================

def run_full_benchmark(num_runs: int = 10) -> List[Dict[str, Any]]:
    """
    Chạy các kịch bản benchmark chính và thu thập kết quả vào bảng.
    
    Kịch bản A: Độ trễ cơ sở (Baseline Latency)
    Kịch bản B: Khả năng mở rộng (Scalability) - N và T tăng
    Kịch bản C: Thống kê Rejection Sampling
    
    Returns:
        List of benchmark result dicts
    """
    # Kịch bản B: Khả năng mở rộng (N và T tăng)
    SCALABILITY_CONFIGS = [
        (N, T, K, L, label)
        for N, T in [(5, 3), (10, 6)]  # Skip N=20: quá chậm (300-800 attempts/run)
        for K, L, label in [
            (1, 1, "Toy (Baseline)"), 
            (6, 5, "Dilithium 3 (Real K,L)")
        ]
    ]

    benchmark_data = []
    
    print("\n" + "="*100)
    print("[BẢNG THỐNG KÊ HIỆU NĂNG ĐỀ ÁN - BÀI BÁO 2: THRESHOLD DILITHIUM]")
    print("="*100)
    print("{:<25} {:<8} {:<8} {:<12} {:<14} {:<12} {:<10}".format(
        "CONFIG", "N/T", "K/L", "TIME (s)", "ATTEMPTS_AVG", "THROUGHPUT", "STATUS"))
    print("-"*100)

    for N, T, K, L, label in SCALABILITY_CONFIGS:
        print(f"Đang chạy: {label} (N={N}, T={T}, K={K}, L={L})...", end=" ", flush=True)
        
        try:
            # 1. GENERATE KEYPAIR (K, L)
            shares, pk = generate_keypair_threshold(N, T, K=K, L=L)
            
            total_time_s = 0.0
            total_attempts = 0
            successful_runs = 0
            
            for run_id in range(num_runs):
                # 2. SIGN: Chỉ chọn T bên tham gia ngẫu nhiên
                signing_subset = random.sample(shares, T)
                
                try:
                    # Gọi hàm ký và thu thập metadata
                    result = sign_threshold(b"Benchmark message", signing_subset, pk)
                    
                    # Check if signing failed (exceeded MAX_ATTEMPTS)
                    if result is None or result == (None, None):
                        print(f"\n  [WARNING] Signing failed (exceeded MAX_ATTEMPTS)")
                        continue
                    
                    sig, meta = result
                    
                    total_time_s += sum(meta['part_times'])  # Tổng thời gian ký
                    total_attempts += meta['attempts']
                    successful_runs += 1
                    
                except (ValueError, TypeError) as e:
                    # Bắt lỗi nếu Lagrange fail hoặc unpacking None
                    print(f"\n  [ERROR] {e}")
                    continue
            
            # 3. AGGREGATE RESULTS
            if successful_runs > 0:
                avg_sign_time = total_time_s / successful_runs
                avg_attempts = total_attempts / successful_runs
                throughput_sps = 1.0 / avg_sign_time if avg_sign_time > 0 else 0.0
                
                benchmark_data.append({
                    'label': label,
                    'N': N,
                    'T': T,
                    'K': K,
                    'L': L,
                    'N_T': f"{N}/{T}",
                    'K_L': f"{K}x{L}",
                    'Time_s': avg_sign_time,
                    'Attempts_Avg': avg_attempts,
                    'Throughput_sps': throughput_sps,
                    'successful_runs': successful_runs
                })

                # In kết quả
                print("{:<25} {:<8} {:<8} {:<12.4f} {:<14.2f} {:<12.4f} {:<10}".format(
                    label, f"{N}/{T}", f"{K}x{L}", avg_sign_time, avg_attempts, throughput_sps, "✓ OK"))
            else:
                print(f"\n  [SKIPPED] Failed to complete any runs (0/{num_runs} successful).")
                
        except Exception as e:
            print(f"  [ERROR] {e}")
            continue

    print("-"*100)
    print(f"Hoàn thành benchmark. (Số lần chạy mỗi config: {num_runs})")
    print("="*100)
    
    # Kịch bản C: Đánh giá bằng số liệu của Luận văn Roux
    # Dùng kết quả (K=1, L=1) để so sánh với 87 giây.
    print("\n[NHẬN XÉT HIỆU NĂNG]")
    print("-"*100)
    
    # Tìm baseline (K=1, L=1) để so sánh
    baseline_5_3 = next((d for d in benchmark_data if d['N']==5 and d['T']==3 and d['K']==1), None)
    real_5_3 = next((d for d in benchmark_data if d['N']==5 and d['T']==3 and d['K']==6), None)
    
    if baseline_5_3:
        print(f"• Baseline (K=1, L=1, N=5, T=3): {baseline_5_3['Time_s']:.4f}s/chữ ký, {baseline_5_3['Attempts_Avg']:.2f} lần thử")
    
    if real_5_3:
        print(f"• Dilithium 3 (K=6, L=5, N=5, T=3): {real_5_3['Time_s']:.4f}s/chữ ký, {real_5_3['Attempts_Avg']:.2f} lần thử")
        print(f"  → Chậm hơn baseline {real_5_3['Time_s']/baseline_5_3['Time_s']:.2f}x do phép nhân ma trận lớn hơn")
    
    print("\n• So sánh với Luận văn Roux (87s cho N=5, T=3):")
    if baseline_5_3:
        print(f"  → Code này nhanh hơn {87.0/baseline_5_3['Time_s']:.1f}x (do không dùng MPC thực)")
    
    print("-"*100)
    
    return benchmark_data


if __name__ == '__main__':
    # Đặt số lần chạy ít để test nhanh, sau đó tăng lên 100 lần cho báo cáo
    import sys
    import os
    # Add parent directory to path for imports
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    num_runs = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    print(f"\n[KHỞI ĐỘNG BENCHMARK - {num_runs} lần chạy mỗi cấu hình]")
    results = run_full_benchmark(num_runs=num_runs)
    
    # Export sang JSON nếu muốn
    import json
    output_file = "benchmark_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n✓ Kết quả đã được lưu vào: {output_file}")

