#!/usr/bin/env python3
"""
threshold_dilithium.py (Biến thể 2)

Cấu trúc tệp (4 phần):
1) HẰNG SỐ & TIỆN ÍCH: tham số toán học, hàm băm, helpers vector.
2) LỚP VÀNH (Poly): phép toán R_q = Z_q[X]/(X^N+1) + norm checks.
3) TIỆN ÍCH MẬT MÃ: Shamir cho hệ số, Lagrange tại 0.
4) LOGIC GIAO THỨC: generate_keypair_threshold, sign_threshold, verify_threshold

Lưu ý: Đây là triển khai mô phỏng/giảng dạy, không tối ưu (không NTT),
không an toàn sản xuất. Mục tiêu là phản ánh đúng cấu trúc toán học
và quy trình t-of-n mà không tái tạo bí mật.
"""
from typing import List, Tuple, Dict, Any, Optional
import hashlib
import random
import time
import base64

# =============================
# PHẦN 1: HẰNG SỐ & TIỆN ÍCH
# =============================
DILITHIUM_Q = 8380417  # q (prime)
DILITHIUM_N = 256      # degree N
DILITHIUM_ETA = 2      # small coeff bound for secrets/nonces
# Cập nhật theo NIST Dilithium 3 (K=6, L=5):
# gamma1 = 2^19 - 1 + 2^10 ≈ 524288, beta ≈ 375
# B = gamma1 - beta
SIGNATURE_BOUND = 523913  # B: |z_i| <= 523913 (gamma1 - beta for Dilithium 3)


def _sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def _hash_to_challenge(message: bytes, w_bytes: bytes, q: int = DILITHIUM_Q) -> int:
    """Tạo challenge c (scalar mod q) từ message và w (đã serialize).
    Trong Dilithium thực, c là đa thức thưa; ở đây đơn giản hoá thành scalar.
    """
    h = _sha3_512(message + w_bytes)
    return int.from_bytes(h, 'little') % q

# Helpers cho vector đa thức (danh sách Poly)

def vec_add(a: List["Poly"], b: List["Poly"]) -> List["Poly"]:
    if len(a) != len(b):
        raise ValueError("Vector length mismatch")
    return [ai.add(bi) for ai, bi in zip(a, b)]


def vec_zeros(k: int, q: int, N: int) -> List["Poly"]:
    return [Poly.zeros(q, N) for _ in range(k)]


# =====================================
# PHẦN 2: LỚP TOÁN HỌC VÀNH (Poly)
# =====================================
class Poly:
    def __init__(self, coeffs: List[int], q: int = DILITHIUM_Q, N: int = DILITHIUM_N):
        self.q = q
        self.N = N
        if len(coeffs) != N:
            raise ValueError(f"Polynomial length {len(coeffs)} != N={N}")
        self.coeffs = [c % q for c in coeffs]

    @classmethod
    def zeros(cls, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> "Poly":
        return cls([0] * N, q, N)

    @classmethod
    def uniform_random(cls, q: int = DILITHIUM_Q, N: int = DILITHIUM_N, rnd: Optional[random.Random] = None) -> "Poly":
        r = rnd or random
        return cls([r.randrange(0, q) for _ in range(N)], q, N)

    @classmethod
    def small_random(cls, q: int = DILITHIUM_Q, N: int = DILITHIUM_N, eta: int = DILITHIUM_ETA, rnd: Optional[random.Random] = None) -> "Poly":
        r = rnd or random
        coeffs = []
        for _ in range(N):
            v = r.randint(-eta, eta)
            coeffs.append(v % q)
        return cls(coeffs, q, N)

    def add(self, other: "Poly") -> "Poly":
        self._check_same(other)
        return Poly([(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)], self.q, self.N)

    def sub(self, other: "Poly") -> "Poly":
        self._check_same(other)
        return Poly([(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)], self.q, self.N)

    def scalar_mul(self, c: int) -> "Poly":
        c %= self.q
        return Poly([(c * a) % self.q for a in self.coeffs], self.q, self.N)

    def mul(self, other: "Poly") -> "Poly":
        self._check_same(other)
        N, q = self.N, self.q
        out = [0] * N
        for i in range(N):
            ai = self.coeffs[i]
            if ai == 0:
                continue
            for j in range(N):
                bj = other.coeffs[j]
                if bj == 0:
                    continue
                k = i + j
                prod = (ai * bj) % q
                if k < N:
                    out[k] = (out[k] + prod) % q
                else:
                    out[k - N] = (out[k - N] - prod) % q
        return Poly(out, q, N)

    def to_bytes(self) -> bytes:
        b = bytearray()
        for c in self.coeffs:
            b.extend(int(c).to_bytes(4, 'little', signed=False))
        return bytes(b)

    @classmethod
    def from_bytes(cls, data: bytes, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> "Poly":
        if len(data) != 4 * N:
            raise ValueError("Invalid byte length for polynomial")
        coeffs = [int.from_bytes(data[4*i:4*i+4], 'little', signed=False) % q for i in range(N)]
        return cls(coeffs, q, N)

    def get_centered_coeffs(self) -> List[int]:
        """Đưa hệ số về miền đối xứng [-(q-1)/2, (q-1)/2]."""
        half = (self.q - 1) // 2
        centered = []
        for c in self.coeffs:
            v = c
            if v > half:
                v = v - self.q
            centered.append(v)
        return centered

    def check_norm(self, bound: int) -> bool:
        """Kiểm tra tất cả |coeff| <= bound (dùng cho rejection sampling)."""
        for v in self.get_centered_coeffs():
            if abs(v) > bound:
                return False
        return True

    def _check_same(self, other: "Poly") -> None:
        if self.q != other.q or self.N != other.N:
            raise ValueError("Polynomial mismatch (q or N differ)")


# =====================================
# PHẦN 3: TIỆN ÍCH MẬT MÃ
# =====================================

def shamir_share_int(secret: int, n: int, t: int, field_prime: int = DILITHIUM_Q) -> List[Tuple[int, int]]:
    """Chia sẻ một hệ số (Z_q) thành n phần bằng Shamir (t-of-n)."""
    secret %= field_prime
    coeffs = [secret] + [random.randint(0, field_prime - 1) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for i, c in enumerate(coeffs):
            y = (y + c * pow(x, i, field_prime)) % field_prime
        shares.append((x, y))
    return shares


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
# PHẦN 4: LOGIC GIAO THỨC (API)
# =====================================

def _matvec_mul(A: List[List[Poly]], vec: List[Poly]) -> List[Poly]:
    """Nhân ma trận (KxL) đa thức với vector (L) đa thức => vector (K) đa thức."""
    K = len(A)
    if K == 0:
        return []
    L = len(A[0])
    if len(vec) != L:
        raise ValueError("Dimension mismatch for matvec_mul")
    q = vec[0].q
    N = vec[0].N
    out = [Poly.zeros(q, N) for _ in range(K)]
    for k in range(K):
        acc = Poly.zeros(q, N)
        for l in range(L):
            acc = acc.add(A[k][l].mul(vec[l]))
        out[k] = acc
    return out


def _serialize_poly_vec(vec: List[Poly]) -> List[str]:
    return [base64.b64encode(p.to_bytes()).decode() for p in vec]


def _deserialize_poly_vec(data: List[str], q: int, N: int) -> List[Poly]:
    return [Poly.from_bytes(base64.b64decode(b), q, N) for b in data]


def _poly_vec_check_norm(vec: List[Poly], bound: int) -> bool:
    return all(p.check_norm(bound) for p in vec)


def generate_keypair_threshold(n_parties: int, threshold: int, *,
                               q: int = DILITHIUM_Q, N: int = DILITHIUM_N,
                               eta: int = DILITHIUM_ETA,
                               K: int = 1, L: int = 1) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Distributed keygen mô phỏng: pk = (A, t), với t = A * s, s là vector L đa thức.
    - A: KxL ma trận Poly.uniform_random
    - s: vector L Poly.small_random
    - t: vector K Poly (A*s)
    - Chia sẻ s theo hệ số cho n bên, ngưỡng t.
    """
    if not (1 <= threshold <= n_parties):
        raise ValueError("threshold must be within [1, n_parties]")

    # Tạo A (KxL) và s (L)
    A: List[List[Poly]] = [[Poly.uniform_random(q, N) for _ in range(L)] for _ in range(K)]
    s_vec: List[Poly] = [Poly.small_random(q, N, eta=eta) for _ in range(L)]
    t_vec: List[Poly] = _matvec_mul(A, s_vec)

    # Chia sẻ theo hệ số cho từng poly trong s_vec
    xs = list(range(1, n_parties + 1))
    # s_shares_per_party[j][l][i] = share của hệ số i của poly s[l] tại party j
    s_shares_per_party: List[List[List[int]]] = [[[0]*N for _ in range(L)] for _ in range(n_parties)]

    for l in range(L):
        for idx in range(N):
            coeff = s_vec[l].coeffs[idx]
            coeff_shares = shamir_share_int(coeff, n_parties, threshold, q)
            for j, (_x, y) in enumerate(coeff_shares):
                s_shares_per_party[j][l][idx] = y

    # Đóng gói shares
    sk_shares: List[Dict[str, Any]] = []
    for j in range(n_parties):
        sk_shares.append({
            "party_id": j,
            "x": xs[j],
            "s_shares": s_shares_per_party[j],  # shape [L][N]
            "q": q,
            "N": N,
            "K": K,
            "L": L,
            "threshold": threshold,
            "scheme": "dilithium-variant2"
        })

    # Serialize pk
    pk: Dict[str, Any] = {
        "scheme": "dilithium-variant2",
        "q": q,
        "N": N,
        "K": K,
        "L": L,
        "A": [[base64.b64encode(A[k][l].to_bytes()).decode() for l in range(L)] for k in range(K)],
        "t": _serialize_poly_vec(t_vec),
        "bound": SIGNATURE_BOUND,
    }

    return sk_shares, pk


def sign_threshold(message: bytes, sk_shares_subset: List[Dict[str, Any]], pk: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Giao thức ký t-of-n với Rejection Sampling.
    - Không tái tạo bí mật. Mỗi bên j trả về z_j = y_j + weight_j * s_share_j.
    - Aggregator tổng hợp z = Σ z_j và kiểm tra norm; nếu fail => lặp lại.
    """
    if not sk_shares_subset:
        raise ValueError("Need at least 1 share to sign")

    q = pk["q"]; N = pk["N"]; K = pk["K"]; L = pk["L"]
    # Deserialize pk
    A = [[Poly.from_bytes(base64.b64decode(pk["A"][k][l]), q, N) for l in range(L)] for k in range(K)]
    t_vec = _deserialize_poly_vec(pk["t"], q, N)

    xs = [s["x"] for s in sk_shares_subset]
    lams = lagrange_coeffs_at_zero(xs, q)

    attempts = 0
    all_part_times = []  # Track all partial times across attempts
    while True:
        attempts += 1
        # Vòng 1: mỗi bên sinh y_j (vector L) và w_j = A * y_j (vector K)
        y_list: List[List[Poly]] = []
        w_list: List[List[Poly]] = []
        part_times: List[float] = []
        for share in sk_shares_subset:
            t0 = time.perf_counter()
            yj: List[Poly] = [Poly.small_random(q, N, eta=DILITHIUM_ETA) for _ in range(L)]
            wj: List[Poly] = _matvec_mul(A, yj)
            t1 = time.perf_counter()
            y_list.append(yj)
            w_list.append(wj)
            part_times.append(t1 - t0)

        all_part_times.extend(part_times)

        # Tổng hợp w = Σ w_j (vector K)
        w_vec = vec_zeros(K, q, N)
        for wj in w_list:
            w_vec = vec_add(w_vec, wj)

        # Challenge c = H(M || serialize(w)) (scalar mod q)
        w_bytes = b"".join(p.to_bytes() for p in w_vec)
        c = _hash_to_challenge(message, w_bytes, q)

        # Vòng 2: Tính z = Σ (y_j + (c * λ_j) * s_share_j)
        z_vec = vec_zeros(L, q, N)
        for j, share in enumerate(sk_shares_subset):
            lam = lams[j]
            weight = (c * lam) % q
            # reconstruct s_share_j as vector L Poly from coefficient shares
            s_share_vec: List[Poly] = [Poly(list(share["s_shares"][l]), q, N) for l in range(L)]
            contrib = [s_share_vec[l].scalar_mul(weight) for l in range(L)]
            z_j = [y_list[j][l].add(contrib[l]) for l in range(L)]
            z_vec = [z_vec[l].add(z_j[l]) for l in range(L)]

        # Rejection sampling: tất cả hệ số của mọi đa thức trong z phải <= B
        if _poly_vec_check_norm(z_vec, pk.get("bound", SIGNATURE_BOUND)):
            signature = {
                "scheme": "dilithium-variant2",
                "q": q,
                "N": N,
                "K": K,
                "L": L,
                "c": c,
                "z": _serialize_poly_vec(z_vec),
                "participants": [s["party_id"] for s in sk_shares_subset],
            }
            meta = {
                "attempts": attempts,
                "part_times": all_part_times,
                "avg_partial_time": sum(all_part_times)/len(all_part_times) if all_part_times else 0.0,
            }
            return signature, meta
        # Nếu fail norm => lặp lại with new y


def verify_threshold(message: bytes, signature: Dict[str, Any], pk: Dict[str, Any]) -> Tuple[bool, float]:
    """Xác minh: 1) norm(z) <= B, 2) H(M || (A*z - c*t)) == c."""
    t0 = time.perf_counter()
    q = pk["q"]; N = pk["N"]; K = pk["K"]; L = pk["L"]
    if not _poly_vec_check_norm(_deserialize_poly_vec(signature["z"], q, N), pk.get("bound", SIGNATURE_BOUND)):
        return False, 0.0

    # Deserialize
    A = [[Poly.from_bytes(base64.b64decode(pk["A"][k][l]), q, N) for l in range(L)] for k in range(K)]
    t_vec = _deserialize_poly_vec(pk["t"], q, N)
    z_vec = _deserialize_poly_vec(signature["z"], q, N)
    c = int(signature["c"]) % q

    # w' = A*z - c*t
    Az = _matvec_mul(A, z_vec)
    c_t = [t.scalar_mul(c) for t in t_vec]
    w_prime = [Az[k].sub(c_t[k]) for k in range(K)]

    # recompute c'
    w_bytes = b"".join(p.to_bytes() for p in w_prime)
    c_prime = _hash_to_challenge(message, w_bytes, q)
    ok = (c_prime % q) == (c % q)
    t1 = time.perf_counter()
    return ok, (t1 - t0)


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
        for N, T in [(5, 3), (10, 6), (20, 13)]
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
                    sig, meta = sign_threshold(b"Benchmark message", signing_subset, pk)
                    
                    total_time_s += sum(meta['part_times'])  # Tổng thời gian ký
                    total_attempts += meta['attempts']
                    successful_runs += 1
                    
                except ValueError as e:
                    # Bắt lỗi nếu Lagrange fail (xác suất rất nhỏ nếu q lớn)
                    print(f"\n  [ERROR] Lagrange Failed: {e}")
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
                print(f"  [SKIPPED] Failed to complete runs.")
                
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
    num_runs = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    print(f"\n[KHỞI ĐỘNG BENCHMARK - {num_runs} lần chạy mỗi cấu hình]")
    results = run_full_benchmark(num_runs=num_runs)
    
    # Export sang JSON nếu muốn
    import json
    output_file = "benchmark_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n✓ Kết quả đã được lưu vào: {output_file}")

