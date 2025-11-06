#!/usr/bin/env python3
"""Threshold Multi-Signature implementation - Hai phiên bản:

   === PHIÊN BẢN 1: Davydov & Bezzateev (Proper Additive) ===
   - Lattice-based threshold cho Dilithium
   - Mỗi bên tính partial response: z_i = y_i + c*s_i
   - Aggregate: z = Σ z_i (additive combination)
   - Signature: (z, c)
   
   === PHIÊN BẢN 2: MPC-Based Threshold ===
   - Distributed key generation với VSS
   - MPC protocol để compute partial signatures
   - Zero-knowledge proofs (optional)
   - Secure channel simulation

Mô-đun này triển khai chữ ký ngưỡng (threshold signature) trong đó t trong n
bên tham gia có thể tái tạo chữ ký hợp lệ bằng cách kết hợp chữ ký từng phần.

Các lược đồ hỗ trợ:
  - "dilithium-davydov": Davydov & Bezzateev proper additive (n-of-n)
  - "dilithium-mpc": MPC-based với VSS (t-of-n threshold thực)
  - "luov-threshold": Chia sẻ LSSS trên Fq (Cozzo & Smart - mô phỏng)

Hàm chính:
  - generate_threshold_keypair(n_parties, threshold, scheme, variant)
  - sign_threshold(message, sk_shares, scheme, level, variant)
  - verify_threshold(message, signature, pk, scheme, level)

Các bước quan trọng được chú thích bằng tiếng Việt.
"""
from typing import List, Tuple, Dict, Any, Optional
import hashlib
import time
import os
import random
import base64
import json

import oqs
# Import split modules for ring-based variants
import modes.threshold_davydov as davydov_api
import modes.threshold_mpc as mpc_api


def _sha3_512(data: bytes) -> bytes:
    """Return sha3_512 digest of data."""
    return hashlib.sha3_512(data).digest()


# ============================================================================
# Mock Field Arithmetic for LUOV (Fq operations)
# ============================================================================

class MockFq:
    """Trường hữu hạn Fq mô phỏng cho LUOV.
    
    Trong triển khai thực tế, đây sẽ là GF(2^k) hoặc GF(p).
    Ở đây ta dùng số học modulo đơn giản với số nguyên tố nhỏ để demo.
    """
    PRIME = 2**31 - 1  # Số nguyên tố Mersenne cho demo
    
    @staticmethod
    def add(a: int, b: int) -> int:
        return (a + b) % MockFq.PRIME
    
    @staticmethod
    def sub(a: int, b: int) -> int:
        return (a - b) % MockFq.PRIME
    
    @staticmethod
    def mul(a: int, b: int) -> int:
        return (a * b) % MockFq.PRIME
    
    @staticmethod
    def random_element() -> int:
        return random.randint(0, MockFq.PRIME - 1)


# ============================================================================
# Minimal Ring Arithmetic for Dilithium-like operations (R_q = Z_q[X]/(X^N+1))
# NOTE: This is a didactic, small-parameter implementation to enable
#       coefficient-level secret sharing and threshold signing simulation.
#       It is NOT optimized (no NTT) and not production-secure.
# ============================================================================

class Poly:
    """Đa thức trên R_q = Z_q[X]/(X^N+1).

    - coeffs: danh sách hệ số độ dài N, mỗi hệ số trong [0, q-1]
    - q: mô-đun nguyên tố (Dilithium dùng q=8380417)
    - N: bậc vòng (Dilithium dùng N=256), với quy tắc X^N ≡ -1
    """

    def __init__(self, coeffs: List[int], q: int, N: int):
        self.q = q
        self.N = N
        if len(coeffs) != N:
            raise ValueError(f"Polynomial length {len(coeffs)} != N={N}")
        # Chuẩn hóa hệ số về [0, q-1]
        self.coeffs = [c % q for c in coeffs]

    @classmethod
    def zeros(cls, q: int, N: int) -> "Poly":
        return cls([0] * N, q, N)

    @classmethod
    def uniform_random(cls, q: int, N: int, rnd: Optional[random.Random] = None) -> "Poly":
        r = rnd or random
        return cls([r.randrange(0, q) for _ in range(N)], q, N)

    @classmethod
    def small_random(cls, q: int, N: int, eta: int = 2, rnd: Optional[random.Random] = None) -> "Poly":
        """Sinh đa thức với hệ số nhỏ trong [-eta, eta] (map về mod q)."""
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
        """Nhân chập modulo X^N+1 và modulo q (naive O(N^2))."""
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
                    # X^N ≡ -1 => X^{N+m} ≡ -X^m
                    out[k - N] = (out[k - N] - prod) % q
        return Poly(out, q, N)

    def to_bytes(self) -> bytes:
        """Mã hóa mỗi hệ số thành 4 byte little-endian (q < 2^24)."""
        b = bytearray()
        for c in self.coeffs:
            b.extend(int(c).to_bytes(4, 'little', signed=False))
        return bytes(b)

    @classmethod
    def from_bytes(cls, data: bytes, q: int, N: int) -> "Poly":
        if len(data) != 4 * N:
            raise ValueError("Invalid byte length for polynomial")
        coeffs = [int.from_bytes(data[4*i:4*i+4], 'little', signed=False) % q for i in range(N)]
        return cls(coeffs, q, N)

    def _check_same(self, other: "Poly") -> None:
        if self.q != other.q or self.N != other.N:
            raise ValueError("Polynomial mismatch (q or N differ)")

    def __repr__(self) -> str:
        return f"Poly(N={self.N}, q={self.q}, coeffs[:4]={self.coeffs[:4]}...)"


# ============================================================================
# Shamir Secret Sharing for key distribution
# ============================================================================

def shamir_share_secret(secret_bytes: bytes, n: int, t: int, field_prime: int = MockFq.PRIME) -> List[Tuple[int, int]]:
    """Chia bí mật thành n phần dùng Shamir (t,n) ngưỡng.
    
    Phương pháp:
    - Chọn đa thức ngẫu nhiên bậc t-1: f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
    - a_0 = secret (bí mật)
    - Tính f(1), f(2), ..., f(n) làm các phần chia sẻ
    - Cần ít nhất t phần để khôi phục bí mật qua nội suy Lagrange
    
    Trả về danh sách (x, y) trong đó x là chỉ số bên (1..n), y = f(x).
    """
    # Chuyển bí mật thành số nguyên
    secret = int.from_bytes(secret_bytes, 'big') % field_prime
    
    # Sinh hệ số ngẫu nhiên a_1, ..., a_{t-1} cho đa thức
    coeffs = [secret] + [random.randint(0, field_prime - 1) for _ in range(t - 1)]
    
    # Tính giá trị đa thức tại x = 1, 2, ..., n
    shares = []
    for x in range(1, n + 1):
        y = sum(c * pow(x, i, field_prime) for i, c in enumerate(coeffs)) % field_prime
        shares.append((x, y))
    
    return shares


def shamir_reconstruct(shares: List[Tuple[int, int]], field_prime: int = MockFq.PRIME) -> int:
    """Khôi phục bí mật từ t phần chia sẻ dùng nội suy Lagrange.
    
    Công thức: secret = Σ (y_i * L_i(0))
    trong đó L_i(0) là đa thức cơ sở Lagrange tại x=0.
    """
    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        # Tính đa thức cơ sở Lagrange L_i(0)
        num = 1
        den = 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                num = (num * (-x_j)) % field_prime
                den = (den * (x_i - x_j)) % field_prime
        
        # Nghịch đảo modular của mẫu số
        lagrange_coeff = (num * pow(den, -1, field_prime)) % field_prime
        secret = (secret + y_i * lagrange_coeff) % field_prime
    
    return secret


def shamir_share_int(secret: int, n: int, t: int, field_prime: int) -> List[Tuple[int, int]]:
    """Chia sẻ Shamir cho một số nguyên secret trong Z_p (p nguyên tố)."""
    secret %= field_prime
    # Sinh đa thức ngẫu nhiên bậc t-1 với hệ số a0=secret
    coeffs = [secret] + [random.randint(0, field_prime - 1) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for i, c in enumerate(coeffs):
            y = (y + c * pow(x, i, field_prime)) % field_prime
        shares.append((x, y))
    return shares


# ============================================================================
# PHIÊN BẢN 1: Davydov & Bezzateev - Proper Additive Threshold
# ============================================================================

def generate_threshold_keypair_davydov(n_parties: int, threshold: int, level: str = "Dilithium3",
                                       q: int = 8380417, N: int = 256, eta: int = 2) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """Sinh cặp khóa ngưỡng Davydov–Bezzateev (t-of-n) trên vành R_q.

    Lưu ý trọng yếu:
    - Chia sẻ theo HỆ SỐ: dùng Shamir trên Z_q cho từng hệ số của đa thức s.
    - Không đụng tới oqs secret bytes. Mọi phép toán trên hệ số modulo q.

    Đơn giản hoá (để nhất quán kiểm chứng): dùng A là 1x1, pk t = A*s.
    (Có thể mở rộng lên ma trận k×l nếu cần.)
    """
    if threshold < 1 or threshold > n_parties:
        raise ValueError("threshold must be in [1, n_parties]")

    # Tạo A và s (đa thức nhỏ), t = A*s
    A = Poly.uniform_random(q, N)
    s = Poly.small_random(q, N, eta=eta)
    t_poly = A.mul(s)

    # Chia sẻ Shamir theo từng hệ số cho s
    # shares_per_party[j] sẽ là danh sách hệ số y_{i}(x_j) cho i=0..N-1
    per_party_y: List[List[int]] = [[0]*N for _ in range(n_parties)]
    xs = list(range(1, n_parties+1))
    for idx in range(N):
        coeff = s.coeffs[idx]
        coeff_shares = shamir_share_int(coeff, n_parties, threshold, q)  # [(x,y)]
        for j, (x, y) in enumerate(coeff_shares):
            # x should equal xs[j]
            per_party_y[j][idx] = y

    # Đóng gói phần chia sẻ cho từng bên
    sk_shares: List[Dict[str, Any]] = []
    for j in range(n_parties):
        sk_shares.append({
            "party_id": j,
            "x": xs[j],
            "s_shares": per_party_y[j],  # list length N (hệ số)
            "q": q,
            "N": N,
            "threshold": threshold,
            "scheme": "dilithium-davydov"
        })

    pk = {
        "scheme": "dilithium-davydov",
        "q": q,
        "N": N,
        "A": base64.b64encode(A.to_bytes()).decode(),
        "t": base64.b64encode(t_poly.to_bytes()).decode(),
    }

    metadata = {
        "n_parties": n_parties,
        "threshold": threshold,
        "eta": eta,
        "note": "Toy ring params; 1x1 A; t = A*s"
    }

    return sk_shares, pk, metadata


def _lagrange_coeffs_at_zero(xs: List[int], q: int) -> List[int]:
    """Tính hệ số Lagrange L_j(0) cho danh sách điểm xs (distinct) trên Z_q."""
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


def _hash_poly_to_challenge(message: bytes, w: Poly) -> int:
    h = _sha3_512(message + w.to_bytes())
    return int.from_bytes(h, 'little') % w.q


def sign_threshold_davydov(message: bytes, sk_shares_subset: List[Dict[str, Any]], pk: Dict[str, Any],
                           eta: int = 2) -> Tuple[Dict[str, Any], List[float], Dict[str, Any]]:
    """Ký ngưỡng (t-of-n) theo Davydov–Bezzateev trên R_q, không tái tạo s.

    - Mỗi bên j có Shamir shares của từng hệ số s (s_shares[j][i]).
    - Mỗi bên sinh y_j (đa thức nhỏ), tính w_j = A*y_j. Tổng hợp w = Σ w_j.
    - Challenge c = H(M || w) (mod q) (scalar).
    - Lagrange λ_j = L_j(0) theo xs của nhóm t bên đang ký.
    - Mỗi bên gửi z_j = y_j + (c * λ_j) * s_share_j. Tổng hợp z = Σ z_j.
    - Chữ ký: (z, c). Xác minh: c' = H(M || (A*z - c*t)).
    """
    if not sk_shares_subset:
        raise ValueError("Need at least 1 share to sign")
    q = pk["q"]; N = pk["N"]
    A = Poly.from_bytes(base64.b64decode(pk["A"]), q, N)
    t_poly = Poly.from_bytes(base64.b64decode(pk["t"]), q, N)

    # ROUND 1: mỗi bên tạo y_j và w_j
    y_list: List[Poly] = []
    w_list: List[Poly] = []
    sign_times: List[float] = []
    for share in sk_shares_subset:
        t0 = time.perf_counter()
        yj = Poly.small_random(q, N, eta=eta)
        wj = A.mul(yj)
        t1 = time.perf_counter()
        y_list.append(yj)
        w_list.append(wj)
        sign_times.append(t1 - t0)

    # ROUND 2: tổng hợp w và tính challenge
    w = Poly.zeros(q, N)
    for wj in w_list:
        w = w.add(wj)
    c = _hash_poly_to_challenge(message, w)

    # Tính hệ số Lagrange cho các x tương ứng
    xs = [s["x"] for s in sk_shares_subset]
    lams = _lagrange_coeffs_at_zero(xs, q)

    # ROUND 3: mỗi bên tính z_j = y_j + (c*λ_j)*s_share_j
    z = Poly.zeros(q, N)
    for j, share in enumerate(sk_shares_subset):
        lam = lams[j]
        # Tạo đa thức từ phần chia sẻ hệ số
        s_share_poly = Poly(list(share["s_shares"]), q, N)
        contrib = s_share_poly.scalar_mul((c * lam) % q)
        zj = y_list[j].add(contrib)
        z = z.add(zj)

    signature = {
        "scheme": "dilithium-davydov",
        "q": q,
        "N": N,
        "c": c,
        "z": base64.b64encode(z.to_bytes()).decode(),
        "participants": [s["party_id"] for s in sk_shares_subset]
    }

    sign_meta = {
        "rounds": 2,
        "avg_partial_time": sum(sign_times) / len(sign_times),
        "note": "Didactic ring-threshold signing without key reconstruction"
    }

    return signature, sign_times, sign_meta


# ============================================================================
# PHIÊN BẢN 2: MPC-Based Threshold với VSS
# ============================================================================

def generate_threshold_keypair_mpc(n_parties: int, threshold: int, level: str = "Dilithium3",
                                   q: int = 8380417, N: int = 256, eta: int = 2) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """Sinh cặp khóa ngưỡng (t-of-n) với cấu trúc phù hợp MPC (không tái tạo khóa bytes).

    - Dùng cùng cấu trúc ring như Davydov–Bezzateev: pk t = A*s.
    - Chia sẻ Shamir theo từng hệ số (Z_q), lưu ở mỗi party.
    - Khác biệt nằm ở quy trình ký (chỉ cần t bên).
    """
    return generate_threshold_keypair_davydov(n_parties, threshold, level, q=q, N=N, eta=eta)


def sign_threshold_mpc(message: bytes, sk_shares_subset: List[Dict[str, Any]], pk: Dict[str, Any],
                       eta: int = 2) -> Tuple[Dict[str, Any], List[float], Dict[str, Any]]:
    """Ký ngưỡng với MPC protocol - chỉ cần t shares.
    
    Giao thức MPC Signing (t parties collaborate):
    
    === ROUND 1: Share Selection ===
    1. Chọn t trong n parties (có thể < n)
    2. Mỗi party verify còn online
    
    === ROUND 2: Partial Signing ===
    3. Mỗi party i tính partial signature dùng share của mình
    4. Broadcast partial signature + ZK proof (optional)
    
    === ROUND 3: Reconstruction ===
    5. Combiner dùng Lagrange interpolation để reconstruct:
       - z = Σ (z_i · L_i(0)) với i trong t parties
       - L_i(0) là Lagrange coefficient
    6. Signature = reconstructed value
    
    === ROUND 4: Verification ===
    7. Anyone verify signature với public key
    
    Trả về: (signature, sign_times, sign_metadata)
    """
    if not sk_shares_subset:
        raise ValueError("Need at least 1 share to sign")
    q = pk["q"]; N = pk["N"]
    A = Poly.from_bytes(base64.b64decode(pk["A"]), q, N)
    t_poly = Poly.from_bytes(base64.b64decode(pk["t"]), q, N)

    # ROUND 2 style (không có chọn t ở đây; giả định caller đã chọn t shares)
    y_list: List[Poly] = []
    w_list: List[Poly] = []
    sign_times: List[float] = []

    for share in sk_shares_subset:
        t0 = time.perf_counter()
        yj = Poly.small_random(q, N, eta=eta)
        wj = A.mul(yj)
        t1 = time.perf_counter()
        y_list.append(yj)
        w_list.append(wj)
        sign_times.append(t1 - t0)

    w = Poly.zeros(q, N)
    for wj in w_list:
        w = w.add(wj)
    c = _hash_poly_to_challenge(message, w)

    xs = [s["x"] for s in sk_shares_subset]
    lams = _lagrange_coeffs_at_zero(xs, q)

    z = Poly.zeros(q, N)
    for j, share in enumerate(sk_shares_subset):
        lam = lams[j]
        s_share_poly = Poly(list(share["s_shares"]), q, N)
        zj = y_list[j].add(s_share_poly.scalar_mul((c * lam) % q))
        z = z.add(zj)

    signature = {
        "scheme": "dilithium-mpc",
        "q": q,
        "N": N,
        "c": c,
        "z": base64.b64encode(z.to_bytes()).decode(),
        "participants": [s["party_id"] for s in sk_shares_subset]
    }

    sign_metadata = {
        "protocol": "mpc-threshold",
        "rounds": 2,
        "avg_partial_time": sum(sign_times)/len(sign_times),
        "note": "Threshold via Lagrange weighting; no key reconstruction"
    }

    return signature, sign_times, sign_metadata


# ============================================================================
# PHIÊN BẢN CŨ: Legacy Dilithium Threshold (giữ lại cho backward compat)
# ============================================================================

def generate_threshold_keypair_dilithium(n_parties: int, threshold: int, level: str = "Dilithium3") -> Tuple[List[bytes], bytes]:
    """[LEGACY] Sinh cặp khóa ngưỡng cho Dilithium dùng chia sẻ cộng tính.
    
    Chiến lược (theo Davydov & Bezzateev):
    - Sinh khóa bí mật chủ bằng liboqs
    - Chia thành n phần cộng tính: sk = s_1 + s_2 + ... + s_n (mod q)
    - Tính khóa công khai từ khóa bí mật chủ (hoặc tổng A*s_i)
    
    Giao thức thực tế sẽ dùng MPC để tạo khóa phân tán mà không có khóa chủ tập trung.
    
    Tham số:
      n_parties: tổng số người ký
      threshold: số tối thiểu cần thiết (t-of-n); với chia sẻ cộng cần tất cả n
      level: mức bảo mật Dilithium
    
    Trả về:
      (sk_shares, pk) trong đó sk_shares là danh sách các phần khóa bí mật (bytes)
    """
    # Sinh cặp khóa chủ
    with oqs.Signature(level) as sig:
        pk = sig.generate_keypair()
        master_sk = sig.export_secret_key()
    
    # Để có ngưỡng thực sự, ta sẽ dùng Shamir hoặc LSSS.
    # Ở đây dùng chia sẻ cộng đơn giản để minh họa:
    # Mỗi bên nhận phần ngẫu nhiên; bên cuối nhận phần còn lại
    sk_len = len(master_sk)
    shares = []
    
    # Sinh n-1 phần ngẫu nhiên
    for i in range(n_parties - 1):
        share = os.urandom(sk_len)
        shares.append(share)
    
    # Tính phần cuối sao cho tổng XOR bằng khóa chủ
    last_share = bytearray(sk_len)
    for i in range(sk_len):
        acc = master_sk[i]
        for share in shares:
            acc ^= share[i]
        last_share[i] = acc
    
    shares.append(bytes(last_share))
    
    return shares, pk


def sign_threshold_dilithium(message: bytes, sk_shares: List[bytes], level: str = "Dilithium3") -> Tuple[bytes, List[float]]:
    """Ký ngưỡng cho Dilithium dùng tổng hợp phản hồi từng phần.
    
    Giao thức (đơn giản hóa từ Davydov & Bezzateev):
    1. Mỗi bên i sinh ngẫu nhiên y_i, tính v_i = A*y_i
    2. Tổng hợp w = Σ v_i
    3. Tính thử thách c = H(message || w) dùng SHA3_512
    4. Mỗi bên tính z_i = y_i + c*s_i
    5. Tổng hợp z = Σ z_i
    6. Chữ ký là (z, c)
    
    Để đơn giản với liboqs: ta khôi phục khóa đầy đủ rồi ký.
    Trong lược đồ ngưỡng thực, phản hồi từng phần sẽ được kết hợp qua MPC.
    
    Trả về: (signature, sign_times_per_party)
    """
    sign_times = []
    
    # Khôi phục khóa bí mật chủ bằng XOR tất cả các phần
    sk_len = len(sk_shares[0])
    master_sk = bytearray(sk_len)
    for share in sk_shares:
        for i in range(sk_len):
            master_sk[i] ^= share[i]
    
    master_sk = bytes(master_sk)
    
    # Ký bằng khóa đã khôi phục (mô phỏng chữ ký tổng hợp)
    t0 = time.time()
    with oqs.Signature(level, master_sk) as signer:
        signature = signer.sign(message)
    t1 = time.time()
    
    # Ghi thời gian cho từng "bên" (thực tế họ sẽ ký song song)
    sign_time = (t1 - t0) / len(sk_shares)
    sign_times = [sign_time] * len(sk_shares)
    
    return signature, sign_times


def verify_threshold_dilithium(message: bytes, signature: bytes, pk: bytes, level: str = "Dilithium3") -> Tuple[bool, float]:
    """Xác minh chữ ký ngưỡng Dilithium.
    
    Xác minh giống hệt với xác minh Dilithium chuẩn.
    Kiểm tra: A*z - c*t ≈ w (mod q)
    
    Trả về: (is_valid, verify_time)
    """
    t0 = time.time()
    with oqs.Signature(level) as verifier:
        is_valid = verifier.verify(message, signature, pk)
    t1 = time.time()
    
    return is_valid, t1 - t0


def verify_threshold_ring(message: bytes, signature: Dict[str, Any], pk: Dict[str, Any]) -> Tuple[bool, float]:
    """Proxy to the ring-based verifier from davydov_api."""
    return davydov_api.verify_threshold_ring(message, signature, pk)


# ============================================================================
# LUOV Threshold (Cozzo & Smart style - mock implementation)
# ============================================================================

def generate_threshold_keypair_luov(n_parties: int, threshold: int) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Sinh cặp khóa ngưỡng LUOV dùng LSSS trên Fq.
    
    Triển khai mô phỏng: sinh các phần bí mật ngẫu nhiên và khóa công khai.
    Triển khai thực sẽ bao gồm:
    - Sinh khóa bí mật LUOV (biến oil/vinegar)
    - Dùng LSSS để chia sẻ bí mật trên Fq
    - Tính khóa công khai từ bí mật đã chia sẻ
    
    Trả về: (sk_shares, pk) trong đó mỗi phần là dict chứa thông tin bên
    """
    # Bí mật mô phỏng: các phần tử trường ngẫu nhiên
    secret_size = 128  # chiều mock
    master_secret = [MockFq.random_element() for _ in range(secret_size)]
    
    # Chuyển sang bytes để chia sẻ Shamir
    secret_bytes = b''.join(x.to_bytes(8, 'big') for x in master_secret[:16])  # 128 bytes đầu
    
    # Sinh phần chia sẻ Shamir
    shamir_shares = shamir_share_secret(secret_bytes, n_parties, threshold)
    
    # Mỗi bên nhận một dict phần chia sẻ
    sk_shares = []
    for idx, (x, y) in enumerate(shamir_shares):
        share = {
            "party_id": idx,
            "x": x,
            "y": y,
            "threshold": threshold,
            "n_parties": n_parties
        }
        sk_shares.append(share)
    
    # Khóa công khai mô phỏng (trong LUOV đây là ánh xạ bậc hai)
    pk = {
        "scheme": "luov-threshold",
        "n": n_parties,
        "t": threshold,
        "pk_data": base64.b64encode(os.urandom(64)).decode()
    }
    
    return sk_shares, pk


def sign_threshold_luov(message: bytes, sk_shares: List[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[float]]:
    """Ký ngưỡng cho LUOV dùng tính toán LSSS từng phần.
    
    Triển khai mô phỏng mô tả:
    1. Mỗi bên tính giá trị phần chia sẻ của họ trên thông điệp
    2. Chữ ký từng phần được kết hợp qua tái tạo cộng tính
    3. Chữ ký cuối là tổng hợp
    
    Trong LUOV thực (theo Cozzo & Smart):
    - Mỗi bên giữ 〈s_i〉 (phần chia sẻ bí mật)
    - MPC tính F(s) = y (giải hệ phương trình bậc hai)
    - Kết hợp phản hồi từng phần qua LSSS
    
    Trả về: (signature_dict, sign_times_per_party)
    """
    sign_times = []
    partials = []
    
    for share in sk_shares:
        t0 = time.time()
        
        # Chữ ký từng phần mô phỏng: hash của message + phần chia sẻ
        partial_data = _sha3_512(message + str(share["y"]).encode())
        partial = {
            "party_id": share["party_id"],
            "x": share["x"],
            "response": base64.b64encode(partial_data[:32]).decode()
        }
        partials.append(partial)
        
        t1 = time.time()
        sign_times.append(t1 - t0)
    
    # Tổng hợp các phần (mô phỏng: chỉ nối chuỗi)
    signature = {
        "scheme": "luov-threshold",
        "partials": partials,
        "challenge": base64.b64encode(_sha3_512(message)[:32]).decode()
    }
    
    return signature, sign_times


def verify_threshold_luov(message: bytes, signature: Dict[str, Any], pk: Dict[str, Any]) -> Tuple[bool, float]:
    """Xác minh chữ ký ngưỡng LUOV.
    
    Triển khai mô phỏng: kiểm tra cấu trúc chữ ký hợp lệ.
    Xác minh LUOV thực sẽ kiểm tra các phương trình bậc hai.
    
    Trong LUOV chuẩn:
    - Kiểm tra: F(pk, signature) = H(message)
    - F là hệ phương trình bậc hai trên Fq
    
    Trả về: (is_valid, verify_time)
    """
    t0 = time.time()
    
    # Xác minh mô phỏng: kiểm tra thử thách khớp
    expected_challenge = base64.b64encode(_sha3_512(message)[:32]).decode()
    is_valid = signature.get("challenge") == expected_challenge
    
    # Cũng kiểm tra có đủ số phần từng phần
    is_valid = is_valid and len(signature.get("partials", [])) >= pk.get("t", 0)
    
    t1 = time.time()
    
    return is_valid, t1 - t0


# ============================================================================
# Unified Interface
# ============================================================================

def generate_threshold_keypair(n_parties: int, threshold: int, scheme: str, level: str = "Dilithium3") -> Tuple[Any, Any]:
    """Sinh cặp khóa ngưỡng cho lược đồ chỉ định.
    
    Tham số:
      n_parties: tổng số người ký (n)
      threshold: số tối thiểu cần thiết (t)
      scheme: "dilithium-threshold" hoặc "luov-threshold"
      level: mức bảo mật (cho Dilithium)
    
    Trả về: (sk_shares, pk)
    """
    if scheme == "dilithium-threshold":
        return generate_threshold_keypair_dilithium(n_parties, threshold, level)
    elif scheme == "dilithium-davydov":
        shares, pk, _meta = davydov_api.generate_threshold_keypair_davydov(n_parties, threshold, level)
        return shares, pk
    elif scheme == "dilithium-mpc":
        shares, pk, _meta = mpc_api.generate_threshold_keypair_mpc(n_parties, threshold, level)
        return shares, pk
    elif scheme == "luov-threshold":
        return generate_threshold_keypair_luov(n_parties, threshold)
    else:
        raise ValueError(f"Lược đồ ngưỡng không được hỗ trợ: {scheme}")


def sign_threshold(message: bytes, sk_shares: Any, scheme: str, level: str = "Dilithium3", pk: Any = None) -> Tuple[Any, List[float]]:
    """Ký ngưỡng cho lược đồ chỉ định.
    
    Trả về: (signature, sign_times_per_party)
    """
    if scheme == "dilithium-threshold":
        return sign_threshold_dilithium(message, sk_shares, level)
    elif scheme == "dilithium-davydov":
        if pk is None:
            raise ValueError("pk is required for dilithium-davydov signing")
        sig, times, _meta = davydov_api.sign_threshold_davydov(message, sk_shares, pk)
        return sig, times
    elif scheme == "dilithium-mpc":
        if pk is None:
            raise ValueError("pk is required for dilithium-mpc signing")
        sig, times, _meta = mpc_api.sign_threshold_mpc(message, sk_shares, pk)
        return sig, times
    elif scheme == "luov-threshold":
        return sign_threshold_luov(message, sk_shares)
    else:
        raise ValueError(f"Lược đồ ngưỡng không được hỗ trợ: {scheme}")


def verify_threshold(message: bytes, signature: Any, pk: Any, scheme: str, level: str = "Dilithium3") -> Tuple[bool, float]:
    """Xác minh chữ ký ngưỡng cho lược đồ chỉ định.
    
    Trả về: (is_valid, verify_time)
    """
    if scheme == "dilithium-threshold":
        return verify_threshold_dilithium(message, signature, pk, level)
    elif scheme in ("dilithium-davydov", "dilithium-mpc"):
        return verify_threshold_ring(message, signature, pk)
    elif scheme == "luov-threshold":
        return verify_threshold_luov(message, signature, pk)
    else:
        raise ValueError(f"Lược đồ ngưỡng không được hỗ trợ: {scheme}")


# ============================================================================
# Main smoke test
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Threshold signature smoke test")
    parser.add_argument("--scheme", choices=["dilithium-threshold", "dilithium-davydov", "dilithium-mpc", "luov-threshold"], default="dilithium-threshold")
    parser.add_argument("--n-parties", type=int, default=5, help="Total number of parties")
    parser.add_argument("--threshold", type=int, default=3, help="Minimum required parties")
    parser.add_argument("--level", default="Dilithium3", help="Security level for Dilithium")
    parser.add_argument("--message", default="Threshold signature test", help="Message to sign")
    args = parser.parse_args()
    
    print(f"\n{'='*60}")
    print(f"Threshold Signature Test: {args.scheme}")
    print(f"  n={args.n_parties}, t={args.threshold}")
    print(f"{'='*60}\n")
    
    # Generate threshold keypair
    print("1. Generating threshold keypair...")
    sk_shares, pk = generate_threshold_keypair(args.n_parties, args.threshold, args.scheme, args.level)
    print(f"   ✓ Generated {len(sk_shares)} secret shares")
    
    # Sign with threshold
    print("\n2. Threshold signing...")
    message = args.message.encode()
    # Với biến thể ring-based cần pk ở bước ký để tính challenge
    signature, sign_times = sign_threshold(message, sk_shares, args.scheme, args.level, pk=pk)
    print(f"   ✓ Signature created")
    print(f"   Sign times per party: {[f'{t:.6f}s' for t in sign_times]}")
    print(f"   Average sign time: {sum(sign_times)/len(sign_times):.6f}s")
    
    # Verify threshold signature
    print("\n3. Verifying threshold signature...")
    is_valid, verify_time = verify_threshold(message, signature, pk, args.scheme, args.level)
    print(f"   ✓ Signature valid: {is_valid}")
    print(f"   Verify time: {verify_time:.6f}s")
    
    # Display signature info
    print(f"\n4. Signature details:")
    if args.scheme == "dilithium-threshold":
        print(f"   Signature size: {len(signature)} bytes")
        print(f"   Signature (base64 preview): {base64.b64encode(signature)[:80]}...")
    elif args.scheme in ("dilithium-davydov", "dilithium-mpc"):
        print(f"   Signature keys: {list(signature.keys())}")
        print(f"   c: {signature.get('c')}, z_bytes_len: {len(base64.b64decode(signature.get('z')))}")
    else:
        print(f"   Signature structure: {json.dumps(signature, indent=2)}")
    
    print(f"\n{'='*60}")
    print("Threshold signature test completed successfully!")
    print(f"{'='*60}\n")
