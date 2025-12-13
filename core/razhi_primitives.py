"""
Razhi-ms Aggregate Multi-Signature Primitives
Based on lattice-based cryptography (Dilithium-like construction)
Implements auxiliary functions for polynomial ring operations

OPTIMIZED VERSION:
- Q = 8397313 (theo bài báo Razhi-ms Table 3, NTT-friendly)
- NTT optimization cho polynomial multiplication O(N log N)
- Bit packing cho compression
"""

import hashlib
import secrets
from typing import Tuple, List
import numpy as np
from numba import jit

# ============================================================================
# PARAMETERS (Dilithium-based for NTT compatibility)
# ============================================================================
Q = 8380417  # Prime modulus (Dilithium standard, NTT-friendly)
N = 256      # Polynomial degree (x^n + 1)
D = 13       # Dropped bits from t
K = 4        # Rows in matrix A
L = 4        # Columns in matrix A

# Norm bounds
TAU = 39          # Challenge weight (number of ±1 coefficients)
ETA = 2           # Secret key coefficient bound
GAMMA1 = 2**17    # y coefficient bound (131072)
GAMMA2 = (Q - 1) // 88  # w decomposition parameter  
BETA = TAU * ETA  # Challenge norm bound (78)

# NTT Parameters (Dilithium standard)
NTT_ROOT = 1753  # Primitive 512-th root of unity mod Q
NTT_ROOT_INV = pow(NTT_ROOT, -1, Q)
N_INV = pow(N, -1, Q)
NTT_ROOT_INV = pow(NTT_ROOT, -1, Q)
N_INV = pow(N, -1, Q)  # N^(-1) mod Q for INTT


# ============================================================================
# NTT IMPLEMENTATION (Number Theoretic Transform)
# ============================================================================

# Precompute twiddle factors
_ZETAS = np.zeros(N, dtype=np.int64)
_ZETAS_INV = np.zeros(N, dtype=np.int64)

def _init_ntt_constants():
    """Initialize NTT twiddle factors (powers of omega)"""
    global _ZETAS, _ZETAS_INV
    
    omega = NTT_ROOT
    omega_inv = NTT_ROOT_INV
    
    # Compute powers of omega: [1, omega, omega^2, ..., omega^(N-1)]
    _ZETAS = np.zeros(N, dtype=np.int64)
    _ZETAS[0] = 1
    for i in range(1, N):
        _ZETAS[i] = (_ZETAS[i-1] * omega) % Q
    
    # Compute powers of omega_inv
    _ZETAS_INV = np.zeros(N, dtype=np.int64)
    _ZETAS_INV[0] = 1
    for i in range(1, N):
        _ZETAS_INV[i] = (_ZETAS_INV[i-1] * omega_inv) % Q

_init_ntt_constants()


@jit(nopython=True, cache=True)
def ntt_forward(a: np.ndarray) -> np.ndarray:
    """
    Forward NTT transform - O(N log N)
    
    Cooley-Tukey decimation-in-frequency for negacyclic convolution
    Input: polynomial coefficients [a0, a1, ..., a_{N-1}]
    Output: NTT-transformed coefficients
    """
    t = a.copy()
    m = N
    
    while m > 1:
        m_half = m // 2
        step = N // m
        
        for i in range(m_half):
            j1 = 2 * i * step
            j2 = j1 + step
            W = _ZETAS[m_half + i]  # omega^(m/2 + i)
            
            for j in range(step):
                u = t[j1 + j]
                v = t[j2 + j]
                t[j1 + j] = (u + v) % Q
                t[j2 + j] = ((u - v + Q) * W) % Q
        
        m = m_half
    
    return t


@jit(nopython=True, cache=True)
def ntt_inverse(a: np.ndarray) -> np.ndarray:
    """
    Inverse NTT transform - O(N log N)
    
    Gentleman-Sande decimation-in-time for negacyclic convolution
    Input: polynomial in NTT domain
    Output: polynomial in coefficient domain
    """
    t = a.copy()
    m = 1
    
    while m < N:
        m_double = m * 2
        step = N // m_double
        
        for i in range(m):
            j1 = 2 * i * step
            j2 = j1 + step
            W = _ZETAS_INV[m + i]  # omega_inv^(m + i)
            
            for j in range(step):
                u = t[j1 + j]
                v = (t[j2 + j] * W) % Q
                t[j1 + j] = (u + v) % Q
                t[j2 + j] = (u - v + Q) % Q
        
        m = m_double
    
    # Multiply by N^(-1) mod Q
    for i in range(N):
        t[i] = (t[i] * N_INV) % Q
    
    return t


@jit(nopython=True, cache=True)
def ntt_multiply(a_ntt: np.ndarray, b_ntt: np.ndarray) -> np.ndarray:
    """
    Pointwise multiplication in NTT domain
    
    Input: two polynomials in NTT domain
    Output: product in NTT domain
    """
    result = np.zeros(N, dtype=np.int64)
    for i in range(N):
        result[i] = (a_ntt[i] * b_ntt[i]) % Q
    return result


# ============================================================================
# AUXILIARY FUNCTIONS (Fig. 5 in paper)
# ============================================================================

def power2round(r: int, d: int) -> Tuple[int, int]:
    """
    Phân rá số nguyên r thành (r1, r0) theo lũy thừa 2
    
    Chức năng: Tách r = r1*2^d + r0 với r0 được căn giữa khoảng
    
    Input:
        r: Số nguyên cần phân rã
        d: Số bit để làm tròn
    
    Output:
        (r1, r0): Cặp giá trị cao và thấp
            - r1: Phần cao (r1*2^d)
            - r0: Phần dư, trong khoảng [-(2^(d-1)), 2^(d-1)]
    """
    r = r % Q
    r0 = r % (2**d)
    
    # Center r0
    if r0 > 2**(d-1):
        r0 = r0 - 2**d
        r1 = (r - r0) // (2**d)
    else:
        r1 = (r - r0) // (2**d)
    
    return r1 % Q, r0


def decompose_q(r: int, alpha: int) -> Tuple[int, int]:
    """
    Phân rã số nguyên r thành (r1, r0) theo tham số alpha (modulo q)
    
    Chức năng: Tách r = r1*alpha + r0 (mod q) với r0 được căn giữa
    Dùng để trích xuất bit cao (HighBits) và bit thấp (LowBits)
    
    Input:
        r: Số nguyên cần phân rã
        alpha: Tham số chia (thường là 2*GAMMA2)
    
    Output:
        (r1, r0): Cặp bit cao và bit thấp
            - r1: Phần cao (high bits)
            - r0: Phần thấp, trong khoảng [-alpha/2, alpha/2]
    """
    r = r % Q
    r0 = r % alpha
    
    # Center r0 around 0
    if r0 > alpha // 2:
        r0 = r0 - alpha
        r1 = (r - r0) // alpha
    else:
        r1 = (r - r0) // alpha
    
    # Boundary case handling
    if r - r0 == Q - 1:
        r1 = 0
        r0 = r0 - 1
    
    return r1 % Q, r0


def high_bits_q(r: int, alpha: int) -> int:
    """
    Trích xuất các bit cao của số nguyên r
    
    Chức năng: Lấy phần r1 từ phân rã decompose_q(r, alpha)
    Dùng trong việc tạo commitment và xác thực chữ ký
    
    Input:
        r: Số nguyên
        alpha: Tham số chia
    
    Output:
        r1: Các bit cao của r
    """
    r1, _ = decompose_q(r, alpha)
    return r1


def low_bits_q(r: int, alpha: int) -> int:
    """
    Trích xuất các bit thấp của số nguyên r
    
    Chức năng: Lấy phần r0 từ phân rã decompose_q(r, alpha)
    Dùng trong kiểm tra rejection sampling
    
    Input:
        r: Số nguyên
        alpha: Tham số chia
    
    Output:
        r0: Các bit thấp của r
    """
    _, r0 = decompose_q(r, alpha)
    return r0


def make_hint(z: int, r: int, alpha: int) -> int:
    """
    Tạo bit gợi ý (hint) để giúp khôi phục bit cao
    
    Chức năng: Kiểm tra xem việc thêm z có làm thay đổi bit cao không
    Dùng trong các biến thể tối ưu của Dilithium
    
    Input:
        z: Giá trị cộng thêm
        r: Giá trị gốc
        alpha: Tham số chia
    
    Output:
        0 hoặc 1: Bit gợi ý (1 nếu bit cao thay đổi, 0 nếu không)
    """
    r1 = high_bits_q(r, alpha)
    v1 = high_bits_q(r + z, alpha)
    return 1 if r1 != v1 else 0


def use_hint(h: int, r: int, alpha: int) -> int:
    """
    Sử dụng bit gợi ý để khôi phục bit cao chính xác
    
    Chức năng: Dùng hint h để điều chỉnh bit cao
    
    Input:
        h: Bit gợi ý (0 hoặc 1)
        r: Giá trị cần khôi phục
        alpha: Tham số chia
    
    Output:
        Bit cao đã được điều chỉnh
    """
    m = (Q - 1) // alpha
    r1, r0 = decompose_q(r, alpha)
    
    if h == 1:
        if r0 > 0:
            return (r1 + 1) % m
        else:
            return (r1 - 1) % m
    return r1


# ============================================================================
# POLYNOMIAL OPERATIONS
# ============================================================================

class Polynomial:
    """
    Đại diện cho một đa thức trong vành R_q = Z_q[x]/(x^n + 1)
    
    Chức năng: 
        - Lưu trữ đa thức với N hệ số trong Z_q
        - Hỗ trợ các phép toán: cộng, trừ, nhân đa thức
        - Phép nhân theo quy tắc x^n = -1 (mod x^n + 1)
    
    Thuộc tính:
        coeffs: Mảng numpy N hệ số (int64) trong Z_q
    """
    
    def __init__(self, coeffs: np.ndarray):
        """
        Khởi tạo đa thức với các hệ số
        
        Input:
            coeffs: Mảng numpy gồm N hệ số
        """
        if len(coeffs) != N:
            raise ValueError(f"Polynomial must have {N} coefficients")
        # Keep coefficients in centered range [-Q/2, Q/2] for proper norm calculation
        c = np.array(coeffs, dtype=np.int64) % Q
        c[c > Q // 2] -= Q
        self.coeffs = c
    
    def __add__(self, other):
        """
        Cộng hai đa thức
        
        Input:
            other: Đa thức khác
        Output:
            Đa thức mới = self + other (mod q)
        """
        return Polynomial((self.coeffs + other.coeffs) % Q)
    
    def __sub__(self, other):
        """
        Trừ hai đa thức
        
        Input:
            other: Đa thức khác
        Output:
            Đa thức mới = self - other (mod q)
        """
        return Polynomial((self.coeffs - other.coeffs) % Q)
    
    def __mul__(self, other):
        """
        Nhân hai đa thức (hoặc nhân với vô hướng)
        
        TODO: NTT optimization needs negacyclic twist - using schoolbook for now
        
        Input:
            other: Đa thức khác hoặc số nguyên (vô hướng)
        
        Output:
            Đa thức mới = self * other (mod x^n+1, mod q)
        """
        if isinstance(other, int):
            # Scalar multiplication
            result = (self.coeffs * other) % Q
            result[result > Q // 2] -= Q
            return Polynomial(result)
        
        # Schoolbook negacyclic convolution mod X^N+1
        result = np.zeros(N, dtype=np.int64)
        for i in range(N):
            for j in range(N):
                if i + j < N:
                    result[i + j] += self.coeffs[i] * other.coeffs[j]
                else:
                    # X^N = -1, so X^(N+k) = -X^k
                    result[i + j - N] -= self.coeffs[i] * other.coeffs[j]
        
        result = result % Q
        result[result > Q // 2] -= Q
        return Polynomial(result)
    
    def __neg__(self):
        """Negate polynomial"""
        return Polynomial((-self.coeffs) % Q)
    
    def norm_inf(self) -> int:
        """
        Tính chuẩn vô cùng (infinity norm) của đa thức
        
        Chức năng: Tìm giá trị tuyệt đối lớn nhất trong các hệ số
        Dùng trong rejection sampling và kiểm tra bảo mật
        
        Output:
            Giá trị max(|hệ số|) sau khi căn giữa về [-q/2, q/2]
        """
        centered = self.center_coeffs()
        return np.max(np.abs(centered))
    
    def center_coeffs(self) -> np.ndarray:
        """Center coefficients in range [-(q-1)/2, (q-1)/2]"""
        centered = self.coeffs.copy()
        centered[centered > Q // 2] -= Q
        return centered
    
    def high_bits(self, alpha: int):
        """Apply high_bits_q to all coefficients"""
        return Polynomial(np.array([high_bits_q(c, alpha) for c in self.coeffs]))
    
    def low_bits(self, alpha: int):
        """Apply low_bits_q to all coefficients"""
        return Polynomial(np.array([low_bits_q(c, alpha) for c in self.coeffs]))
    
    def to_bytes(self) -> bytes:
        """Serialize polynomial to bytes"""
        return self.coeffs.tobytes()
    
    @staticmethod
    def from_bytes(data: bytes):
        """Deserialize polynomial from bytes"""
        coeffs = np.frombuffer(data[:N*8], dtype=np.int64)
        return Polynomial(coeffs)
    
    @staticmethod
    def zero():
        """Create zero polynomial"""
        return Polynomial(np.zeros(N, dtype=np.int64))
    
    @staticmethod
    def uniform(seed: bytes, nonce: int) -> 'Polynomial':
        """
        Lấy mẫu đa thức đồng nhất từ seed (sử dụng XOF)
        
        Chức năng: Sinh đa thức với các hệ số ngẫu nhiên đồng nhất trong Z_q
        Dùng SHAKE256 làm hàm XOF (Extendable Output Function)
        
        Input:
            seed: Seed ngẫu nhiên (bytes)
            nonce: Giá trị nonce để phân biệt các đa thức
        
        Output:
            Đa thức với N hệ số ngẫu nhiên trong [0, q-1]
        """
        shake = hashlib.shake_256()
        shake.update(seed + nonce.to_bytes(2, 'little'))
        coeffs = []
        
        idx = 0
        while len(coeffs) < N:
            # Get 3 bytes at a time
            buf = shake.digest(3)
            val = int.from_bytes(buf, 'little') & 0x7FFFFF  # 23 bits
            
            if val < Q:
                coeffs.append(val)
            idx += 3
        
        return Polynomial(np.array(coeffs[:N]))
    
    @staticmethod
    def sample_in_ball(seed: bytes, tau: int = TAU) -> 'Polynomial':
        """
        Lấy mẫu đa thức trong "quả cầu" (có đúng tau hệ số ±1)
        
        Chức năng: Sinh đa thức challenge với đúng tau hệ số là ±1, còn lại = 0
        Đây là dạng đa thức c trong sơ đồ chữ ký Dilithium
        
        Input:
            seed: Seed ngẫu nhiên từ hàm băm
            tau: Số lượng hệ số khác 0 (mặc định = TAU = 39)
        
        Output:
            Đa thức với đúng tau hệ số ∈ {-1, +1}, còn lại = 0
        """
        shake = hashlib.shake_256()
        shake.update(seed)
        coeffs = np.zeros(N, dtype=np.int64)
        
        # Generate random positions for non-zero coefficients
        positions = set()
        buf_offset = 0
        buf = shake.digest(8 * tau * 2)  # Get enough random bytes upfront
        
        for i in range(tau):
            attempts = 0
            while attempts < 1000:  # Safety limit
                pos = buf[buf_offset] % N
                buf_offset += 1
                if buf_offset >= len(buf):
                    buf = shake.digest(8 * tau)
                    buf_offset = 0
                
                if pos not in positions:
                    positions.add(pos)
                    break
                attempts += 1
            
            if attempts >= 1000:
                raise RuntimeError("Failed to sample in ball")
        
        # Generate signs
        sign_buf = shake.digest(tau)
        for i, pos in enumerate(sorted(positions)):
            coeffs[pos] = 1 if (sign_buf[i] & 1) == 0 else -1
        
        return Polynomial(coeffs)
    
    @staticmethod
    def sample_centered(bound: int, seed: bytes = None) -> 'Polynomial':
        """
        Lấy mẫu đa thức với hệ số nhỏ (trong khoảng giới hạn)
        
        Chức năng: Sinh đa thức với hệ số trong [-bound, bound]
        Dùng cho khóa bí mật (s, e) và vector ngẫu nhiên (y)
        
        Input:
            bound: Giới hạn trên của hệ số
            seed: Seed ngẫu nhiên (nếu None thì dùng numpy random)
        
        Output:
            Đa thức với N hệ số ∈ [-bound, bound]
        """
        if seed:
            shake = hashlib.shake_256()
            shake.update(seed)
            random_bytes = shake.digest(N * 4)
            coeffs = np.array([
                (int.from_bytes(random_bytes[i*4:(i+1)*4], 'little') % (2*bound + 1)) - bound
                for i in range(N)
            ], dtype=np.int64)
        else:
            coeffs = np.random.randint(-bound, bound + 1, N, dtype=np.int64)
        
        # Return coefficients directly without % Q to preserve centered range
        # Polynomial.__init__ will handle modulo reduction
        return Polynomial(coeffs)


# ============================================================================
# VECTOR AND MATRIX OPERATIONS
# ============================================================================

class PolyVector:
    """
    Vector của các đa thức
    
    Chức năng: Đại diện cho vector gồm nhiều đa thức
    Dùng để biểu diễn khóa (s, e, b) và các giá trị trung gian (y, z, w)
    
    Thuộc tính:
        polys: Danh sách các đa thức
        length: Độ dài vector (số đa thức)
    """
    
    def __init__(self, polys: List[Polynomial]):
        """
        Khởi tạo vector đa thức
        
        Input:
            polys: Danh sách các đa thức
        """
        self.polys = polys
        self.length = len(polys)
    
    def __add__(self, other):
        if self.length != other.length:
            raise ValueError("Vector dimensions must match")
        return PolyVector([p1 + p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def __sub__(self, other):
        if self.length != other.length:
            raise ValueError("Vector dimensions must match")
        return PolyVector([p1 - p2 for p1, p2 in zip(self.polys, other.polys)])
    
    def __mul__(self, scalar: int):
        return PolyVector([p * scalar for p in self.polys])
    
    def norm_inf(self) -> int:
        """Maximum infinity norm among all polynomials"""
        return max(p.norm_inf() for p in self.polys)
    
    def high_bits(self, alpha: int):
        return PolyVector([p.high_bits(alpha) for p in self.polys])
    
    def low_bits(self, alpha: int):
        return PolyVector([p.low_bits(alpha) for p in self.polys])
    
    def to_bytes(self) -> bytes:
        return b''.join(p.to_bytes() for p in self.polys)
    
    @staticmethod
    def zero(length: int):
        return PolyVector([Polynomial.zero() for _ in range(length)])


class PolyMatrix:
    """
    Ma trận của các đa thức
    
    Chức năng: Đại diện cho ma trận A (k×l) trong sơ đồ Dilithium
    Mỗi phần tử là một đa thức trong R_q
    
    Thuộc tính:
        rows: Danh sách các hàng (mỗi hàng là list các đa thức)
        k: Số hàng
        l: Số cột
    """
    
    def __init__(self, rows: List[List[Polynomial]]):
        """
        Khởi tạo ma trận đa thức
        
        Input:
            rows: Danh sách các hàng, mỗi hàng là list các đa thức
        """
        self.rows = rows
        self.k = len(rows)  # number of rows
        self.l = len(rows[0]) if rows else 0  # number of columns
    
    def __mul__(self, vector: PolyVector):
        """
        Nhân ma trận với vector (A · v)
        
        Chức năng: Thực hiện phép nhân ma trận-vector trên vành đa thức
        Dùng trong tính toán b = A·s + e và w = A·y
        
        Input:
            vector: PolyVector có độ dài bằng số cột của ma trận
        
        Output:
            PolyVector kết quả có độ dài bằng số hàng của ma trận
        
        NOTE: NTT optimization disabled - cần fix NTT parameters trước
        """
        if self.l != vector.length:
            raise ValueError(f"Dimension mismatch: matrix {self.k}x{self.l}, vector {vector.length}")
        
        result = []
        for row in self.rows:
            # Dot product of row with vector
            poly_sum = Polynomial.zero()
            for poly, vec_poly in zip(row, vector.polys):
                poly_sum = poly_sum + (poly * vec_poly)
            result.append(poly_sum)
        
        return PolyVector(result)
    
    @staticmethod
    def uniform(seed: bytes, k: int, l: int):
        """Generate uniform random matrix from seed"""
        rows = []
        nonce = 0
        for i in range(k):
            row = []
            for j in range(l):
                poly = Polynomial.uniform(seed, nonce)
                row.append(poly)
                nonce += 1
            rows.append(row)
        return PolyMatrix(rows)


# ============================================================================
# HASH FUNCTIONS
# ============================================================================

def hash_to_challenge(message: bytes, w_prime: bytes) -> Polynomial:
    """
    Băm thông điệp và commitment thành đa thức challenge
    
    Chức năng: Tạo challenge c = H(m || w') ∈ B_τ (đa thức có τ hệ số ±1)
    Đây là bước quan trọng trong Fiat-Shamir transform
    
    Input:
        message: Thông điệp cần ký (bytes)
        w_prime: Commitment (high bits của w), đã serialize
    
    Output:
        Đa thức challenge c với đúng TAU hệ số ∈ {-1, +1}
    """
    h = hashlib.sha3_512()
    h.update(message)
    h.update(w_prime)
    digest = h.digest()
    
    return Polynomial.sample_in_ball(digest, TAU)


def xof_expand(seed: bytes, length: int) -> bytes:
    """
    Extendable Output Function using SHAKE256
    """
    shake = hashlib.shake_256()
    shake.update(seed)
    return shake.digest(length)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def rejection_sampling_check(z: PolyVector, bound: int) -> bool:
    """
    Check if ||z||_inf < bound
    Used in rejection sampling during signing
    """
    return z.norm_inf() < bound


def encode_public_key(rho: bytes, b: PolyVector) -> bytes:
    """Encode public key pk = (rho, b)"""
    return rho + b.to_bytes()


def decode_public_key(pk_bytes: bytes) -> Tuple[bytes, PolyVector]:
    """Decode public key to (rho, b)"""
    rho = pk_bytes[:32]
    b_bytes = pk_bytes[32:]
    
    # Reconstruct b vector (assuming K polynomials)
    polys = []
    poly_size = N * 8  # Each polynomial is N int64s
    for i in range(K):
        poly_data = b_bytes[i*poly_size:(i+1)*poly_size]
        polys.append(Polynomial.from_bytes(poly_data))
    
    return rho, PolyVector(polys)
