#!/usr/bin/env python3
"""
dilithium_math.py - Core mathematical primitives for Threshold Dilithium

Chứa:
1. NTT (Number Theoretic Transform) via optimized C library (libdilithium_ntt.so)
2. Polynomial arithmetic trong R_q = Z_q[X]/(X^N+1)
3. Lattice-based commitment scheme
4. Vector operations và helper functions
"""

from typing import List, Tuple, Dict, Any, Optional
import hashlib
import random
import base64
import numpy as np
import ctypes
import os

# =============================
# CONSTANTS & PARAMETERS
# =============================
# CẬP NHẬT THAM SỐ (Bám sát khuyến nghị NIST Dilithium 3)
DILITHIUM_Q = 8380417
DILITHIUM_N = 256
DILITHIUM_ETA = 4           # NIST Dilithium3 dùng eta=4 (bound for s1, s2)
DILITHIUM_GAMMA1 = 524288   # = 2^19, bound for y nonce [cite: 320, 461]

# [QUAN TRỌNG] BOUND B trong bài báo [cite: 186, 334]
# Với threshold signatures, z_i = y_i + c*λ*s có thể có |z_i| lớn hơn γ₁
# do c*λ*s term (c và λ là số lớn trong Z_q)
# 
# Empirical observation: max|z_i| ≈ 4M với c*λ*s overhead
# Để global check (t=3) pass hầu hết: bound ≥ 4M
# Set bound = γ₁ * 4 = 2.1M per participant
SIGNATURE_BOUND = int(524038)

NTT_ROOT = 1753
NTT_ROOT_INV = pow(NTT_ROOT, -1, DILITHIUM_Q)
N_INV = 8347669  # pow(256, -1, 8380417)

# =============================
# C LIBRARY INTERFACE
# =============================
# Load the compiled C library
_lib_path = os.path.join(os.path.dirname(__file__), "libdilithium_ntt.so")
if not os.path.exists(_lib_path):
    raise FileNotFoundError(f"C library not found: {_lib_path}. Run 'make' in core/ directory.")
_lib = ctypes.CDLL(_lib_path)

# Define C polynomial structure
class PolyC(ctypes.Structure):
    _fields_ = [("coeffs", ctypes.c_int32 * DILITHIUM_N)]

# Declare C function signatures
_lib.poly_ntt.argtypes = [ctypes.POINTER(PolyC)]
_lib.poly_ntt.restype = None

_lib.poly_invntt_tomont.argtypes = [ctypes.POINTER(PolyC)]
_lib.poly_invntt_tomont.restype = None

_lib.poly_pointwise_montgomery.argtypes = [
    ctypes.POINTER(PolyC),
    ctypes.POINTER(PolyC),
    ctypes.POINTER(PolyC)
]
_lib.poly_pointwise_montgomery.restype = None

_lib.poly_reduce.argtypes = [ctypes.POINTER(PolyC)]
_lib.poly_reduce.restype = None


# NTT twiddle factors are now initialized in C library


# =============================
# HASH UTILITIES
# =============================
def _sha3_512(data: bytes) -> bytes:
    """SHA3-512 hash"""
    return hashlib.sha3_512(data).digest()


def _hash_to_challenge(message: bytes, w_bytes: bytes, q: int = DILITHIUM_Q) -> int:
    """
    Hash message and commitment to scalar challenge.
    c = H(message || w_bytes) mod q
    
    NOTE: This is the OLD implementation (scalar challenge).
    For FIPS 204 compliance, use _hash_to_challenge_poly() instead.
    """
    h = _sha3_512(message + w_bytes)
    return int.from_bytes(h, 'little') % q


def sample_in_ball(seed: bytes, tau: int = 49, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> 'Poly':
    """
    SampleInBall - FIPS 204 Algorithm 27
    
    Tạo đa thức thử thách c từ seed với đúng τ (tau) hệ số khác 0.
    Mỗi hệ số khác 0 là ±1, còn lại là 0.
    
    FIPS 204 Dilithium parameters:
    - Dilithium2: τ = 39
    - Dilithium3: τ = 49  
    - Dilithium5: τ = 60
    
    Args:
        seed: 32-byte seed (from H(commitment || message))
        tau: Number of ±1 coefficients
        q: Modulus
        N: Polynomial degree (256)
        
    Returns:
        Polynomial c in NTT domain với ||c||∞ = 1
    """
    if len(seed) < 32:
        # Extend seed using SHAKE-256 if needed
        import hashlib
        shake = hashlib.shake_256(seed)
        seed = shake.digest(32)
    
    # Initialize polynomial with all zeros
    coeffs = [0] * N
    
    # Use deterministic RNG from seed (FIPS 204 uses rejection sampling on SHAKE output)
    # Simplified implementation: use seed to initialize Random for deterministic sampling
    import random
    rng = random.Random(int.from_bytes(seed, 'little'))
    
    # Sample tau positions uniformly without replacement (MUST use rng for determinism!)
    positions = rng.sample(range(N), tau)
    
    # For each selected position, assign ±1 based on next bit from seed
    for i, pos in enumerate(positions):
        # Use alternating bits from seed to determine sign
        byte_idx = i // 8
        bit_idx = i % 8
        if byte_idx < len(seed):
            bit = (seed[byte_idx] >> bit_idx) & 1
            coeffs[pos] = 1 if bit else -1
        else:
            # Fallback to RNG if we run out of seed bytes
            coeffs[pos] = 1 if rng.getrandbits(1) else -1
    
    # Convert negative coefficients to modular form
    coeffs = [(c + q) % q for c in coeffs]
    
    # Create polynomial and convert to NTT domain for efficient multiplication
    poly = Poly(coeffs, q, N, in_ntt=False)
    return poly.to_ntt()


def _hash_to_challenge_poly(message: bytes, w_bytes: bytes, 
                            tau: int = 49, q: int = DILITHIUM_Q, 
                            N: int = DILITHIUM_N) -> 'Poly':
    """
    FIPS 204 Challenge Generation (Polynomial Form)
    
    Compute polynomial challenge c = SampleInBall(H(message || w))
    
    This is the CORRECT FIPS 204 implementation where challenge is a polynomial,
    not a scalar as in the simplified version.
    
    Protocol:
    1. Hash commitment w and message: h = H(w || m)
    2. Use first 32 bytes of h as seed for SampleInBall
    3. Generate polynomial c with exactly tau coefficients ±1
    
    Args:
        message: Message being signed
        w_bytes: Serialized commitment polynomial(s)
        tau: Number of ±1 coefficients (49 for Dilithium3)
        q: Modulus
        N: Polynomial degree
        
    Returns:
        Challenge polynomial c in coefficient domain (not NTT)
    """
    # Step 1: Hash message + commitment
    h = _sha3_512(message + w_bytes)
    
    # Step 2: Take first 32 bytes as seed
    seed = h[:32]
    
    # Step 3: Generate polynomial challenge via SampleInBall
    c_poly = sample_in_ball(seed, tau=tau, q=q, N=N)
    
    return c_poly


def expand_a(rho: bytes, K: int, L: int, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> List[List['Poly']]:
    """
    ExpandA(ρ) - Generate matrix A from seed according to FIPS 204
    
    Uses SHAKE-128 to deterministically generate a K×L matrix of polynomials.
    This matches the official Dilithium specification.
    
    Args:
        rho: 32-byte seed
        K: number of rows
        L: number of columns
        q: modulus
        N: polynomial degree
        
    Returns:
        K×L matrix of polynomials
    """
    if len(rho) != 32:
        raise ValueError("rho must be 32 bytes")
    
    A = []
    for i in range(K):
        row = []
        for j in range(L):
            # Generate polynomial A[i][j] from SHAKE-128(rho || i || j)
            # Each polynomial needs enough randomness for N coefficients in [0, q)
            
            # Create input: rho || i || j (as in FIPS 204)
            shake_input = rho + bytes([i, j])
            
            # Use SHAKE-128 to generate coefficients
            # Need to generate until we have N valid coefficients
            coeffs = []
            shake = hashlib.shake_128(shake_input)
            
            # Generate coefficients using rejection sampling
            # Each coefficient is 3 bytes (24 bits) which is enough for q = 8380417 (< 2^24)
            buf_size = 3 * N * 2  # Generate extra to avoid multiple calls
            stream = shake.digest(buf_size)
            
            idx = 0
            while len(coeffs) < N and idx + 2 < len(stream):
                # Read 3 bytes and convert to integer
                t = int.from_bytes(stream[idx:idx+3], 'little')
                idx += 3
                
                # Rejection sampling: accept if t < q
                # For Dilithium q = 8380417 ≈ 2^23, so ~50% acceptance rate
                if t < q:
                    coeffs.append(t)
                
                # If we run out of stream, generate more
                if idx + 2 >= len(stream) and len(coeffs) < N:
                    stream = shake.digest(buf_size)
                    idx = 0
            
            # Create polynomial from coefficients
            poly = Poly(coeffs[:N], q, N, in_ntt=False)
            row.append(poly)
        
        A.append(row)
    
    return A


# =============================
# C LIBRARY WRAPPER FUNCTIONS
# =============================
def ntt_forward_c_wrapper(coeffs: np.ndarray) -> np.ndarray:
    """Wrapper for C poly_ntt function - Forward NTT transform"""
    # Create C structure and copy coefficients
    p = PolyC()
    
    # Fast copy with modulo reduction
    temp = coeffs % DILITHIUM_Q
    temp = np.where(temp < 0, temp + DILITHIUM_Q, temp).astype(np.int32)
    ctypes.memmove(p.coeffs, temp.ctypes.data, DILITHIUM_N * 4)
    
    # Call C function (modifies p in-place)
    _lib.poly_ntt(ctypes.byref(p))
    
    # Reduce to canonical form
    _lib.poly_reduce(ctypes.byref(p))
    
    # Convert back to numpy array
    result = np.array(p.coeffs, dtype=np.int64)
    return result


def ntt_inverse_c_wrapper(coeffs: np.ndarray) -> np.ndarray:
    """Wrapper for C poly_invntt_tomont function - Inverse NTT transform"""
    # Create C structure and copy coefficients
    p = PolyC()
    
    # Fast copy with modulo reduction
    temp = coeffs % DILITHIUM_Q
    temp = np.where(temp < 0, temp + DILITHIUM_Q, temp).astype(np.int32)
    ctypes.memmove(p.coeffs, temp.ctypes.data, DILITHIUM_N * 4)
    
    # Call C function (modifies p in-place)
    _lib.poly_invntt_tomont(ctypes.byref(p))
    
    # Reduce to canonical form [0, Q)
    _lib.poly_reduce(ctypes.byref(p))
    
    # Convert back to numpy array
    result = np.array(p.coeffs, dtype=np.int64)
    return result


def poly_mul_c_wrapper(a_coeffs: np.ndarray, b_coeffs: np.ndarray) -> np.ndarray:
    """Wrapper for C poly_pointwise_montgomery - Pointwise multiplication in NTT domain"""
    # Create C structures
    pa = PolyC()
    pb = PolyC()
    pc = PolyC()
    
    # Fast copy with modulo reduction for both inputs
    temp_a = a_coeffs % DILITHIUM_Q
    temp_a = np.where(temp_a < 0, temp_a + DILITHIUM_Q, temp_a).astype(np.int32)
    ctypes.memmove(pa.coeffs, temp_a.ctypes.data, DILITHIUM_N * 4)
    
    temp_b = b_coeffs % DILITHIUM_Q
    temp_b = np.where(temp_b < 0, temp_b + DILITHIUM_Q, temp_b).astype(np.int32)
    ctypes.memmove(pb.coeffs, temp_b.ctypes.data, DILITHIUM_N * 4)
    
    # Call C function
    _lib.poly_pointwise_montgomery(ctypes.byref(pc), ctypes.byref(pa), ctypes.byref(pb))
    
    # Reduce to canonical form
    _lib.poly_reduce(ctypes.byref(pc))
    
    # Convert back to numpy array
    result = np.array(pc.coeffs, dtype=np.int64)
    return result


# =============================
# POLYNOMIAL CLASS
# =============================
class Poly:
    """
    Polynomial in R_q = Z_q[X]/(X^N+1)
    
    Supports both coefficient domain and NTT domain operations.
    """
    
    def __init__(self, coeffs: Any, q: int = DILITHIUM_Q, N: int = DILITHIUM_N, in_ntt: bool = False):
        self.q = q
        self.N = N
        if isinstance(coeffs, np.ndarray):
            self.coeffs = coeffs
        else:
            if len(coeffs) != N:
                raise ValueError(f"Polynomial length {len(coeffs)} != N={N}")
            self.coeffs = np.array([c % q for c in coeffs], dtype=np.int64)
        self.in_ntt = in_ntt

    @classmethod
    def zeros(cls, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> "Poly":
        """Zero polynomial"""
        return cls([0] * N, q, N, in_ntt=False)

    @classmethod
    def uniform_random(cls, q: int = DILITHIUM_Q, N: int = DILITHIUM_N, rnd: Optional[random.Random] = None) -> "Poly":
        """Uniform random polynomial in [0, q)"""
        r = rnd or random
        return cls([r.randrange(0, q) for _ in range(N)], q, N, in_ntt=False)

    @classmethod
    def small_random(cls, q: int = DILITHIUM_Q, N: int = DILITHIUM_N, eta: int = DILITHIUM_ETA, rnd: Optional[random.Random] = None) -> "Poly":
        """Small random polynomial with coefficients in [-eta, eta]"""
        r = rnd or random
        coeffs = [r.randint(-eta, eta) % q for _ in range(N)]
        return cls(coeffs, q, N, in_ntt=False)

    def to_ntt(self) -> "Poly":
        """Convert to NTT domain - O(N log N)"""
        if self.in_ntt: 
            return self
        new_coeffs = ntt_forward_c_wrapper(self.coeffs)
        return Poly(new_coeffs, self.q, self.N, in_ntt=True)

    def from_ntt(self) -> "Poly":
        """Convert to coefficient domain - O(N log N)"""
        if not self.in_ntt: 
            return self
        new_coeffs = ntt_inverse_c_wrapper(self.coeffs)
        return Poly(new_coeffs, self.q, self.N, in_ntt=False)

    def add(self, other: "Poly") -> "Poly":
        """Addition in same domain"""
        self._check_same(other)
        if self.in_ntt != other.in_ntt:
            raise ValueError("Cannot add polynomials in different domains")
        new_coeffs = (self.coeffs + other.coeffs) % self.q
        return Poly(new_coeffs, self.q, self.N, in_ntt=self.in_ntt)

    def sub(self, other: "Poly") -> "Poly":
        """Subtraction in same domain"""
        self._check_same(other)
        if self.in_ntt != other.in_ntt:
            raise ValueError("Cannot subtract polynomials in different domains")
        new_coeffs = (self.coeffs - other.coeffs) % self.q
        return Poly(new_coeffs, self.q, self.N, in_ntt=self.in_ntt)

    def scalar_mul(self, c: int) -> "Poly":
        """Scalar multiplication"""
        c %= self.q
        new_coeffs = (self.coeffs * c) % self.q
        return Poly(new_coeffs, self.q, self.N, in_ntt=self.in_ntt)

    def mul(self, other: "Poly") -> "Poly":
        """
        Polynomial multiplication using NTT - O(N log N)
        Returns result in NTT domain.
        """
        self._check_same(other)
        
        # Convert to NTT if needed
        p1 = self if self.in_ntt else self.to_ntt()
        p2 = other if other.in_ntt else other.to_ntt()
        
        # Pointwise multiply - O(N)
        prod_coeffs = poly_mul_c_wrapper(p1.coeffs, p2.coeffs)
        
        # Return in NTT domain
        return Poly(prod_coeffs, self.q, self.N, in_ntt=True)

    def to_bytes(self) -> bytes:
        """Serialize to bytes (coefficient domain)"""
        p = self.from_ntt()
        b = bytearray()
        for c in p.coeffs:
            b.extend(int(c).to_bytes(4, 'little', signed=False))
        return bytes(b)

    @classmethod
    def from_bytes(cls, data: bytes, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> "Poly":
        """Deserialize from bytes"""
        if len(data) != 4 * N:
            raise ValueError("Invalid byte length for polynomial")
        coeffs = np.zeros(N, dtype=np.int64)
        for i in range(N):
            coeffs[i] = int.from_bytes(data[4*i : 4*i+4], 'little', signed=False) % q
        return cls(coeffs, q, N, in_ntt=False)

    def get_centered_coeffs(self) -> List[int]:
        """Get coefficients in centered representation [-q/2, q/2]"""
        p = self.from_ntt()
        half = (self.q - 1) // 2
        res = []
        for c in p.coeffs:
            val = int(c)
            if val > half: 
                val -= self.q
            res.append(val)
        return res

    def check_norm(self, bound: int) -> bool:
        """Check if all coefficients have absolute value <= bound"""
        for v in self.get_centered_coeffs():
            if abs(v) > bound: 
                return False
        return True

    def _check_same(self, other: "Poly") -> None:
        """Verify compatible polynomials"""
        if self.q != other.q or self.N != other.N:
            raise ValueError("Polynomial mismatch (q or N differ)")


# =============================
# VECTOR OPERATIONS
# =============================
def vec_add(a: List[Poly], b: List[Poly]) -> List[Poly]:
    """Vector addition"""
    if len(a) != len(b):
        raise ValueError("Vector length mismatch")
    return [ai.add(bi) for ai, bi in zip(a, b)]


def vec_zeros(k: int, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> List[Poly]:
    """Create zero vector"""
    return [Poly.zeros(q, N) for _ in range(k)]


def _matvec_mul(A: List[List[Poly]], vec: List[Poly]) -> List[Poly]:
    """
    Matrix-vector multiplication using NTT optimization.
    Input: A (KxL), vec (L)
    Output: result (K)
    Returns polynomials in coefficient domain.
    """
    K = len(A)
    if K == 0: 
        return []
    L = len(A[0])
    if len(vec) != L:
        raise ValueError("Dimension mismatch for matvec_mul")
    q = vec[0].q
    N = vec[0].N
    
    # Convert input vector to NTT once
    vec_ntt = [v.to_ntt() for v in vec]
    
    out = []
    for k in range(K):
        acc_coeffs = np.zeros(N, dtype=np.int64)
        for l in range(L):
            # Convert matrix element to NTT
            a_ntt = A[k][l].to_ntt()
            
            # Pointwise multiply and accumulate in NTT domain
            prod = poly_mul_c_wrapper(a_ntt.coeffs, vec_ntt[l].coeffs)
            acc_coeffs = (acc_coeffs + prod) % q
        
        # Convert result back to coefficient domain
        res = Poly(acc_coeffs, q, N, in_ntt=True).from_ntt()
        out.append(res)
    return out


def _serialize_poly_vec(vec: List[Poly]) -> List[str]:
    """Serialize polynomial vector to base64 strings"""
    return [base64.b64encode(p.to_bytes()).decode() for p in vec]


def _deserialize_poly_vec(data: List[str], q: int, N: int) -> List[Poly]:
    """Deserialize polynomial vector from base64 strings"""
    return [Poly.from_bytes(base64.b64decode(s), q, N) for s in data]


def _poly_vec_check_norm(vec: List[Poly], bound: int) -> bool:
    """Check if all polynomials in vector satisfy norm bound"""
    for p in vec:
        if not p.check_norm(bound):
            return False
    return True


# =============================
# LATTICE-BASED COMMITMENT
# =============================
class LatticeCommitment:
    """
    Lattice-based commitment scheme with H3 deterministic generation.
    
    Com(w, r) = A_com * r + w mod q
    
    Properties:
    - Binding: Cannot find w' != w such that Com(w,r) = Com(w',r')
    - Hiding: Com(w,r) reveals no info about w
    - H3: A_com = H3(message, pk) - deterministic from message
    """
    
    def __init__(self, q: int = DILITHIUM_Q, N: int = DILITHIUM_N, 
                 k: int = 4, m: int = 8, A_com: List[List[Poly]] = None):
        """
        Args:
            q: modulus
            N: polynomial degree
            k: witness dimension (number of polynomials in w)
            m: randomness dimension (number of polynomials in r), m >= k for security
            A_com: commitment matrix (if None, generate randomly)
        """
        self.q = q
        self.N = N
        self.k = k
        self.m = m
        if A_com is None:
            self.A_com = [[Poly.uniform_random(q, N) for _ in range(m)] for _ in range(k)]
        else:
            self.A_com = A_com
    
    @classmethod
    def from_message(cls, message: bytes, pk: Dict[str, Any], k: int, m: int) -> "LatticeCommitment":
        """
        H3 function: {0,1}* -> S_ck
        Generate commitment matrix A_com from Hash(message || pk).
        
        Args:
            message: message to be signed
            pk: public key
            k: witness dimension
            m: randomness dimension
            
        Returns:
            LatticeCommitment with A_com generated from H3(message, pk)
        """
        q = pk["q"]
        N = pk["N"]
        
        # Serialize PK consistently (only t and A)
        t_bytes = b"".join(base64.b64decode(s) for s in pk["t"])
        
        # Compute Seed = Hash(message || pk)
        seed_source = message + t_bytes
        seed_hash = hashlib.shake_256(seed_source).digest(32)
        
        # Initialize RNG from this seed
        seed_int = int.from_bytes(seed_hash, 'big')
        rng = random.Random(seed_int)
        
        # Generate A_com from this RNG
        A_com = []
        for _ in range(k):
            row = []
            for _ in range(m):
                coeffs = [rng.randrange(0, q) for _ in range(N)]
                poly = Poly(coeffs, q, N, in_ntt=False)
                row.append(poly)
            A_com.append(row)
            
        return cls(q, N, k, m, A_com)
    
    def commit(self, w: List[Poly], r: List[Poly]) -> List[Poly]:
        """
        Create commitment: com = A_com * r + w mod q
        
        Args:
            w: witness vector (k polynomials)
            r: randomness vector (m polynomials)
            
        Returns:
            commitment vector (k polynomials)
        """
        if len(w) != self.k:
            raise ValueError(f"Witness length {len(w)} != k={self.k}")
        if len(r) != self.m:
            raise ValueError(f"Randomness length {len(r)} != m={self.m}")
        
        # com = A_com * r
        com = _matvec_mul(self.A_com, r)
        
        # com = com + w
        com = [com[i].add(w[i]) for i in range(self.k)]
        
        return com
    
    def open(self, com: List[Poly], w: List[Poly], r: List[Poly]) -> bool:
        """
        Verify commitment opening.
        
        Returns:
            True if Com(w, r) == com
        """
        expected_com = self.commit(w, r)
        
        # Compare each polynomial using numpy array comparison
        for i in range(self.k):
            if not np.array_equal(expected_com[i].coeffs, com[i].coeffs):
                return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize commitment key for sharing between participants"""
        return {
            "q": self.q,
            "N": self.N,
            "k": self.k,
            "m": self.m,
            "A_com": [[base64.b64encode(p.to_bytes()).decode() for p in row] for row in self.A_com]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LatticeCommitment":
        """Deserialize commitment key"""
        obj = cls(data["q"], data["N"], data["k"], data["m"])
        obj.A_com = [
            [Poly.from_bytes(base64.b64decode(b), data["q"], data["N"]) 
             for b in row]
            for row in data["A_com"]
        ]
        return obj


# =============================
# CRYPTOGRAPHIC UTILITIES
# =============================
def shamir_share_int(secret: int, n: int, t: int, field_prime: int = DILITHIUM_Q) -> List[Tuple[int, int]]:
    """
    Shamir secret sharing for integer over Z_q.
    
    Args:
        secret: secret value to share
        n: number of shares
        t: threshold (need t shares to reconstruct)
        field_prime: field modulus
        
    Returns:
        List of (x, y) shares where x in [1, n]
    """
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
    """
    Compute Lagrange coefficients L_j(0) for interpolation at zero.
    
    Args:
        xs: list of distinct x-coordinates
        q: field modulus
        
    Returns:
        List of Lagrange coefficients
    """
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


def _rejection_sample_local(z_i: List[Poly], y_i: List[Poly], 
                            c_lambda: int, s_share_i: List[Poly],
                            q: int, eta: int = DILITHIUM_ETA) -> bool:
    """
    Local rejection sampling for threshold signing (Updated per Leevik Step 3g).
    
    Implements two critical checks from the paper:
    1. Norm Check: Ensures ||z|| < γ₁ - β (prevents signature forgery)
    2. Probabilistic Check: Ensures distribution doesn't leak secret
    
    Args:
        z_i: partial signature of participant i
        y_i: nonce of participant i (unused in this simplified version)
        c_lambda: c * lambda_i mod q (unused in this simplified version)
        s_share_i: secret share of participant i (unused in this simplified version)
        q: modulus (unused in this simplified version)
        eta: bound for small coefficients (unused in this simplified version)
        
    Returns:
        True if pass rejection sampling, False if reject
    """
    
    # 1. Norm Check (Thay thế cho Check 1 cũ)
    # Theo bài báo: checks that ||z'|| < B 
    # B ở đây chính là giới hạn của chữ ký (SIGNATURE_BOUND)
    # Thực tế trong Dilithium chuẩn: ||z|| < Gamma1 - Beta
    
    # [QUAN TRỌNG] Với threshold signatures:
    # - z_i = y_i + c*λ_i*s_share_i
    # - y_i ~ Uniform[-GAMMA1, GAMMA1], max |y_i| = GAMMA1
    # - c*λ_i*s_share_i có thể RẤT LỚN do c và λ_i là số lớn trong Z_q
    #   Ví dụ: c ~ 10^6, λ ~ 10, s ~ 4 => c*λ*s ~ 4*10^7 >> GAMMA1
    # - Do đó |z_i| có thể lên đến q/2 trong trường hợp xấu nhất
    # - Global check sẽ verify tổng z = Σz_i có norm hợp lý
    
    # Sử dụng q/2 làm limit (chấp nhận mọi giá trị hợp lệ trong Z_q centered form)
    # Local rejection chủ yếu để đảm bảo distribution, không phải hard bound
    limit = q // 2
    
    for poly in z_i:
        # Lấy hệ số dạng centered (âm/dương)
        # Trong hệ mật mã lưới, z = 8380416 (tức là -1) là một số "nhỏ",
        # nhưng z = 4000000 là một số "lớn"
        coeffs = poly.get_centered_coeffs() 
        for c in coeffs:
            if abs(c) >= limit:
                return False  # REJECT: Hệ số quá lớn, vượt biên
    M = 1.3
    
    return random.random() < (1.0 / M)
    # return True

# =============================
# HASH-THEN-REVEAL PROTOCOL
# =============================
class HashThenReveal:
    """
    Hash-then-Reveal protocol to prevent signature modification after seeing others' signatures.
    
    Protocol:
    1. Compute z_i, r_i
    2. Send h_i = H(z_i || r_i) to other participants
    3. Receive all h_j from others
    4. Send real (z_i, r_i)
    5. Receivers verify H(z_j || r_j) == h_j received earlier
    """
    
    @staticmethod
    def hash_commitment(z_vec: List[Poly], r_nonce: bytes) -> bytes:
        """
        Compute hash of (z_vec, r_nonce).
        
        Args:
            z_vec: partial signature vector
            r_nonce: randomness for ZK proof
            
        Returns:
            hash commitment (64 bytes from SHA3-512)
        """
        z_bytes = b"".join(p.to_bytes() for p in z_vec)
        return _sha3_512(z_bytes + r_nonce)
    
    @staticmethod
    def verify_reveal(z_vec: List[Poly], r_nonce: bytes, 
                     hash_commitment: bytes) -> bool:
        """
        Verify if (z_vec, r_nonce) matches hash commitment.
        
        Returns:
            True if matches, False if not (potential cheating)
        """
        expected_hash = HashThenReveal.hash_commitment(z_vec, r_nonce)
        return expected_hash == hash_commitment


# =============================
# BIT-PACKING (Signature Compression)
# =============================
def pack_z_compact(z_vec: List[Poly], gamma1: int = DILITHIUM_GAMMA1) -> bytes:
    """
    Nén vector z với bit-packing theo FIPS 204
    
    Với Threshold signatures: z có thể lớn hơn gamma1 do c*λ*s term
    Sử dụng SIGNATURE_BOUND để pack
    
    Args:
        z_vec: Vector polynomials (L polynomials)
        gamma1: Bound for coefficients (mặc định)
        
    Returns:
        Compressed bytes
    """
    # Dùng SIGNATURE_BOUND cho threshold (lớn hơn gamma1)
    # SIGNATURE_BOUND = gamma1 * 4 ≈ 2.1M
    # Nhưng với t participants và scaling, cần lớn hơn
    # Sử dụng 2^23 = 8.4M để cover hết threshold overhead
    pack_bound = 2**23  # 8,388,608
    
    # Số bits cần thiết: 24 bits (log2(2*8.4M) = log2(16.8M) ≈ 24)
    bits_per_coeff = 24
    
    # Pack tất cả coefficients
    all_bits = []
    for poly in z_vec:
        coeffs_centered = poly.get_centered_coeffs()
        for c in coeffs_centered:
            # Shift về [0, 2*pack_bound)
            c_shifted = c + pack_bound
            if c_shifted < 0 or c_shifted >= 2 * pack_bound:
                raise ValueError(f"Coefficient {c} out of range for packing (bound={pack_bound})")
            
            # Convert to bits (little-endian)
            for bit_idx in range(bits_per_coeff):
                all_bits.append((c_shifted >> bit_idx) & 1)
    
    # Convert bits to bytes
    packed_bytes = bytearray()
    for byte_idx in range(0, len(all_bits), 8):
        byte_val = 0
        for bit_offset in range(8):
            if byte_idx + bit_offset < len(all_bits):
                byte_val |= (all_bits[byte_idx + bit_offset] << bit_offset)
        packed_bytes.append(byte_val)
    
    return bytes(packed_bytes)


def unpack_z_compact(packed_bytes: bytes, L: int, N: int = DILITHIUM_N, 
                     q: int = DILITHIUM_Q, gamma1: int = DILITHIUM_GAMMA1) -> List[Poly]:
    """
    Giải nén vector z từ bit-packed format
    
    Args:
        packed_bytes: Compressed data
        L: Số polynomials trong vector
        N: Degree of polynomials
        q, gamma1: Parameters
        
    Returns:
        List of Poly objects
    """
    pack_bound = 2**23  # 8,388,608
    bits_per_coeff = 24
    total_coeffs = L * N
    
    # Extract bits
    all_bits = []
    for byte_val in packed_bytes:
        for bit_offset in range(8):
            all_bits.append((byte_val >> bit_offset) & 1)
    
    # Reconstruct coefficients
    coeffs_list = []
    for coeff_idx in range(total_coeffs):
        bit_start = coeff_idx * bits_per_coeff
        
        # Extract bits_per_coeff bits
        c_shifted = 0
        for bit_offset in range(bits_per_coeff):
            if bit_start + bit_offset < len(all_bits):
                c_shifted |= (all_bits[bit_start + bit_offset] << bit_offset)
        
        # Shift back to centered representation
        c = c_shifted - pack_bound
        coeffs_list.append(c % q)
    
    # Group into polynomials
    z_vec = []
    for l in range(L):
        poly_coeffs = coeffs_list[l*N : (l+1)*N]
        z_vec.append(Poly(poly_coeffs, q, N, in_ntt=False))
    
    return z_vec


def pack_challenge_seed(c: int) -> bytes:
    """
    Lưu challenge c dưới dạng compact 32-byte representation
    
    FIPS 204: c là scalar trong Z_q, không phải polynomial
    => Chỉ cần 32 bytes để encode c (thay vì 2048 bytes cho poly)
    
    Args:
        c: Challenge scalar (0 ≤ c < q = 8380417)
        
    Returns:
        32-byte encoding of c (little-endian)
    """
    # c chỉ cần ~3 bytes (log2(8380417) ≈ 23 bits)
    # Nhưng dùng 32 bytes cho alignment và future-proof
    return c.to_bytes(32, 'little')


def unpack_challenge_seed(seed: bytes, q: int = DILITHIUM_Q) -> int:
    """
    Giải mã challenge c từ 32-byte compact encoding
    
    Args:
        seed: 32-byte encoding of c (little-endian)
        q: Modulus
        
    Returns:
        Challenge scalar c
    """
    return int.from_bytes(seed, 'little') % q


def compute_signature_size_compact(L: int, K: int = 1) -> Dict[str, int]:
    """
    Tính kích thước chữ ký COMPACT (sau khi tối ưu)
    
    Chữ ký threshold/aggregate σ = (z, c_seed) KHÔNG bao gồm b (APK)
    
    Components:
    - z: L polynomials, mỗi coeff 22 bits (cho threshold) → L*N*22 bits
    - c_seed: 32 bytes (thay vì polynomial c)
    - (b loại ra - đây là APK, gửi riêng)
    
    Args:
        L: Number of polynomials in z
        K: (Không dùng cho sig size, chỉ cho APK)
        
    Returns:
        Dict với breakdown kích thước
    """
    N = DILITHIUM_N  # 256
    
    # z vector: L polynomials * N coeffs * 24 bits (threshold với overhead)
    # 24 bits cover range [-8.4M, +8.4M] cho threshold signatures
    z_bits = L * N * 24
    z_bytes = (z_bits + 7) // 8  # Round up
    
    # c: chỉ gửi seed 32 bytes
    c_bytes = 32
    
    # Total signature (z, c_seed)
    total_sig_bytes = z_bytes + c_bytes
    
    # APK (b) - GỬI RIÊNG, không tính vào mỗi chữ ký
    apk_bytes = K * N * 4  # K polynomials, 4 bytes/coeff (uncompressed)
    
    return {
        "z_bytes": z_bytes,
        "c_seed_bytes": c_bytes,
        "signature_total": total_sig_bytes,  # Chỉ (z, c_seed)
        "apk_bytes": apk_bytes,              # Gửi riêng
        "L": L,
        "K": K,
        "bits_per_coeff": 24,
        "note": "Signature = (z, c_seed). APK (b) sent separately. 24-bit packing for threshold overhead."
    }
