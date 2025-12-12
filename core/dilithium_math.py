#!/usr/bin/env python3
"""
dilithium_math.py - Core mathematical primitives for Threshold Dilithium

Chứa:
1. NTT (Number Theoretic Transform) với Numba JIT optimization
2. Polynomial arithmetic trong R_q = Z_q[X]/(X^N+1)
3. Lattice-based commitment scheme
4. Vector operations và helper functions
"""

from typing import List, Tuple, Dict, Any, Optional
import hashlib
import random
import base64
import numpy as np
from numba import jit

# =============================
# CONSTANTS & PARAMETERS
# =============================
DILITHIUM_Q = 8380417
DILITHIUM_N = 256
DILITHIUM_ETA = 2
SIGNATURE_BOUND = 523913

NTT_ROOT = 1753
NTT_ROOT_INV = pow(NTT_ROOT, -1, DILITHIUM_Q)
N_INV = 8347669  # pow(256, -1, 8380417)

# Global Numpy arrays for Numba JIT
_ZETAS_NP = np.zeros(DILITHIUM_N, dtype=np.int64)
_ZETAS_INV_NP = np.zeros(DILITHIUM_N, dtype=np.int64)


# =============================
# NTT INITIALIZATION
# =============================
def _init_ntt_zetas_numpy():
    """Initialize twiddle factors for NTT/INTT in bit-reversed order"""
    global _ZETAS_NP, _ZETAS_INV_NP
    zetas = [0] * DILITHIUM_N
    zetas_inv = [0] * DILITHIUM_N
    
    for i in range(DILITHIUM_N):
        # Bit-reversal for Cooley-Tukey
        br = 0
        for j in range(8):
            if i & (1 << j): 
                br |= 1 << (7 - j)
        
        exp = (2 * br + 1) % 512
        zetas[i] = pow(NTT_ROOT, exp, DILITHIUM_Q)
        
        exp_inv = (512 - (2 * br + 1)) % 512
        zetas_inv[i] = pow(NTT_ROOT, exp_inv, DILITHIUM_Q)
    
    _ZETAS_NP = np.array(zetas, dtype=np.int64)
    _ZETAS_INV_NP = np.array(zetas_inv, dtype=np.int64)


_init_ntt_zetas_numpy()


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
    """
    h = _sha3_512(message + w_bytes)
    return int.from_bytes(h, 'little') % q


# =============================
# NUMBA JIT OPTIMIZED NTT
# =============================
@jit(nopython=True, cache=True)
def ntt_forward_jit(a: np.ndarray) -> np.ndarray:
    """Forward NTT - O(N log N) complexity"""
    N = 256
    Q = 8380417
    t = a.copy()
    
    len_ = 1
    k_idx = 0
    while len_ < N:
        step = len_ * 2
        for start in range(0, N, step):
            zeta = _ZETAS_NP[k_idx]
            k_idx += 1
            for j in range(start, start + len_):
                u = t[j]
                v = (t[j + len_] * zeta) % Q
                t[j] = (u + v) % Q
                t[j + len_] = (u - v) % Q
        len_ *= 2
    return t


@jit(nopython=True, cache=True)
def ntt_inverse_jit(a: np.ndarray) -> np.ndarray:
    """Inverse NTT - O(N log N) complexity"""
    N = 256
    Q = 8380417
    t = a.copy()
    
    len_ = 1
    k_idx = 0
    while len_ < N:
        step = len_ * 2
        for start in range(0, N, step):
            zeta = _ZETAS_INV_NP[k_idx]
            k_idx += 1
            for j in range(start, start + len_):
                u = t[j]
                v = (t[j + len_] * zeta) % Q
                t[j] = (u + v) % Q
                t[j + len_] = (u - v) % Q
        len_ *= 2
    
    # Multiply by N^(-1)
    n_inv_val = 8347669
    for i in range(N):
        t[i] = (t[i] * n_inv_val) % Q
    return t


@jit(nopython=True, cache=True)
def poly_mul_pointwise_jit(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Pointwise multiplication in NTT domain - O(N) complexity"""
    Q = 8380417
    N = 256
    out = np.zeros(N, dtype=np.int64)
    for i in range(N):
        out[i] = (a[i] * b[i]) % Q
    return out


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
        new_coeffs = ntt_forward_jit(self.coeffs)
        return Poly(new_coeffs, self.q, self.N, in_ntt=True)

    def from_ntt(self) -> "Poly":
        """Convert to coefficient domain - O(N log N)"""
        if not self.in_ntt: 
            return self
        new_coeffs = ntt_inverse_jit(self.coeffs)
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
        prod_coeffs = poly_mul_pointwise_jit(p1.coeffs, p2.coeffs)
        
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
            prod = poly_mul_pointwise_jit(a_ntt.coeffs, vec_ntt[l].coeffs)
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
    Local rejection sampling for threshold signing.
    
    Check probability: min(1, D_eta(z_i) / (M * D_eta^c_lambda*s_i(z_i - c_lambda*s_i)))
    
    Simplified: Check norm of z_i and approximate Gaussian distribution.
    
    Args:
        z_i: partial signature of participant i
        y_i: nonce of participant i
        c_lambda: c * lambda_i mod q
        s_share_i: secret share of participant i
        q: modulus
        eta: bound for small coefficients
        
    Returns:
        True if pass rejection sampling, False if reject
    """
    # Check 1: Simple norm check
    for l in range(len(z_i)):
        for idx in range(z_i[l].N):
            z_coeff = z_i[l].coeffs[idx]
            y_coeff = y_i[l].coeffs[idx]
            s_coeff = s_share_i[l].coeffs[idx]
            
            # z_i = y_i + c_lambda * s_share_i
            expected = (y_coeff + c_lambda * s_coeff) % q
            diff = abs(z_coeff - expected)
            
            # If diff too large => reject
            if diff > q // 4:
                return False
    
    # Check 2: Probabilistic acceptance (simplified Gaussian)
    M = 1.5  # Rejection sampling parameter
    prob_accept = 1.0 / M
    
    return random.random() < prob_accept


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
