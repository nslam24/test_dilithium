#!/usr/bin/env python3
"""
linalg.py - Linear Algebra Operations for Module Lattices

Định nghĩa toán học:
- R_q^k: Vector space of k polynomials over R_q
- Matrix operations: matrix-vector multiplication, vector addition
- Naming convention: Chữ in đậm trong toán học → snake_case trong code
  - A (matrix) → A
  - v (vector) → v or vec
  - A·v (matvec) → matvec_mul(A, v)
"""
from typing import List
from .poly_ring import Poly, DILITHIUM_Q, DILITHIUM_N


# =============================
# VECTOR OPERATIONS (R_q^k)
# =============================

def vec_zeros(k: int, q: int = DILITHIUM_Q, N: int = DILITHIUM_N) -> List[Poly]:
    """
    Create zero vector in R_q^k.
    
    Args:
        k: Vector dimension
        q: Modulus
        N: Polynomial degree
        
    Returns:
        [0, 0, ..., 0] (k polynomials)
    """
    return [Poly.zeros(q, N) for _ in range(k)]


def vec_add(a: List[Poly], b: List[Poly]) -> List[Poly]:
    """
    Vector addition in R_q^k: a + b.
    
    Args:
        a: Vector of k polynomials
        b: Vector of k polynomials
        
    Returns:
        a + b (componentwise)
    """
    if len(a) != len(b):
        raise ValueError(f"Vector length mismatch: {len(a)} vs {len(b)}")
    return [ai.add(bi) for ai, bi in zip(a, b)]


def vec_sub(a: List[Poly], b: List[Poly]) -> List[Poly]:
    """
    Vector subtraction in R_q^k: a - b.
    
    Args:
        a: Vector of k polynomials
        b: Vector of k polynomials
        
    Returns:
        a - b (componentwise)
    """
    if len(a) != len(b):
        raise ValueError(f"Vector length mismatch: {len(a)} vs {len(b)}")
    return [ai.sub(bi) for ai, bi in zip(a, b)]


def vec_scalar_mul(v: List[Poly], c: int) -> List[Poly]:
    """
    Scalar multiplication: c·v.
    
    Args:
        v: Vector of polynomials
        c: Scalar (integer mod q)
        
    Returns:
        c·v (componentwise)
    """
    return [vi.scalar_mul(c) for vi in v]


def vec_poly_mul(v: List[Poly], p: Poly) -> List[Poly]:
    """
    Polynomial multiplication with vector: v·p.
    
    Multiplies each element of vector v by polynomial p.
    
    Args:
        v: Vector of polynomials
        p: Polynomial
        
    Returns:
        [v[0]·p, v[1]·p, ..., v[k-1]·p]
    """
    return [vi.mul(p) for vi in v]


def vec_check_norm(vec: List[Poly], bound: int) -> bool:
    """
    Check if all polynomials in vector satisfy norm bound.
    
    Args:
        vec: Vector of polynomials
        bound: Infinity norm bound B
        
    Returns:
        True if ∀i: ‖vec[i]‖_∞ ≤ bound, False otherwise
    """
    return all(p.check_norm(bound) for p in vec)


# =============================
# MATRIX-VECTOR OPERATIONS
# =============================

def matvec_mul(A: List[List[Poly]], v: List[Poly]) -> List[Poly]:
    """
    Matrix-vector multiplication: A·v.
    
    A ∈ R_q^(k×ℓ), v ∈ R_q^ℓ → A·v ∈ R_q^k
    
    Args:
        A: Matrix of polynomials (k rows, ℓ columns)
        v: Vector of polynomials (length ℓ)
        
    Returns:
        A·v (vector of length k)
        
    Example:
        A = [[a11, a12], [a21, a22]]  # 2×2 matrix
        v = [v1, v2]                   # vector of length 2
        Result: [a11·v1 + a12·v2, a21·v1 + a22·v2]
    """
    k = len(A)  # Number of rows
    if k == 0:
        return []
    
    ell = len(A[0])  # Number of columns
    if len(v) != ell:
        raise ValueError(f"Dimension mismatch: A is {k}×{ell}, v has length {len(v)}")
    
    q = v[0].q
    N = v[0].N
    
    result = []
    for i in range(k):
        # Compute i-th component: Σ_j A[i][j]·v[j]
        acc = Poly.zeros(q, N)
        for j in range(ell):
            acc = acc.add(A[i][j].mul(v[j]))
        result.append(acc)
    
    return result


def matmat_mul(A: List[List[Poly]], B: List[List[Poly]]) -> List[List[Poly]]:
    """
    Matrix-matrix multiplication: A·B.
    
    A ∈ R_q^(m×n), B ∈ R_q^(n×p) → A·B ∈ R_q^(m×p)
    
    Args:
        A: Matrix (m×n)
        B: Matrix (n×p)
        
    Returns:
        A·B (matrix m×p)
    """
    m = len(A)
    if m == 0:
        return []
    
    n = len(A[0])
    if len(B) != n:
        raise ValueError(f"Dimension mismatch: A is {m}×{n}, B has {len(B)} rows")
    
    p = len(B[0]) if B else 0
    
    q = A[0][0].q
    N = A[0][0].N
    
    result = [[Poly.zeros(q, N) for _ in range(p)] for _ in range(m)]
    
    for i in range(m):
        for j in range(p):
            acc = Poly.zeros(q, N)
            for k in range(n):
                acc = acc.add(A[i][k].mul(B[k][j]))
            result[i][j] = acc
    
    return result


# =============================
# SPECIALIZED OPERATIONS
# =============================

def inner_product(a: List[Poly], b: List[Poly]) -> Poly:
    """
    Inner product (dot product) of two vectors: ⟨a, b⟩ = Σ a_i·b_i.
    
    Args:
        a: Vector of polynomials (length k)
        b: Vector of polynomials (length k)
        
    Returns:
        Single polynomial (sum of products)
    """
    if len(a) != len(b):
        raise ValueError(f"Vector length mismatch: {len(a)} vs {len(b)}")
    
    if not a:
        return Poly.zeros()
    
    q = a[0].q
    N = a[0].N
    result = Poly.zeros(q, N)
    
    for ai, bi in zip(a, b):
        result = result.add(ai.mul(bi))
    
    return result


def hadamard_product(a: List[Poly], b: List[Poly]) -> List[Poly]:
    """
    Hadamard (elementwise) product: a ∘ b = [a[0]·b[0], ..., a[k-1]·b[k-1]].
    
    Args:
        a: Vector of polynomials
        b: Vector of polynomials
        
    Returns:
        Elementwise product vector
    """
    if len(a) != len(b):
        raise ValueError(f"Vector length mismatch: {len(a)} vs {len(b)}")
    return [ai.mul(bi) for ai, bi in zip(a, b)]
