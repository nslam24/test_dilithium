#!/usr/bin/env python3
"""
Debug NTT implementation
"""
from modes.threshold_dilithium import Poly, DILITHIUM_Q, DILITHIUM_N, NTT_ROOT

def test_root_value():
    """Check if NTT_ROOT is correct"""
    print("Testing NTT_ROOT value:")
    print(f"  NTT_ROOT (ω) = {NTT_ROOT}")
    
    # ω should be 512th root: ω^512 = 1, ω^256 = -1
    omega_512 = pow(NTT_ROOT, 512, DILITHIUM_Q)
    omega_256 = pow(NTT_ROOT, 256, DILITHIUM_Q)
    print(f"  ω^512 mod q = {omega_512} (should be 1)")
    print(f"  ω^256 mod q = {omega_256} (should be {DILITHIUM_Q-1} = -1 mod q)")
    print()

def test_simple_multiply():
    """Test simplest case: (1) * (1)"""
    print("Testing (1) * (1):")
    
    a = Poly([1] + [0] * (DILITHIUM_N - 1), DILITHIUM_Q, DILITHIUM_N)
    b = Poly([1] + [0] * (DILITHIUM_N - 1), DILITHIUM_Q, DILITHIUM_N)
    
    c_ntt = a.mul(b)
    c_naive = a.mul_naive(b)
    
    print(f"  NTT result (first 8): {c_ntt.coeffs[:8]}")
    print(f"  Naive result (first 8): {c_naive.coeffs[:8]}")
    print(f"  Match: {c_ntt.coeffs == c_naive.coeffs}")
    print()

def test_x_multiply():
    """Test: X * X = X^2"""
    print("Testing X * X = X^2:")
    
    a = Poly([0, 1] + [0] * (DILITHIUM_N - 2), DILITHIUM_Q, DILITHIUM_N)
    b = Poly([0, 1] + [0] * (DILITHIUM_N - 2), DILITHIUM_Q, DILITHIUM_N)
    
    c_ntt = a.mul(b)
    c_naive = a.mul_naive(b)
    
    print(f"  NTT result (first 8): {c_ntt.coeffs[:8]}")
    print(f"  Naive result (first 8): {c_naive.coeffs[:8]}")
    print(f"  Expected: [0, 0, 1, 0, 0, ...]")
    print(f"  Match: {c_ntt.coeffs == c_naive.coeffs}")
    print()

def test_xn_multiply():
    """Test: X^255 * X = X^256 = -1 (mod X^N+1)"""
    print(f"Testing X^255 * X = X^256 = -1 (mod X^N+1):")
    
    a = Poly([0] * 255 + [1], DILITHIUM_Q, DILITHIUM_N)
    b = Poly([0, 1] + [0] * (DILITHIUM_N - 2), DILITHIUM_Q, DILITHIUM_N)
    
    c_ntt = a.mul(b)
    c_naive = a.mul_naive(b)
    
    print(f"  NTT result (first 8): {c_ntt.coeffs[:8]}")
    print(f"  Naive result (first 8): {c_naive.coeffs[:8]}")
    print(f"  Expected: [{DILITHIUM_Q-1}, 0, 0, ...] = [-1, 0, 0, ...]")
    print(f"  Match: {c_ntt.coeffs == c_naive.coeffs}")
    print()

if __name__ == "__main__":
    print("=" * 60)
    print("NTT Debug Tests")
    print("=" * 60 + "\n")
    
    test_root_value()
    test_simple_multiply()
    test_x_multiply()
    test_xn_multiply()
