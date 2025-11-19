#!/usr/bin/env python3
"""
Test NTT implementation correctness
"""
from modes.threshold_dilithium import Poly, DILITHIUM_Q, DILITHIUM_N

def test_ntt_basic():
    """Test that NTT → INTT returns original polynomial"""
    print("Test 1: NTT round-trip")
    
    # Create a simple polynomial
    coeffs = [1, 2, 3, 4] + [0] * (DILITHIUM_N - 4)
    p = Poly(coeffs, DILITHIUM_Q, DILITHIUM_N)
    
    # Transform to NTT and back
    p_ntt = p.to_ntt()
    p_back = p_ntt.from_ntt()
    
    # Check if we get back the original
    match = all(c1 == c2 for c1, c2 in zip(p.coeffs, p_back.coeffs))
    print(f"  Original coeffs (first 8): {p.coeffs[:8]}")
    print(f"  After NTT→INTT (first 8): {p_back.coeffs[:8]}")
    print(f"  Match: {match}")
    assert match, "NTT round-trip failed"
    print("  ✅ PASSED\n")

def test_ntt_multiplication():
    """Test that NTT multiplication matches naive multiplication"""
    print("Test 2: NTT multiplication vs naive")
    
    # Two simple polynomials
    a_coeffs = [1, 2, 3] + [0] * (DILITHIUM_N - 3)
    b_coeffs = [4, 5] + [0] * (DILITHIUM_N - 2)
    
    a = Poly(a_coeffs, DILITHIUM_Q, DILITHIUM_N)
    b = Poly(b_coeffs, DILITHIUM_Q, DILITHIUM_N)
    
    # Multiply using NTT
    c_ntt = a.mul(b)
    
    # Multiply using naive method
    c_naive = a.mul_naive(b)
    
    # Compare
    match = all(c1 == c2 for c1, c2 in zip(c_ntt.coeffs, c_naive.coeffs))
    print(f"  NTT result (first 8): {c_ntt.coeffs[:8]}")
    print(f"  Naive result (first 8): {c_naive.coeffs[:8]}")
    print(f"  Match: {match}")
    assert match, "NTT multiplication doesn't match naive"
    print("  ✅ PASSED\n")

def test_domain_tracking():
    """Test that domain tracking works correctly"""
    print("Test 3: Domain tracking")
    
    p = Poly([1, 2, 3] + [0] * (DILITHIUM_N - 3), DILITHIUM_Q, DILITHIUM_N)
    
    print(f"  Initial: in_ntt={p.in_ntt}")
    assert not p.in_ntt, "Should start in coefficient domain"
    
    p_ntt = p.to_ntt()
    print(f"  After to_ntt(): in_ntt={p_ntt.in_ntt}")
    assert p_ntt.in_ntt, "Should be in NTT domain"
    
    p_back = p_ntt.from_ntt()
    print(f"  After from_ntt(): in_ntt={p_back.in_ntt}")
    assert not p_back.in_ntt, "Should be back in coefficient domain"
    print("  ✅ PASSED\n")

def test_serialization():
    """Test that serialization handles NTT domain correctly"""
    print("Test 4: Serialization with NTT domain")
    
    p = Poly([1, 2, 3, 4, 5] + [0] * (DILITHIUM_N - 5), DILITHIUM_Q, DILITHIUM_N)
    
    # Serialize from coefficient domain
    bytes1 = p.to_bytes()
    
    # Convert to NTT and serialize (should auto-convert back)
    p_ntt = p.to_ntt()
    bytes2 = p_ntt.to_bytes()
    
    # Should be identical
    match = bytes1 == bytes2
    print(f"  Coefficient bytes (first 20): {bytes1[:20].hex()}")
    print(f"  NTT bytes (first 20): {bytes2[:20].hex()}")
    print(f"  Match: {match}")
    assert match, "Serialization should be identical regardless of domain"
    
    # Deserialize and check
    p_restored = Poly.from_bytes(bytes1)
    assert not p_restored.in_ntt, "Deserialized poly should be in coefficient domain"
    print("  ✅ PASSED\n")

def test_performance_hint():
    """Quick timing comparison (not a strict test)"""
    print("Test 5: Performance hint (NTT vs Naive)")
    import time
    
    # Larger coefficients to see difference
    a = Poly([i % 100 for i in range(DILITHIUM_N)], DILITHIUM_Q, DILITHIUM_N)
    b = Poly([(i * 2) % 100 for i in range(DILITHIUM_N)], DILITHIUM_Q, DILITHIUM_N)
    
    # Time naive
    t0 = time.perf_counter()
    for _ in range(10):
        _ = a.mul_naive(b)
    t_naive = time.perf_counter() - t0
    
    # Time NTT
    t0 = time.perf_counter()
    for _ in range(10):
        _ = a.mul(b)
    t_ntt = time.perf_counter() - t0
    
    speedup = t_naive / t_ntt if t_ntt > 0 else 0
    print(f"  Naive (10x): {t_naive*1000:.2f} ms")
    print(f"  NTT (10x): {t_ntt*1000:.2f} ms")
    print(f"  Speedup: {speedup:.2f}×")
    print("  ℹ️  (Note: Speedup will be higher for matrix operations)\n")

if __name__ == "__main__":
    print("=" * 60)
    print("NTT Implementation Correctness Tests")
    print("=" * 60 + "\n")
    
    try:
        test_ntt_basic()
        test_ntt_multiplication()
        test_domain_tracking()
        test_serialization()
        test_performance_hint()
        
        print("=" * 60)
        print("✅ All tests PASSED!")
        print("=" * 60)
        print("\n🚀 NTT optimization is ready for benchmarking")
        print("   Run: python modes/threshold_dilithium.py 10")
        
    except AssertionError as e:
        print(f"\n❌ Test FAILED: {e}")
        exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
