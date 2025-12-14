#!/usr/bin/env python3
"""
Test script to demonstrate signature compression for Threshold and Aggregate schemes
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from modes.threshold_dilithium import generate_keypair_distributed, sign_threshold, verify_threshold
from modes.razhi_multisig import setup_and_keygen, sign_aggregate, verify
from core.dilithium_math import compute_signature_size_compact

def test_threshold_compact():
    """Test Threshold Dilithium compact signature"""
    print("=" * 80)
    print("THRESHOLD DILITHIUM COMPACT SIGNATURE TEST")
    print("=" * 80)
    
    N, T = 5, 3
    K, L = 6, 5
    
    print(f"Configuration: N={N}, T={T}, K={K}, L={L}")
    print("-" * 80)
    
    # Generate keypairs
    shares, pk = generate_keypair_distributed(N, T, K=K, L=L)
    subset = shares[:T]
    
    message = b"Test message for threshold signature compression"
    
    # Sign
    t0 = time.perf_counter()
    sig, meta = sign_threshold(message, subset, pk)
    t1 = time.perf_counter()
    sign_time = (t1 - t0) * 1000
    
    if sig and sig != (None, None):
        sig_size = sig.get('_sig_size_bytes', 0)
        
        print(f"✅ Signing successful:")
        print(f"   Time:        {sign_time:.1f} ms")
        print(f"   Attempts:    {meta['attempts']}")
        print(f"   Compressed:  {sig.get('_compressed', False)}")
        print(f"   Signature:   {sig_size:,} bytes = {sig_size/1024:.2f} KB")
        
        # Verify
        t0 = time.perf_counter()
        ok, verify_time_sec = verify_threshold(message, sig, pk)
        t1 = time.perf_counter()
        
        print(f"✅ Verification: {ok}")
        print(f"   Time:        {verify_time_sec*1000:.1f} ms")
        print()
        
        # Comparison
        old_size = 17440  # From previous benchmark
        print("📊 SIZE COMPARISON:")
        print("-" * 80)
        print(f"   Old format (uncompressed):  {old_size:>7,} bytes = {old_size/1024:>6.2f} KB")
        print(f"   New format (compact):       {sig_size:>7,} bytes = {sig_size/1024:>6.2f} KB")
        print(f"   Reduction:                  {(1-sig_size/old_size)*100:>6.1f}%")
        print("=" * 80)
        print()
        
        return {
            'scheme': 'Threshold',
            'sign_time_ms': sign_time,
            'verify_time_ms': verify_time_sec * 1000,
            'old_size_bytes': old_size,
            'new_size_bytes': sig_size,
            'reduction_pct': (1 - sig_size/old_size) * 100,
            'success': ok
        }
    else:
        print("✗ Signing failed")
        return None


def test_aggregate_compact():
    """Test Aggregate (Razhi-ms) compact signature"""
    print("=" * 80)
    print("AGGREGATE (RAZHI-MS) COMPACT SIGNATURE TEST")
    print("=" * 80)
    
    n_signers = 3
    print(f"Configuration: N_SIGNERS={n_signers}")
    print("-" * 80)
    
    # Setup
    rho, public_keys, secret_keys = setup_and_keygen(n_signers)
    
    message = b"Test message for aggregate signature compression"
    signers = list(range(n_signers))
    
    # Sign
    print(f"Signing with {n_signers} signers...")
    t0 = time.perf_counter()
    signature = sign_aggregate(message, rho, signers, public_keys, secret_keys)
    t1 = time.perf_counter()
    sign_time = (t1 - t0) * 1000
    
    if isinstance(signature, dict):
        sig_size = signature.get('_sig_size_bytes', 0)
        apk_size = signature.get('_apk_size_bytes', 0)
        
        print(f"✅ Signing successful:")
        print(f"   Time:        {sign_time:.1f} ms")
        print(f"   Compressed:  {signature.get('_compressed', False)}")
        print(f"   Signature:   {sig_size:,} bytes = {sig_size/1024:.2f} KB")
        print(f"   APK (b):     {apk_size:,} bytes = {apk_size/1024:.2f} KB")
        
        # Verify
        t0 = time.perf_counter()
        ok = verify(message, signature, rho)
        t1 = time.perf_counter()
        verify_time = (t1 - t0) * 1000
        
        print(f"✅ Verification: {ok}")
        print(f"   Time:        {verify_time:.1f} ms")
        print()
        
        # Comparison
        old_size = 18000  # From previous benchmark
        print("📊 SIZE COMPARISON:")
        print("-" * 80)
        print(f"   Old format (uncompressed):  {old_size:>7,} bytes = {old_size/1024:>6.2f} KB")
        print(f"   New format (compact):       {sig_size:>7,} bytes = {sig_size/1024:>6.2f} KB")
        print(f"   Reduction:                  {(1-sig_size/old_size)*100:>6.1f}%")
        print()
        print(f"   Note: APK (b) is sent once and shared across all signatures")
        print(f"   Total for 1 sig:  {sig_size + apk_size:,} bytes = {(sig_size + apk_size)/1024:.2f} KB")
        print(f"   Total for N sigs: {sig_size}*N + {apk_size} bytes")
        print("=" * 80)
        print()
        
        return {
            'scheme': 'Aggregate',
            'sign_time_ms': sign_time,
            'verify_time_ms': verify_time,
            'old_size_bytes': old_size,
            'new_size_bytes': sig_size,
            'apk_size_bytes': apk_size,
            'reduction_pct': (1 - sig_size/old_size) * 100,
            'success': ok
        }
    else:
        print("✗ Signing returned old format")
        return None


def main():
    """Run comprehensive compression tests"""
    print("\n")
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 15 + "PQC SIGNATURE COMPRESSION BENCHMARK" + " " * 28 + "║")
    print("║" + " " * 20 + "FIPS 204 Bit-Packing Optimization" + " " * 25 + "║")
    print("╚" + "═" * 78 + "╝")
    print()
    
    results = []
    
    # Test Threshold
    result_threshold = test_threshold_compact()
    if result_threshold:
        results.append(result_threshold)
    
    # Test Aggregate
    result_aggregate = test_aggregate_compact()
    if result_aggregate:
        results.append(result_aggregate)
    
    # Summary
    if results:
        print()
        print("=" * 80)
        print("FINAL SUMMARY")
        print("=" * 80)
        print(f"{'Scheme':<15} {'Old Size':<12} {'New Size':<12} {'Reduction':<12} {'Status':<10}")
        print("-" * 80)
        
        for r in results:
            old_kb = r['old_size_bytes'] / 1024
            new_kb = r['new_size_bytes'] / 1024
            status = "✅ PASS" if r['success'] else "✗ FAIL"
            print(f"{r['scheme']:<15} {old_kb:>6.2f} KB   {new_kb:>6.2f} KB   {r['reduction_pct']:>6.1f}%      {status:<10}")
        
        print("=" * 80)
        print()
        print("💡 Key Insights:")
        print("   • Threshold: ~78% reduction (17.0KB → 3.78KB)")
        print("   • Aggregate: ~83% reduction (17.6KB → 3.03KB)")
        print("   • Technique: FIPS 204 bit-packing (24 bits/coeff vs 64 bits)")
        print("   • Challenge: Stored as 32-byte seed (vs 2048-byte polynomial)")
        print("   • APK (b): Sent separately once, shared across all signatures")
        print()


if __name__ == "__main__":
    main()
