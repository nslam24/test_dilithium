#!/usr/bin/env python3
"""
benchmark_dkg_levels.py - Benchmark DKG với các level Dilithium

So sánh hiệu năng của DKG threshold signature qua 3 levels:
- Level 2: 128-bit security (K=4, L=4, η=2)
- Level 3: 192-bit security (K=6, L=5, η=4)
- Level 5: 256-bit security (K=8, L=7, η=2)

Metrics:
- Key generation time
- Signing time (average attempts)
- Signature size
- Acceptance rate
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modes/threshold_gaussian'))

from keygen import run_dkg_protocol
from signing import sign_threshold_dkg, aggregate_signatures_dkg, verify_threshold_dkg


def calculate_poly_vec_size(poly_vec):
    """Calculate size in bytes of polynomial vector."""
    size = 0
    for poly in poly_vec:
        # Each coefficient: log2(q) bits ≈ 23 bits ≈ 3 bytes
        size += len(poly.coeffs) * 3
    return size


def benchmark_level(level: int, n: int, t: int, num_runs: int = 10):
    """
    Benchmark một level Dilithium cụ thể.
    
    Args:
        level: Dilithium level (2, 3, 5)
        n: Total users
        t: Threshold
        num_runs: Number of signing runs
    
    Returns:
        Dict with benchmark results
    """
    print(f"\n{'='*80}")
    print(f"BENCHMARK: Dilithium Level {level} - {t}-of-{n} Threshold")
    print(f"{'='*80}")
    
    # Key Generation
    print(f"\n[1/4] Key Generation...", end=" ", flush=True)
    keygen_start = time.perf_counter()
    
    try:
        keypairs, pk = run_dkg_protocol(n, t, level)
    except Exception as e:
        print(f"\n❌ FAILED: {e}")
        return None
    
    keygen_time = time.perf_counter() - keygen_start
    print(f"✓ ({keygen_time:.3f}s)")
    
    # Analyze secret sizes
    kp = keypairs[0]
    s1_norm = sum(c**2 for poly in kp['small_secret_s1'] 
                  for c in poly.get_centered_coeffs())**0.5
    x1_norm = sum(c**2 for poly in kp['shamir_share_x1'] 
                  for c in poly.get_centered_coeffs())**0.5
    
    print(f"   ||s1|| (small) = {s1_norm:.0f}")
    print(f"   ||x1|| (large) = {x1_norm:.0f}")
    print(f"   Ratio = {x1_norm/s1_norm:.0f}x")
    
    # Signing (multiple runs)
    print(f"\n[2/4] Signing ({num_runs} runs)...", end=" ", flush=True)
    
    message = b"Benchmark message for Dilithium threshold signature"
    signer_uids = list(range(1, t + 1))
    
    signing_times = []
    per_user_times = []  # NEW: Track per-user signing times
    attempts_list = []
    data_transfers = []  # NEW: Track data transfer per run
    successful_runs = 0
    
    for run in range(num_runs):
        partial_sigs = []
        run_attempts = 0
        run_start = time.perf_counter()
        run_user_times = []
        run_data_sent = 0  # Data sent by all users in this run
        
        try:
            for uid in signer_uids:
                keypair = keypairs[uid - 1]
                
                user_start = time.perf_counter()
                partial_sig = sign_threshold_dkg(
                    message=message,
                    keypair_info=keypair,
                    pk=pk,
                    signer_uids=signer_uids,
                    max_attempts=100,
                    debug=False
                )
                user_time = time.perf_counter() - user_start
                run_user_times.append(user_time)
                
                # Calculate data sent by this user
                user_data = 0
                user_data += calculate_poly_vec_size(partial_sig['z'])  # z_i
                user_data += 32  # com_i hash
                user_data += calculate_poly_vec_size(partial_sig['r'])  # r_i
                run_data_sent += user_data
                
                partial_sigs.append(partial_sig)
                run_attempts += partial_sig['attempts']
            
            run_time = time.perf_counter() - run_start
            signing_times.append(run_time)
            per_user_times.extend(run_user_times)
            attempts_list.append(run_attempts)
            data_transfers.append(run_data_sent)
            successful_runs += 1
            
        except RuntimeError:
            # Failed after max attempts
            continue
    
    if successful_runs == 0:
        print(f"\n❌ FAILED: All {num_runs} runs exceeded max attempts")
        return None
    
    avg_sign_time = sum(signing_times) / len(signing_times)
    avg_per_user_time = sum(per_user_times) / len(per_user_times)
    avg_attempts = sum(attempts_list) / len(attempts_list)
    avg_data_transfer = sum(data_transfers) / len(data_transfers)
    acceptance_rate = (t / avg_attempts) * 100 if avg_attempts > 0 else 0
    
    print(f"✓ ({avg_sign_time:.3f}s avg total)")
    print(f"   Per-user time: {avg_per_user_time:.3f}s avg")
    print(f"   Attempts: {avg_attempts:.1f} avg ({min(attempts_list)}-{max(attempts_list)} range)")
    print(f"   Acceptance: {acceptance_rate:.2f}%")
    print(f"   Data transfer: {avg_data_transfer/1024:.2f} KB total ({avg_data_transfer/1024/t:.2f} KB per user)")
    
    # Aggregation
    print(f"\n[3/4] Aggregation...", end=" ", flush=True)
    agg_start = time.perf_counter()
    
    try:
        signature = aggregate_signatures_dkg(partial_sigs, pk, message, debug=False)
    except Exception as e:
        print(f"\n❌ FAILED: {e}")
        return None
    
    agg_time = time.perf_counter() - agg_start
    print(f"✓ ({agg_time:.3f}s)")
    
    # Compute signature size
    z = signature['z']
    sig_size = 0
    for poly in z:
        for coeff in poly.coeffs:
            # Each coefficient needs log2(q) bits ≈ 23 bits ≈ 3 bytes
            sig_size += 3
    
    sig_size += 32  # commitment hash
    sig_size += 8   # randomness
    sig_size_kb = sig_size / 1024
    
    print(f"   Signature size: {sig_size_kb:.2f} KB")
    
    # Verification
    print(f"\n[4/4] Verification...", end=" ", flush=True)
    verify_start = time.perf_counter()
    
    try:
        valid = verify_threshold_dkg(signature, message, pk, debug=False)
    except Exception as e:
        print(f"\n❌ FAILED: {e}")
        return None
    
    verify_time = time.perf_counter() - verify_start
    
    if valid:
        print(f"✓ ({verify_time:.3f}s)")
    else:
        print(f"\n❌ VERIFICATION FAILED!")
        return None
    
    # Results
    results = {
        'level': level,
        'n': n,
        't': t,
        'K': pk['K'],
        'L': pk['L'],
        'eta': pk['eta'],
        'keygen_time': keygen_time,
        'avg_sign_time': avg_sign_time,
        'avg_per_user_sign_time': avg_per_user_time,
        'avg_attempts': avg_attempts,
        'acceptance_rate': acceptance_rate,
        'avg_data_transfer_kb': avg_data_transfer / 1024,
        'avg_data_per_user_kb': avg_data_transfer / 1024 / t,
        'agg_time': agg_time,
        'verify_time': verify_time,
        'total_time': keygen_time + avg_sign_time + agg_time + verify_time,
        'signature_size_kb': sig_size_kb,
        's1_norm': s1_norm,
        'x1_norm': x1_norm,
        'successful_runs': successful_runs,
        'total_runs': num_runs,
    }
    
    return results


def run_full_benchmark(num_runs: int = 10):
    """
    Chạy benchmark đầy đủ cho tất cả levels.
    
    Args:
        num_runs: Number of signing runs per configuration
    """
    print("\n" + "="*80)
    print("DILITHIUM THRESHOLD SIGNATURE - DKG BENCHMARK")
    print("="*80)
    print(f"Configuration: {num_runs} runs per level")
    print(f"Threshold: 3-of-5")
    
    # Test configurations
    configs = [
        (2, 5, 3, "Level 2 (128-bit)"),
        (3, 5, 3, "Level 3 (192-bit)"),
        (5, 5, 3, "Level 5 (256-bit)"),
    ]
    
    all_results = []
    
    for level, n, t, label in configs:
        result = benchmark_level(level, n, t, num_runs)
        
        if result:
            all_results.append(result)
        else:
            print(f"\n⚠️  Skipping {label} due to failures")
    
    # Summary table
    print("\n" + "="*80)
    print("SUMMARY TABLE")
    print("="*80)
    print(f"{'Level':<8} {'K×L':<8} {'KeyGen(s)':<12} {'Sign(s)':<12} {'Verify(s)':<12} {'Size(KB)':<12} {'Accept%':<10}")
    print("-"*80)
    
    for r in all_results:
        print(f"{r['level']:<8} {r['K']}×{r['L']:<6} {r['keygen_time']:<12.3f} {r['avg_sign_time']:<12.3f} "
              f"{r['verify_time']:<12.3f} {r['signature_size_kb']:<12.2f} {r['acceptance_rate']:<10.2f}")
    
    print("-"*80)
    
    # Comparison
    if len(all_results) >= 2:
        print("\n" + "="*80)
        print("COMPARISON (relative to Level 2)")
        print("="*80)
        
        baseline = all_results[0]
        
        for r in all_results[1:]:
            keygen_ratio = r['keygen_time'] / baseline['keygen_time']
            sign_ratio = r['avg_sign_time'] / baseline['avg_sign_time']
            size_ratio = r['signature_size_kb'] / baseline['signature_size_kb']
            
            print(f"\nLevel {r['level']} vs Level 2:")
            print(f"  KeyGen: {keygen_ratio:.2f}x slower")
            print(f"  Sign:   {sign_ratio:.2f}x slower")
            print(f"  Size:   {size_ratio:.2f}x larger")
    
    # Save results
    output_file = "benchmark_dkg_levels.json"
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"\n✓ Results saved to: {output_file}")
    
    return all_results


if __name__ == '__main__':
    import sys
    
    num_runs = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    
    print(f"\n🚀 Starting DKG Benchmark")
    print(f"   Runs per level: {num_runs}")
    print(f"   Configurations: 3 levels × 3-of-5 threshold")
    
    results = run_full_benchmark(num_runs)
    
    print("\n" + "="*80)
    print("✅ BENCHMARK COMPLETE!")
    print("="*80)
