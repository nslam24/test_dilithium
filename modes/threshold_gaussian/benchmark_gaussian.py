#!/usr/bin/env python3
"""
benchmark_gaussian.py - Benchmark for Gaussian threshold scheme

Compares the new Gaussian-based scheme with:
- Different (n, t) configurations
- Different (K, L) matrix sizes
- Performance metrics: time, attempts, norm statistics
"""

import sys
import os
import time
import json
import random

# Add parent to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from modes.threshold_gaussian.trusted_dealer import trusted_dealer_setup
from modes.threshold_gaussian.threshold_sign import (
    sign_threshold_gaussian,
    verify_threshold_gaussian,
)
from modes.threshold_gaussian.gaussian_primitives import SIGMA, B_BOUND


def run_benchmark(num_runs: int = 10):
    """
    Run comprehensive benchmark comparing configurations.
    
    Scenarios:
    1. Baseline: (5, 3) with (K=1, L=1) - toy parameters
    2. Realistic: (5, 3) with (K=6, L=5) - Dilithium3-like
    3. Scalability: (10, 6) with (K=1, L=1)
    """
    
    configs = [
        # (n, t, K, L, label)
        (5, 3, 1, 1, "Baseline (5,3) K=1,L=1"),
        (5, 3, 6, 5, "Dilithium3 (5,3) K=6,L=5"),
        (10, 6, 1, 1, "Scalable (10,6) K=1,L=1"),
    ]
    
    results = []
    
    print("\n" + "=" * 80)
    print("BENCHMARK: Gaussian Threshold Signature Scheme")
    print("=" * 80)
    print(f"Parameters: σ={SIGMA}, B={B_BOUND}")
    print(f"Runs per config: {num_runs}")
    print("=" * 80)
    
    for n, t, K, L, label in configs:
        print(f"\n[CONFIG] {label}")
        print("-" * 80)
        
        try:
            # Setup
            setup_start = time.perf_counter()
            shares, pk = trusted_dealer_setup(
                n_parties=n,
                threshold=t,
                K=K,
                L=L,
            )
            setup_time = time.perf_counter() - setup_start
            
            # Run multiple signing attempts
            sign_times = []
            verify_times = []
            attempts_list = []
            norm_ratios = []
            successful = 0
            
            for run_id in range(num_runs):
                # Random subset of t signers
                signing_shares = random.sample(shares, t)
                
                # Sign
                message = f"Benchmark message {run_id}".encode()
                sig, meta = sign_threshold_gaussian(message, signing_shares, pk)
                
                if sig is None:
                    print(f"  [Run {run_id+1}] FAILED (max attempts)")
                    continue
                
                # Verify
                valid, vtime = verify_threshold_gaussian(message, sig, pk)
                
                if not valid:
                    print(f"  [Run {run_id+1}] VERIFICATION FAILED!")
                    continue
                
                # Record metrics
                sign_times.append(meta['total_time'])
                verify_times.append(vtime)
                attempts_list.append(meta['attempts'])
                norm_ratios.append(meta['norm_ratio'])
                successful += 1
                
                print(f"  [Run {run_id+1}/{num_runs}] "
                      f"Sign: {meta['total_time']:.4f}s, "
                      f"Verify: {vtime:.6f}s, "
                      f"Attempts: {meta['attempts']}, "
                      f"Norm ratio: {meta['norm_ratio']:.3f}")
            
            # Aggregate results
            if successful > 0:
                result = {
                    'config': label,
                    'n': n,
                    't': t,
                    'K': K,
                    'L': L,
                    'setup_time': setup_time,
                    'avg_sign_time': sum(sign_times) / successful,
                    'avg_verify_time': sum(verify_times) / successful,
                    'avg_attempts': sum(attempts_list) / successful,
                    'avg_norm_ratio': sum(norm_ratios) / successful,
                    'successful_runs': successful,
                    'total_runs': num_runs,
                    'success_rate': successful / num_runs,
                }
                
                results.append(result)
                
                print(f"\n  [SUMMARY]")
                print(f"    Success rate: {result['success_rate']*100:.1f}%")
                print(f"    Avg sign time: {result['avg_sign_time']:.4f}s")
                print(f"    Avg verify time: {result['avg_verify_time']:.6f}s")
                print(f"    Avg attempts: {result['avg_attempts']:.2f}")
                print(f"    Avg norm ratio: {result['avg_norm_ratio']:.3f}")
            else:
                print(f"  [SUMMARY] All runs failed!")
                
        except Exception as e:
            print(f"  [ERROR] {e}")
            import traceback
            traceback.print_exc()
            continue
    
    # Print comparison table
    print("\n" + "=" * 80)
    print("COMPARISON TABLE")
    print("=" * 80)
    print(f"{'Config':<30} {'Sign(s)':<10} {'Verify(s)':<12} {'Attempts':<10} {'Norm%':<8}")
    print("-" * 80)
    
    for r in results:
        print(f"{r['config']:<30} "
              f"{r['avg_sign_time']:<10.4f} "
              f"{r['avg_verify_time']:<12.6f} "
              f"{r['avg_attempts']:<10.2f} "
              f"{r['avg_norm_ratio']*100:<8.1f}")
    
    print("=" * 80)
    
    # Save results
    output_file = "benchmark_gaussian_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Results saved to {output_file}")
    
    return results


if __name__ == '__main__':
    num_runs = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    
    print(f"\n[STARTING BENCHMARK - {num_runs} runs per configuration]")
    
    results = run_benchmark(num_runs=num_runs)
    
    print("\n✓ Benchmark completed successfully")
