#!/usr/bin/env python3
"""
Test riêng cho Aggregate (Razhi-ms) với timeout
"""
import sys
import os
import time
import signal
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modes.razhi_multisig import setup, keygen, sign_aggregate, verify

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Execution timed out")

def test_aggregate_with_timeout(n_signers, timeout_sec=30):
    """Test với timeout"""
    # Set alarm
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout_sec)
    
    try:
        print(f"\n🔬 TEST AGGREGATE N={n_signers} (timeout={timeout_sec}s)")
        print("-"*60)
        
        # Setup & Keygen
        t0 = time.perf_counter()
        rho = setup()
        pks = {}
        sks = {}
        for i in range(n_signers):
            pk, sk = keygen(rho, i)
            pks[i] = pk
            sks[i] = sk
        t_keygen = time.perf_counter() - t0
        
        print(f"  ✓ Keygen: {t_keygen*1000:.1f}ms")
        
        # Sign
        msg = b'Benchmark test message'
        signers = list(range(n_signers))
        
        t0 = time.perf_counter()
        sig = sign_aggregate(msg, rho, signers, pks, sks)
        t_sign = time.perf_counter() - t0
        
        print(f"  ✓ Sign: {t_sign*1000:.1f}ms")
        
        # Verify
        t0 = time.perf_counter()
        ok = verify(msg, sig, rho)
        t_verify = time.perf_counter() - t0
        
        print(f"  ✓ Verify: {t_verify*1000:.1f}ms, Valid: {ok}")
        
        # Signature size
        sig_size = len(sig[0]) + len(sig[1]) + len(sig[2])
        print(f"  ✓ Signature size: {sig_size/1024:.2f}KB")
        
        signal.alarm(0)  # Cancel alarm
        return {
            'success': True,
            'keygen_ms': t_keygen*1000,
            'sign_ms': t_sign*1000,
            'verify_ms': t_verify*1000,
            'sig_size_kb': sig_size/1024
        }
        
    except TimeoutError:
        signal.alarm(0)
        print(f"  ✗ TIMEOUT after {timeout_sec}s")
        return {'success': False, 'reason': 'timeout'}
        
    except Exception as e:
        signal.alarm(0)
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return {'success': False, 'reason': str(e)}

def main():
    print("\n" + "="*80)
    print("BENCHMARK: RAZHI-MS AGGREGATE MULTI-SIGNATURE")
    print("="*80)
    print("⚠️  Warning: Aggregate có rejection sampling cao, có thể chậm")
    print("="*80)
    
    results = []
    
    # Test với N nhỏ trước
    for N in [2, 3, 5]:
        result = test_aggregate_with_timeout(N, timeout_sec=60)
        results.append((N, result))
        
        if not result['success']:
            print(f"\n⚠️  N={N} failed, skipping larger configs")
            break
        
        # Nếu N=5 mất >30s, không test N=10
        if N == 5 and result.get('sign_ms', 0) > 30000:
            print(f"\n⚠️  N=5 too slow ({result['sign_ms']:.0f}ms), skipping N=10")
            break
    else:
        # Chỉ test N=10 nếu N=5 pass và nhanh
        result = test_aggregate_with_timeout(10, timeout_sec=120)
        results.append((10, result))
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"{'N':<8} {'Keygen(ms)':<12} {'Sign(ms)':<12} {'Verify(ms)':<12} {'SigSize(KB)':<12} {'Status':<10}")
    print("-"*80)
    
    for N, res in results:
        if res['success']:
            print(f"{N:<8} {res['keygen_ms']:<12.1f} {res['sign_ms']:<12.1f} "
                  f"{res['verify_ms']:<12.1f} {res['sig_size_kb']:<12.2f} {'✓ OK':<10}")
        else:
            print(f"{N:<8} {'N/A':<12} {'N/A':<12} {'N/A':<12} {'N/A':<12} "
                  f"{'✗ ' + res.get('reason', 'failed'):<10}")
    
    print("="*80)
    print("\n📊 SO SÁNH VỚI THRESHOLD:")
    print("-"*80)
    print("• Aggregate: Kích thước O(1), nhưng rejection sampling RẤT CAO")
    print("• Threshold: Cũng O(1), rejection sampling thấp hơn (có scaling)")
    print("• Independent: Kích thước O(N), nhưng NHANH NHẤT (~1-3ms)")
    print("\n💡 KHUYẾN NGHỊ:")
    print("  → Nếu cần tốc độ: dùng Independent/Sequential")
    print("  → Nếu cần compact + fault tolerance: dùng Threshold")
    print("  → Aggregate phù hợp cho research, chưa tối ưu cho production")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
