#!/usr/bin/env python3
"""
test_dkg_signing.py - So sánh DKG (không còn Trusted Dealer)

KIỂM CHỨNG:
===========
DKG: Check với s_i nhỏ, gửi với x_i lớn → PASS!

KẾT QUẢ MONG ĐỢI:
==================
- DKG: 2-10% acceptance (rejection sampling bình thường)
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modes/threshold_gaussian'))

from keygen import run_dkg_protocol
from signing import (
    sign_threshold_dkg, aggregate_signatures_dkg, verify_threshold_dkg
)


def test_dkg_threshold_signing():
    """Test DKG threshold signing workflow."""
    
    print("\n" + "="*80)
    print("TEST: DKG THRESHOLD SIGNING (3-of-5)")
    print("="*80)
    
    # Setup
    n, t = 5, 3
    level = 2
    
    # Run DKG protocol
    keypairs, pk = run_dkg_protocol(n, t, level)
    
    print(f"\n✓ DKG Setup Complete")
    print(f"  - Public key hash: {pk['pk_hash']}")
    print(f"  - Threshold: {t}-of-{n}")
    
    # Message
    message = b"Test message for DKG threshold signature"
    
    # Choose signers: [1, 2, 3]
    signer_uids = [1, 2, 3]
    
    print(f"\n{'='*80}")
    print(f"SIGNING PHASE")
    print(f"{'='*80}")
    print(f"Signers: {signer_uids}")
    
    # Each signer generates partial signature
    partial_sigs = []
    
    for uid in signer_uids:
        keypair = keypairs[uid - 1]
        
        print(f"\n[User {uid}] Signing...")
        
        try:
            partial_sig = sign_threshold_dkg(
                message=message,
                keypair_info=keypair,
                pk=pk,
                signer_uids=signer_uids,
                max_attempts=100,
                debug=True
            )
            
            print(f"[User {uid}] ✓ Signature generated in {partial_sig['attempts']} attempts")
            partial_sigs.append(partial_sig)
            
        except RuntimeError as e:
            print(f"[User {uid}] ❌ FAILED: {e}")
            return False
    
    # Aggregate
    print(f"\n{'='*80}")
    print(f"AGGREGATION PHASE")
    print(f"{'='*80}")
    
    signature = aggregate_signatures_dkg(partial_sigs, pk, message, debug=True)
    
    # Verify
    print(f"\n{'='*80}")
    print(f"VERIFICATION PHASE")
    print(f"{'='*80}")
    
    valid = verify_threshold_dkg(signature, message, pk, debug=True)
    
    if valid:
        print(f"\n{'='*80}")
        print(f"✅ TEST PASSED: DKG Threshold Signing WORKS!")
        print(f"{'='*80}")
        
        # Print statistics
        total_attempts = sum(sig['attempts'] for sig in partial_sigs)
        avg_attempts = total_attempts / len(partial_sigs)
        
        print(f"\n📊 STATISTICS:")
        print(f"   - Total attempts: {total_attempts}")
        print(f"   - Average per signer: {avg_attempts:.1f}")
        print(f"   - Acceptance rate: {100/avg_attempts:.2f}%")
        
        return True
    else:
        print(f"\n❌ TEST FAILED: Verification failed")
        return False


def test_different_signer_sets():
    """Test với nhiều tập signers khác nhau (t-of-n flexibility)."""
    
    print("\n" + "="*80)
    print("TEST: DKG với nhiều tập signers (t-of-n flexibility)")
    print("="*80)
    
    n, t = 5, 3
    level = 2
    
    # DKG
    keypairs, pk = run_dkg_protocol(n, t, level)
    
    message = b"Test t-of-n flexibility"
    
    # Test 2 tập signers khác nhau
    signer_sets = [
        [1, 2, 3],
        [2, 4, 5],
    ]
    
    for signer_uids in signer_sets:
        print(f"\n{'─'*80}")
        print(f"Testing với signers: {signer_uids}")
        print(f"{'─'*80}")
        
        partial_sigs = []
        
        for uid in signer_uids:
            keypair = keypairs[uid - 1]
            
            try:
                partial_sig = sign_threshold_dkg(
                    message=message,
                    keypair_info=keypair,
                    pk=pk,
                    signer_uids=signer_uids,
                    max_attempts=100,
                    debug=False
                )
                
                partial_sigs.append(partial_sig)
                
            except RuntimeError as e:
                print(f"[User {uid}] ❌ FAILED: {e}")
                return False
        
        # Aggregate & verify
        signature = aggregate_signatures_dkg(partial_sigs, pk, message, debug=False)
        valid = verify_threshold_dkg(signature, message, pk, debug=False)
        
        if valid:
            attempts = [sig['attempts'] for sig in partial_sigs]
            print(f"✓ PASS - Attempts: {attempts}")
        else:
            print(f"❌ FAIL")
            return False
    
    print(f"\n{'='*80}")
    print(f"✅ t-of-n Flexibility Test PASSED!")
    print(f"{'='*80}")
    
    return True


def analyze_rejection_rate():
    """Phân tích rejection rate của DKG."""
    
    print("\n" + "="*80)
    print("ANALYSIS: DKG Rejection Rate")
    print("="*80)
    
    n, t = 3, 2
    level = 2
    
    keypairs, pk = run_dkg_protocol(n, t, level)
    
    message = b"Rejection rate analysis"
    signer_uids = [1, 2]
    
    num_trials = 20
    all_attempts = []
    
    print(f"\nRunning {num_trials} signing trials...")
    
    for trial in range(num_trials):
        partial_sigs = []
        
        for uid in signer_uids:
            keypair = keypairs[uid - 1]
            
            try:
                partial_sig = sign_threshold_dkg(
                    message=message,
                    keypair_info=keypair,
                    pk=pk,
                    signer_uids=signer_uids,
                    max_attempts=100,
                    debug=False
                )
                
                all_attempts.append(partial_sig['attempts'])
                partial_sigs.append(partial_sig)
                
            except RuntimeError:
                all_attempts.append(100)  # Failed
    
    # Statistics
    avg_attempts = sum(all_attempts) / len(all_attempts)
    min_attempts = min(all_attempts)
    max_attempts = max(all_attempts)
    acceptance_rate = 100 / avg_attempts if avg_attempts > 0 else 0
    
    print(f"\n📊 RESULTS ({len(all_attempts)} signatures):")
    print(f"   - Average attempts: {avg_attempts:.2f}")
    print(f"   - Min attempts: {min_attempts}")
    print(f"   - Max attempts: {max_attempts}")
    print(f"   - Acceptance rate: {acceptance_rate:.2f}%")
    print(f"   - Attempts distribution: {sorted(all_attempts)}")
    
    # So sánh với lý thuyết
    print(f"\n📖 THEORETICAL vs ACTUAL:")
    print(f"   - Paper (Leevik et al.): ~2-5% acceptance")
    print(f"   - Our implementation: {acceptance_rate:.2f}%")
    
    if 1 <= acceptance_rate <= 10:
        print(f"   ✓ Within expected range!")
    else:
        print(f"   ⚠️  Outside expected range")
    
    return True


if __name__ == '__main__':
    print("\n🧪 TESTING DKG THRESHOLD SIGNATURE SYSTEM")
    print("=" * 80)
    
    # Test 1: Basic workflow
    success1 = test_dkg_threshold_signing()
    
    if not success1:
        print("\n❌ Basic test failed, stopping")
        sys.exit(1)
    
    # Test 2: t-of-n flexibility
    success2 = test_different_signer_sets()
    
    if not success2:
        print("\n❌ Flexibility test failed")
        sys.exit(1)
    
    # Test 3: Rejection rate analysis
    success3 = analyze_rejection_rate()
    
    # Summary
    print("\n" + "="*80)
    print("FINAL SUMMARY")
    print("="*80)
    print(f"✅ All tests PASSED!")
    print(f"\n💡 KEY TAKEAWAYS:")
    print(f"   1. DKG uses 2 secrets: s_i (small, for checking) + x_i (large, for signing)")
    print(f"   2. Rejection check với s_i → PASS ✓")
    print(f"   3. Gửi z_i với x_i → Aggregate về nhỏ ✓")
    print(f"   4. Không cần flooding!")
    print(f"\n🎯 CONCLUSION: DKG resolves Trusted Dealer deadlock!")
