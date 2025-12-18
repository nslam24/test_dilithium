#!/usr/bin/env python3
"""
test_dkg_simple.py - Simple DKG test với debug chi tiết
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modes/threshold_gaussian'))

from keygen import run_dkg_protocol
from signing import sign_threshold_dkg

def test_simple_dkg():
    """Test đơn giản: 2-of-3, chỉ 1 user sign."""
    
    print("\n" + "="*80)
    print("SIMPLE DKG TEST: 2-of-3")
    print("="*80)
    
    # Setup
    n, t = 3, 2
    level = 2
    
    print("\n[STEP 1] Running DKG protocol...")
    keypairs, pk = run_dkg_protocol(n, t, level)
    
    print(f"\n✓ DKG Complete - Public key: {pk['pk_hash']}")
    
    # Analyze secrets
    kp = keypairs[0]  # User 1
    s1_norm = sum(c**2 for poly in kp['small_secret_s1'] 
                  for c in poly.get_centered_coeffs())**0.5
    x1_norm = sum(c**2 for poly in kp['shamir_share_x1'] 
                  for c in poly.get_centered_coeffs())**0.5
    
    print(f"\n[STEP 2] User 1 Secret Analysis:")
    print(f"  - ||s1|| (own small) = {s1_norm:.0f}")
    print(f"  - ||x1|| (Shamir) = {x1_norm:.0f}")
    print(f"  - Ratio: {x1_norm/s1_norm:.0f}x")
    
    # Try signing
    message = b"Test"
    signer_uids = [1, 2]
    
    print(f"\n[STEP 3] User 1 signing (max 20 attempts)...")
    
    try:
        sig = sign_threshold_dkg(
            message=message,
            keypair_info=keypairs[0],
            pk=pk,
            signer_uids=signer_uids,
            max_attempts=20,
            debug=True
        )
        
        print(f"\n✅ SUCCESS! Signed in {sig['attempts']} attempts")
        print(f"   Acceptance rate: {100/sig['attempts']:.2f}%")
        
        return True
        
    except RuntimeError as e:
        print(f"\n❌ FAILED: {e}")
        print(f"\n💡 This means rejection sampling không pass sau 20 lần")
        print(f"   → Có thể cần điều chỉnh B_BOUND hoặc SIGMA")
        
        return False


if __name__ == '__main__':
    test_simple_dkg()
