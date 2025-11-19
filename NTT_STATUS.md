# NTT Implementation Status

## Current Status
The NTT optimization attempt has encountered issues with the negacyclic NTT implementation for the ring Z_q[X]/(X^N + 1).

## Problem
While the naive O(N²) polynomial multiplication correctly handles the X^256 + 1 reduction, the NTT-based approach does not properly handle the negacyclic structure. The tests show:
- ✅ Round-trip (NTT → INTT) works for some cases
- ❌ Polynomial multiplication results don't match naive implementation
- ❌ Even simple cases like X × X = X² fail

## Root Cause
The negacyclic NTT for Dilithium requires careful handling of:
1. Zeta preprocessing: multiply by ω^(2*bitrev(i)+1) before NTT
2. Proper butterfly twiddle factors
3. Inverse zeta postprocessing

The current implementation has errors in either the zeta computation or the butterfly operations.

## Workaround
The `mul_naive()` method works correctly and can be used for now. To use it:

```python
# In threshold_dilithium.py, temporarily change Poly.mul():
def mul(self, other: "Poly") -> "Poly":
    """Use naive multiplication until NTT is fixed"""
    return self.mul_naive(other)
```

## Performance Impact
- Without NTT: O(N²) ≈ 256² = 65,536 operations per multiplication
- With working NTT: O(N log N) ≈ 256 × 8 = 2,048 operations  
- Expected speedup: ~32×

For K=6, L=5 Dilithium (30 polys per signature):
- Current: ~35s per signature
- With NTT: ~1-2s per signature (estimated)

## Next Steps to Fix
1. Study reference Dilithium NTT implementation (pqcrypto/dilithium)
2. Verify zeta computation matches spec exactly
3. Ensure butterfly operations use correct twiddle factors
4. Test with known test vectors from Dilithium KAT files

## Alternative
Consider using liboqs's optimized NTT via ctypes/FFI if pure Python implementation proves too difficult.
