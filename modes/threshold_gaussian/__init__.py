"""
threshold_gaussian - Threshold Signature with DKG

Implements threshold signature scheme following Leevik et al.:
- DKG (Distributed Key Generation) - no Trusted Dealer
- Gaussian discrete distribution for noise sampling
- Shamir Secret Sharing for t-of-n threshold
- Dual secrets: s_i (small, for checking) + x_i (large, for signing)
- Proper rejection sampling with probabilistic checks
"""

from .gaussian_primitives import (
    gaussian_sample_poly,
    sample_small_secret_poly,
    SIGMA,
    B_BOUND,
)

from .keygen import (
    run_dkg_protocol,
    DKGNode,
)

from .signing import (
    sign_threshold_dkg,
    aggregate_signatures_dkg,
    verify_threshold_dkg,
)

__all__ = [
    'gaussian_sample_poly',
    'sample_small_secret_poly',
    'SIGMA',
    'B_BOUND',
    'run_dkg_protocol',
    'DKGNode',
    'sign_threshold_dkg',
    'aggregate_signatures_dkg',
    'verify_threshold_dkg',
]
