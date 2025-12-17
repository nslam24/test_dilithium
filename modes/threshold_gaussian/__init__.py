"""
threshold_gaussian - Threshold Dilithium with Gaussian Sampling

Implements threshold signature scheme following the paper's specifications:
- Gaussian discrete distribution for noise sampling
- Trusted Dealer setup with Shamir Secret Sharing
- Weighted noise with Lagrange inverse
- Probabilistic rejection sampling
"""

from .gaussian_primitives import (
    gaussian_sample_poly,
    SIGMA,
    B_BOUND,
)

from .trusted_dealer import (
    trusted_dealer_setup,
    compute_lagrange_coeff,
)

from .threshold_sign import (
    sign_threshold_gaussian,
    verify_threshold_gaussian,
)

__all__ = [
    'gaussian_sample_poly',
    'SIGMA',
    'B_BOUND',
    'trusted_dealer_setup',
    'compute_lagrange_coeff',
    'sign_threshold_gaussian',
    'verify_threshold_gaussian',
]
