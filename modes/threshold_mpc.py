#!/usr/bin/env python3
from typing import List, Tuple, Dict, Any
from .threshold_davydov import (
    Poly,
    generate_threshold_keypair_davydov,
    verify_threshold_ring,
    _hash_poly_to_challenge,
    _lagrange_coeffs_at_zero,
)
import time


def generate_threshold_keypair_mpc(n_parties: int, threshold: int, level: str = "Dilithium3",
                                   q: int = 8380417, N: int = 256, eta: int = 2) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """Use same ring-based structure as Davydov but with MPC-style threshold usage."""
    return generate_threshold_keypair_davydov(n_parties, threshold, level, q=q, N=N, eta=eta)


def sign_threshold_mpc(message: bytes, sk_shares_subset: List[Dict[str, Any]], pk: Dict[str, Any],
                       eta: int = 2) -> Tuple[Dict[str, Any], List[float], Dict[str, Any]]:
    if not sk_shares_subset:
        raise ValueError("Need at least 1 share to sign")
    q = pk["q"]; N = pk["N"]
    A = Poly.from_bytes(__import__('base64').b64decode(pk["A"]), q, N)

    y_list: List[Poly] = []
    w_list: List[Poly] = []
    sign_times: List[float] = []

    for share in sk_shares_subset:
        t0 = time.perf_counter()
        yj = Poly.small_random(q, N, eta=eta)
        wj = A.mul(yj)
        t1 = time.perf_counter()
        y_list.append(yj)
        w_list.append(wj)
        sign_times.append(t1 - t0)

    w = Poly.zeros(q, N)
    for wj in w_list:
        w = w.add(wj)
    c = _hash_poly_to_challenge(message, w)

    xs = [s["x"] for s in sk_shares_subset]
    lams = _lagrange_coeffs_at_zero(xs, q)

    z = Poly.zeros(q, N)
    for j, share in enumerate(sk_shares_subset):
        lam = lams[j]
        s_share_poly = Poly(list(share["s_shares"]), q, N)
        zj = y_list[j].add(s_share_poly.scalar_mul((c * lam) % q))
        z = z.add(zj)

    signature = {
        "scheme": "dilithium-mpc",
        "q": q,
        "N": N,
        "c": c,
        "z": __import__('base64').b64encode(z.to_bytes()).decode(),
        "participants": [s["party_id"] for s in sk_shares_subset]
    }

    sign_metadata = {
        "protocol": "mpc-threshold",
        "rounds": 2,
        "avg_partial_time": sum(sign_times)/len(sign_times),
        "note": "Threshold via Lagrange weighting; no key reconstruction"
    }

    return signature, sign_times, sign_metadata
