#!/usr/bin/env python3
from typing import List, Tuple, Dict, Any, Optional
import hashlib
import time
import random
import base64

# Minimal ring arithmetic for R_q = Z_q[X]/(X^N+1)
class Poly:
    def __init__(self, coeffs: List[int], q: int, N: int):
        self.q = q
        self.N = N
        if len(coeffs) != N:
            raise ValueError(f"Polynomial length {len(coeffs)} != N={N}")
        self.coeffs = [c % q for c in coeffs]

    @classmethod
    def zeros(cls, q: int, N: int) -> "Poly":
        return cls([0] * N, q, N)

    @classmethod
    def uniform_random(cls, q: int, N: int, rnd: Optional[random.Random] = None) -> "Poly":
        r = rnd or random
        return cls([r.randrange(0, q) for _ in range(N)], q, N)

    @classmethod
    def small_random(cls, q: int, N: int, eta: int = 2, rnd: Optional[random.Random] = None) -> "Poly":
        r = rnd or random
        coeffs = []
        for _ in range(N):
            v = r.randint(-eta, eta)
            coeffs.append(v % q)
        return cls(coeffs, q, N)

    def add(self, other: "Poly") -> "Poly":
        self._check_same(other)
        return Poly([(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)], self.q, self.N)

    def sub(self, other: "Poly") -> "Poly":
        self._check_same(other)
        return Poly([(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)], self.q, self.N)

    def scalar_mul(self, c: int) -> "Poly":
        c %= self.q
        return Poly([(c * a) % self.q for a in self.coeffs], self.q, self.N)

    def mul(self, other: "Poly") -> "Poly":
        self._check_same(other)
        N, q = self.N, self.q
        out = [0] * N
        for i in range(N):
            ai = self.coeffs[i]
            if ai == 0:
                continue
            for j in range(N):
                bj = other.coeffs[j]
                if bj == 0:
                    continue
                k = i + j
                prod = (ai * bj) % q
                if k < N:
                    out[k] = (out[k] + prod) % q
                else:
                    out[k - N] = (out[k - N] - prod) % q
        return Poly(out, q, N)

    def to_bytes(self) -> bytes:
        b = bytearray()
        for c in self.coeffs:
            b.extend(int(c).to_bytes(4, 'little', signed=False))
        return bytes(b)

    @classmethod
    def from_bytes(cls, data: bytes, q: int, N: int) -> "Poly":
        if len(data) != 4 * N:
            raise ValueError("Invalid byte length for polynomial")
        coeffs = [int.from_bytes(data[4*i:4*i+4], 'little', signed=False) % q for i in range(N)]
        return cls(coeffs, q, N)

    def _check_same(self, other: "Poly") -> None:
        if self.q != other.q or self.N != other.N:
            raise ValueError("Polynomial mismatch (q or N differ)")


def _sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def _lagrange_coeffs_at_zero(xs: List[int], q: int) -> List[int]:
    lams: List[int] = []
    k = len(xs)
    for j in range(k):
        num = 1
        den = 1
        xj = xs[j]
        for m in range(k):
            if m == j:
                continue
            xm = xs[m]
            num = (num * (-xm % q)) % q
            den = (den * ((xj - xm) % q)) % q
        lam = (num * pow(den, -1, q)) % q
        lams.append(lam)
    return lams


def _hash_poly_to_challenge(message: bytes, w: Poly) -> int:
    h = _sha3_512(message + w.to_bytes())
    return int.from_bytes(h, 'little') % w.q


def shamir_share_int(secret: int, n: int, t: int, field_prime: int) -> List[Tuple[int, int]]:
    secret %= field_prime
    coeffs = [secret] + [random.randint(0, field_prime - 1) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for i, c in enumerate(coeffs):
            y = (y + c * pow(x, i, field_prime)) % field_prime
        shares.append((x, y))
    return shares


def generate_threshold_keypair_davydov(n_parties: int, threshold: int, level: str = "Dilithium3",
                                       q: int = 8380417, N: int = 256, eta: int = 2) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    if threshold < 1 or threshold > n_parties:
        raise ValueError("threshold must be in [1, n_parties]")

    A = Poly.uniform_random(q, N)
    s = Poly.small_random(q, N, eta=eta)
    t_poly = A.mul(s)

    per_party_y: List[List[int]] = [[0]*N for _ in range(n_parties)]
    xs = list(range(1, n_parties+1))
    for idx in range(N):
        coeff = s.coeffs[idx]
        coeff_shares = shamir_share_int(coeff, n_parties, threshold, q)
        for j, (_x, y) in enumerate(coeff_shares):
            per_party_y[j][idx] = y

    sk_shares: List[Dict[str, Any]] = []
    for j in range(n_parties):
        sk_shares.append({
            "party_id": j,
            "x": xs[j],
            "s_shares": per_party_y[j],
            "q": q,
            "N": N,
            "threshold": threshold,
            "scheme": "dilithium-davydov"
        })

    pk = {
        "scheme": "dilithium-davydov",
        "q": q,
        "N": N,
        "A": base64.b64encode(A.to_bytes()).decode(),
        "t": base64.b64encode(t_poly.to_bytes()).decode(),
    }

    metadata = {
        "n_parties": n_parties,
        "threshold": threshold,
        "eta": eta,
        "note": "Toy ring params; 1x1 A; t = A*s"
    }

    return sk_shares, pk, metadata


def sign_threshold_davydov(message: bytes, sk_shares_subset: List[Dict[str, Any]], pk: Dict[str, Any],
                           eta: int = 2) -> Tuple[Dict[str, Any], List[float], Dict[str, Any]]:
    if not sk_shares_subset:
        raise ValueError("Need at least 1 share to sign")
    q = pk["q"]; N = pk["N"]
    A = Poly.from_bytes(base64.b64decode(pk["A"]), q, N)
    t_poly = Poly.from_bytes(base64.b64decode(pk["t"]), q, N)

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
        contrib = s_share_poly.scalar_mul((c * lam) % q)
        zj = y_list[j].add(contrib)
        z = z.add(zj)

    signature = {
        "scheme": "dilithium-davydov",
        "q": q,
        "N": N,
        "c": c,
        "z": base64.b64encode(z.to_bytes()).decode(),
        "participants": [s["party_id"] for s in sk_shares_subset]
    }

    sign_meta = {
        "rounds": 2,
        "avg_partial_time": sum(sign_times) / len(sign_times),
        "note": "Didactic ring-threshold signing without key reconstruction"
    }

    return signature, sign_times, sign_meta


def verify_threshold_ring(message: bytes, signature: Dict[str, Any], pk: Dict[str, Any]) -> Tuple[bool, float]:
    t0 = time.perf_counter()
    q = pk["q"]; N = pk["N"]
    A = Poly.from_bytes(base64.b64decode(pk["A"]), q, N)
    t_poly = Poly.from_bytes(base64.b64decode(pk["t"]), q, N)
    z = Poly.from_bytes(base64.b64decode(signature["z"]), q, N)
    c = int(signature["c"]) % q

    w_prime = A.mul(z).sub(t_poly.scalar_mul(c))
    c_prime = _hash_poly_to_challenge(message, w_prime)
    ok = (c_prime % q) == (c % q)
    t1 = time.perf_counter()
    return ok, (t1 - t0)
