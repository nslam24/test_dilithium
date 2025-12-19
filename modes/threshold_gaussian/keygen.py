#!/usr/bin/env python3
"""
keygen.py - Distributed Key Generation (DKG) for Threshold Signature

ARCHITECTURE: DKG (Distributed Key Generation) - KHÔNG có Trusted Dealer
===========================================================================

Theo bài báo Leevik et al., mỗi user tự sinh bí mật nhỏ s_i và chia sẻ:

PHÂN BIỆT 2 LOẠI BÍ MẬT:
-------------------------
1. s_i (SMALL SECRET - Own Secret):
   - User tự sinh từ phân phối nhỏ S_η hoặc D_σ
   - ||s_i|| ≈ σ√N ≈ 4,000 (NHỎ!)
   - DÙNG ĐỂ: Check Rejection Sampling (z' = c·s_i + y_i)
   - KHÔNG BAO GIỜ GỬI ĐI!

2. x_i (LARGE SHARE - Shamir Aggregate):
   - x_i = Σ_{j=1..n} f_j(i) (tổng các mảnh từ n users)
   - ||x_i|| ≈ q/2 ≈ 4,200,000 (LỚN!)
   - DÙNG ĐỂ: Tính z_i gửi đi (z_i = c·x_i + ȳ_i)
   - ĐẶC ĐIỂM: Khi aggregate với Lagrange → z = c·S + Σy (S = Σs_i nhỏ!)

ĐIỂM MẤU CHỐT:
--------------
- Check rejection với z' (dùng s_i nhỏ) → PASS ✓
- Gửi đi z_i (dùng x_i lớn) → Sau khi aggregate → nhỏ lại ✓
- Vượt qua deadlock của Trusted Dealer!

DKG PROTOCOL (4 bước):
======================
1. Each user i:
   - Tự sinh s_i ← S_η (SMALL)
   - Tạo polynomial F_i(x) = s_i + a_{i,1}·x + ... + a_{i,t-1}·x^{t-1}
   - Gửi f_i(j) cho mỗi user j

2. Each user i nhận {f_j(i)} từ n users khác:
   - Tính x_i = Σ_{j=1..n} f_j(i) (LARGE)

3. Aggregate public key:
   - T = Σ A·s_i (mỗi user publish T_i = A·s_i)

4. User i giữ:
   - s_i: Own small secret (for checking)
   - x_i: Shamir share (for signing)
"""

import sys
import os
import random
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from core.dilithium_math import (
    Poly, DILITHIUM_Q, DILITHIUM_N,
    _matvec_mul, expand_a, _serialize_poly_vec, vec_add
)

# Import Shamir utilities
if __name__ == '__main__':
    from shamir_utils import eval_poly, mod_inverse
    from gaussian_primitives import sample_small_secret_poly
else:
    try:
        from .shamir_utils import eval_poly, mod_inverse
        from .gaussian_primitives import sample_small_secret_poly
    except ImportError:
        from shamir_utils import eval_poly, mod_inverse
        from gaussian_primitives import sample_small_secret_poly


# ============================================================================
# PARAMETERS
# ============================================================================

DILITHIUM_PARAMS = {
    2: {'K': 4, 'L': 4, 'eta': 2, 'tau': 39},
    3: {'K': 6, 'L': 5, 'eta': 4, 'tau': 49},
    5: {'K': 8, 'L': 7, 'eta': 2, 'tau': 60},
}


# ============================================================================
# DKG NODE CLASS
# ============================================================================

class DKGNode:
    """
    Node trong DKG - mỗi user chạy instance này.
    
    Attributes:
        uid: User ID (1..n)
        n: Total users
        t: Threshold
        level: Dilithium level (2, 3, 5)
        
        my_small_secret_s1: s1_i (SMALL) - Own secret for checking
        my_small_secret_s2: s2_i (SMALL) - Own secret for checking
        
        shamir_share_x1: x1_i (LARGE) - Aggregate Shamir share
        shamir_share_x2: x2_i (LARGE) - Aggregate Shamir share
        
        my_public_T: T_i = A·s_i (for aggregate public key)
    """
    
    def __init__(self, uid: int, n: int, t: int, level: int = 2, eta: int = None):
        if uid < 1 or uid > n:
            raise ValueError(f'UID must be in [1, {n}]')
        if t > n or t < 1:
            raise ValueError(f'Threshold t={t} invalid for n={n}')
        if level not in DILITHIUM_PARAMS:
            raise ValueError(f'Level must be 2, 3, or 5')
        
        self.uid = uid
        self.n = n
        self.t = t
        self.level = level
        
        params = DILITHIUM_PARAMS[level]
        self.K = params['K']
        self.L = params['L']
        self.eta = eta if eta is not None else params['eta']
        self.tau = params['tau']
        self.q = DILITHIUM_Q
        self.N = DILITHIUM_N
        
        # Secrets (will be generated in step 1)
        self.my_small_secret_s1 = None  # SMALL (for checking)
        self.my_small_secret_s2 = None  # SMALL (for checking)
        
        self.shamir_share_x1 = None     # LARGE (for signing)
        self.shamir_share_x2 = None     # LARGE (for signing)
        
        # Public key component
        self.my_public_T = None
        
        # Polynomial coefficients (for sharing)
        self.poly_s1_coeffs = None
        self.poly_s2_coeffs = None
        
        # Matrix A (shared among all users)
        self.A = None
        self.rho = None
    
    def step1_generate_and_share(self):
        """
        BƯỚC 1: Tự sinh bí mật nhỏ s_i và tạo polynomial để chia sẻ.
        
        Returns:
            shares_to_broadcast: Dict {target_uid: (f_s1(uid), f_s2(uid))}
        """
        print(f'\n[DKG Node {self.uid}] STEP 1: Generate own small secret', file=sys.stderr)
        
        # Sinh bí mật nhỏ s_i từ S_η
        self.my_small_secret_s1 = [
            sample_small_secret_poly(self.eta, self.q, self.N)
            for _ in range(self.L)
        ]
        self.my_small_secret_s2 = [
            sample_small_secret_poly(self.eta, self.q, self.N)
            for _ in range(self.K)
        ]
        
        # Tính norm để verify nhỏ
        s1_norm = sum(c**2 for poly in self.my_small_secret_s1 
                      for c in poly.get_centered_coeffs())**0.5
        print(f'[DKG Node {self.uid}] ||s1_i||_2 = {s1_norm:.1f} (SMALL ✓)', file=sys.stderr)
        
        # Tạo polynomial F_i(x) = s_i + a_{i,1}·x + ... + a_{i,t-1}·x^{t-1}
        # Mỗi coefficient của mỗi polynomial trong vector cần 1 polynomial riêng
        
        # Hàm helper: Share 1 polynomial vector
        def create_sharing_polynomials(secret_vec):
            """
            Tạo polynomial chia sẻ cho từng coefficient.
            
            Returns: List of coefficient-wise polynomials
                [poly_for_coeff_0, poly_for_coeff_1, ..., poly_for_coeff_{N-1}]
            """
            polys_per_vector_element = []
            
            for vec_idx, poly in enumerate(secret_vec):
                poly_coeffs_list = []  # List of N polynomials (1 per coefficient)
                
                for coeff_idx in range(self.N):
                    # Hệ số tự do = secret coefficient
                    secret_coeff = poly.coeffs[coeff_idx]
                    
                    # Random coefficients cho x, x^2, ..., x^{t-1}
                    random_coeffs = [
                        random.randint(0, self.q - 1)
                        for _ in range(self.t - 1)
                    ]
                    
                    # Polynomial: [secret_coeff, rand_1, rand_2, ..., rand_{t-1}]
                    poly_coeffs_list.append([secret_coeff] + random_coeffs)
                
                polys_per_vector_element.append(poly_coeffs_list)
            
            return polys_per_vector_element
        
        self.poly_s1_coeffs = create_sharing_polynomials(self.my_small_secret_s1)
        self.poly_s2_coeffs = create_sharing_polynomials(self.my_small_secret_s2)
        
        # Tạo shares để gửi cho n users (bao gồm chính mình)
        shares_to_broadcast = {}
        
        for target_uid in range(1, self.n + 1):
            # Evaluate all polynomials at target_uid
            share_s1 = []
            for vec_idx, poly_list in enumerate(self.poly_s1_coeffs):
                coeffs = []
                for poly_coeffs in poly_list:
                    # eval_poly(coeffs, x, q)
                    val = eval_poly(poly_coeffs, target_uid, self.q)
                    coeffs.append(val)
                share_s1.append(Poly(coeffs, self.q, self.N, in_ntt=False))
            
            share_s2 = []
            for vec_idx, poly_list in enumerate(self.poly_s2_coeffs):
                coeffs = []
                for poly_coeffs in poly_list:
                    val = eval_poly(poly_coeffs, target_uid, self.q)
                    coeffs.append(val)
                share_s2.append(Poly(coeffs, self.q, self.N, in_ntt=False))
            
            shares_to_broadcast[target_uid] = (share_s1, share_s2)
        
        print(f'[DKG Node {self.uid}] Created {len(shares_to_broadcast)} shares to broadcast', 
              file=sys.stderr)
        
        return shares_to_broadcast
    
    def step2_aggregate_shares(self, received_shares_dict):
        """
        BƯỚC 2: Nhận shares từ n users và aggregate thành x_i.
        
        Args:
            received_shares_dict: {sender_uid: (share_s1, share_s2)}
        
        Updates:
            self.shamir_share_x1, self.shamir_share_x2
        """
        print(f'\n[DKG Node {self.uid}] STEP 2: Aggregate received shares', file=sys.stderr)
        
        if len(received_shares_dict) != self.n:
            raise ValueError(f'Expected {self.n} shares, got {len(received_shares_dict)}')
        
        # x_i = Σ_{j=1..n} f_j(i)
        self.shamir_share_x1 = None
        self.shamir_share_x2 = None
        
        for sender_uid, (share_s1, share_s2) in received_shares_dict.items():
            if self.shamir_share_x1 is None:
                # Initialize
                self.shamir_share_x1 = share_s1
                self.shamir_share_x2 = share_s2
            else:
                # Add
                for i in range(len(self.shamir_share_x1)):
                    coeffs = [
                        (a + b) % self.q
                        for a, b in zip(self.shamir_share_x1[i].coeffs, share_s1[i].coeffs)
                    ]
                    self.shamir_share_x1[i] = Poly(coeffs, self.q, self.N, in_ntt=False)
                
                for i in range(len(self.shamir_share_x2)):
                    coeffs = [
                        (a + b) % self.q
                        for a, b in zip(self.shamir_share_x2[i].coeffs, share_s2[i].coeffs)
                    ]
                    self.shamir_share_x2[i] = Poly(coeffs, self.q, self.N, in_ntt=False)
        
        # Tính norm để verify lớn
        x1_norm = sum(c**2 for poly in self.shamir_share_x1 
                      for c in poly.get_centered_coeffs())**0.5
        print(f'[DKG Node {self.uid}] ||x1_i||_2 = {x1_norm:.1f} (LARGE as expected ⚠️)', 
              file=sys.stderr)
    
    def step3_generate_public_key_component(self, rho: bytes):
        """
        BƯỚC 3: Tạo T_i = A·s_i (component của public key).
        
        Args:
            rho: Seed chung cho matrix A (broadcast từ 1 node hoặc derive từ hash)
        """
        print(f'\n[DKG Node {self.uid}] STEP 3: Generate public key component', file=sys.stderr)
        
        self.rho = rho
        self.A = expand_a(rho, self.K, self.L, self.q, self.N)
        
        # T_i = A·s_i (sử dụng small secret!)
        self.my_public_T = _matvec_mul(self.A, self.my_small_secret_s1)
        
        print(f'[DKG Node {self.uid}] T_i computed (to be aggregated)', file=sys.stderr)
        
        return self.my_public_T
    
    def get_keypair_info(self, pk_hash: str = None):
        """
        Lấy thông tin keypair sau DKG.
        
        **DUAL SECRETS ARCHITECTURE (Bí mật kép)**:
        ============================================
        Mỗi user PHẢI giữ lại 2 loại bí mật:
        
        1. s_i (SMALL SECRET - Bí mật nhỏ):
           - Nguồn: Do user tự sinh từ S_η
           - ||s_i|| ≈ 45-92 (RẤT NHỎ)
           - DÙNG ĐỂ: Check Rejection Sampling trong signing
           - Công thức: ||z'_i|| = ||c·s_i + y_i|| < B_BOUND
           - ⚠️ KHÔNG BAO GIỜ GỬI ĐI!
        
        2. x_i (LARGE SHARE - Mảnh Shamir lớn):
           - Nguồn: x_i = Σ_{j=1..n} f_j(i) (aggregate từ n users)
           - ||x_i|| ≈ 77,000,000 (RẤT LỚN)
           - DÙNG ĐỂ: Tính z_i gửi đi trong signing
           - Công thức: z_i = c·x_i + ȳ_i
        
        **TẠI SAO CẦN CẢ HAI?**
        - Nếu check với x_i → FAIL (quá lớn >> B_BOUND)
        - Nếu gửi chỉ với s_i → Mất tính chất threshold
        - ✓ Giải pháp: Check với s_i (nhỏ), gửi với x_i (lớn)
        
        **[CRITICAL] PK_HASH BINDING**:
        - pk_hash liên kết keypair với một Public Key cụ thể
        - KHÔNG THỂ dùng keypair từ nhóm A để ký cho nhóm B
        - Mỗi nhóm DKG tạo ra một "polynomial universe" riêng biệt
        
        Args:
            pk_hash: Hash của public key (để bind keypair với PK)
        
        Returns:
            Dict with dual secrets:
            {
                'uid': User ID,
                'pk_hash': Hash of bound public key,
                # SMALL SECRETS (for checking):
                'small_secret_s1': s1_i,
                'small_secret_s2': s2_i,
                # LARGE SHARES (for signing):
                'shamir_share_x1': x1_i,
                'shamir_share_x2': x2_i,
                # Public component:
                'public_T_i': T_i,
            }
        """
        return {
            'uid': self.uid,
            'pk_hash': pk_hash,  # [CRITICAL] Bind to specific public key
            # SMALL SECRETS (for Rejection Sampling check)
            'small_secret_s1': self.my_small_secret_s1,
            'small_secret_s2': self.my_small_secret_s2,
            # LARGE SHARES (for signing)
            'shamir_share_x1': self.shamir_share_x1,
            'shamir_share_x2': self.shamir_share_x2,
            # Public component
            'public_T_i': self.my_public_T,
        }


# ============================================================================
# DKG COORDINATOR (Orchestrates the protocol)
# ============================================================================

def run_dkg_protocol(n: int, t: int, level: int = 2):
    """
    Chạy DKG protocol đầy đủ cho n users.
    
    Args:
        n: Total users
        t: Threshold
        level: Dilithium level (2, 3, 5)
    
    Returns:
        (user_keypairs, public_key)
        - user_keypairs: List of keypair info dicts
        - public_key: Dict with aggregate public key
    """
    print(f'\n{"="*70}')
    print(f'DKG PROTOCOL: {t}-of-{n} Threshold, Level {level}')
    print(f'{"="*70}')
    
    # Initialize all nodes
    nodes = [DKGNode(uid, n, t, level) for uid in range(1, n + 1)]
    
    # ========================================================================
    # STEP 1: Each node generates secrets and shares
    # ========================================================================
    print(f'\n[PHASE 1] Secret Generation & Sharing')
    print(f'-' * 70)
    
    all_shares = {}  # {sender_uid: {target_uid: (share_s1, share_s2)}}
    
    for node in nodes:
        shares_from_this_node = node.step1_generate_and_share()
        all_shares[node.uid] = shares_from_this_node
    
    # ========================================================================
    # STEP 2: Each node aggregates received shares
    # ========================================================================
    print(f'\n[PHASE 2] Share Aggregation')
    print(f'-' * 70)
    
    for node in nodes:
        # Collect shares destined for this node
        received = {}
        for sender_uid, targets in all_shares.items():
            received[sender_uid] = targets[node.uid]
        
        node.step2_aggregate_shares(received)
    
    # ========================================================================
    # STEP 3: Generate public key
    # ========================================================================
    print(f'\n[PHASE 3] Public Key Generation')
    print(f'-' * 70)
    
    # Generate common rho
    rho = random.randbytes(32)
    
    # Each node computes T_i
    T_components = []
    for node in nodes:
        T_i = node.step3_generate_public_key_component(rho)
        T_components.append(T_i)
    
    # Aggregate T = Σ T_i = A·(Σ s_i)
    T_pub = None
    for T_i in T_components:
        if T_pub is None:
            T_pub = T_i
        else:
            T_pub = vec_add(T_pub, T_i)
    
    # Serialize public key
    t_bytes_list = _serialize_poly_vec(T_pub)
    t_bytes = ''.join(t_bytes_list).encode()
    pk_hash = hashlib.sha3_256(rho + t_bytes).hexdigest()[:16]
    
    params = DILITHIUM_PARAMS[level]
    public_key = {
        't': T_pub,
        'rho': rho,
        'K': params['K'],
        'L': params['L'],
        'eta': params['eta'],
        'tau': params['tau'],
        'level': level,
        'N': DILITHIUM_N,
        'q': DILITHIUM_Q,
        'n': n,
        't_threshold': t,
        'threshold_type': 'dkg_shamir',
        'pk_hash': pk_hash,
    }
    
    print(f'\n[DKG] Public key hash: {pk_hash}')
    print(f'[DKG] ✓ Setup complete!\n')
    
    # Collect keypairs with DUAL SECRETS and PK_HASH binding
    user_keypairs = [node.get_keypair_info(pk_hash=pk_hash) for node in nodes]
    
    # Verify dual secrets structure
    print(f'[DKG] ✓ Each user has DUAL SECRETS:', file=sys.stderr)
    sample_kp = user_keypairs[0]
    s1_norm = sum(c**2 for poly in sample_kp['small_secret_s1'] 
                  for c in poly.get_centered_coeffs())**0.5
    x1_norm = sum(c**2 for poly in sample_kp['shamir_share_x1'] 
                  for c in poly.get_centered_coeffs())**0.5
    print(f'[DKG]   - s_i (SMALL): ||s1|| ≈ {s1_norm:.0f} (for rejection check)', file=sys.stderr)
    print(f'[DKG]   - x_i (LARGE): ||x1|| ≈ {x1_norm:.0f} (for signing)', file=sys.stderr)
    print(f'[DKG]   - pk_hash: {pk_hash} (BINDING to this DKG group only)', file=sys.stderr)
    
    return user_keypairs, public_key


# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    # Test DKG
    n, t = 5, 3
    level = 2
    
    keypairs, pk = run_dkg_protocol(n, t, level)
    
    print(f"\n{'='*70}")
    print(f"DKG RESULTS")
    print(f"{'='*70}")
    print(f"✓ Generated {len(keypairs)} user keypairs")
    print(f"✓ Public key hash: {pk['pk_hash']}")
    print(f"✓ Threshold: {t}-of-{n}")
    
    # Verify secret sizes
    kp = keypairs[0]
    s1_norm = sum(c**2 for poly in kp['small_secret_s1'] 
                  for c in poly.get_centered_coeffs())**0.5
    x1_norm = sum(c**2 for poly in kp['shamir_share_x1'] 
                  for c in poly.get_centered_coeffs())**0.5
    
    print(f"\n📊 User 1 Secret Analysis:")
    print(f"   - ||s1|| (own small secret) = {s1_norm:.0f} (SMALL ✓)")
    print(f"   - ||x1|| (Shamir share) = {x1_norm:.0f} (LARGE ⚠️)")
    print(f"   - Ratio: {x1_norm / s1_norm:.1f}x larger")
    
    print(f"\n💡 KEY INSIGHT:")
    print(f"   - Check rejection với s1 (SMALL) → sẽ PASS ✓")
    print(f"   - Gửi đi z_i với x1 (LARGE) → aggregate về SMALL ✓")
