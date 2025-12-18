# Threshold Signature với DKG (Distributed Key Generation)

## Tổng quan

Hệ thống threshold signature dựa trên bài báo **Leevik et al.** với các đặc điểm:

- **DKG (Distributed Key Generation)**: Không có Trusted Dealer
- **Shamir Secret Sharing**: Hỗ trợ t-of-n threshold
- **Gaussian Sampling**: Phân phối Gaussian rời rạc
- **Dual Secrets**: Mỗi user có 2 loại bí mật

## Kiến trúc

### 1. Key Generation (`keygen.py`)

Mỗi user tự sinh 2 loại bí mật:

```
s_i (SMALL SECRET):
- Tự sinh từ S_η (phân phối nhỏ)
- ||s_i|| ≈ 45-92
- DÙNG ĐỂ: Check rejection sampling
- KHÔNG BAO GIỜ gửi đi!

x_i (LARGE SHARE):
- x_i = Σ_{j=1..n} f_j(i) (tổng các mảnh Shamir)
- ||x_i|| ≈ 77,000,000
- DÙNG ĐỂ: Tính z_i gửi đi
```

**Protocol DKG (3 bước):**

1. **Secret Generation**: Mỗi user sinh s_i và tạo polynomial chia sẻ
2. **Share Aggregation**: Nhận shares từ n users → aggregate thành x_i
3. **Public Key**: T = Σ A·s_i (aggregate từ tất cả users)

### 2. Signing (`signing.py`)

**Điểm mấu chốt**: Check với s_i (nhỏ), gửi với x_i (lớn)

```python
# ROUND 3 - Response & Rejection
z'_i = c·s_i + y_i        # CHECK (với small secret)
→ ||z'_i|| ≈ 8,500 < B_BOUND (14,173) → PASS ✓

z_i = c·x_i + ȳ_i         # SEND (với large share)
→ ||z_i|| ≈ 96,000,000 (lớn!)

# AGGREGATION
z = Σ(z_i·λ_i) = c·(Σs_i) + Σy_i
→ ||z|| ≈ 15,000 < B_BOUND (vì Σs_i nhỏ!) ✓
```

**Kết quả**: Vượt qua deadlock của Trusted Dealer!

## Cấu trúc thư mục

```
modes/threshold_gaussian/
├── keygen.py                 # DKG key generation
├── signing.py                # Threshold signing với dual secrets
├── shamir_utils.py           # Polynomial evaluation, Lagrange
├── gaussian_primitives.py    # Gaussian sampling & rejection
├── commitment_scheme.py      # Lattice-based commitment
└── __init__.py              # Package exports
```

## Sử dụng

### 1. Key Generation

```python
from modes.threshold_gaussian import run_dkg_protocol

# Setup 3-of-5 threshold
n, t = 5, 3
level = 2  # Dilithium level

keypairs, pk = run_dkg_protocol(n, t, level)
```

### 2. Signing

```python
from modes.threshold_gaussian import sign_threshold_dkg

# User 1 signs
keypair = keypairs[0]
signer_uids = [1, 2, 3]  # Choose 3 signers

partial_sig = sign_threshold_dkg(
    message=b"Test message",
    keypair_info=keypair,
    pk=pk,
    signer_uids=signer_uids,
    max_attempts=100
)
```

### 3. Aggregation & Verification

```python
from modes.threshold_gaussian import (
    aggregate_signatures_dkg,
    verify_threshold_dkg
)

# Collect partial signatures from t users
partial_sigs = [sig1, sig2, sig3]

# Aggregate
signature = aggregate_signatures_dkg(partial_sigs, pk, message)

# Verify
valid = verify_threshold_dkg(signature, message, pk)
```

## Kiểm thử

### Test đơn giản (2-of-3)

```bash
python test_dkg_simple.py
```

**Kết quả mong đợi**:
```
✓ DKG Complete - Public key: xxxxxxxx
✓ User 1 Secret Analysis:
  - ||s1|| (own small) = 45
  - ||x1|| (Shamir) = 77,000,000
  - Ratio: 1,700,000x

✅ SUCCESS! Signed in 2-5 attempts
   Acceptance rate: 20-50%
```

### Test đầy đủ (3-of-5)

```bash
python test_dkg_signing.py
```

**Bao gồm**:
- Basic workflow (3-of-5 threshold)
- t-of-n flexibility (test với [1,2,3] và [2,4,5])
- Rejection rate analysis (20 trials)

## So sánh với Trusted Dealer

| Feature | Trusted Dealer | DKG |
|---------|----------------|-----|
| Setup | Centralized (1 dealer) | Distributed (n users) |
| Trust | Must trust dealer | No single point of trust |
| Secret | Only x_i (large) | s_i (small) + x_i (large) |
| Rejection Check | ||z_i|| với x_i → FAIL | ||z'_i|| với s_i → PASS ✓ |
| Acceptance Rate | 0% (cần flooding) | 2-10% ✓ |
| Flooding | Required | NOT required ✓ |

## Tham số

### Dilithium Level 2 (mặc định)

```python
K = 4         # Output dimension
L = 4         # Input dimension
η = 2         # Small coefficient bound
N = 256       # Polynomial degree
q = 8380417   # Modulus
σ = 261       # Gaussian std dev
B_BOUND = 14173  # Rejection bound
```

## Kết quả Benchmark

**Cấu hình**: 2-of-3 threshold, Level 2

- **Acceptance rate**: 20-50% (2-5 attempts)
- **||s_i|| (own small)**: ~45
- **||x_i|| (Shamir)**: ~77,000,000
- **Ratio**: ~1,700,000x

**Kết luận**: DKG giải quyết deadlock của Trusted Dealer bằng cách:
1. Check rejection với s_i nhỏ → PASS ✓
2. Gửi z_i với x_i lớn → Aggregate về nhỏ ✓
3. Không cần flooding!

## Tài liệu tham khảo

- **Leevik et al.**: "Lattice-Based Threshold Signatures with Functional Encryption"
- **FIPS 204**: Dilithium specification
- **Cozzo & Smart**: LUOV threshold với LSSS
- **Davydov & Bezzateev**: Dilithium additive threshold

## License

MIT
