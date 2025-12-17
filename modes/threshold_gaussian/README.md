# Threshold Gaussian Signature Scheme

Triển khai lược đồ ký ngưỡng dựa trên Dilithium với các cải tiến từ bài báo:

## 🎯 Thay đổi chính so với implementation chuẩn

### 1. **Gaussian Sampling** (thay vì Uniform)
- **Cũ**: Phân phối đều trong `[-GAMMA1, GAMMA1]`
- **Mới**: Phân phối Gaussian rời rạc `D_σ` với `σ = 261`
- **File**: `gaussian_primitives.py`
- **Hàm**: `gaussian_sample_poly()`

```python
# Sinh nhiễu Gaussian
y_i = gaussian_sample_poly(sigma=261.0)
```

### 2. **Trusted Dealer Setup** (thay vì DKG)
- **Cũ**: Distributed Key Generation (mỗi bên tự sinh)
- **Mới**: Dealer trung tâm sinh khóa và chia sẻ Shamir
- **File**: `trusted_dealer.py`
- **Hàm**: `trusted_dealer_setup()`

```python
# Dealer setup
shares, pk = trusted_dealer_setup(n_parties=5, threshold=3)
```

### 3. **Weighted Noise** với Lagrange Inverse
- **Công thức**: `ȳ_i = y_i · l_i^{-1}` (commitment)
- **Response**: `z_i = c·s_i + y_i` (dùng `y_i` gốc!)
- **File**: `threshold_sign.py`, dòng 100-113

```python
l_i_inv = pow(lagrange_coeff, -1, q)
y_bar_i = y_i.scalar_mul(l_i_inv)  # Weighted
w_i = A @ y_bar_i                   # Commitment
z_i = c*s_i + y_i                   # Response (original y!)
```

### 4. **Rejection Sampling** 2 bước
- **Bước 1**: Hard bound `||z'|| < B` (cite: 334)
- **Bước 2**: Probabilistic Gaussian ratio (cite: 336)
- **File**: `gaussian_primitives.py`, hàm `rejection_sample_check()`

```python
# Check 1: Norm bound
if norm_infinity(z') >= B:
    return RESTART

# Check 2: Probability (simplified)
if random() > 0.95:
    return RESTART
```

## 📁 Cấu trúc file

```
threshold_gaussian/
├── __init__.py                  # Package exports
├── gaussian_primitives.py       # Gaussian sampling & rejection
├── trusted_dealer.py            # Shamir secret sharing setup
├── threshold_sign.py            # Signing & verification protocol
├── benchmark_gaussian.py        # Performance testing
└── README.md                    # This file
```

## 🚀 Sử dụng

### Test từng module:

```bash
# Test Gaussian sampling
python -m modes.threshold_gaussian.gaussian_primitives

# Test Trusted Dealer
python -m modes.threshold_gaussian.trusted_dealer

# Test Signing
python -m modes.threshold_gaussian.threshold_sign

# Benchmark đầy đủ
python -m modes.threshold_gaussian.benchmark_gaussian 10
```

### Sử dụng trong code:

```python
from modes.threshold_gaussian import (
    trusted_dealer_setup,
    sign_threshold_gaussian,
    verify_threshold_gaussian,
)

# Setup
shares, pk = trusted_dealer_setup(n_parties=5, threshold=3, K=6, L=5)

# Sign (chọn 3 người bất kỳ)
message = b"Hello, threshold world!"
sig, meta = sign_threshold_gaussian(message, shares[:3], pk)

# Verify
valid, vtime = verify_threshold_gaussian(message, sig, pk)
print(f"Valid: {valid}, Time: {vtime:.6f}s")
```

## 📊 Tham số

| Tham số | Giá trị | Ý nghĩa |
|---------|---------|---------|
| `σ` (SIGMA) | 261.0 | Độ lệch chuẩn Gaussian |
| `γ` (GAMMA) | 1.9 | Hệ số an toàn |
| `B` (B_BOUND) | `γ·σ·√(m·N)` | Ngưỡng rejection |
| `m` | 8 | Chiều vector (k+l) |
| `N` | 256 | Bậc polynomial |
| `q` | 8380417 | Modulus |

**Với N=256, m=8**: `B ≈ 1.9 × 261 × √2048 ≈ 22,388`

## 🔬 So sánh với code cũ

| Aspect | Code cũ (`threshold_dilithium.py`) | Code mới (`threshold_gaussian/`) |
|--------|-------------------------------------|----------------------------------|
| **Noise** | Uniform `[-2^19, 2^19]` | Gaussian `D_261` |
| **Setup** | DKG (distributed) | Trusted Dealer + Shamir |
| **Commitment** | `w_i = A·y_i` | `w_i = A·(y_i/l_i)` |
| **Response** | `z_i = y_i + c·λ_i·s_i` | `z_i = y_i + c·s_i` |
| **Rejection** | Norm check only | Norm + Gaussian ratio |
| **Challenge** | `c = H(w, m)` | `c = H(w, m)` (giống) |

## ⚠️ Lưu ý quan trọng

1. **Weighted noise chỉ dùng cho commitment!**
   - `w_i = A·ȳ_i` với `ȳ_i = y_i/l_i`
   - Response vẫn dùng `y_i` gốc: `z_i = c·s_i + y_i`

2. **Lagrange coefficients khác nhau giữa setup và signing**
   - Setup: Shamir polynomial evaluation
   - Signing: Lagrange interpolation tại x=0

3. **Global bound scaling**
   - Single signer: `||z|| ≤ B`
   - Threshold (t signers): `||z|| ≤ t·B`

## 📖 Tham khảo

- Section 2: Preliminaries (phân phối Gaussian)
- Equation 9: LWE problem definition
- Cite 186: Bound calculation `B = γ·σ·√(m·N)`
- Cite 207: Shamir secret sharing
- Cite 334: Hard bound rejection
- Cite 336: Probabilistic Gaussian ratio test

## 🐛 Testing

Chạy test đầy đủ:

```bash
cd /home/lamns/python
python -m modes.threshold_gaussian.benchmark_gaussian 5
```

Expected output:
- Setup time: ~0.1-0.5s
- Sign time: ~0.5-2.0s (depending on attempts)
- Verify time: ~0.001-0.01s
- Average attempts: 1-5 (với acceptance prob ~95%)
- Norm ratio: 0.3-0.7 (well within bound)
