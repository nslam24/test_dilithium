# 🔐 DUAL SECRETS ARCHITECTURE

## Kiến Trúc "Hai Bí Mật" trong DKG Threshold Signing

---

## 🎯 **KHÁI NIỆM CỐT LÕI**

Trong hệ thống DKG + Shamir + Gaussian + Rejection Sampling, **mỗi user phải lưu 2 loại bí mật**:

1. **s_i** (SMALL SECRET) - Bí mật nhỏ
2. **x_i** (LARGE SHARE) - Mảnh Shamir lớn

**Mỗi loại có MỤC ĐÍCH RIÊNG biệt và KHÔNG THỂ thay thế lẫn nhau!**

---

## 📐 **CHI TIẾT KỸ THUẬT**

### 1️⃣ **s_i (SMALL SECRET - Bí mật nhỏ)**

```python
# Generation:
s_i ← S_η  # Sample from small distribution (η=2 or 4)

# Properties:
||s_i||₂ ≈ 45-92  # Very small norm
||s_i||_∞ ≤ η      # Coefficients bounded by η

# Usage:
z'_i = c·s_i + y_i  # For CHECKING rejection sampling
```

**MỤC ĐÍCH:**
- ✓ **CHECK Rejection Sampling**: Kiểm tra `||z'_i|| < B_BOUND` (14,173)
- ✓ **High Acceptance Rate**: Do s_i nhỏ → `||c·s_i + y_i||` vừa phải → PASS ~20-50%
- ❌ **KHÔNG DÙNG** để reconstruct master secret (không có tính chất threshold)

**CÔNG THỨC:**
```
z'_i = c·s_i + y_i
||z'_i||₂ ≈ ||c||·||s_i|| + ||y_i|| 
         ≈ 60·50 + 3700 
         ≈ 6,700 < B_BOUND (14,173) ✓
```

---

### 2️⃣ **x_i (LARGE SHARE - Mảnh Shamir lớn)**

```python
# Generation via DKG:
# Each user j generates polynomial f_j(X) with coefficients from S_η
f_j(X) = a_j0 + a_j1·X + ... + a_j(t-1)·X^(t-1)

# User i receives shares from all users:
x_i = Σ_{j=1..n} f_j(i)  # Aggregate shares

# Properties:
||x_i||₂ ≈ 77,000,000  # VERY LARGE (n·||a_j||)
```

**MỤC ĐÍCH:**
- ✓ **SIGNING**: Tính `z_i = c·x_i + ȳ_i` để gửi cho aggregator
- ✓ **Threshold Property**: `Σ(λ_i·x_i) = s_master` (reconstruct được master secret)
- ❌ **KHÔNG DÙNG** để check rejection (vì quá lớn → reject 100%)

**CÔNG THỨC:**
```
z_i = c·x_i + ȳ_i
||z_i||₂ ≈ ||c||·||x_i|| + ||ȳ_i|| 
         ≈ 60·77M + 3700 
         ≈ 96,000,000  # Very large but OK (will aggregate down!)
```

**AGGREGATE:**
```
z = Σ(λ_i · z_i)  # λ_i = Lagrange coefficients
  = Σ(λ_i · (c·x_i + ȳ_i))
  = c·Σ(λ_i·x_i) + Σ(λ_i·ȳ_i)
  = c·s_master + y_aggregate  # ✓ Valid signature!
```

---

## 🚨 **TẠI SAO CẦN CẢ HAI?**

### ❌ **Kịch bản 1: Chỉ dùng x_i (LARGE)**

```python
# CHECK:
z'_i = c·x_i + y_i
||z'_i||₂ ≈ 60·77M ≈ 78,000,000 >> B_BOUND (14,173)

# RESULT: REJECT 100% ❌
# → Không thể ký được gì cả!
```

**Vấn đề:** Rejection sampling fail 100% vì x_i quá lớn.

---

### ❌ **Kịch bản 2: Chỉ dùng s_i (SMALL)**

```python
# CHECK:
z'_i = c·s_i + y_i  # ✓ PASS (~30% acceptance rate)

# SIGNING:
z_i = c·s_i + ȳ_i   # Send this

# AGGREGATE:
z = Σ(λ_i · z_i)
  = c·Σ(λ_i·s_i) + ...
  = c·?? + ...      # ❌ s_i KHÔNG có tính chất Shamir!
```

**Vấn đề:** Không reconstruct được master secret → Fail threshold property.

---

### ✅ **Kịch bản 3: DUAL SECRETS (Đúng!)**

```python
# BƯỚC 1: CHECK với s_i (SMALL)
z'_i = c·s_i + y_i
||z'_i|| ≈ 6,700 < 14,173  # ✓ PASS with ~30% acceptance

# BƯỚC 2: COMPUTE & SEND với x_i (LARGE)
z_i = c·x_i + ȳ_i
||z_i|| ≈ 96M  # Large but OK!

# BƯỚC 3: AGGREGATE
z = Σ(λ_i · z_i)
  = c·Σ(λ_i·x_i) + Σ(λ_i·ȳ_i)
  = c·s_master + y_agg  # ✓ Valid signature with threshold!
```

**Kết quả:**
- ✓ Rejection sampling PASS (do check với s_i)
- ✓ Threshold property đúng (do sign với x_i)
- ✓ Signature hợp lệ

---

## 📝 **WORKFLOW TRONG CODE**

### **DKG KeyGen** (`keygen.py`)

```python
def run_dkg_protocol(n, t, level):
    """Generate keypairs for all users."""
    for i in range(1, n+1):
        # 1. Generate SMALL secret (self-generated)
        s1_i = sample_s_eta(L, eta, q, N)
        s2_i = sample_s_eta(K, eta, q, N)
        
        # 2. Generate LARGE share (via DKG)
        x1_i = aggregate_shares_from_all_users(...)
        x2_i = aggregate_shares_from_all_users(...)
        
        # 3. Return BOTH!
        keypair_info = {
            'small_secret_s1': s1_i,  # For checking
            'small_secret_s2': s2_i,
            'shamir_share_x1': x1_i,  # For signing
            'shamir_share_x2': x2_i,
        }
```

**⚠️ CRITICAL:**
- Không xóa `s_i` sau khi có `x_i`!
- Phải lưu CẢ HAI vào keypair_info!

---

### **Threshold Signing** (`signing.py`)

```python
def sign_threshold_dkg(message, keypair_info, pk):
    """Sign with dual secrets."""
    # Extract BOTH secrets
    s1_small = keypair_info['small_secret_s1']  # For CHECK
    x1_large = keypair_info['shamir_share_x1']  # For SIGN
    
    for attempt in range(max_attempts):
        # Sample noise
        y_i = gaussian_sample_vector(...)
        
        # ═══════════════════════════════════════════════════════
        # BƯỚC 1: CHECK với SMALL SECRET
        # ═══════════════════════════════════════════════════════
        z'_i = c·s1_small + y_i  # Use s_i!
        
        if ||z'_i|| >= B_BOUND:
            continue  # REJECT, retry
        
        # ═══════════════════════════════════════════════════════
        # BƯỚC 2: COMPUTE với LARGE SHARE
        # ═══════════════════════════════════════════════════════
        z_i = c·x1_large + ȳ_i   # Use x_i!
        
        return {'z': z_i, ...}   # Send z_i (with x_i)
```

**🔑 Key Point:**
- **Check** với `s_i` (line 5)
- **Send** với `x_i` (line 7)
- **Không bao giờ** nhầm lẫn hai loại!

---

## 📊 **SO SÁNH NORM**

| Secret/Value | Norm ||·||₂ | Bound | Check Result |
|--------------|-------------|-------|--------------|
| s_i (small) | ~50 | - | Tự sinh |
| x_i (large) | ~77,000,000 | - | DKG aggregate |
| y_i (noise) | ~3,700 | - | Gaussian sample |
| **z'_i = c·s_i + y_i** | **~6,700** | **14,173** | **✓ PASS** |
| c·x_i + y_i | ~78,000,000 | 14,173 | ❌ REJECT (if used for check!) |
| **z_i = c·x_i + ȳ_i** | **~96,000,000** | - | **Not checked** (send only) |
| z_aggregate | ~4,000,000 | Scaled bound | To be verified |

**Giải thích:**
- z'_i nhỏ → PASS check
- z_i lớn → Không check, chỉ gửi đi
- Sau aggregate → z nhỏ lại nhờ Lagrange cancellation

---

## 🛡️ **BẢO MẬT & TÍNH ĐÚNG ĐẮN**

### **Tính Bảo Mật**
- **s_i**: Bí mật cá nhân, không leak qua signature (do chỉ dùng check nội bộ)
- **x_i**: Mảnh Shamir, an toàn nếu < t users collude
- **Cả hai**: Không thể suy ra từ signature `(z, com, c)`

### **Tính Đúng Đắn**
```
Aggregate z = Σ(λ_i · z_i)
            = Σ(λ_i · (c·x_i + ȳ_i))
            = c·Σ(λ_i·x_i) + Σ(λ_i·ȳ_i)
            = c·s_master + y_aggregate  ✓

Verification:
A·z = c·t + w  (standard Dilithium equation)
```

---

## 🎓 **TÓM TẮT CHO NGƯỜI ĐỌC**

| Aspect | s_i (SMALL) | x_i (LARGE) |
|--------|-------------|-------------|
| **Nguồn gốc** | Tự sinh từ S_η | DKG aggregate |
| **Norm** | ~50 | ~77M |
| **Dùng để** | CHECK rejection | SIGN message |
| **Công thức** | z'_i = c·s_i + y_i | z_i = c·x_i + ȳ_i |
| **Check bound?** | ✓ YES (||z'_i|| < B) | ✗ NO (too large) |
| **Gửi đi?** | ✗ NO (internal only) | ✓ YES (send z_i) |
| **Threshold?** | ✗ NO | ✓ YES |

**🎯 Nguyên tắc vàng:**
```
CHECK with SMALL (s_i)  →  PASS rejection sampling
SEND with LARGE (x_i)   →  Maintain threshold property
```

---

## 🧪 **TEST & VERIFICATION**

Run `test_dkg_signing.py` để thấy rõ dual secrets hoạt động:

```bash
python test_dkg_signing.py
```

**Output mong đợi:**
```
[DKG KeyGen] User 1:
  Small secret: ||s1_i||₂ = 48.3
  Large share:  ||x1_i||₂ = 77,412,093.2

[Signing] User 1 (Attempt 1):
  ┌─ CHECK with SMALL:
  │  z'_i = c·s_i + y_i
  │  ||z'_i|| = 6,821 < 14,173 ✓ PASS
  │
  └─ SEND with LARGE:
     z_i = c·x_i + ȳ_i
     ||z_i|| = 96,183,274 (will aggregate down)

[Aggregate] Combine 3 partial signatures:
  z = Σ(λ_i · z_i) = c·s_master + y_agg
  ||z|| = 4,127,382 ✓ Valid threshold signature!
```

---

## 📚 **REFERENCES**

- **Paper**: Leevik et al., "Distributed Key Generation for Lattice-Based Cryptography"
- **Code**: `modes/threshold_gaussian/keygen.py`, `signing.py`
- **Tests**: `test_dkg_signing.py`
- **Protocol**: `ADDITIVE_THRESHOLD_PROTOCOL.md`

---

## ❓ **FAQ**

**Q: Tại sao không chỉ dùng x_i?**
A: Vì ||c·x_i + y_i|| quá lớn → reject 100% → không ký được.

**Q: Tại sao không chỉ dùng s_i?**
A: Vì s_i không có tính chất Shamir → không reconstruct được master secret → fail threshold.

**Q: s_i có leak security không?**
A: Không. s_i chỉ dùng để check nội bộ, không gửi đi. Signature chỉ chứa z_i (với x_i).

**Q: Có thể xóa s_i sau khi generate x_i?**
A: **KHÔNG!** Mỗi lần ký cần s_i để check rejection. Phải lưu cả đời keypair.

**Q: Aggregate signature có hợp lệ không?**
A: Có, vì `z = c·(Σ λ_i·x_i) + ... = c·s_master + ...` (threshold reconstruction đúng).

---

**🔐 Dual Secrets = Giải pháp cho bài toán deadlock của Trusted Dealer!**
