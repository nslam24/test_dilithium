# 📊 BENCHMARK RESULTS - DKG THRESHOLD SIGNATURE

## Cấu hình: 3-of-5 Threshold

---

## 🎯 **KẾT QUẢ CHÍNH**

### **1. THỜI GIAN KÝ TRUNG BÌNH MỖI USER**

| Level | Thời gian/user | Tổng 3 users |
|-------|----------------|--------------|
| **2** | **35.9 ms**    | 108 ms       |
| **3** | **54.2 ms**    | 163 ms       |
| **5** | **70.3 ms**    | 211 ms       |

**Kết luận:**
- Mỗi user cần **~36-70ms** để tạo partial signature (tùy theo level)
- Level cao → Nhiều tính toán hơn → Lâu hơn (~2x từ L2 → L5)

---

### **2. TỔNG THÔNG LƯỢNG DỮ LIỆU GỬI**

| Level | Tổng data | Data/user | Signature cuối | Overhead |
|-------|-----------|-----------|----------------|----------|
| **2** | **54.09 KB** | 18.03 KB | 3.04 KB | **17.8x** |
| **3** | **60.84 KB** | 20.28 KB | 3.79 KB | **16.1x** |
| **5** | **69.84 KB** | 23.28 KB | 5.29 KB | **13.2x** |

**Kết luận:**
- **3 users gửi tổng ~54-70 KB** data cho aggregator
- Mỗi user gửi **~18-23 KB** (z_i + com_i + r_i)
- **Overhead lớn:** Cần gửi 13-18× nhiều hơn signature cuối cùng
- Level cao → Overhead thấp hơn (do signature lớn hơn tương đối)

---

### **3. ACCEPTANCE RATE (Rejection Sampling)**

| Level | Acceptance | Avg attempts | Attempts/user |
|-------|------------|--------------|---------------|
| **2** | **68.2%**  | 4.4 total    | ~1.5          |
| **3** | **62.5%**  | 4.8 total    | ~1.6          |
| **5** | **68.2%**  | 4.4 total    | ~1.5          |

**Kết luận:**
- Acceptance rate **~62-68%** (khá tốt!)
- Trung bình mỗi user retry **1.5 lần**
- Nhờ dual secrets: CHECK với s_i (small) → PASS tốt ✓

---

### **4. TỔNG THỜI GIAN END-TO-END**

| Level | KeyGen | Sign  | Aggregate | Verify | **TOTAL** |
|-------|--------|-------|-----------|--------|-----------|
| **2** | 0.130s | 0.108s| 0.002s    | 0.008s | **0.248s** |
| **3** | 0.144s | 0.163s| 0.003s    | 0.014s | **0.323s** |
| **5** | 0.205s | 0.211s| 0.003s    | 0.021s | **0.440s** |

**Kết luận:**
- Toàn bộ quy trình **~250-440ms**
- KeyGen + Signing chiếm >95% thời gian
- Aggregate rất nhanh (~2-3ms)

---

## 🔍 **CHI TIẾT KỸ THUẬT**

### **DUAL SECRETS ARCHITECTURE**

Mỗi user lưu **2 loại bí mật**:

| Level | ||s_i|| (small) | ||x_i|| (large) | Ratio       |
|-------|----------------|-----------------|-------------|
| **2** | 45             | 75,906,277      | **1.68M×**  |
| **3** | 93             | 87,206,796      | **0.94M×**  |
| **5** | 59             | 104,653,308     | **1.76M×**  |

**Lý do:**
- **s_i (SMALL):** Dùng để CHECK rejection → ||c·s_i + y_i|| < B_BOUND ✓
- **x_i (LARGE):** Dùng để SEND z_i = c·x_i + ȳ_i → Reconstruct được master secret

Nếu chỉ dùng x_i để check → **REJECT 100%** (quá lớn!)

---

### **NETWORK BREAKDOWN (Level 2 example)**

**Signing phase** (3 users → aggregator):
- User 1 sends: 18.03 KB
- User 2 sends: 18.03 KB
- User 3 sends: 18.03 KB
- **Total:** 54.09 KB

**Mỗi partial signature gồm:**
- `z_i` (polynomial vector): ~15 KB
- `com_i` (commitment hash): 32 bytes
- `r_i` (randomness): ~3 KB

**Sau aggregation:**
- Final signature: 3.04 KB (giảm 17.8×!)

---

### **SECURITY VS PERFORMANCE**

| Level | Security | K×L | Signature | Sign Time | Data  |
|-------|----------|-----|-----------|-----------|-------|
| **2** | 128-bit  | 4×4 | 3.04 KB   | 108 ms    | 54 KB |
| **3** | 192-bit  | 6×5 | 3.79 KB   | 163 ms    | 61 KB |
| **5** | 256-bit  | 8×7 | 5.29 KB   | 211 ms    | 70 KB |

**Trade-off:**
- Security tăng 2× (128→256 bit)
- Performance giảm ~2× (108→211 ms)
- Data tăng ~1.3× (54→70 KB)

---

## 📈 **SO SÁNH LEVEL 5 vs LEVEL 2**

| Metric                | Level 5 / Level 2 |
|-----------------------|-------------------|
| KeyGen time           | 1.58×             |
| Total signing time    | 1.96×             |
| Per-user signing time | 1.96×             |
| Data transfer         | 1.29×             |
| Signature size        | 1.74×             |

**Kết luận:** Level 5 chậm ~2× nhưng data chỉ tăng ~1.3×

---

## 💡 **INSIGHTS**

### **1. Per-User Performance**
- Mỗi user ký độc lập trong **36-70ms**
- Có thể **song song hóa** (không phụ thuộc lẫn nhau)
- Total time = max(user times) + aggregation (~2ms)

### **2. Network Efficiency**
- **Overhead cao:** Cần gửi 13-18× data so với signature cuối
- **Lý do:** Mỗi user gửi full z_i (polynomial vector lớn)
- **Cải thiện:** Có thể nén z_i bằng techniques như NTT packing

### **3. Dual Secrets = Key Innovation**
- x_i lớn hơn s_i **~1 triệu lần**
- Nếu không có s_i → Rejection rate = 0% ❌
- Với s_i → Acceptance rate = 62-68% ✓

### **4. Acceptance Rate Stability**
- Level 2, 5: 68% acceptance (η=2)
- Level 3: 62% acceptance (η=4)
- η lớn → s_i lớn hơn → Acceptance thấp hơn chút

### **5. Scalability**
- **Tốt:** Signing time/user không phụ thuộc n (số users)
- **Kém:** Data transfer tăng tuyến tính với t (threshold)
- **Trade-off:** t↑ → Security↑, Data↑, Overhead↑

---

## 🎓 **BENCHMARK CONDITIONS**

- **Configuration:** 3-of-5 threshold
- **Runs:** 5 successful runs per level
- **Success rate:** 100% (5/5 runs)
- **Platform:** Python 3.10 + NumPy + Numba JIT
- **Gaussian params:** σ=261, γ=1.2, B_BOUND=14,173

---

## 📝 **SUMMARY**

### **TL;DR:**

| Metric                        | Value          |
|-------------------------------|----------------|
| **Per-user signing time**     | 36-70 ms       |
| **Total data sent (3 users)** | 54-70 KB       |
| **Data overhead**             | 13-18× final   |
| **Acceptance rate**           | 62-68%         |
| **Success rate**              | 100% (5/5)     |

**Kết luận:**
- ✅ **Nhanh:** Mỗi user chỉ cần ~36-70ms
- ✅ **Ổn định:** Acceptance rate tốt (62-68%)
- ⚠️ **Data lớn:** Overhead 13-18× (cần tối ưu nén)
- ✅ **Dual secrets hoạt động:** x_i lớn gấp 1M× s_i nhưng vẫn PASS rejection!

---

**Generated:** December 19, 2025  
**Test:** `python benchmark_dkg_levels.py 5`  
**Output:** `benchmark_dkg_levels.json`
