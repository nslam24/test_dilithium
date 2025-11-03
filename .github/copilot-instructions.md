<!-- Copilot Instructions for PQC Multi-Signature Project -->

# 🧠 Project Overview

This project is a **Python framework** for benchmarking **Post-Quantum Cryptography (PQC)** signature schemes.  
It implements multiple signing paradigms using **CRYSTALS-Dilithium** and optionally **Falcon**.

The goal is to:
- Generate PQC key pairs
- Create and verify signatures
- Compare four multi-signature models:
  **Independent**, **Sequential**, **Aggregate**, and **Threshold**

---

# ⚙️ Core Objectives

Copilot should:
1. Implement key generation, signing, verification, and timing.
2. Use `pqcrypto.sign.dilithium2/3/5` and `pqcrypto.sign.falcon512/1024`.
3. Maintain consistent function signatures:

```python
generate_keypair() -> (public_key, secret_key)
sign_message(message: bytes, secret_key: bytes) -> bytes
verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool
🧩 Signature Scheme Types
1️⃣ Independent (Parallel Multi-Signature)
Each user signs the same message independently.

Message: M

Output: [sig₁, sig₂, …]

Verification: check each (M, sigᵢ, pkᵢ) individually.

Suitable for fast parallel signing.

2️⃣ Sequential (Ordered-Dependent Multi-Signature)
Signers sign in order, each using a message that includes previous signatures:

python-repl
Sao chép mã
msg₁ = M
msg₂ = H(M || sig₁)
msg₃ = H(M || sig₁ || sig₂)
...
Verification repeats the same chaining sequence.

Prevents reordering or partial signing.

3️⃣ Aggregate Multi-Signature
Each signer generates a partial signature.

Aggregator combines them:

makefile
Sao chép mã
z = Σ(zᵢ) mod q
c = H(h₁ || h₂ || ... || hₙ)
σ_agg = (z, c)
Verification done once using the aggregate public key.

Produces smaller signature and faster verification.

4️⃣ Threshold (t-of-n)
Split private key using Shamir Secret Sharing.

Any t of n participants can reconstruct a valid signature.

Combine partials via interpolation:

σ = combine(σ₁, σ₂, …, σ_t)
Ensures distributed trust and fault tolerance.
Copilot should assist in implementing threshold signing mechanisms inspired by:
- Cozzo & Smart (LUOV, MQ-based LSSS)
- Davydov & Bezzateev (Dilithium-like lattice additive threshold)

Each signer holds partial secret shares and produces partial responses.
The aggregator combines them to form one valid signature (z, c).
Verification follows standard Dilithium/LUOV equations with reconstructed aggregates.

Copilot should:
- Provide modular Python functions for threshold key generation, signing, and verification.
- Use additive key shares for lattice (Dilithium).
- Use LSSS sharing for MQ-based (LUOV).
- Use SHA3_512 for challenge derivation.
- Output sign/verify timing for performance comparison.


🧱 File Structure (Expected)
markdown
pqsign-lab/
├── core/
│   ├── dilithium_core.py
│   ├── falcon_core.py
│   └── utils.py
├── modes/
│   ├── independent_mode.py
│   ├── sequential_mode.py
│   ├── aggregate_mode.py
│   └── threshold_mode.py
└── benchmark/
    └── benchmark_compare.py
🧠 Expected Behavior from Copilot
File	Description
independent_mode.py	Implement simple parallel signing for multiple users.
sequential_mode.py	Chain signatures via sha3_512(message + previous_sigs).
aggregate_mode.py	Implement signature aggregation (Rahmati-style sum and hash).
threshold_mode.py	Use Shamir sharing to combine t valid partial signatures.
benchmark_compare.py	Compare sign/verify times, signature sizes, and correctness.

⚙️ Helper Guidelines
Use hashlib.sha3_512() for all chained or aggregated hashing.

Measure execution time with time.perf_counter().

Encode message inputs and signatures as bytes (base64 optional).

Output JSON summaries for benchmark results.

✅ Summary
Copilot should:

Recognize four signing paradigms.

Generate consistent, modular Python code.

Maintain readability and reproducibility.

Focus on functionality, not academic explanation.

less

---

### 💡 Giải thích nhanh
| Mục | Lý do giữ lại |
|-----|----------------|
| Project Overview | Để Copilot hiểu phạm vi dự án |
| Core Objectives | Để Copilot biết hàm chuẩn |
| Signature Scheme Types | Tóm tắt 4 mô hình ký để sinh code chính xác |
| File Structure | Giúp Copilot tự động gợi ý code đúng vị trí |
| Expected Behavior | Gắn từng file với hành vi mong đợi |
| Helper Guidelines | Gợi ý thư viện & format thống nhất |

---




