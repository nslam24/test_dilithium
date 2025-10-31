<!--
Use this file to provide workspace-specific custom instructions to Copilot.
For more details, visit:
https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file
-->

# 🧠 Project Overview

This project is a **Python research framework** for **Post-Quantum Cryptography (PQC)** signatures.

It includes implementations and benchmarks of:
- **CRYSTALS-Dilithium** (lattice-based)
- **Falcon** (NTRU lattice-based)
- Optional comparison with **threshold and aggregate** signature schemes

The goal is to generate keys, create and verify signatures, and compare multiple signing paradigms.

---

# ⚙️ Core Objectives

Copilot should:
1. Help implement modules for key generation, signing, verification, and performance measurement.
2. Provide clean, modular Python code using:
   - `pqcrypto.sign.dilithium2` / `dilithium3` / `dilithium5`
   - `pqcrypto.sign.falcon512` or `falcon1024`
3. Maintain a consistent interface for all algorithms:
   ```python
   generate_keypair()
   sign_message(message: bytes, secret_key: bytes) -> bytes
   verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool
