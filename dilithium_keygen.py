import oqs
import base64
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

ALGORITHMS = [
    ("Dilithium2", "NIST Level 2"),
    ("Dilithium3", "NIST Level 3"),
    ("Dilithium5", "NIST Level 5")
]

TEST_MESSAGE = b"Test message for signature benchmarking"

# Đo thời gian ký và xác minh, kích thước khóa/chữ ký, tỷ lệ thành công

def test_dilithium(algoname):
    with oqs.Signature(algoname) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()
        pub_b64 = base64.b64encode(public_key).decode()
        priv_b64 = base64.b64encode(private_key).decode()  
        # Ký
        t1 = time.time()
        signature = signer.sign(TEST_MESSAGE)
        t2 = time.time()
        sign_time = t2 - t1
        sig_b64 = base64.b64encode(signature).decode()
    # Xác minh
    with oqs.Signature(algoname) as verifier:
        t3 = time.time()
        valid = verifier.verify(TEST_MESSAGE, signature, public_key)
        t4 = time.time()
        verify_time = t4 - t3
    return {
        "algo": algoname,
        "pub_len": len(public_key),
        "priv_len": len(private_key),
        "sig_len": len(signature),
        "sign_time": sign_time,
        "verify_time": verify_time,
        "verify_success": valid,
    }

def test_rsa():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Ký
    t1 = time.time()
    signature = private_key.sign(
        TEST_MESSAGE,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    t2 = time.time()
    sign_time = t2 - t1
    # Xác minh
    t3 = time.time()
    try:
        public_key.verify(
            signature,
            TEST_MESSAGE,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        valid = True
    except Exception:
        valid = False
    t4 = time.time()
    verify_time = t4 - t3
    return {
        "algo": "RSA-2048",
        "pub_len": len(pub_bytes),
        "priv_len": len(priv_bytes),
        "sig_len": len(signature),
        "sign_time": sign_time,
        "verify_time": verify_time,
        "verify_success": valid,
    }

def test_ecc():
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Ký
    t1 = time.time()
    signature = private_key.sign(
        TEST_MESSAGE,
        ec.ECDSA(hashes.SHA256())
    )
    t2 = time.time()
    sign_time = t2 - t1
    # Xác minh
    t3 = time.time()
    try:
        public_key.verify(
            signature,
            TEST_MESSAGE,
            ec.ECDSA(hashes.SHA256())
        )
        valid = True
    except Exception:
        valid = False
    t4 = time.time()
    verify_time = t4 - t3
    return {
        "algo": "ECC-P256",
        "pub_len": len(pub_bytes),
        "priv_len": len(priv_bytes),
        "sig_len": len(signature),
        "sign_time": sign_time,
        "verify_time": verify_time,
        "verify_success": valid,
    }

def main():
    print("\n===== Benchmark các thuật toán chữ ký số =====\n")
    results = []
    for algo, level in ALGORITHMS:
        print(f"Đang kiểm thử {algo} ({level})...")
        res = test_dilithium(algo)
        results.append(res)
    print("Đang kiểm thử RSA-2048...")
    results.append(test_rsa())
    print("Đang kiểm thử ECC-P256...")
    results.append(test_ecc())
    print("\nKết quả:")
    print(f"{'Thuật toán':<15}{'PubKey':>10}{'PrivKey':>10}{'Chữ ký':>10}{'Ký (s)':>10}{'Xác minh (s)':>15}{'Tỉ lệ đúng':>12}")
    for r in results:
        print(f"{r['algo']:<15}{r['pub_len']:>10}{r['priv_len']:>10}{r['sig_len']:>10}{r['sign_time']:>10.6f}{r['verify_time']:>15.6f}{str(r['verify_success']):>12}")

if __name__ == "__main__":
    main()
