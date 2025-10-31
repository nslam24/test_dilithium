import oqs
import base64
import time
import os
import json
import argparse
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
    # Mở context signer cho thuật toán `algoname` (vd: Dilithium2)
    # - sinh keypair
    # - ký thử thông điệp TEST_MESSAGE
    # - xuất secret key (để lưu nếu cần)
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
    # Xác minh chữ ký vừa tạo bằng public key
    # Sử dụng một context verifier riêng (không cần secret key)
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
    # Sinh khóa RSA-2048, ký và xác minh để so sánh với Dilithium.
    # Trả về cấu trúc chứa kích thước khóa, thời gian ký/xác minh và kết quả verify.
    
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
    # Sinh khóa ECC P-256, ký và xác minh tương tự như test_rsa.
    # Dùng để so sánh về kích thước và hiệu năng.

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
    # Hàm chính: chạy benchmark cho các thuật toán đã định và in kết quả
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


def generate_and_save_dilithium_keys(users=None, levels=None, outdir="keys"):
    """Generate Dilithium keypairs for given users and levels and save to disk.

    Directory layout created:
    keys/<username>/<level>/public.key  (binary)
    keys/<username>/<level>/private.key (binary)
    keys/<username>/metadata.json (json summary)
    """
    # Thiết lập giá trị mặc định cho users/levels nếu không được truyền
    if users is None:
        users = [f"user{i+1}" for i in range(5)]
    if levels is None:
        levels = ["Dilithium2", "Dilithium3", "Dilithium5"]

    os.makedirs(outdir, exist_ok=True)

    # Với mỗi user và mỗi level:
    # 1) tạo thư mục user/level
    # 2) generate keypair với liboqs
    # 3) lưu public.key và private.key ở dạng nhị phân
    # 4) ghi metadata (kích thước + đường dẫn) vào metadata.json per-user
    keystore = {}

    for user in users:
        user_dir = os.path.join(outdir, user)
        os.makedirs(user_dir, exist_ok=True)
        meta = {"user": user, "keys": {}}
        for level in levels:
            lvl_dir = os.path.join(user_dir, level)
            os.makedirs(lvl_dir, exist_ok=True)
            # generate keypair
            with oqs.Signature(level) as signer:
                public_key = signer.generate_keypair()
                private_key = signer.export_secret_key()

            pub_path = os.path.join(lvl_dir, "public.key")
            priv_path = os.path.join(lvl_dir, "private.key")

            # write raw bytes
            with open(pub_path, "wb") as f:
                f.write(public_key)
            with open(priv_path, "wb") as f:
                f.write(private_key)

            # Lưu đường dẫn relative so với `outdir` để keystore dễ dùng
            meta["keys"][level] = {
                "pub_len": len(public_key),
                "priv_len": len(private_key),
                "pub_path": os.path.relpath(pub_path, start=outdir),
                "priv_path": os.path.relpath(priv_path, start=outdir),
            }

            # Tạo alias cho keystore: định dạng "<user>@<level>"
            alias = f"{user}@{level}"
            keystore[alias] = {
                "user": user,
                "level": level,
                "pub_path": os.path.relpath(pub_path, start=outdir),
                "priv_path": os.path.relpath(priv_path, start=outdir),
            }

        # write metadata per user
        meta_path = os.path.join(user_dir, "metadata.json")
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    # Sau khi tạo xong cho tất cả người dùng, ghi keystore.json mapping alias -> key paths
    keystore_path = os.path.join(outdir, "keystore.json")
    with open(keystore_path, "w", encoding="utf-8") as f:
        json.dump(keystore, f, indent=2)

    return outdir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="dilithium keygen and benchmark")
    parser.add_argument("--save-keys", action="store_true", help="Generate and save Dilithium keys for 5 users and 3 levels into keys/")
    parser.add_argument("--outdir", default="keys", help="Output directory for generated keys")
    args = parser.parse_args()

    if args.save_keys:
        users = [f"user{i+1}" for i in range(5)]
        levels = ["Dilithium2", "Dilithium3", "Dilithium5"]
        out = generate_and_save_dilithium_keys(users=users, levels=levels, outdir=args.outdir)
        print(f"Saved keys to: {out}")
    else:
        main()

if __name__ == "__main__":
    main()
