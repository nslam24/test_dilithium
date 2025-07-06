# dilithium Key Generation Project

This project provides a Python script to run the dilithium algorithm and generate cryptographic keys.

## Requirements
- Python 3.7+
- (Optional) Install dependencies with `pip install -r requirements.txt` if required

## Usage
Run the script to generate dilithium keys:

```bash
python dilithium_keygen.py
```

The script will output the generated public and private keys.

## Note
This is a minimal example. For production or research use, consider using a well-maintained cryptographic library that implements dilithium, such as `pqcrypto` or `py-dilithium` if available.

# Hướng dẫn cài đặt và benchmark thuật toán chữ ký số hậu lượng tử (Dilithium, RSA, ECC)

## 1. Cài đặt thư viện cần thiết

### a. Cài đặt liboqs và python-oqs (dành cho Linux)

```bash
sudo apt-get update
sudo apt-get install cmake gcc ninja-build libssl-dev python3-dev
# Clone mã nguồn liboqs-python
cd /home/lamns/python
git clone --recursive https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
python3 -m pip install .
```

### b. Cài đặt thư viện cryptography (cho RSA/ECC)

```bash
pip install cryptography
```

## 2. Chạy kiểm thử và benchmark

- Đảm bảo bạn đang ở thư mục chứa file `dilithium_keygen.py`.
- Chạy script:

```bash
python dilithium_keygen.py
```

## 3. Ý nghĩa các thuật toán và chỉ số
- **Dilithium2/3/5**: Các cấp độ bảo mật hậu lượng tử (NIST Level 2/3/5)
- **RSA-2048**: Thuật toán chữ ký số truyền thống
- **ECC-P256**: Thuật toán chữ ký số Elliptic Curve
- **PubKey/PrivKey/Chữ ký**: Kích thước khóa công khai, bí mật, chữ ký (byte)
- **Ký (s)/Xác minh (s)**: Thời gian ký và xác minh (giây)
- **Tỉ lệ đúng**: Tỷ lệ xác minh chữ ký thành công

## 4. Lưu ý
- Nếu gặp lỗi `No module named 'oqs'`, kiểm tra lại bước cài đặt liboqs-python.
- Nên sử dụng Python 3.8 trở lên.

---

Mọi thắc mắc về cài đặt hoặc sử dụng, vui lòng liên hệ hoặc tham khảo tài liệu chính thức của [Open Quantum Safe](https://github.com/open-quantum-safe/liboqs-python).
