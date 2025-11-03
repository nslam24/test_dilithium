#!/bin/bash
# Script rebuild liboqs với các implementation options khác nhau

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  liboqs Rebuild Script - Choose Implementation           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Kiểm tra dependencies
echo "=== 1. Kiểm tra dependencies ==="
DEPS=("cmake" "gcc" "ninja-build" "git")
MISSING=()

for dep in "${DEPS[@]}"; do
    if ! command -v $dep &> /dev/null; then
        MISSING+=($dep)
    fi
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "⚠️  Thiếu dependencies: ${MISSING[*]}"
    echo "Cài đặt bằng: sudo apt-get install ${MISSING[*]}"
    exit 1
fi
echo "✅ Tất cả dependencies đã có"

# Menu chọn implementation
echo ""
echo "=== 2. Chọn Implementation Type ==="
echo "1) AVX2 + AES-NI (Fastest - yêu cầu CPU Skylake+)"
echo "2) AVX2 Only (Fast - yêu cầu CPU Haswell+)"
echo "3) Reference (Portable - chạy trên mọi CPU)"
echo "4) Auto-detect (Mặc định - liboqs tự chọn)"
echo ""
read -p "Chọn option [1-4]: " IMPL_CHOICE

case $IMPL_CHOICE in
    1)
        OPT_FLAG="-DOQS_USE_AVX2_INSTRUCTIONS=ON -DOQS_USE_AES_INSTRUCTIONS=ON"
        IMPL_NAME="AVX2+AES"
        ;;
    2)
        OPT_FLAG="-DOQS_USE_AVX2_INSTRUCTIONS=ON -DOQS_USE_AES_INSTRUCTIONS=OFF"
        IMPL_NAME="AVX2"
        ;;
    3)
        OPT_FLAG="-DOQS_USE_AVX2_INSTRUCTIONS=OFF -DOQS_USE_AES_INSTRUCTIONS=OFF"
        IMPL_NAME="Reference"
        ;;
    4)
        OPT_FLAG=""
        IMPL_NAME="Auto-detect"
        ;;
    *)
        echo "❌ Lựa chọn không hợp lệ"
        exit 1
        ;;
esac

echo "→ Chọn: $IMPL_NAME"

# Clone hoặc update liboqs
echo ""
echo "=== 3. Tải mã nguồn liboqs ==="
LIBOQS_DIR="$HOME/liboqs-src"

if [ -d "$LIBOQS_DIR" ]; then
    echo "Thư mục đã tồn tại. Cập nhật..."
    cd "$LIBOQS_DIR"
    git pull
else
    echo "Clone liboqs repository..."
    git clone --branch main https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_DIR"
    cd "$LIBOQS_DIR"
fi

# Build liboqs
echo ""
echo "=== 4. Build liboqs với $IMPL_NAME ==="
mkdir -p build
cd build

# Configure với CMake
echo "Configure CMake..."
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=$HOME/_oqs \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    $OPT_FLAG \
    ..

echo "Compile..."
ninja

echo "Install..."
ninja install

echo ""
echo "✅ Build hoàn tất!"
echo "liboqs installed to: $HOME/_oqs"

# Rebuild python bindings
echo ""
echo "=== 5. Rebuild liboqs-python bindings ==="
LIBOQS_PYTHON_DIR="$HOME/liboqs-python-rebuild"

if [ -d "$LIBOQS_PYTHON_DIR" ]; then
    rm -rf "$LIBOQS_PYTHON_DIR"
fi

git clone https://github.com/open-quantum-safe/liboqs-python.git "$LIBOQS_PYTHON_DIR"
cd "$LIBOQS_PYTHON_DIR"

# Set environment variables
export liboqs_DIR=$HOME/_oqs
export LD_LIBRARY_PATH=$HOME/_oqs/lib:$LD_LIBRARY_PATH

echo "Build Python bindings..."
pip uninstall -y oqs 2>/dev/null || true
pip install .

echo ""
echo "✅ Python bindings rebuilt!"

# Verify installation
echo ""
echo "=== 6. Kiểm tra installation ==="
python3 << EOF
import oqs
print(f"liboqs version: {oqs.oqs_version()}")
print(f"Enabled algorithms: {len(oqs.get_enabled_sig_mechanisms())} signature schemes")
EOF

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  BUILD COMPLETED!                                          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Implementation: $IMPL_NAME"
echo "Install path: $HOME/_oqs"
echo ""
echo "⚠️  Quan trọng: Thêm vào ~/.bashrc:"
echo "export LD_LIBRARY_PATH=$HOME/_oqs/lib:\$LD_LIBRARY_PATH"
echo ""
echo "Sau đó chạy: source ~/.bashrc"
echo ""
echo "Kiểm tra lại implementation:"
echo "python check_implementation.py"
