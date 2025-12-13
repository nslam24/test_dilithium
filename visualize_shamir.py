#!/usr/bin/env python3
"""
visualize_shamir.py - Minh họa trực quan Shamir Secret Sharing

Vẽ sơ đồ giải thích cơ chế toán học của chia sẻ khóa bí mật Shamir:
- Đa thức bậc t-1 đi qua điểm bí mật (0, s)
- Các mảnh khóa là các điểm trên đường cong
- Nội suy Lagrange để khôi phục khóa từ t điểm
"""
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.patches as mpatches

def shamir_polynomial(x, secret, coeffs):
    """
    Tính giá trị đa thức Shamir tại điểm x.
    f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    
    Args:
        x: điểm cần tính
        secret: hệ số tự do (khóa bí mật)
        coeffs: list các hệ số [a1, a2, ..., a_{t-1}]
    """
    result = secret
    for i, coeff in enumerate(coeffs, start=1):
        result += coeff * (x ** i)
    return result

def lagrange_interpolation(points, x):
    """
    Nội suy Lagrange để tính giá trị tại x từ danh sách điểm.
    
    Args:
        points: list of (xi, yi) tuples
        x: điểm cần tính
    """
    n = len(points)
    result = 0.0
    
    for i in range(n):
        xi, yi = points[i]
        
        # Tính hệ số Lagrange L_i(x)
        L_i = 1.0
        for j in range(n):
            if i != j:
                xj, _ = points[j]
                L_i *= (x - xj) / (xi - xj)
        
        result += yi * L_i
    
    return result

def visualize_shamir_secret_sharing(n=5, t=3, secret=42, output_file='shamir_visualization.png'):
    """
    Tạo sơ đồ minh họa Shamir Secret Sharing.
    
    Args:
        n: tổng số mảnh khóa
        t: ngưỡng (số mảnh tối thiểu cần để khôi phục)
        secret: khóa bí mật (giá trị tại x=0)
        output_file: tên file ảnh đầu ra
    """
    # 1. Sinh đa thức ngẫu nhiên bậc t-1
    np.random.seed(42)  # Để kết quả ổn định
    coeffs = np.random.randint(-10, 10, size=t-1)  # Các hệ số a1, a2, ..., a_{t-1}
    
    # 2. Tính các mảnh khóa (shares)
    x_shares = list(range(1, n+1))  # x = 1, 2, 3, ..., n
    y_shares = [shamir_polynomial(x, secret, coeffs) for x in x_shares]
    
    # 3. Vẽ đồ thị
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # 3a. Vẽ đường cong đa thức (smooth curve)
    x_curve = np.linspace(0, n+0.5, 500)
    y_curve = [shamir_polynomial(x, secret, coeffs) for x in x_curve]
    ax.plot(x_curve, y_curve, 'b-', linewidth=2.5, label=f'Đa thức bậc {t-1}: f(x)', zorder=1)
    
    # 3b. Đánh dấu điểm bí mật (0, s)
    ax.plot(0, secret, 'ro', markersize=20, label='Khóa bí mật Master (0, s)', zorder=5)
    ax.annotate(f'Secret\n(0, {secret})', 
                xy=(0, secret), 
                xytext=(-0.8, secret + 15),
                fontsize=12, 
                fontweight='bold',
                color='red',
                bbox=dict(boxstyle='round,pad=0.5', facecolor='yellow', alpha=0.7),
                arrowprops=dict(arrowstyle='->', color='red', lw=2))
    
    # 3c. Đánh dấu các mảnh khóa (shares)
    colors = plt.cm.tab10(np.linspace(0, 1, n))
    for i, (x, y) in enumerate(zip(x_shares, y_shares)):
        ax.plot(x, y, 'o', markersize=15, color=colors[i], 
                label=f'Share {i+1}: ({x}, {y:.1f})', zorder=4)
        ax.annotate(f'User {i+1}\n({x}, {y:.1f})', 
                    xy=(x, y), 
                    xytext=(x + 0.3, y + 8),
                    fontsize=10,
                    bbox=dict(boxstyle='round,pad=0.4', facecolor=colors[i], alpha=0.6),
                    arrowprops=dict(arrowstyle='->', color=colors[i], lw=1.5))
    
    # 3d. Minh họa nội suy: chọn t điểm đầu tiên
    selected_points = list(zip(x_shares[:t], y_shares[:t]))
    
    # Vẽ đường nét đứt nối các điểm được chọn
    for i in range(len(selected_points)):
        x1, y1 = selected_points[i]
        # Nối với điểm tiếp theo (hoặc điểm đầu tiên nếu là điểm cuối)
        x2, y2 = selected_points[(i+1) % len(selected_points)]
        ax.plot([x1, x2], [y1, y2], 'g--', linewidth=1.5, alpha=0.6, zorder=2)
    
    # Nối các điểm được chọn với secret
    for x, y in selected_points:
        ax.plot([0, x], [secret, y], 'r--', linewidth=1, alpha=0.4, zorder=2)
    
    # 3e. Vẽ đường nội suy để tìm lại secret
    x_interp = np.linspace(0, t, 100)
    y_interp = [lagrange_interpolation(selected_points, x) for x in x_interp]
    ax.plot(x_interp, y_interp, 'm:', linewidth=3, 
            label=f'Nội suy Lagrange từ {t} điểm', zorder=3)
    
    # 4. Thêm vùng highlight cho threshold
    ax.axvspan(0, t, alpha=0.1, color='green', 
               label=f'Vùng Threshold (cần {t} điểm)')
    
    # 5. Thêm text box giải thích
    textstr = f'''SHAMIR SECRET SHARING
━━━━━━━━━━━━━━━━━━━━━━━━
• Tổng số mảnh: n = {n}
• Ngưỡng: t = {t}
• Khóa bí mật: s = {secret}

NGUYÊN LÝ:
1. Tạo đa thức bậc {t-1}: f(x) = {secret}'''
    
    for i, c in enumerate(coeffs, start=1):
        textstr += f' {"+" if c >= 0 else ""}{c}x^{i}'
    
    textstr += f'''

2. Chia sẻ: User_i nhận (i, f(i))
3. Khôi phục: Cần ≥ {t} mảnh để nội suy
   tìm lại f(0) = {secret}
'''
    
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.8)
    ax.text(0.02, 0.98, textstr, transform=ax.transAxes, fontsize=11,
            verticalalignment='top', bbox=props, family='monospace')
    
    # 6. Cấu hình trục và lưới
    ax.set_xlabel('x (ID của User)', fontsize=14, fontweight='bold')
    ax.set_ylabel('y = f(x) (Giá trị mảnh khóa)', fontsize=14, fontweight='bold')
    ax.set_title('SƠ ĐỒ MINH HỌA SHAMIR SECRET SHARING\n' + 
                 f'Chia sẻ bí mật {t}-of-{n} trên trường số thực',
                 fontsize=16, fontweight='bold', pad=20)
    ax.grid(True, alpha=0.3, linestyle='--')
    ax.axhline(y=0, color='k', linewidth=0.5)
    ax.axvline(x=0, color='k', linewidth=0.5)
    
    # Đặt giới hạn trục
    ax.set_xlim(-1, n+1)
    y_min = min(min(y_curve), min(y_shares)) - 20
    y_max = max(max(y_curve), max(y_shares)) + 20
    ax.set_ylim(y_min, y_max)
    
    # 7. Legend
    ax.legend(loc='upper right', fontsize=10, framealpha=0.9)
    
    # 8. Thêm chú thích về threshold property
    ax.text(t/2, y_min + 10, 
            f'✓ Bất kỳ {t} điểm nào cũng khôi phục được secret',
            fontsize=12, color='green', fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgreen', alpha=0.7),
            ha='center')
    
    ax.text((t+n)/2, y_min + 10,
            f'✗ Ít hơn {t} điểm → KHÔNG thể khôi phục',
            fontsize=12, color='red', fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='lightcoral', alpha=0.7),
            ha='center')
    
    # 9. Lưu file
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"✓ Đã lưu sơ đồ vào: {output_file}")
    
    # Hiển thị (nếu chạy interactive)
    plt.show()
    
    return fig, ax

def create_drawio_compatible_svg(n=5, t=3, secret=42, output_file='shamir_visualization.svg'):
    """
    Tạo file SVG tương thích với draw.io.
    """
    fig, ax = visualize_shamir_secret_sharing(n, t, secret, 
                                              output_file.replace('.svg', '.png'))
    
    # Lưu thêm bản SVG để import vào draw.io
    svg_file = output_file
    plt.savefig(svg_file, format='svg', dpi=300, bbox_inches='tight')
    print(f"✓ Đã lưu file SVG cho draw.io: {svg_file}")
    
    return svg_file

if __name__ == '__main__':
    import sys
    
    # Đọc tham số từ command line (nếu có)
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    t = int(sys.argv[2]) if len(sys.argv) > 2 else 3
    secret = int(sys.argv[3]) if len(sys.argv) > 3 else 42
    
    print(f"\n[KHỞI TẠO SƠ ĐỒ SHAMIR SECRET SHARING]")
    print(f"Tham số: n={n}, t={t}, secret={secret}")
    print("="*60)
    
    # Tạo cả PNG và SVG
    visualize_shamir_secret_sharing(n, t, secret, 'shamir_visualization.png')
    create_drawio_compatible_svg(n, t, secret, 'shamir_visualization.svg')
    
    print("\n" + "="*60)
    print("[HƯỚNG DẪN SỬ DỤNG]")
    print("• File PNG: Dùng để xem trực tiếp hoặc chèn vào báo cáo")
    print("• File SVG: Import vào draw.io để chỉnh sửa thêm")
    print("  → File > Import > Chọn shamir_visualization.svg")
    print("="*60)
