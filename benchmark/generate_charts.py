#!/usr/bin/env python3
"""
Tạo biểu đồ so sánh 4 mô hình ký
Lưu dưới dạng ASCII art (không cần matplotlib)
"""
import json

def create_bar_chart(values, labels, title, max_width=60, unit="ms"):
    """Tạo biểu đồ ASCII bar chart"""
    print(f"\n{title}")
    print("="*80)
    
    max_val = max(values)
    
    for i, (label, val) in enumerate(zip(labels, values)):
        bar_len = int((val / max_val) * max_width) if max_val > 0 else 0
        bar = "█" * bar_len
        print(f"{label:<25} {bar} {val:.2f}{unit}")
    
    print()

def main():
    with open("../multisig_comparison_results.json", 'r') as f:
        data = json.load(f)
    
    results = data['results']
    
    print("\n" + "="*80)
    print("BIỂU ĐỒ SO SÁNH HIỆU NĂNG - 4 MÔ HÌNH KÝ POST-QUANTUM")
    print("="*80)
    
    # Nhóm theo N
    for N in [5, 10]:
        group = [m for m in results if m['num_signers'] == N]
        
        print(f"\n📊 N={N} NGƯỜI KÝ:")
        print("-"*80)
        
        # 1. THỜI GIAN KÝ (ms)
        labels = [m['scheme'] for m in group]
        sign_times = [m['sign_time'] * 1000 for m in group]
        create_bar_chart(sign_times, labels, "1. THỜI GIAN KÝ (ms) - Càng thấp càng tốt", unit="ms")
        
        # 2. KÍCH THƯỚC CHỮ KÝ (KB)
        sig_sizes = [m['signature_size'] / 1024 for m in group]
        create_bar_chart(sig_sizes, labels, "2. KÍCH THƯỚC CHỮ KÝ (KB) - Càng nhỏ càng tốt", unit="KB")
        
        # 3. BĂNG THÔNG (KB)
        comm = [m['communication_bytes'] / 1024 for m in group]
        create_bar_chart(comm, labels, "3. BĂNG THÔNG TRAO ĐỔI (KB) - Càng thấp càng tốt", unit="KB")
        
        # 4. SỐ VÒNG TƯƠNG TÁC
        rounds = [m['rounds'] for m in group]
        create_bar_chart(rounds, labels, "4. SỐ VÒNG TƯƠNG TÁC - Càng ít càng tốt", max_width=40, unit=" rounds")
    
    # BẢNG SO SÁNH KHẢ NĂNG MỞ RỘNG (SCALABILITY)
    print("\n" + "="*80)
    print("📈 KHẢI NĂNG MỞ RỘNG (SCALABILITY)")
    print("="*80)
    print(f"\n{'Scheme':<25} {'N=5 (ms)':<12} {'N=10 (ms)':<12} {'Tăng trưởng':<15}")
    print("-"*80)
    
    schemes = sorted(set(m['scheme'].split('-')[0] for m in results))
    
    for scheme_prefix in schemes:
        n5 = next((m for m in results if m['num_signers']==5 and m['scheme'].startswith(scheme_prefix)), None)
        n10 = next((m for m in results if m['num_signers']==10 and m['scheme'].startswith(scheme_prefix)), None)
        
        if n5 and n10:
            time5 = n5['sign_time'] * 1000
            time10 = n10['sign_time'] * 1000
            growth = time10 / time5 if time5 > 0 else 0
            
            print(f"{scheme_prefix:<25} {time5:<12.1f} {time10:<12.1f} {growth:.2f}x")
    
    print("\n💡 NHẬN XÉT:")
    print("-"*80)
    print("  • Independent/Sequential: Tăng tuyến tính O(N) - ổn định")
    print("  • Threshold: Tăng QUADRATIC O(N²) - do rejection sampling cao khi N lớn")
    print("  → Threshold phù hợp cho N nhỏ (<10), Independent/Sequential cho N lớn")
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    main()
