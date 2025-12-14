#!/usr/bin/env python3
"""
Tạo bảng tổng kết đẹp từ kết quả benchmark
"""
import json
import sys

def format_size(bytes_val):
    """Format bytes thành KB với 2 chữ số thập phân"""
    return f"{bytes_val/1024:.2f}"

def format_time(seconds):
    """Format giây thành ms với 1 chữ số thập phân"""
    return f"{seconds*1000:.1f}"

def print_summary_table(filepath="multisig_comparison_results.json"):
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    results = data['results']
    config = data['benchmark_config']
    
    print("\n" + "="*140)
    print("BẢNG TỔNG KẾT: SO SÁNH HIỆU NĂNG 4 MÔ HÌNH KÝ ĐA PHƯƠNG (POST-QUANTUM)")
    print("="*140)
    print(f"Tham số: Dilithium 3 (K={config['K']}, L={config['L']}), Message={config['message_size']} bytes")
    print("="*140)
    
    # HEADER
    print(f"\n{'MÔ HÌNH':<25} {'N/T':<8} {'KEYGEN':<10} {'SIGN':<10} {'VERIFY':<10} "
          f"{'SIG_SIZE':<10} {'COMM':<10} {'ROUNDS':<8} {'ATTEMPTS':<10}")
    print(f"{'(Scheme)':<25} {'Signers':<8} {'(ms)':<10} {'(ms)':<10} {'(ms)':<10} "
          f"{'(KB)':<10} {'(KB)':<10} {'':<8} {'':<10}")
    print("-"*140)
    
    for m in results:
        n_t = f"{m['num_signers']}/{m['threshold']}" if m['threshold'] != m['num_signers'] else f"{m['num_signers']}"
        
        print(f"{m['scheme']:<25} {n_t:<8} "
              f"{format_time(m['keygen_time']):<10} "
              f"{format_time(m['sign_time']):<10} "
              f"{format_time(m['verify_time']):<10} "
              f"{format_size(m['signature_size']):<10} "
              f"{format_size(m['communication_bytes']):<10} "
              f"{m['rounds']:<8} "
              f"{m['attempts']:<10}")
    
    print("="*140)
    
    # PHÂN TÍCH
    print("\n📊 PHÂN TÍCH SO SÁNH:")
    print("-"*140)
    
    # Nhóm theo N
    for N in sorted(set(m['num_signers'] for m in results)):
        group = [m for m in results if m['num_signers'] == N]
        
        print(f"\n🔍 N={N} người ký:")
        
        fastest_sign = min(group, key=lambda x: x['sign_time'])
        fastest_verify = min(group, key=lambda x: x['verify_time'])
        smallest_sig = min(group, key=lambda x: x['signature_size'])
        lowest_comm = min(group, key=lambda x: x['communication_bytes'])
        fewest_rounds = min(group, key=lambda x: x['rounds'])
        
        print(f"   ✓ Ký nhanh nhất:        {fastest_sign['scheme']:<20} → {format_time(fastest_sign['sign_time'])} ms")
        print(f"   ✓ Verify nhanh nhất:    {fastest_verify['scheme']:<20} → {format_time(fastest_verify['verify_time'])} ms")
        print(f"   ✓ Chữ ký gọn nhất:      {smallest_sig['scheme']:<20} → {format_size(smallest_sig['signature_size'])} KB")
        print(f"   ✓ Băng thông thấp nhất: {lowest_comm['scheme']:<20} → {format_size(lowest_comm['communication_bytes'])} KB")
        print(f"   ✓ Ít vòng nhất:         {fewest_rounds['scheme']:<20} → {fewest_rounds['rounds']} rounds")
    
    print("\n" + "="*140)
    
    # ĐÁNH GIÁ TỔNG QUAN
    print("\n📝 ĐÁNH GIÁ TỔNG QUAN:")
    print("-"*140)
    print("""
1. INDEPENDENT (Ký độc lập):
   ✅ NHANH NHẤT cho cả signing và verification (~1-2ms)
   ✅ Ít vòng tương tác nhất (1 round)
   ✅ Song song hóa hoàn toàn
   ❌ Kích thước chữ ký lớn: O(N) - tăng tuyến tính theo số người ký
   ❌ Băng thông cao: phải gửi N chữ ký đầy đủ
   → Phù hợp: Hệ thống cần tốc độ cao, băng thông không là vấn đề

2. SEQUENTIAL (Ký tuần tự):
   ✅ Tương đương Independent về tốc độ (~1-3ms)
   ✅ Chống replay attack tốt (hash chaining)
   ❌ Số vòng tương tác = N (phải đợi người trước)
   ❌ Không song song hóa được
   ❌ Kích thước giống Independent: O(N)
   → Phù hợp: Hệ thống cần audit trail rõ ràng, thứ tự ký quan trọng

3. THRESHOLD (Ký ngưỡng - t-of-n):
   ✅ Kích thước chữ ký GỌN NHẤT: O(1) - KHÔNG phụ thuộc N (~17KB)
   ✅ Fault tolerance: chỉ cần t/n người (Byzantine resilience)
   ✅ Privacy: không lộ người ký cụ thể
   ⚠️  Chậm hơn nhiều: 800ms - 7.7s (do rejection sampling)
   ⚠️  Keygen phức tạp: 85-220ms (DKG với Shamir sharing)
   ⚠️  Số attempts cao: 10-64 lần (tăng theo N)
   ⚠️  Băng thông cao khi DKG: O(N²) shares
   → Phù hợp: Blockchain, multi-party signing, cần fault tolerance

4. AGGREGATE (Razhi-ms) - CHƯA TEST:
   (Dự kiến: Kích thước O(1), 3 rounds, rejection sampling cao)
   → Phù hợp: Cần chữ ký gọn, multi-party authentication

KHUYẾN NGHỊ:
- Nếu ưu tiên TỐC ĐỘ: dùng INDEPENDENT hoặc SEQUENTIAL
- Nếu ưu tiên KÍCH THƯỚC chữ ký: dùng THRESHOLD
- Nếu cần FAULT TOLERANCE: dùng THRESHOLD (t<N)
- Nếu cần AUDIT TRAIL: dùng SEQUENTIAL
    """)
    
    print("="*140 + "\n")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "../multisig_comparison_results.json"
    print_summary_table(filepath)
