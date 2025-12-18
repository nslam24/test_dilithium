#!/usr/bin/env python3
"""
print_benchmark_summary.py - In kết quả benchmark chi tiết

Hiển thị:
- Thời gian ký trung bình mỗi user
- Tổng thông lượng dữ liệu cần gửi
- Thông lượng trung bình mỗi user
"""

import json

def print_detailed_summary():
    """In summary chi tiết với các metrics mới."""
    
    with open('benchmark_dkg_levels.json', 'r') as f:
        results = json.load(f)  # Direct array
    
    print("\n" + "="*100)
    print("📊 BENCHMARK SUMMARY - DKG THRESHOLD SIGNATURE (3-of-5)")
    print("="*100)
    
    print("\n┌─ TIMING METRICS")
    print("│")
    print("│  Level  │  KeyGen  │  Total Sign  │  Per-User Sign  │  Aggregate  │  Verify  │  TOTAL   │")
    print("│  ──────────────────────────────────────────────────────────────────────────────────────────")
    
    for result in results:
        level = result['level']
        keygen = result['keygen_time']
        sign_total = result['avg_sign_time']
        sign_per_user = result['avg_per_user_sign_time']
        agg = result['agg_time']
        verify = result['verify_time']
        total = result['total_time']
        
        print(f"│  {level:5d}  │  {keygen:6.3f}s │    {sign_total:6.3f}s  │     {sign_per_user:6.3f}s    │   {agg:6.3f}s  │ {verify:6.3f}s │ {total:6.3f}s │")
    
    print("└──────────────────────────────────────────────────────────────────────────────────────────\n")
    
    print("┌─ DATA TRANSFER METRICS (Signing Phase)")
    print("│")
    print("│  Level  │  Total Data  │  Per-User Data  │  Signature Size  │  Overhead Ratio  │")
    print("│  ───────────────────────────────────────────────────────────────────────────────────")
    
    for result in results:
        level = result['level']
        total_data = result['avg_data_transfer_kb']
        per_user = result['avg_data_per_user_kb']
        sig_size = result['signature_size_kb']
        overhead = total_data / sig_size
        
        print(f"│  {level:5d}  │   {total_data:7.2f} KB │    {per_user:7.2f} KB  │     {sig_size:6.2f} KB   │      {overhead:5.2f}x     │")
    
    print("└───────────────────────────────────────────────────────────────────────────────────\n")
    
    print("┌─ REJECTION SAMPLING METRICS")
    print("│")
    print("│  Level  │  Avg Attempts  │  Acceptance Rate  │  ||s1|| (small)  │  ||x1|| (large)  │  Ratio    │")
    print("│  ──────────────────────────────────────────────────────────────────────────────────────────────")
    
    for result in results:
        level = result['level']
        attempts = result['avg_attempts']
        accept = result['acceptance_rate']
        s1_norm = result['s1_norm']
        x1_norm = result['x1_norm']
        ratio = x1_norm / s1_norm
        
        print(f"│  {level:5d}  │      {attempts:4.1f}     │      {accept:5.2f}%      │       {s1_norm:5.0f}      │   {x1_norm:11,.0f}   │ {ratio:9,.0f}x │")
    
    print("└──────────────────────────────────────────────────────────────────────────────────────────────\n")
    
    print("┌─ SECURITY PARAMETERS")
    print("│")
    print("│  Level  │  Security  │  K × L  │  η  │  Signature Size  │  Success Rate  │")
    print("│  ────────────────────────────────────────────────────────────────────────────────")
    
    for result in results:
        level = result['level']
        security = {2: "128-bit", 3: "192-bit", 5: "256-bit"}[level]
        K = result['K']
        L = result['L']
        eta = result['eta']
        sig_size = result['signature_size_kb']
        success = result['successful_runs']
        total = result['total_runs']
        
        print(f"│  {level:5d}  │  {security:8s}  │  {K} × {L}  │  {eta}  │     {sig_size:6.2f} KB   │    {success}/{total} runs   │")
    
    print("└────────────────────────────────────────────────────────────────────────────────\n")
    
    print("┌─ PERFORMANCE COMPARISON (vs Level 2)")
    print("│")
    
    base = results[0]
    
    for i, result in enumerate(results[1:], 1):
        level = result['level']
        
        keygen_ratio = result['keygen_time'] / base['keygen_time']
        sign_ratio = result['avg_sign_time'] / base['avg_sign_time']
        per_user_ratio = result['avg_per_user_sign_time'] / base['avg_per_user_sign_time']
        data_ratio = result['avg_data_transfer_kb'] / base['avg_data_transfer_kb']
        size_ratio = result['signature_size_kb'] / base['signature_size_kb']
        
        print(f"│  Level {level} vs Level 2:")
        print(f"│    KeyGen time:      {keygen_ratio:5.2f}x")
        print(f"│    Total sign time:  {sign_ratio:5.2f}x")
        print(f"│    Per-user time:    {per_user_ratio:5.2f}x")
        print(f"│    Data transfer:    {data_ratio:5.2f}x")
        print(f"│    Signature size:   {size_ratio:5.2f}x")
        print("│")
    
    print("└─────────────────────────────────────────────────────────────────────")
    
    print("\n" + "="*100)
    print("💡 KEY INSIGHTS")
    print("="*100)
    
    print("\n1. PER-USER SIGNING TIME:")
    for result in results:
        per_user = result['avg_per_user_sign_time'] * 1000
        print(f"   Level {result['level']}: {per_user:.1f}ms average per user")
    
    print("\n2. TOTAL NETWORK TRAFFIC (all users send partial signatures):")
    for result in results:
        total = result['avg_data_transfer_kb']
        per_user = result['avg_data_per_user_kb']
        t = result['t']
        print(f"   Level {result['level']}: {total:.2f} KB total ({per_user:.2f} KB × {t} users)")
    
    print("\n3. DATA OVERHEAD (vs final signature size):")
    for result in results:
        overhead = result['avg_data_transfer_kb'] / result['signature_size_kb']
        print(f"   Level {result['level']}: {overhead:.1f}x overhead (need to send {overhead:.1f}× more data than final signature)")
    
    print("\n4. ACCEPTANCE RATE:")
    for result in results:
        accept = result['acceptance_rate']
        attempts = result['avg_attempts']
        t = result['t']
        print(f"   Level {result['level']}: {accept:.1f}% ({attempts:.1f} attempts for {t} users → ~{attempts/t:.1f} per user)")
    
    print("\n5. DUAL SECRETS ARCHITECTURE:")
    for result in results:
        ratio = result['x1_norm'] / result['s1_norm']
        print(f"   Level {result['level']}: x_i is {ratio:,.0f}× larger than s_i (CHECK with small, SEND with large)")
    
    print("\n" + "="*100 + "\n")


if __name__ == '__main__':
    print_detailed_summary()
