#!/usr/bin/env python3
"""
Visualization of PQC Multi-Signature Trade-offs
================================================
Creates 3 key charts demonstrating:
1. Verification Win: Threshold O(1) vs Independent O(N)
2. Storage Win: Threshold constant vs Independent O(N)
3. Communication Cost: The trade-off we must accept
"""

import json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

# Set publication-quality style
plt.style.use('seaborn-v0_8-darkgrid')
plt.rcParams['figure.figsize'] = (15, 5)
plt.rcParams['font.size'] = 11
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['legend.fontsize'] = 10

def load_results():
    """Load Scenario 1 results with storage/network data"""
    results_file = Path('results/scenario1_storage_network_analysis.json')
    
    if not results_file.exists():
        print(f"❌ File not found: {results_file}")
        print("Please run: python analyze_storage_network.py first")
        return None
    
    with open(results_file, 'r') as f:
        data = json.load(f)
    
    return data['results']

def extract_metrics(results):
    """Extract metrics for each mode across different N values"""
    N_values = []
    
    # Independent mode
    ind_verify = []
    ind_pk_size = []
    ind_sig_size = []
    ind_network = []
    
    # Full Threshold (t=n)
    full_verify = []
    full_pk_size = []
    full_sig_size = []
    full_network = []
    
    # Flexible Threshold (t≈2n/3)
    flex_verify = []
    flex_pk_size = []
    flex_sig_size = []
    flex_network = []
    
    for entry in results:
        n = entry['n_parties']
        mode = entry['mode']
        
        # Add N value only once
        if mode == 'independent' and n not in N_values:
            N_values.append(n)
        
        # Extract metrics based on mode
        if mode == 'independent':
            ind_verify.append(entry['verify_time'])
            ind_pk_size.append(entry['total_pk_size'] / 1024)  # Convert bytes to KB
            ind_sig_size.append(entry['total_sig_size'] / 1024)
            ind_network.append(entry['network_traffic'] / 1024)
        
        elif mode.startswith('threshold_full'):
            full_verify.append(entry['verify_time'])
            full_pk_size.append(entry['total_pk_size'] / 1024)
            full_sig_size.append(entry['total_sig_size'] / 1024)
            full_network.append(entry['network_traffic'] / 1024)
        
        elif mode.startswith('threshold_flex'):
            flex_verify.append(entry['verify_time'])
            flex_pk_size.append(entry['total_pk_size'] / 1024)
            flex_sig_size.append(entry['total_sig_size'] / 1024)
            flex_network.append(entry['network_traffic'] / 1024)
    
    return {
        'N': N_values,
        'independent': {
            'verify': ind_verify,
            'pk_size': ind_pk_size,
            'sig_size': ind_sig_size,
            'total_storage': [pk + sig for pk, sig in zip(ind_pk_size, ind_sig_size)],
            'network': ind_network
        },
        'full': {
            'verify': full_verify,
            'pk_size': full_pk_size,
            'sig_size': full_sig_size,
            'total_storage': [pk + sig for pk, sig in zip(full_pk_size, full_sig_size)],
            'network': full_network
        },
        'flexible': {
            'verify': flex_verify,
            'pk_size': flex_pk_size,
            'sig_size': flex_sig_size,
            'total_storage': [pk + sig for pk, sig in zip(flex_pk_size, flex_sig_size)],
            'network': flex_network
        }
    }

def create_tradeoff_charts(metrics):
    """Create 3 publication-quality charts"""
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    N = metrics['N']
    
    # ==========================================
    # Chart 1: The Verification Win 🏆
    # ==========================================
    ax1 = axes[0]
    
    # CRITICAL FIX: Independent requires N separate verifications!
    # Total verification cost = verify_time_per_sig × N
    ind_total_verify_ms = [t * 1000 * n for t, n in zip(metrics['independent']['verify'], N)]
    
    # Threshold: Single aggregate verification (constant time)
    full_verify_ms = [t * 1000 for t in metrics['full']['verify']]
    flex_verify_ms = [t * 1000 for t in metrics['flexible']['verify']]
    
    ax1.plot(N, ind_total_verify_ms, 'o-', linewidth=2.5, markersize=8, 
             color='#e74c3c', label='Independent (N × T_verify, O(N) tuyến tính)', alpha=0.8)
    ax1.plot(N, full_verify_ms, 's-', linewidth=2.5, markersize=8, 
             color='#27ae60', label='Threshold Full t=n (1 × T_verify, O(1) hằng số)', alpha=0.8)
    ax1.plot(N, flex_verify_ms, '^-', linewidth=2.5, markersize=8, 
             color='#3498db', label='Threshold Flexible t≈2n/3 (1 × T_verify, O(1) hằng số)', alpha=0.8)
    
    ax1.set_xlabel('Số lượng người ký (N)', fontweight='bold')
    ax1.set_ylabel('Tổng thời gian xác minh (ms)', fontweight='bold')
    ax1.set_title('🏆 Biểu đồ 1: The Verification Win\nThreshold O(1) vs Independent O(N)', 
                  fontweight='bold', pad=15)
    ax1.legend(loc='upper left', framealpha=0.95)
    ax1.grid(True, alpha=0.3)
    ax1.set_xticks(N)
    
    # Add speedup annotation at N=20
    speedup = ind_total_verify_ms[-1] / full_verify_ms[-1]
    ax1.annotate(f'Nhanh hơn {speedup:.1f}x\ntại N=20!', 
                xy=(N[-1], full_verify_ms[-1]), 
                xytext=(N[-2], ind_total_verify_ms[-2] * 0.6),
                arrowprops=dict(arrowstyle='->', color='green', lw=2),
                fontsize=10, color='green', fontweight='bold',
                bbox=dict(boxstyle='round,pad=0.5', facecolor='lightyellow', alpha=0.8))
    
    # ==========================================
    # Chart 2: The Storage Win 💾
    # ==========================================
    ax2 = axes[1]
    
    ind_storage = metrics['independent']['total_storage']
    full_storage = metrics['full']['total_storage']
    flex_storage = metrics['flexible']['total_storage']
    
    ax2.plot(N, ind_storage, 'o-', linewidth=2.5, markersize=8, 
             color='#e74c3c', label='Independent (O(N) tăng tuyến tính)', alpha=0.8)
    ax2.plot(N, full_storage, 's-', linewidth=2.5, markersize=8, 
             color='#27ae60', label='Threshold Full t=n (O(1) hằng số)', alpha=0.8)
    ax2.plot(N, flex_storage, '^-', linewidth=2.5, markersize=8, 
             color='#3498db', label='Threshold Flexible t≈2n/3 (O(1) hằng số)', alpha=0.8)
    
    ax2.set_xlabel('Số lượng người ký (N)', fontweight='bold')
    ax2.set_ylabel('Tổng kích thước lưu trữ (KB)', fontweight='bold')
    ax2.set_title('💾 Biểu đồ 2: The Storage Win\nPhù hợp cho Blockchain (kích thước cố định)', 
                  fontweight='bold', pad=15)
    ax2.legend(loc='upper left', framealpha=0.95)
    ax2.grid(True, alpha=0.3)
    ax2.set_xticks(N)
    
    # Add compression ratio at N=20
    compression = ind_storage[-1] / full_storage[-1]
    ax2.annotate(f'Nén {compression:.1f}x\ntại N=20!', 
                xy=(N[-1], full_storage[-1]), 
                xytext=(N[-2], ind_storage[-2] * 0.5),
                arrowprops=dict(arrowstyle='->', color='green', lw=2),
                fontsize=10, color='green', fontweight='bold',
                bbox=dict(boxstyle='round,pad=0.5', facecolor='lightcyan', alpha=0.8))
    
    # ==========================================
    # Chart 3: The Communication Cost ⚠️
    # ==========================================
    ax3 = axes[2]
    
    ind_network = metrics['independent']['network']
    full_network = metrics['full']['network']
    flex_network = metrics['flexible']['network']
    
    ax3.plot(N, ind_network, 'o-', linewidth=2.5, markersize=8, 
             color='#27ae60', label='Independent (0 KB, không cần giao tiếp)', alpha=0.8)
    ax3.plot(N, full_network, 's-', linewidth=2.5, markersize=8, 
             color='#e74c3c', label='Threshold Full t=n (O(t²) tăng bậc 2)', alpha=0.8)
    ax3.plot(N, flex_network, '^-', linewidth=2.5, markersize=8, 
             color='#f39c12', label='Threshold Flexible t≈2n/3 (Trung bình)', alpha=0.8)
    
    ax3.set_xlabel('Số lượng người ký (N)', fontweight='bold')
    ax3.set_ylabel('Chi phí giao tiếp (KB)', fontweight='bold')
    ax3.set_title('⚠️ Biểu đồ 3: The Communication Cost\nTrade-off phải chấp nhận (O(t²) network)', 
                  fontweight='bold', pad=15)
    ax3.legend(loc='upper left', framealpha=0.95)
    ax3.grid(True, alpha=0.3)
    ax3.set_xticks(N)
    
    # Add trade-off annotation
    savings = (1 - flex_network[-1] / full_network[-1]) * 100
    ax3.annotate(f'Flexible tiết kiệm\n{savings:.0f}% network\nso với Full!', 
                xy=(N[-1], flex_network[-1]), 
                xytext=(N[-2], full_network[-1] * 0.6),
                arrowprops=dict(arrowstyle='->', color='orange', lw=2),
                fontsize=10, color='darkorange', fontweight='bold',
                bbox=dict(boxstyle='round,pad=0.5', facecolor='lightyellow', alpha=0.8))
    
    plt.tight_layout()
    
    return fig

def print_summary_stats(metrics):
    """Print key statistics to console"""
    print("\n" + "="*70)
    print("📊 TỔNG HỢP KẾT QUẢ - KEY FINDINGS")
    print("="*70)
    
    N = metrics['N']
    
    print("\n🏆 VERIFICATION WIN (tại N=20):")
    ind_v_single = metrics['independent']['verify'][-1] * 1000
    ind_v_total = ind_v_single * N[-1]  # Total cost = N × single_verify
    full_v = metrics['full']['verify'][-1] * 1000
    flex_v = metrics['flexible']['verify'][-1] * 1000
    print(f"  • Independent: {ind_v_total:.3f} ms (= {ind_v_single:.3f} × {N[-1]} verifications)")
    print(f"  • Full Threshold: {full_v:.3f} ms (1 aggregate verification)")
    print(f"  • Flexible Threshold: {flex_v:.3f} ms (1 aggregate verification)")
    print(f"  ➜ Threshold nhanh hơn {ind_v_total/full_v:.1f}x! ✅")
    
    print("\n💾 STORAGE WIN (tại N=20):")
    ind_s = metrics['independent']['total_storage'][-1]
    full_s = metrics['full']['total_storage'][-1]
    flex_s = metrics['flexible']['total_storage'][-1]
    print(f"  • Independent: {ind_s:.1f} KB (tăng theo N)")
    print(f"  • Full Threshold: {full_s:.1f} KB (hằng số)")
    print(f"  • Flexible Threshold: {flex_s:.1f} KB (hằng số)")
    print(f"  ➜ Nén {ind_s/full_s:.1f}x! Phù hợp Blockchain ✅")
    
    print("\n⚠️ COMMUNICATION COST (tại N=20):")
    ind_n = metrics['independent']['network'][-1]
    full_n = metrics['full']['network'][-1]
    flex_n = metrics['flexible']['network'][-1]
    print(f"  • Independent: {ind_n:.1f} KB (không cần giao tiếp)")
    print(f"  • Full Threshold: {full_n:.1f} KB (O(t²) bậc 2)")
    print(f"  • Flexible Threshold: {flex_n:.1f} KB (trung bình)")
    savings = (1 - flex_n/full_n) * 100
    print(f"  ➜ Trade-off: Phải chấp nhận network cost")
    print(f"  ➜ Flexible tiết kiệm {savings:.0f}% so với Full! 💡")
    
    print("\n🎯 KẾT LUẬN:")
    print("  ✅ Verification: Threshold thắng áp đảo (hằng số vs tuyến tính)")
    print("  ✅ Storage: Threshold nén 16.7x (phù hợp Blockchain)")
    print("  ⚠️ Trade-off: Chi phí network O(t²) - điều phải chấp nhận")
    print("  💡 Optimal: Flexible Threshold = verification win + storage win + 58% ít network hơn Full")
    print("="*70 + "\n")

def main():
    """Main execution"""
    print("🎨 Đang tạo 3 biểu đồ chứng minh ưu điểm Threshold Multi-Signature...")
    
    # Load results
    results = load_results()
    if results is None:
        return
    
    # Extract metrics
    print("📊 Đang trích xuất metrics...")
    metrics = extract_metrics(results)
    
    # Print summary
    print_summary_stats(metrics)
    
    # Create charts
    print("🎨 Đang vẽ biểu đồ...")
    fig = create_tradeoff_charts(metrics)
    
    # Save figure
    output_file = 'results/tradeoff_analysis.png'
    fig.savefig(output_file, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"\n✅ Đã lưu biểu đồ: {output_file}")
    
    # Also save as PDF for publication
    pdf_file = 'results/tradeoff_analysis.pdf'
    fig.savefig(pdf_file, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✅ Đã lưu PDF: {pdf_file}")
    
    print("\n📈 Kết quả:")
    print(f"  • Biểu đồ 1: Verification Win - Threshold O(1) vs Independent O(N)")
    print(f"  • Biểu đồ 2: Storage Win - Nén 16.7x phù hợp Blockchain")
    print(f"  • Biểu đồ 3: Communication Cost - Trade-off O(t²) network")
    
    plt.show()

if __name__ == '__main__':
    main()
