#!/usr/bin/env python3
"""
multisig_performance_test.py - Comprehensive Performance Benchmark

Đo lường và so sánh 4 mô hình ký:
1. INDEPENDENT - Ký độc lập (mỗi người ký riêng)
2. SEQUENTIAL - Ký tuần tự (hash-chaining)
3. AGGREGATE (Razhi-ms) - Ký gộp (one-round lattice-based)
4. THRESHOLD - Ký ngưỡng (t-of-n distributed)

Chỉ số đánh giá:
✓ Thời gian sinh khóa (keygen_time)
✓ Kích thước khóa công khai (pk_size)
✓ Kích thước khóa bí mật (sk_size)
✓ Thời gian ký (sign_time)
✓ Thời gian xác minh (verify_time)
✓ Kích thước chữ ký (signature_size)
✓ Dung lượng dữ liệu trao đổi (communication_bytes)
✓ Số vòng tương tác (rounds)
✓ Khả năng mở rộng (scalability: N=5,10,20)

Tham số Dilithium 3:
- K = 6 (số hàng ma trận A)
- L = 5 (số cột ma trận A)
- Q = 8380417
- N = 256
"""

import time
import sys
import os
import json
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass, asdict
import random

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import các module ký
from modes.independent_mode import sign_independent, verify_independent
from modes.sequential_mode import sign_sequential, verify_sequential
from modes.razhi_multisig import (
    setup as razhi_setup,
    keygen as razhi_keygen,
    sign_aggregate as razhi_sign,
    verify as razhi_verify,
    K as RAZHI_K, L as RAZHI_L
)
from modes.threshold_dilithium import (
    generate_keypair_distributed,
    sign_threshold,
    verify_threshold,
    DILITHIUM_Q, DILITHIUM_N
)

# Import liboqs để sinh khóa Dilithium cho Independent/Sequential
try:
    import oqs
    HAS_OQS = True
except ImportError:
    HAS_OQS = False
    print("Warning: liboqs-python not available, skipping Independent/Sequential modes")


@dataclass
class PerformanceMetrics:
    """Chỉ số hiệu năng cho một lần chạy"""
    scheme: str              # Tên mô hình (Independent/Sequential/Aggregate/Threshold)
    num_signers: int         # Số người ký (N)
    threshold: int           # Ngưỡng (t) - chỉ dùng cho Threshold, = N cho các mô hình khác
    
    # Thời gian (giây)
    keygen_time: float       # Thời gian sinh khóa (tổng cho tất cả người ký)
    sign_time: float         # Thời gian ký (tổng)
    verify_time: float       # Thời gian xác minh
    
    # Kích thước (bytes)
    pk_size: int             # Kích thước khóa công khai (tổng hoặc 1 khóa đại diện)
    sk_size: int             # Kích thước khóa bí mật (tổng hoặc 1 khóa đại diện)
    signature_size: int      # Kích thước chữ ký (tổng)
    
    # Băng thông
    communication_bytes: int # Tổng dữ liệu trao đổi (keygen + sign + verify)
    rounds: int              # Số vòng tương tác
    
    # Khác
    success: bool            # Ký và verify thành công?
    attempts: int            # Số lần thử (cho rejection sampling - Threshold/Aggregate)
    
    # Throughput
    sign_throughput: float   # Chữ ký/giây
    verify_throughput: float # Verify/giây


class MultiSigPerformanceTest:
    """
    Class test hiệu năng toàn diện cho 4 mô hình ký
    
    Sử dụng:
    >>> tester = MultiSigPerformanceTest()
    >>> results = tester.run_full_benchmark(num_runs=10)
    >>> tester.print_comparison_table(results)
    >>> tester.export_json(results, "benchmark_results.json")
    """
    
    def __init__(self, dilithium_level: str = "Dilithium3"):
        """
        Args:
            dilithium_level: "Dilithium2" | "Dilithium3" | "Dilithium5"
        """
        self.dilithium_level = dilithium_level
        
        # Tham số Dilithium 3 (theo FIPS 204)
        self.K = 6  # Số hàng ma trận A
        self.L = 5  # Số cột ma trận A
        
        # Message mẫu
        self.test_message = b"Benchmark message for multi-signature performance testing"
    
    # ============================================================================
    # INDEPENDENT MODE
    # ============================================================================
    
    def benchmark_independent(self, num_signers: int, num_runs: int = 1) -> PerformanceMetrics:
        """
        Test INDEPENDENT mode - mỗi người ký riêng biệt
        
        Đặc điểm:
        - Thời gian ký: O(N) (song song)
        - Kích thước chữ ký: O(N) (lưu N chữ ký riêng)
        - Số vòng: 1 (không cần tương tác)
        - Băng thông: Cao (phải gửi N chữ ký đầy đủ)
        """
        if not HAS_OQS:
            return self._create_failed_metrics("Independent", num_signers, num_signers)
        
        total_keygen = 0.0
        total_sign = 0.0
        total_verify = 0.0
        total_attempts = 0
        
        for _ in range(num_runs):
            # 1. KEYGEN - Mỗi người sinh khóa riêng
            t0 = time.perf_counter()
            key_pairs = []
            for i in range(num_signers):
                with oqs.Signature(self.dilithium_level) as signer:
                    public_key = signer.generate_keypair()
                    secret_key = signer.export_secret_key()
                    key_pairs.append((public_key, secret_key))
            t1 = time.perf_counter()
            total_keygen += (t1 - t0)
            
            # 2. SIGN - Mỗi người ký message
            t0 = time.perf_counter()
            signatures, sign_times = sign_independent(
                self.test_message, key_pairs, self.dilithium_level, "dilithium"
            )
            t1 = time.perf_counter()
            total_sign += (t1 - t0)
            
            # 3. VERIFY - Xác minh từng chữ ký
            public_keys = [pk for pk, _ in key_pairs]
            t0 = time.perf_counter()
            ok, results, verify_times = verify_independent(
                self.test_message, signatures, public_keys, self.dilithium_level, "dilithium"
            )
            t1 = time.perf_counter()
            total_verify += (t1 - t0)
        
        # Tính trung bình
        avg_keygen = total_keygen / num_runs
        avg_sign = total_sign / num_runs
        avg_verify = total_verify / num_runs
        
        # Kích thước
        pk_size = len(key_pairs[0][0]) * num_signers  # Tổng tất cả PK
        sk_size = len(key_pairs[0][1]) * num_signers  # Tổng tất cả SK
        sig_size = sum(len(s) for s in signatures)    # Tổng N chữ ký
        
        # Băng thông: PK broadcast + N signatures
        comm_bytes = pk_size + sig_size
        
        return PerformanceMetrics(
            scheme="Independent",
            num_signers=num_signers,
            threshold=num_signers,  # Không có threshold, coi như N-of-N
            keygen_time=avg_keygen,
            sign_time=avg_sign,
            verify_time=avg_verify,
            pk_size=pk_size,
            sk_size=sk_size,
            signature_size=sig_size,
            communication_bytes=comm_bytes,
            rounds=1,  # Không cần tương tác
            success=ok,
            attempts=1,  # Không có rejection sampling
            sign_throughput=1.0/avg_sign if avg_sign > 0 else 0,
            verify_throughput=1.0/avg_verify if avg_verify > 0 else 0
        )
    
    # ============================================================================
    # SEQUENTIAL MODE
    # ============================================================================
    
    def benchmark_sequential(self, num_signers: int, num_runs: int = 1) -> PerformanceMetrics:
        """
        Test SEQUENTIAL mode - ký tuần tự với hash chaining
        
        Đặc điểm:
        - Thời gian ký: O(N) (phải đợi người trước)
        - Kích thước chữ ký: O(N)
        - Số vòng: N (mỗi người 1 vòng)
        - Băng thông: Cao (N chữ ký + N lần hash)
        """
        if not HAS_OQS:
            return self._create_failed_metrics("Sequential", num_signers, num_signers)
        
        total_keygen = 0.0
        total_sign = 0.0
        total_verify = 0.0
        
        for _ in range(num_runs):
            # 1. KEYGEN
            t0 = time.perf_counter()
            key_pairs = []
            for i in range(num_signers):
                with oqs.Signature(self.dilithium_level) as signer:
                    public_key = signer.generate_keypair()
                    secret_key = signer.export_secret_key()
                    key_pairs.append((public_key, secret_key))
            t1 = time.perf_counter()
            total_keygen += (t1 - t0)
            
            # 2. SIGN - Sequential với hash chaining
            t0 = time.perf_counter()
            signatures, sign_times = sign_sequential(
                self.test_message, key_pairs, self.dilithium_level, "dilithium"
            )
            t1 = time.perf_counter()
            total_sign += (t1 - t0)
            
            # 3. VERIFY - Xác minh tuần tự
            public_keys = [pk for pk, _ in key_pairs]
            t0 = time.perf_counter()
            ok, results, verify_times = verify_sequential(
                self.test_message, signatures, public_keys, self.dilithium_level, "dilithium"
            )
            t1 = time.perf_counter()
            total_verify += (t1 - t0)
        
        # Tính trung bình
        avg_keygen = total_keygen / num_runs
        avg_sign = total_sign / num_runs
        avg_verify = total_verify / num_runs
        
        # Kích thước
        pk_size = len(key_pairs[0][0]) * num_signers
        sk_size = len(key_pairs[0][1]) * num_signers
        sig_size = sum(len(s) for s in signatures)
        
        # Băng thông: PK + N signatures + hash overhead
        comm_bytes = pk_size + sig_size + (64 * num_signers)  # SHA3-512 = 64 bytes
        
        return PerformanceMetrics(
            scheme="Sequential",
            num_signers=num_signers,
            threshold=num_signers,
            keygen_time=avg_keygen,
            sign_time=avg_sign,
            verify_time=avg_verify,
            pk_size=pk_size,
            sk_size=sk_size,
            signature_size=sig_size,
            communication_bytes=comm_bytes,
            rounds=num_signers,  # N vòng tuần tự
            success=ok,
            attempts=1,
            sign_throughput=1.0/avg_sign if avg_sign > 0 else 0,
            verify_throughput=1.0/avg_verify if avg_verify > 0 else 0
        )
    
    # ============================================================================
    # AGGREGATE (Razhi-ms)
    # ============================================================================
    
    def benchmark_aggregate(self, num_signers: int, num_runs: int = 1) -> PerformanceMetrics:
        """
        Test AGGREGATE (Razhi-ms) - Ký gộp lattice-based
        
        Đặc điểm:
        - Thời gian ký: O(N) nhưng có rejection sampling
        - Kích thước chữ ký: O(1) - GỌN NHẤT (z, c, h_1...h_n)
        - Số vòng: 3 (commitment → challenge → response)
        - Băng thông: Trung bình (N commitments + 1 aggregate sig)
        """
        total_keygen = 0.0
        total_sign = 0.0
        total_verify = 0.0
        total_attempts = 0
        success_count = 0
        
        for run_idx in range(num_runs):
            try:
                # 1. SETUP
                rho = razhi_setup()
                
                # 2. KEYGEN - N participants
                t0 = time.perf_counter()
                key_pairs = []
                for i in range(num_signers):
                    pk_i, sk_i = razhi_keygen(rho, user_id=i)
                    key_pairs.append((pk_i, sk_i))
                t1 = time.perf_counter()
                total_keygen += (t1 - t0)
                
                # 3. AGGREGATE SIGN (3 rounds)
                # Prepare dicts for sign_aggregate
                signers = list(range(num_signers))
                public_keys = {i: pk for i, (pk, _) in enumerate(key_pairs)}
                secret_keys = {i: sk for i, (_, sk) in enumerate(key_pairs)}
                
                t0 = time.perf_counter()
                result = razhi_sign(self.test_message, rho, signers, public_keys, secret_keys)
                t1 = time.perf_counter()
                
                if result is None:
                    continue  # Rejection sampling failed
                
                total_sign += (t1 - t0)
                
                agg_sig = result  # Tuple (z, c, b) bytes
                total_attempts += 1  # Razhi-ms không có metadata attempts rõ ràng
                
                # 4. VERIFY
                t0 = time.perf_counter()
                ok = razhi_verify(self.test_message, agg_sig, public_keys, rho)
                t1 = time.perf_counter()
                total_verify += (t1 - t0)
                
                if ok:
                    success_count += 1
                    
            except Exception as e:
                print(f"  [WARNING] Aggregate run {run_idx+1} failed: {e}")
                continue
        
        if success_count == 0:
            return self._create_failed_metrics("Aggregate", num_signers, num_signers)
        
        # Tính trung bình chỉ trên các run thành công
        avg_keygen = total_keygen / success_count
        avg_sign = total_sign / success_count
        avg_verify = total_verify / success_count
        avg_attempts = total_attempts / success_count
        
        # Kích thước (ước lượng)
        # PK = (rho, t) với t = K polynomials
        # SK = (rho, s1, s2) với s1=L polys, s2=K polys
        pk_size_single = 32 + (RAZHI_K * 256 * 4)  # rho + t
        sk_size_single = 32 + ((RAZHI_L + RAZHI_K) * 256 * 4)  # rho + s1 + s2
        
        # Aggregate signature = (z, c, h_1, ..., h_n)
        # z: L polynomials, c: 256 bits, h_i: 256 bits each
        sig_size = (RAZHI_L * 256 * 4) + 32 + (num_signers * 32)
        
        # Băng thông: N*PK + N*commitments + 1*sig
        comm_bytes = (num_signers * pk_size_single) + (num_signers * RAZHI_K * 256 * 4) + sig_size
        
        return PerformanceMetrics(
            scheme="Aggregate",
            num_signers=num_signers,
            threshold=num_signers,  # N-of-N
            keygen_time=avg_keygen,
            sign_time=avg_sign,
            verify_time=avg_verify,
            pk_size=pk_size_single * num_signers,
            sk_size=sk_size_single * num_signers,
            signature_size=sig_size,
            communication_bytes=comm_bytes,
            rounds=3,  # Commitment → Challenge → Response
            success=True,
            attempts=int(avg_attempts),
            sign_throughput=1.0/avg_sign if avg_sign > 0 else 0,
            verify_throughput=1.0/avg_verify if avg_verify > 0 else 0
        )
    
    # ============================================================================
    # THRESHOLD MODE
    # ============================================================================
    
    def benchmark_threshold(self, num_signers: int, threshold: int, num_runs: int = 1) -> PerformanceMetrics:
        """
        Test THRESHOLD - Ký ngưỡng t-of-n
        
        Đặc điểm:
        - Thời gian ký: O(t) với rejection sampling
        - Kích thước chữ ký: O(1) - GỌN (z, c, commitment)
        - Số vòng: 4 (DKG + Commit + Challenge + Response + Verify)
        - Băng thông: Thấp (shares + 1 aggregate sig)
        - Ưu điểm: Fault tolerance (chỉ cần t/n người)
        """
        total_keygen = 0.0
        total_sign = 0.0
        total_verify = 0.0
        total_attempts = 0
        success_count = 0
        
        for run_idx in range(num_runs):
            try:
                # 1. DKG (Distributed Key Generation)
                t0 = time.perf_counter()
                shares, pk = generate_keypair_distributed(
                    num_signers, threshold, K=self.K, L=self.L
                )
                t1 = time.perf_counter()
                total_keygen += (t1 - t0)
                
                # 2. SIGN - Chọn ngẫu nhiên t người ký
                signing_subset = random.sample(shares, threshold)
                
                t0 = time.perf_counter()
                result = sign_threshold(self.test_message, signing_subset, pk)
                t1 = time.perf_counter()
                
                if result is None or result == (None, None):
                    continue  # Exceeded MAX_ATTEMPTS
                
                total_sign += (t1 - t0)
                
                sig, meta = result
                total_attempts += meta['attempts']
                
                # 3. VERIFY
                t0 = time.perf_counter()
                ok, verify_time_inner = verify_threshold(self.test_message, sig, pk)
                t1 = time.perf_counter()
                total_verify += (t1 - t0)
                
                if ok:
                    success_count += 1
                    
            except Exception as e:
                print(f"  [WARNING] Threshold run {run_idx+1} failed: {e}")
                continue
        
        if success_count == 0:
            return self._create_failed_metrics("Threshold", num_signers, threshold)
        
        # Tính trung bình
        avg_keygen = total_keygen / success_count
        avg_sign = total_sign / success_count
        avg_verify = total_verify / success_count
        avg_attempts = total_attempts / success_count
        
        # Kích thước (ước lượng)
        # PK = (rho, t, bound) - rho: 32 bytes, t: K polys
        pk_size = 32 + (self.K * 256 * 4) + 8
        
        # SK share = (s1_shares, s2_shares) - L+K polys per share
        sk_size_single = (self.L + self.K) * 256 * 4
        
        # Threshold signature = (z, c, commitment, r)
        # z: L polys, c: 32 bytes, commitment: K polys, r: K polys (ước lượng)
        sig_size = (self.L * 256 * 4) + 32 + (self.K * 256 * 4) + (self.K * 256 * 4)
        
        # Băng thông: DKG shares + signature
        # DKG: mỗi participant nhận n-1 shares (Shamir)
        comm_bytes = (num_signers * (num_signers - 1) * sk_size_single) + pk_size + sig_size
        
        return PerformanceMetrics(
            scheme=f"Threshold-{threshold}of{num_signers}",
            num_signers=num_signers,
            threshold=threshold,
            keygen_time=avg_keygen,
            sign_time=avg_sign,
            verify_time=avg_verify,
            pk_size=pk_size,
            sk_size=sk_size_single * num_signers,
            signature_size=sig_size,
            communication_bytes=comm_bytes,
            rounds=4,  # DKG + Commit + Challenge + Response
            success=True,
            attempts=int(avg_attempts),
            sign_throughput=1.0/avg_sign if avg_sign > 0 else 0,
            verify_throughput=1.0/avg_verify if avg_verify > 0 else 0
        )
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _create_failed_metrics(self, scheme: str, num_signers: int, threshold: int) -> PerformanceMetrics:
        """Tạo metrics cho trường hợp fail"""
        return PerformanceMetrics(
            scheme=scheme,
            num_signers=num_signers,
            threshold=threshold,
            keygen_time=0.0,
            sign_time=0.0,
            verify_time=0.0,
            pk_size=0,
            sk_size=0,
            signature_size=0,
            communication_bytes=0,
            rounds=0,
            success=False,
            attempts=0,
            sign_throughput=0.0,
            verify_throughput=0.0
        )
    
    # ============================================================================
    # BENCHMARK RUNNER
    # ============================================================================
    
    def run_full_benchmark(self, num_runs: int = 10, signer_counts: List[int] = None) -> List[PerformanceMetrics]:
        """
        Chạy benchmark toàn diện cho tất cả mô hình
        
        Args:
            num_runs: Số lần chạy mỗi config (để lấy trung bình)
            signer_counts: Danh sách số người ký [5, 10, 20]
            
        Returns:
            List[PerformanceMetrics] - Kết quả tất cả configs
        """
        if signer_counts is None:
            signer_counts = [5, 10, 20]  # Scalability test
        
        results: List[PerformanceMetrics] = []
        
        print("\n" + "="*120)
        print("BENCHMARK: SO SÁNH MÔ HÌNH KÝ ĐA PHƯƠNG - DILITHIUM 3")
        print("="*120)
        print(f"Config: {num_runs} runs/scheme, Message={len(self.test_message)}B, K={self.K}, L={self.L}")
        print("="*120 + "\n")
        
        for N in signer_counts:
            print(f"📊 TEST N={N} SIGNERS:")
            print("-"*120)
            
            # 1. INDEPENDENT
            print(f"  [1/4] Independent (N={N})...", end=" ", flush=True)
            try:
                metrics = self.benchmark_independent(N, num_runs)
                results.append(metrics)
                print(f"✓ Sign: {metrics.sign_time*1000:.1f}ms, Sig: {metrics.signature_size/1024:.1f}KB")
            except Exception as e:
                print(f"✗ Failed: {e}")
            
            # 2. SEQUENTIAL
            print(f"  [2/4] Sequential (N={N})...", end=" ", flush=True)
            try:
                metrics = self.benchmark_sequential(N, num_runs)
                results.append(metrics)
                print(f"✓ Sign: {metrics.sign_time*1000:.1f}ms, Sig: {metrics.signature_size/1024:.1f}KB")
            except Exception as e:
                print(f"✗ Failed: {e}")
            
            # 3. AGGREGATE (SKIP - quá chậm do rejection sampling cao)
            # print(f"  [3/4] Aggregate/Razhi-ms (N={N})...", end=" ", flush=True)
            # try:
            #     metrics = self.benchmark_aggregate(N, num_runs)
            #     results.append(metrics)
            #     print(f"✓ Sign: {metrics.sign_time*1000:.1f}ms, Sig: {metrics.signature_size/1024:.1f}KB, Attempts: {metrics.attempts}")
            # except Exception as e:
            #     print(f"✗ Failed: {e}")
            
            # 4. THRESHOLD (t = ceil(2N/3) - Byzantine threshold)
            t = max(1, (2*N + 2) // 3)  # Byzantine fault tolerance threshold
            print(f"  [4/4] Threshold (t={t}, N={N})...", end=" ", flush=True)
            try:
                metrics = self.benchmark_threshold(N, t, num_runs)
                results.append(metrics)
                print(f"✓ Sign: {metrics.sign_time*1000:.1f}ms, Sig: {metrics.signature_size/1024:.1f}KB, Attempts: {metrics.attempts}")
            except Exception as e:
                print(f"✗ Failed: {e}")
            
            print()
        
        return results
    
    # ============================================================================
    # OUTPUT & VISUALIZATION
    # ============================================================================
    
    def print_comparison_table(self, results: List[PerformanceMetrics]):
        """In bảng so sánh chi tiết"""
        print("\n" + "="*150)
        print("BẢNG SO SÁNH CHI TIẾT - 4 MÔ HÌNH KÝ")
        print("="*150)
        print(f"{'Scheme':<20} {'N/T':<8} {'KeyGen(ms)':<12} {'Sign(ms)':<12} {'Verify(ms)':<12} "
              f"{'SigSize(KB)':<12} {'Comm(KB)':<12} {'Rounds':<8} {'Attempts':<10}")
        print("-"*150)
        
        for m in results:
            if not m.success:
                continue
            
            n_t = f"{m.num_signers}/{m.threshold}" if m.threshold != m.num_signers else f"{m.num_signers}"
            
            print(f"{m.scheme:<20} {n_t:<8} "
                  f"{m.keygen_time*1000:<12.1f} {m.sign_time*1000:<12.1f} {m.verify_time*1000:<12.1f} "
                  f"{m.signature_size/1024:<12.2f} {m.communication_bytes/1024:<12.1f} "
                  f"{m.rounds:<8} {m.attempts:<10}")
        
        print("="*150)
        
        # PHÂN TÍCH SO SÁNH
        print("\n📈 PHÂN TÍCH SO SÁNH:")
        print("-"*150)
        
        # Tìm các metrics tốt nhất
        valid_results = [m for m in results if m.success]
        
        if not valid_results:
            print("Không có kết quả hợp lệ để so sánh.")
            return
        
        # Nhóm theo N
        for N in sorted(set(m.num_signers for m in valid_results)):
            group = [m for m in valid_results if m.num_signers == N]
            
            print(f"\n🔍 N={N} signers:")
            
            fastest_sign = min(group, key=lambda x: x.sign_time)
            smallest_sig = min(group, key=lambda x: x.signature_size)
            lowest_comm = min(group, key=lambda x: x.communication_bytes)
            fewest_rounds = min(group, key=lambda x: x.rounds)
            
            print(f"  ✓ Nhanh nhất (Sign): {fastest_sign.scheme} - {fastest_sign.sign_time*1000:.1f}ms")
            print(f"  ✓ Gọn nhất (Signature): {smallest_sig.scheme} - {smallest_sig.signature_size/1024:.2f}KB")
            print(f"  ✓ Băng thông thấp nhất: {lowest_comm.scheme} - {lowest_comm.communication_bytes/1024:.1f}KB")
            print(f"  ✓ Ít vòng nhất: {fewest_rounds.scheme} - {fewest_rounds.rounds} rounds")
        
        print("\n" + "="*150)
    
    def export_json(self, results: List[PerformanceMetrics], filepath: str):
        """Xuất kết quả ra JSON"""
        data = {
            "benchmark_config": {
                "dilithium_level": self.dilithium_level,
                "K": self.K,
                "L": self.L,
                "message_size": len(self.test_message)
            },
            "results": [asdict(m) for m in results]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Đã xuất kết quả ra: {filepath}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Chạy benchmark đầy đủ"""
    tester = MultiSigPerformanceTest(dilithium_level="Dilithium3")
    
    # Chạy benchmark với 3 runs mỗi config (giảm từ 10 để test nhanh)
    # Test scalability: N = 5, 10 (skip N=20 vì quá chậm)
    results = tester.run_full_benchmark(
        num_runs=3,
        signer_counts=[5, 10]
    )
    
    # In bảng so sánh
    tester.print_comparison_table(results)
    
    # Xuất JSON
    output_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "multisig_comparison_results.json"
    )
    tester.export_json(results, output_file)
    
    print("\n✅ Benchmark hoàn tất!")


if __name__ == "__main__":
    main()
