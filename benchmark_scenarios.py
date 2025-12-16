#!/usr/bin/env python3
"""
benchmark_scenarios.py - Enhanced PQC Multi-Signature Benchmark Suite

Implements 4 test scenarios with 3 signature modes:
  Mode A: Independent Multi-Signature (N sigs, no interaction)
  Mode B: Full Threshold t=n (max compression, no fault tolerance)
  Mode C: Flexible Threshold t≈2n/3 (balanced compression + fault tolerance)

Scenarios:
1. Performance & Scalability (T_KeyGen, T_Sign, T_Verify vs N)
2. Storage & Communication Efficiency (size comparison)
3. Network Simulation & Interaction Rounds
4. Stability Stress Test (1000 iterations)

Reference: NIST PQC + Dilithium FIPS 204
"""

import json
import time
import sys
import os
import statistics
import traceback
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, asdict
import psutil
import gc

# Import signature schemes
from modes.threshold_dilithium import (
    generate_keypair_distributed,
    sign_threshold,
    verify_threshold
)
from modes.razhi_multisig import (
    setup as razhi_setup,
    keygen as razhi_keygen,
    sign_aggregate as razhi_sign_aggregate,
    verify as razhi_verify
)
from modes.independent_mode import (
    sign_independent,
    verify_independent
)

# Import core primitives
from core.dilithium_math import (
    DILITHIUM_Q, DILITHIUM_N, DILITHIUM_ETA, DILITHIUM_GAMMA1,
    compute_signature_size_compact
)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class PerformanceMetrics:
    """Metrics for Scenario 1: Performance & Scalability"""
    n_parties: int
    threshold: int  # For threshold modes, equals n_parties for independent
    mode: str  # 'independent', 'threshold_full_t=n', 'threshold_flexible_t<n'
    
    # Timing metrics (seconds)
    keygen_time: float
    sign_time: float
    verify_time: float
    
    # Resource metrics
    cpu_percent_max: float
    memory_mb_max: float
    
    # Iteration count (for averaging)
    iterations: int = 1
    
    # Additional info
    security_level: str = "Dilithium3"
    success: bool = True
    error_message: str = ""


@dataclass
class StorageMetrics:
    """Metrics for Scenario 2: Storage & Communication"""
    n_parties: int
    threshold: int
    mode: str
    
    # Size metrics (bytes)
    public_key_size: int
    signature_size: int
    total_communication_bytes: int
    
    # Efficiency ratios (vs Independent mode)
    pk_compression_ratio: float = 1.0
    sig_compression_ratio: float = 1.0
    comm_overhead_ratio: float = 1.0
    
    security_level: str = "Dilithium3"


@dataclass
class NetworkMetrics:
    """Metrics for Scenario 3: Network Simulation"""
    n_parties: int
    threshold: int
    mode: str
    
    # Network conditions
    latency_ms: float
    packet_loss_percent: float
    
    # Performance under network
    end_to_end_time: float
    interaction_rounds: int
    timeouts: int
    retransmissions: int
    
    # Comparison
    baseline_time: float = 0.0
    overhead_factor: float = 1.0


@dataclass
class StabilityMetrics:
    """Metrics for Scenario 4: Stability Stress Test"""
    n_parties: int
    threshold: int
    mode: str
    
    # Test parameters
    total_iterations: int
    
    # Stability metrics
    success_count: int
    success_rate: float
    avg_restarts: float
    max_restarts: int
    
    # Error tracking
    exceptions: List[str]
    crash_count: int
    
    # Performance consistency
    avg_sign_time: float
    std_sign_time: float
    min_sign_time: float
    max_sign_time: float


# ============================================================================
# SCENARIO 1: PERFORMANCE & SCALABILITY (ENHANCED)
# ============================================================================

class Scenario1_Performance:
    """
    Đánh giá hiệu năng theo quy mô với 3 modes
    
    Mode A: Independent (baseline - no interaction, N separate signatures)
    Mode B: Full Threshold t=n (max compression, but 1 node failure = system failure)
    Mode C: Flexible Threshold t≈2n/3 (fault-tolerant, can survive n-t failures)
    
    Configuration: N ∈ {3, 5, 10, 20}, 1000 iterations per config
    """
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def calculate_flexible_threshold(self, n: int) -> int:
        """Calculate t ≈ 2n/3 for flexible threshold mode"""
        # Use 2/3 majority for fault tolerance
        # Examples: n=3→t=2, n=5→t=3, n=10→t=7, n=20→t=14
        return max(2, int(2 * n / 3))
    
    def measure_cpu_memory(self, func, *args, **kwargs) -> Tuple[Any, float, float, float]:
        """Measure CPU and memory usage during function execution"""
        process = psutil.Process()
        
        # Reset metrics
        gc.collect()
        process.cpu_percent()  # Initialize
        mem_before = process.memory_info().rss / (1024 * 1024)  # MB
        
        # Execute
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        
        # Sample CPU
        cpu_percent = process.cpu_percent()
        mem_after = process.memory_info().rss / (1024 * 1024)
        
        elapsed = end_time - start_time
        mem_used = max(0, mem_after - mem_before)
        
        return result, elapsed, cpu_percent, mem_used
    
    def test_independent_mode(self, n: int, message: bytes, iterations: int = 1) -> PerformanceMetrics:
        """Test Mode A: Independent Multi-Signature"""
        try:
            import oqs
            
            total_keygen_time = 0
            total_sign_time = 0
            total_verify_time = 0
            max_cpu = 0
            max_mem = 0
            
            for iter in range(iterations):
                # KeyGen
                def keygen_func():
                    keys = []
                    for _ in range(n):
                        with oqs.Signature("Dilithium3") as sig:
                            pk = sig.generate_keypair()
                            sk = sig.export_secret_key()
                            keys.append((pk, sk))
                    return keys
                
                keys, t_keygen, cpu_kg, mem_kg = self.measure_cpu_memory(keygen_func)
                total_keygen_time += t_keygen
                max_cpu = max(max_cpu, cpu_kg)
                max_mem = max(max_mem, mem_kg)
                
                # Sign
                def sign_func():
                    return sign_independent(message, keys, "Dilithium3", "dilithium")
                
                (sigs, _), t_sign, cpu_sign, mem_sign = self.measure_cpu_memory(sign_func)
                total_sign_time += t_sign
                max_cpu = max(max_cpu, cpu_sign)
                max_mem = max(max_mem, mem_sign)
                
                # Verify
                pks = [pk for pk, _ in keys]
                def verify_func():
                    return verify_independent(message, sigs, pks, "Dilithium3", "dilithium")
                
                (ok, _, _), t_verify, cpu_verify, mem_verify = self.measure_cpu_memory(verify_func)
                total_verify_time += t_verify
                max_cpu = max(max_cpu, cpu_verify)
                max_mem = max(max_mem, mem_verify)
                
                if not ok:
                    raise ValueError(f"Verification failed at iteration {iter}")
            
            return PerformanceMetrics(
                n_parties=n,
                threshold=n,  # All must sign
                mode="independent",
                keygen_time=total_keygen_time / iterations,
                sign_time=total_sign_time / iterations,
                verify_time=total_verify_time / iterations,
                cpu_percent_max=max_cpu,
                memory_mb_max=max_mem,
                iterations=iterations,
                success=True
            )
            
        except Exception as e:
            return PerformanceMetrics(
                n_parties=n, threshold=n, mode="independent",
                keygen_time=0, sign_time=0, verify_time=0,
                cpu_percent_max=0, memory_mb_max=0,
                iterations=iterations, success=False, error_message=str(e)
            )
    
    def test_threshold_mode(self, n: int, t: int, message: bytes, 
                           iterations: int = 1, mode_name: str = None) -> PerformanceMetrics:
        """Test Mode B or C: Threshold Multi-Signature (t=n or t<n)"""
        if mode_name is None:
            mode_name = f"threshold_full_t={n}" if t == n else f"threshold_flex_t={t}"
        
        try:
            total_keygen_time = 0
            total_sign_time = 0
            total_verify_time = 0
            max_cpu = 0
            max_mem = 0
            
            for iter in range(iterations):
                # KeyGen (DKG)
                def keygen_func():
                    return generate_keypair_distributed(n, t, K=4, L=4)
                
                (sk_shares, pk), t_keygen, cpu_kg, mem_kg = self.measure_cpu_memory(keygen_func)
                total_keygen_time += t_keygen
                max_cpu = max(max_cpu, cpu_kg)
                max_mem = max(max_mem, mem_kg)
                
                # Sign (only t participants needed)
                def sign_func():
                    sig, metadata = sign_threshold(message, sk_shares[:t], pk)
                    return sig
                
                sig, t_sign, cpu_sign, mem_sign = self.measure_cpu_memory(sign_func)
                total_sign_time += t_sign
                max_cpu = max(max_cpu, cpu_sign)
                max_mem = max(max_mem, mem_sign)
                
                # Verify
                def verify_func():
                    ok, verify_time = verify_threshold(message, sig, pk)
                    return ok
                
                ok, t_verify, cpu_verify, mem_verify = self.measure_cpu_memory(verify_func)
                total_verify_time += t_verify
                max_cpu = max(max_cpu, cpu_verify)
                max_mem = max(max_mem, mem_verify)
                
                if not ok:
                    raise ValueError(f"Verification failed at iteration {iter}")
            
            return PerformanceMetrics(
                n_parties=n,
                threshold=t,
                mode=mode_name,
                keygen_time=total_keygen_time / iterations,
                sign_time=total_sign_time / iterations,
                verify_time=total_verify_time / iterations,
                cpu_percent_max=max_cpu,
                memory_mb_max=max_mem,
                iterations=iterations,
                success=True
            )
            
        except Exception as e:
            print(f"⚠️  Threshold error (n={n}, t={t}): {e}")
            traceback.print_exc()
            return PerformanceMetrics(
                n_parties=n, threshold=t, mode=mode_name,
                keygen_time=0, sign_time=0, verify_time=0,
                cpu_percent_max=0, memory_mb_max=0,
                iterations=iterations, success=False, error_message=str(e)
            )
    
    def run(self, n_values: List[int] = [3, 5, 10, 20], iterations: int = 10) -> List[PerformanceMetrics]:
        """
        Run Scenario 1 with enhanced 3-mode comparison
        
        For each N:
          - Test Mode A: Independent
          - Test Mode B: Full Threshold (t=n)
          - Test Mode C: Flexible Threshold (t≈2n/3)
        """
        results = []
        message = b"Benchmark message for PQC multi-signature performance test"
        
        print("="*80)
        print("SCENARIO 1: PERFORMANCE & SCALABILITY (3-MODE COMPARISON)")
        print(f"Iterations per configuration: {iterations}")
        print("="*80)
        
        for n in n_values:
            t_full = n  # Mode B: t = n
            t_flex = self.calculate_flexible_threshold(n)  # Mode C: t ≈ 2n/3
            
            print(f"\n📊 Testing N={n}")
            print(f"   Mode B (Full Threshold): t={t_full}/{n}")
            print(f"   Mode C (Flexible Threshold): t={t_flex}/{n}")
            print("-" * 60)
            
            # Mode A: Independent
            print(f"  [1/3] Independent mode...", end=" ", flush=True)
            m1 = self.test_independent_mode(n, message, iterations)
            if m1.success:
                print(f"✓ KeyGen: {m1.keygen_time:.4f}s, Sign: {m1.sign_time:.4f}s, Verify: {m1.verify_time:.4f}s")
            else:
                print(f"✗ FAILED: {m1.error_message[:50]}")
            results.append(m1)
            
            # Mode B: Full Threshold (t=n)
            print(f"  [2/3] Full Threshold (t=n)...", end=" ", flush=True)
            m2 = self.test_threshold_mode(n, t_full, message, iterations, f"threshold_full_t={t_full}")
            if m2.success:
                print(f"✓ KeyGen: {m2.keygen_time:.4f}s, Sign: {m2.sign_time:.4f}s, Verify: {m2.verify_time:.4f}s")
            else:
                print(f"✗ FAILED: {m2.error_message[:50]}")
            results.append(m2)
            
            # Mode C: Flexible Threshold (t<n)
            print(f"  [3/3] Flexible Threshold (t={t_flex})...", end=" ", flush=True)
            m3 = self.test_threshold_mode(n, t_flex, message, iterations, f"threshold_flex_t={t_flex}")
            if m3.success:
                print(f"✓ KeyGen: {m3.keygen_time:.4f}s, Sign: {m3.sign_time:.4f}s, Verify: {m3.verify_time:.4f}s")
            else:
                print(f"✗ FAILED: {m3.error_message[:50]}")
            results.append(m3)
        
        # Save results
        output_file = os.path.join(self.output_dir, "scenario1_performance_3modes.json")
        with open(output_file, 'w') as f:
            json.dump([asdict(m) for m in results], f, indent=2)
        
        print(f"\n✅ Scenario 1 completed. Results saved to {output_file}")
        self._print_summary_table(results)
        return results
    
    def _print_summary_table(self, results: List[PerformanceMetrics]):
        """Print summary comparison table"""
        print("\n" + "="*80)
        print("SUMMARY TABLE: Average Times (seconds)")
        print("="*80)
        print(f"{'N':<4} {'Mode':<25} {'t':<4} {'KeyGen':<10} {'Sign':<10} {'Verify':<10} {'Success':<8}")
        print("-"*80)
        
        for m in results:
            mode_display = m.mode.replace('threshold_', 'Thr. ').replace('_', ' ')
            status = "✓" if m.success else "✗"
            print(f"{m.n_parties:<4} {mode_display:<25} {m.threshold:<4} "
                  f"{m.keygen_time:<10.4f} {m.sign_time:<10.4f} {m.verify_time:<10.4f} {status:<8}")
        print("="*80)


# ============================================================================
# SCENARIO 2: STORAGE & COMMUNICATION (ENHANCED)
# ============================================================================

class Scenario2_Storage:
    """
    Đánh giá hiệu quả lưu trữ với 3 modes
    
    Comparison for N=10:
      - Mode A: 10 separate public keys + 10 signatures
      - Mode B: 1 aggregated key + 1 signature (t=10)
      - Mode C: 1 aggregated key + 1 signature (t=7, fault-tolerant)
    """
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def measure_independent(self, n: int, message: bytes) -> StorageMetrics:
        """Mode A: Independent"""
        import oqs
        
        keys = []
        pk_sizes = []
        
        for _ in range(n):
            with oqs.Signature("Dilithium3") as sig:
                pk = sig.generate_keypair()
                sk = sig.export_secret_key()
                keys.append((pk, sk))
                pk_sizes.append(len(pk))
        
        sigs, _ = sign_independent(message, keys, "Dilithium3", "dilithium")
        sig_sizes = [len(s) for s in sigs]
        
        # No communication needed (independent signing)
        comm_bytes = 0
        
        return StorageMetrics(
            n_parties=n,
            threshold=n,
            mode="independent",
            public_key_size=sum(pk_sizes),
            signature_size=sum(sig_sizes),
            total_communication_bytes=comm_bytes
        )
    
    def measure_threshold(self, n: int, t: int, message: bytes, mode_name: str) -> StorageMetrics:
        """Mode B or C: Threshold"""
        sk_shares, pk = generate_keypair_distributed(n, t, K=4, L=4)
        
        # Public key: seed (32 bytes) + t vector (K polynomials)
        pk_size = 32 + (4 * 256 * 3)
        
        # Sign
        sig, metadata = sign_threshold(message, sk_shares[:t], pk)
        sig_size = len(str(sig))  # Approximate
        
        # Communication: t participants exchange commitments + responses
        # Round 1: t * 32 bytes (commitments)
        # Round 2: t * (L*256*3) bytes (z vectors)
        comm_bytes = t * (32 + 4 * 256 * 3)
        
        return StorageMetrics(
            n_parties=n,
            threshold=t,
            mode=mode_name,
            public_key_size=pk_size,
            signature_size=sig_size,
            total_communication_bytes=comm_bytes
        )
    
    def run(self, n: int = 10) -> List[StorageMetrics]:
        """Run Scenario 2 with 3-mode comparison"""
        results = []
        message = b"Storage benchmark message"
        t_full = n
        t_flex = max(2, int(2 * n / 3))
        
        print("="*80)
        print(f"SCENARIO 2: STORAGE & COMMUNICATION (N={n})")
        print("="*80)
        
        # Mode A
        print(f"\n📦 Independent mode...", end=" ", flush=True)
        m1 = self.measure_independent(n, message)
        print(f"✓ PK: {m1.public_key_size} bytes, Sig: {m1.signature_size} bytes")
        results.append(m1)
        
        # Mode B
        print(f"📦 Full Threshold (t={t_full})...", end=" ", flush=True)
        m2 = self.measure_threshold(n, t_full, message, f"threshold_full_t={t_full}")
        print(f"✓ PK: {m2.public_key_size} bytes, Sig: {m2.signature_size} bytes")
        m2.pk_compression_ratio = m1.public_key_size / m2.public_key_size if m2.public_key_size > 0 else 0
        m2.sig_compression_ratio = m1.signature_size / m2.signature_size if m2.signature_size > 0 else 0
        results.append(m2)
        
        # Mode C
        print(f"📦 Flexible Threshold (t={t_flex})...", end=" ", flush=True)
        m3 = self.measure_threshold(n, t_flex, message, f"threshold_flex_t={t_flex}")
        print(f"✓ PK: {m3.public_key_size} bytes, Sig: {m3.signature_size} bytes")
        m3.pk_compression_ratio = m1.public_key_size / m3.public_key_size if m3.public_key_size > 0 else 0
        m3.sig_compression_ratio = m1.signature_size / m3.signature_size if m3.signature_size > 0 else 0
        results.append(m3)
        
        # Save
        output_file = os.path.join(self.output_dir, "scenario2_storage_3modes.json")
        with open(output_file, 'w') as f:
            json.dump([asdict(m) for m in results], f, indent=2)
        
        print(f"\n✅ Scenario 2 completed. Results saved to {output_file}")
        return results


# ============================================================================
# SCENARIO 3: NETWORK SIMULATION (THRESHOLD ONLY)
# ============================================================================

class Scenario3_Network:
    """Network impact on Threshold modes (B & C)"""
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def simulate_network_delay(self, latency_ms: float, packet_loss: float = 0.0):
        """Simulate network delay"""
        import random
        if random.random() < packet_loss / 100.0:
            time.sleep(latency_ms * 3 / 1000.0)
            return True
        time.sleep(latency_ms / 1000.0)
        return False
    
    def test_with_network(self, n: int, t: int, message: bytes,
                         latency_ms: float, packet_loss: float, mode_name: str) -> NetworkMetrics:
        """Test threshold mode with network simulation"""
        
        # Baseline
        start = time.perf_counter()
        sk_shares, pk = generate_keypair_distributed(n, t, K=4, L=4)
        sig, _ = sign_threshold(message, sk_shares[:t], pk)
        baseline_time = time.perf_counter() - start
        
        # With network
        rounds = 2
        retransmissions = 0
        
        start = time.perf_counter()
        for i in range(t):
            if self.simulate_network_delay(latency_ms, packet_loss):
                retransmissions += 1
        for i in range(t):
            if self.simulate_network_delay(latency_ms, packet_loss):
                retransmissions += 1
        
        sk_shares, pk = generate_keypair_distributed(n, t, K=4, L=4)
        sig, _ = sign_threshold(message, sk_shares[:t], pk)
        end_to_end = time.perf_counter() - start
        
        return NetworkMetrics(
            n_parties=n,
            threshold=t,
            mode=mode_name,
            latency_ms=latency_ms,
            packet_loss_percent=packet_loss,
            end_to_end_time=end_to_end,
            interaction_rounds=rounds,
            timeouts=retransmissions,
            retransmissions=retransmissions,
            baseline_time=baseline_time,
            overhead_factor=end_to_end / baseline_time if baseline_time > 0 else 1.0
        )
    
    def run(self, n: int = 10) -> List[NetworkMetrics]:
        """Run Scenario 3"""
        results = []
        message = b"Network simulation benchmark"
        t_full = n
        t_flex = max(2, int(2 * n / 3))
        
        print("="*80)
        print(f"SCENARIO 3: NETWORK SIMULATION (N={n})")
        print("="*80)
        
        conditions = [
            ("Localhost", 0, 0),
            ("LAN", 20, 0),
            ("WAN", 100, 1.0)
        ]
        
        for name, latency, loss in conditions:
            print(f"\n🌐 {name} (latency={latency}ms, loss={loss}%)")
            
            # Mode B
            print(f"  Full Threshold (t={t_full})...", end=" ", flush=True)
            m1 = self.test_with_network(n, t_full, message, latency, loss, f"threshold_full_t={t_full}")
            print(f"✓ E2E: {m1.end_to_end_time:.3f}s, Overhead: {m1.overhead_factor:.2f}x")
            results.append(m1)
            
            # Mode C
            print(f"  Flex Threshold (t={t_flex})...", end=" ", flush=True)
            m2 = self.test_with_network(n, t_flex, message, latency, loss, f"threshold_flex_t={t_flex}")
            print(f"✓ E2E: {m2.end_to_end_time:.3f}s, Overhead: {m2.overhead_factor:.2f}x")
            results.append(m2)
        
        output_file = os.path.join(self.output_dir, "scenario3_network_3modes.json")
        with open(output_file, 'w') as f:
            json.dump([asdict(m) for m in results], f, indent=2)
        
        print(f"\n✅ Scenario 3 completed. Results saved to {output_file}")
        return results


# ============================================================================
# SCENARIO 4: STABILITY STRESS TEST
# ============================================================================

class Scenario4_Stability:
    """Stability test for all 3 modes"""
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def stress_test(self, n: int, t: int, iterations: int, mode_name: str) -> StabilityMetrics:
        """Stress test for threshold mode"""
        
        message = b"Stability test message"
        success_count = 0
        sign_times = []
        exceptions = []
        crash_count = 0
        
        print(f"\n🔄 Running {iterations} iterations for {mode_name}...")
        
        try:
            sk_shares, pk = generate_keypair_distributed(n, t, K=4, L=4)
        except Exception as e:
            return StabilityMetrics(
                n_parties=n, threshold=t, mode=mode_name,
                total_iterations=iterations, success_count=0, success_rate=0.0,
                avg_restarts=0.0, max_restarts=0, exceptions=[str(e)],
                crash_count=1, avg_sign_time=0.0, std_sign_time=0.0,
                min_sign_time=0.0, max_sign_time=0.0
            )
        
        for i in range(iterations):
            if (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{iterations} ({100*(i+1)//iterations}%)", end="\r", flush=True)
            
            try:
                start = time.perf_counter()
                sig, _ = sign_threshold(message, sk_shares[:t], pk)
                elapsed = time.perf_counter() - start
                
                ok, _ = verify_threshold(message, sig, pk)
                
                if ok:
                    success_count += 1
                    sign_times.append(elapsed)
                    
            except Exception as e:
                exceptions.append(f"Iter {i}: {str(e)[:100]}")
                crash_count += 1
        
        print()
        
        success_rate = 100.0 * success_count / iterations if iterations > 0 else 0.0
        
        return StabilityMetrics(
            n_parties=n,
            threshold=t,
            mode=mode_name,
            total_iterations=iterations,
            success_count=success_count,
            success_rate=success_rate,
            avg_restarts=0.0,
            max_restarts=0,
            exceptions=exceptions[:10],
            crash_count=crash_count,
            avg_sign_time=statistics.mean(sign_times) if sign_times else 0.0,
            std_sign_time=statistics.stdev(sign_times) if len(sign_times) > 1 else 0.0,
            min_sign_time=min(sign_times) if sign_times else 0.0,
            max_sign_time=max(sign_times) if sign_times else 0.0
        )
    
    def run(self, n: int = 10, iterations: int = 1000) -> List[StabilityMetrics]:
        """Run Scenario 4"""
        results = []
        t_full = n
        t_flex = max(2, int(2 * n / 3))
        
        print("="*80)
        print(f"SCENARIO 4: STABILITY STRESS TEST (N={n}, {iterations} iterations)")
        print("="*80)
        
        # Mode B
        m1 = self.stress_test(n, t_full, iterations, f"threshold_full_t={t_full}")
        print(f"📊 Full Threshold: {m1.success_rate:.2f}% success, {m1.avg_sign_time:.4f}s avg")
        results.append(m1)
        
        # Mode C
        m2 = self.stress_test(n, t_flex, iterations, f"threshold_flex_t={t_flex}")
        print(f"📊 Flex Threshold: {m2.success_rate:.2f}% success, {m2.avg_sign_time:.4f}s avg")
        results.append(m2)
        
        output_file = os.path.join(self.output_dir, "scenario4_stability_3modes.json")
        with open(output_file, 'w') as f:
            json.dump([asdict(m) for m in results], f, indent=2)
        
        print(f"\n✅ Scenario 4 completed. Results saved to {output_file}")
        return results


# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

def run_all_scenarios(output_dir: str = "results"):
    """Run all 4 scenarios with 3-mode comparison"""
    
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║              PQC MULTI-SIGNATURE BENCHMARK SUITE (3-MODE)                  ║
║                                                                            ║
║  Mode A: Independent (baseline, no interaction)                           ║
║  Mode B: Full Threshold t=n (max compression, no fault tolerance)         ║
║  Mode C: Flexible Threshold t≈2n/3 (balanced)                             ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Scenario 1: Performance
    s1 = Scenario1_Performance(output_dir)
    results_s1 = s1.run(n_values=[3, 5, 10, 20], iterations=10)
    
    # Scenario 2: Storage
    s2 = Scenario2_Storage(output_dir)
    results_s2 = s2.run(n=10)
    
    # Scenario 3: Network
    s3 = Scenario3_Network(output_dir)
    results_s3 = s3.run(n=10)
    
    # Scenario 4: Stability
    s4 = Scenario4_Stability(output_dir)
    results_s4 = s4.run(n=10, iterations=1000)
    
    # Summary
    summary = {
        "scenario1_performance": [asdict(r) for r in results_s1],
        "scenario2_storage": [asdict(r) for r in results_s2],
        "scenario3_network": [asdict(r) for r in results_s3],
        "scenario4_stability": [asdict(r) for r in results_s4]
    }
    
    summary_file = os.path.join(output_dir, "benchmark_summary_3modes.json")
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("\n" + "="*80)
    print(f"✅ ALL SCENARIOS COMPLETED")
    print(f"📁 Results: {output_dir}")
    print(f"📄 Summary: {summary_file}")
    print("="*80)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PQC Multi-Signature Benchmark (3-Mode)")
    parser.add_argument("--scenario", type=int, choices=[1, 2, 3, 4])
    parser.add_argument("--output", default="results")
    parser.add_argument("--iterations", type=int, default=10, help="Iterations for Scenario 1")
    
    args = parser.parse_args()
    
    if args.scenario == 1:
        s = Scenario1_Performance(args.output)
        s.run(iterations=args.iterations)
    elif args.scenario == 2:
        s = Scenario2_Storage(args.output)
        s.run()
    elif args.scenario == 3:
        s = Scenario3_Network(args.output)
        s.run()
    elif args.scenario == 4:
        s = Scenario4_Stability(args.output)
        s.run()
    else:
        run_all_scenarios(args.output)
