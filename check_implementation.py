#!/usr/bin/env python3
"""Kiểm tra bản triển khai Dilithium đang được sử dụng.

Script này kiểm tra:
1. CPU flags (AVX2, AES-NI)
2. liboqs build configuration
3. Performance benchmark để xác định implementation
"""
import oqs
import subprocess
import platform
import time
import os


def check_cpu_flags():
    """Kiểm tra CPU flags hỗ trợ AVX2 và AES-NI."""
    print("=== 1. CPU Capabilities ===")
    
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()
            
            flags = set()
            for line in cpuinfo.split("\n"):
                if line.startswith("flags"):
                    flags.update(line.split(":")[1].strip().split())
            
            has_avx2 = "avx2" in flags
            has_aes = "aes" in flags
            
            print(f"AVX2 support: {'✅ YES' if has_avx2 else '❌ NO'}")
            print(f"AES-NI support: {'✅ YES' if has_aes else '❌ NO'}")
            
            if has_avx2 and has_aes:
                print("→ CPU hỗ trợ AVX2+AES implementation")
            elif has_avx2:
                print("→ CPU hỗ trợ AVX2 implementation")
            else:
                print("→ CPU chỉ chạy Reference implementation")
            
            return has_avx2, has_aes
        except Exception as e:
            print(f"⚠️  Không đọc được /proc/cpuinfo: {e}")
            return None, None
    else:
        print("⚠️  Script chỉ hỗ trợ Linux")
        return None, None


def check_liboqs_build():
    """Kiểm tra cấu hình build của liboqs."""
    print("\n=== 2. liboqs Build Configuration ===")
    
    try:
        # Kiểm tra liboqs version
        print(f"liboqs version: {oqs.oqs_version()}")
        
        # Kiểm tra các algorithms được enable
        sig_algs = oqs.get_enabled_sig_mechanisms()
        dilithium_algs = [alg for alg in sig_algs if "Dilithium" in alg]
        print(f"Dilithium variants: {dilithium_algs}")
        
        # Thử tìm liboqs.so để check build flags
        try:
            result = subprocess.run(
                ["find", os.path.expanduser("~"), "-name", "liboqs.so*", "-type", "f"],
                capture_output=True,
                text=True,
                timeout=10
            )
            liboqs_paths = [p for p in result.stdout.strip().split("\n") if p and "liboqs.so" in p]
            
            if liboqs_paths:
                liboqs_path = liboqs_paths[0]
                print(f"liboqs path: {liboqs_path}")
                
                # Kiểm tra symbols để xác định implementation
                nm_result = subprocess.run(
                    ["nm", "-D", liboqs_path],
                    capture_output=True,
                    text=True
                )
                symbols = nm_result.stdout.lower()
                
                has_avx2_symbols = "avx2" in symbols
                has_aes_symbols = "aes" in symbols
                
                print(f"AVX2 symbols found: {'✅ YES' if has_avx2_symbols else '❌ NO'}")
                print(f"AES symbols found: {'✅ YES' if has_aes_symbols else '❌ NO'}")
            else:
                print("⚠️  Không tìm thấy liboqs.so")
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"⚠️  Không tìm được liboqs.so: {e}")
            
    except Exception as e:
        print(f"⚠️  Lỗi khi kiểm tra liboqs: {e}")


def benchmark_implementation(level="Dilithium3", iterations=100):
    """Benchmark để ước lượng implementation type dựa trên performance."""
    print(f"\n=== 3. Performance Benchmark ({level}, {iterations} iterations) ===")
    
    try:
        message = b"Benchmark message for implementation detection"
        
        # Keygen
        with oqs.Signature(level) as signer:
            t0 = time.perf_counter()
            for _ in range(iterations):
                pub = signer.generate_keypair()
            t1 = time.perf_counter()
            keygen_time = (t1 - t0) / iterations
            
            # Sign
            priv = signer.export_secret_key()
            t0 = time.perf_counter()
            for _ in range(iterations):
                sig = signer.sign(message)
            t1 = time.perf_counter()
            sign_time = (t1 - t0) / iterations
            
            # Verify
            t0 = time.perf_counter()
            for _ in range(iterations):
                ok = signer.verify(message, sig, pub)
            t1 = time.perf_counter()
            verify_time = (t1 - t0) / iterations
        
        print(f"Avg KeyGen: {keygen_time*1000:.3f} ms")
        print(f"Avg Sign:   {sign_time*1000:.3f} ms")
        print(f"Avg Verify: {verify_time*1000:.3f} ms")
        
        # Ước lượng implementation (dựa trên NIST benchmarks)
        # Reference: ~0.5-1ms sign, AVX2: ~0.1-0.2ms, AVX2+AES: ~0.08-0.15ms
        if sign_time < 0.00015:  # < 0.15ms
            impl = "AVX2+AES (Optimized)"
        elif sign_time < 0.00025:  # < 0.25ms
            impl = "AVX2 (Optimized)"
        else:
            impl = "Reference (Unoptimized)"
        
        print(f"\n→ Estimated implementation: {impl}")
        print(f"   (Based on sign time: {sign_time*1000:.3f} ms)")
        
        return keygen_time, sign_time, verify_time
        
    except Exception as e:
        print(f"⚠️  Lỗi khi benchmark: {e}")
        return None, None, None


def compare_all_levels():
    """So sánh performance của Dilithium2, 3, 5."""
    print("\n=== 4. Comparison Across Security Levels ===")
    
    levels = ["Dilithium2", "Dilithium3", "Dilithium5"]
    results = {}
    
    for level in levels:
        try:
            kg, st, vt = benchmark_implementation(level, iterations=50)
            if kg is not None:
                results[level] = {"keygen": kg, "sign": st, "verify": vt}
        except Exception as e:
            print(f"⚠️  {level}: {e}")
    
    # Print comparison table
    if results:
        print("\n| Level       | KeyGen (ms) | Sign (ms) | Verify (ms) |")
        print("|-------------|-------------|-----------|-------------|")
        for level, times in results.items():
            print(f"| {level:11} | {times['keygen']*1000:11.3f} | {times['sign']*1000:9.3f} | {times['verify']*1000:11.3f} |")


def main():
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  Dilithium Implementation Detection Tool                  ║")
    print("╚════════════════════════════════════════════════════════════╝\n")
    
    # Check 1: CPU flags
    has_avx2, has_aes = check_cpu_flags()
    
    # Check 2: liboqs build
    check_liboqs_build()
    
    # Check 3: Performance benchmark
    benchmark_implementation()
    
    # Check 4: Compare all levels
    compare_all_levels()
    
    print("\n" + "="*60)
    print("📊 KẾT LUẬN:")
    if has_avx2 and has_aes:
        print("CPU hỗ trợ đầy đủ → Có thể chạy AVX2+AES implementation")
        print("Kiểm tra benchmark để xác nhận implementation thực tế.")
    elif has_avx2:
        print("CPU hỗ trợ AVX2 → Có thể chạy AVX2 implementation")
    else:
        print("CPU không hỗ trợ AVX2 → Chỉ chạy Reference implementation")
    print("="*60)


if __name__ == "__main__":
    main()
