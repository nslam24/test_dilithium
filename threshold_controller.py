#!/usr/bin/env python3
"""
threshold_controller.py

Controller class để quản lý Threshold Dilithium Signature Scheme với các API:
1. Tạo khóa và phân mảnh (generate_and_save_shares)
2. Ký với các mảnh khóa (sign_with_shares)
3. Xác minh chữ ký (verify_signature)

Các file được lưu trong cấu trúc thư mục:
keys/
  ├── <session_id>/
  │   ├── metadata.json          # Thông tin về session (n, t, K, L, etc.)
  │   ├── pk.json                # Public key
  │   ├── share_0.json           # Secret share của participant 0
  │   ├── share_1.json           # Secret share của participant 1
  │   └── ...
  └── keystore.json              # Index của tất cả các sessions
"""

import json
import os
import base64
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime

# Import từ threshold_dilithium module
from modes.threshold_dilithium import (
    generate_keypair_distributed,
    sign_threshold,
    verify_threshold,
    DILITHIUM_Q,
    DILITHIUM_N,
    DILITHIUM_ETA,
)


class ThresholdController:
    """
    Controller để quản lý Threshold Dilithium Signature Scheme.
    
    Features:
    - Tạo khóa với DKG và lưu shares vào files
    - Ký với subset của shares (kiểm tra đủ threshold)
    - Verify signatures
    - Quản lý sessions và keystore
    """
    
    def __init__(self, keys_dir: str = "keys"):
        """
        Args:
            keys_dir: Thư mục gốc để lưu tất cả keys và shares
        """
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(exist_ok=True)
        
        self.keystore_path = self.keys_dir / "keystore.json"
        self.keystore = self._load_keystore()
    
    def _load_keystore(self) -> Dict[str, Any]:
        """Load keystore từ file (hoặc tạo mới nếu chưa có)."""
        if self.keystore_path.exists():
            try:
                with open(self.keystore_path, 'r') as f:
                    data = json.load(f)
                    # Ensure 'sessions' key exists
                    if "sessions" not in data:
                        data["sessions"] = {}
                    return data
            except (json.JSONDecodeError, IOError):
                return {"sessions": {}}
        return {"sessions": {}}
    
    def _save_keystore(self):
        """Lưu keystore vào file."""
        with open(self.keystore_path, 'w') as f:
            json.dump(self.keystore, f, indent=2)
    
    def generate_and_save_shares(self,
                                 n_parties: int,
                                 threshold: int,
                                 session_id: Optional[str] = None,
                                 K: int = 1,
                                 L: int = 1,
                                 q: int = DILITHIUM_Q,
                                 N: int = DILITHIUM_N,
                                 eta: int = DILITHIUM_ETA) -> Dict[str, Any]:
        """
        API 1: Tạo khóa với DKG và lưu shares vào files.
        
        Args:
            n_parties: Tổng số participants
            threshold: Số lượng tối thiểu để ký (t-of-n)
            session_id: ID của session (auto-generate nếu None)
            K, L: Kích thước ma trận Dilithium (KxL)
            q, N, eta: Tham số Dilithium
            
        Returns:
            {
                "session_id": str,
                "n_parties": int,
                "threshold": int,
                "K": int,
                "L": int,
                "shares_saved": List[str],  # Paths to share files
                "pk_path": str,
                "created_at": str
            }
        """
        # Generate session ID nếu chưa có
        if session_id is None:
            session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Tạo thư mục cho session
        session_dir = self.keys_dir / session_id
        if session_dir.exists():
            raise ValueError(f"Session {session_id} already exists")
        session_dir.mkdir()
        
        print(f"\n{'='*80}")
        print(f"[THRESHOLD KEY GENERATION]")
        print(f"Session ID: {session_id}")
        print(f"Configuration: N={n_parties}, T={threshold}, K={K}, L={L}")
        print(f"{'='*80}\n")
        
        # Generate keypair với DKG
        print("[1/3] Generating keypair with Distributed Key Generation...")
        t0 = time.perf_counter()
        sk_shares, pk = generate_keypair_distributed(
            n_parties, threshold, q=q, N=N, eta=eta, K=K, L=L
        )
        t1 = time.perf_counter()
        print(f"✓ DKG completed in {(t1-t0)*1000:.2f} ms")
        
        # Lưu metadata
        print("\n[2/3] Saving metadata...")
        metadata = {
            "session_id": session_id,
            "n_parties": n_parties,
            "threshold": threshold,
            "K": K,
            "L": L,
            "q": q,
            "N": N,
            "eta": eta,
            "scheme": "dilithium-dkg",
            "created_at": datetime.now().isoformat()
        }
        metadata_path = session_dir / "metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Metadata saved to: {metadata_path}")
        
        # Lưu public key
        pk_path = session_dir / "pk.json"
        with open(pk_path, 'w') as f:
            json.dump(pk, f, indent=2)
        print(f"✓ Public key saved to: {pk_path}")
        
        # Lưu từng share vào file riêng
        print("\n[3/3] Saving secret shares...")
        share_paths = []
        for i, share in enumerate(sk_shares):
            share_path = session_dir / f"share_{i}.json"
            with open(share_path, 'w') as f:
                json.dump(share, f, indent=2)
            share_paths.append(str(share_path))
            print(f"✓ Share {i} saved to: {share_path}")
        
        # Cập nhật keystore
        self.keystore["sessions"][session_id] = {
            "metadata_path": str(metadata_path),
            "pk_path": str(pk_path),
            "share_paths": share_paths,
            "n_parties": n_parties,
            "threshold": threshold,
            "created_at": metadata["created_at"]
        }
        self._save_keystore()
        
        print(f"\n{'='*80}")
        print("✅ KEY GENERATION COMPLETED")
        print(f"{'='*80}\n")
        
        return {
            "session_id": session_id,
            "n_parties": n_parties,
            "threshold": threshold,
            "K": K,
            "L": L,
            "shares_saved": share_paths,
            "pk_path": str(pk_path),
            "metadata_path": str(metadata_path),
            "created_at": metadata["created_at"]
        }
    
    def load_share(self, share_path: str) -> Dict[str, Any]:
        """Load một secret share từ file."""
        with open(share_path, 'r') as f:
            return json.load(f)
    
    def load_public_key(self, pk_path: str) -> Dict[str, Any]:
        """Load public key từ file."""
        with open(pk_path, 'r') as f:
            return json.load(f)
    
    def load_metadata(self, metadata_path: str) -> Dict[str, Any]:
        """Load metadata từ file."""
        with open(metadata_path, 'r') as f:
            return json.load(f)
    
    def sign_with_shares(self,
                        message: bytes,
                        share_paths: List[str],
                        session_id: str,
                        output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        API 2: Ký message với các mảnh khóa.
        
        Kiểm tra xem số lượng shares có đủ threshold không.
        Nếu đủ, thực hiện ký và trả về signature.
        
        Args:
            message: Thông điệp cần ký
            share_paths: List các đường dẫn đến share files
            session_id: ID của session (để load pk và metadata)
            output_path: Đường dẫn để lưu signature (optional)
            
        Returns:
            {
                "status": "success" | "insufficient_shares",
                "required": int,  # Threshold required
                "provided": int,  # Number of shares provided
                "signature": Dict | None,
                "signature_path": str | None,
                "metadata": Dict  # Timing, attempts, etc.
            }
        """
        print(f"\n{'='*80}")
        print(f"[THRESHOLD SIGNING]")
        print(f"Session ID: {session_id}")
        print(f"{'='*80}\n")
        
        # Load session info
        if session_id not in self.keystore["sessions"]:
            raise ValueError(f"Session {session_id} not found in keystore")
        
        session_info = self.keystore["sessions"][session_id]
        threshold = session_info["threshold"]
        n_parties = session_info["n_parties"]
        
        print(f"[INFO] Threshold: {threshold}/{n_parties}")
        print(f"[INFO] Shares provided: {len(share_paths)}")
        
        # Kiểm tra số lượng shares
        if len(share_paths) < threshold:
            print(f"\n❌ INSUFFICIENT SHARES")
            print(f"   Required: {threshold}")
            print(f"   Provided: {len(share_paths)}")
            print(f"{'='*80}\n")
            return {
                "status": "insufficient_shares",
                "required": threshold,
                "provided": len(share_paths),
                "signature": None,
                "signature_path": None,
                "metadata": {}
            }
        
        print(f"✓ Sufficient shares ({len(share_paths)} >= {threshold})")
        
        # Load shares và public key
        print("\n[1/3] Loading shares and public key...")
        sk_shares_subset = [self.load_share(path) for path in share_paths]
        pk = self.load_public_key(session_info["pk_path"])
        print(f"✓ Loaded {len(sk_shares_subset)} shares")
        print(f"✓ Loaded public key")
        
        # Ký message
        print("\n[2/3] Signing message...")
        print("  • Commitment phase")
        print("  • Challenge generation")
        print("  • Response phase with local rejection sampling")
        print("  • Hash-then-Reveal verification")
        print("  • Global rejection sampling")
        
        t0 = time.perf_counter()
        signature, meta = sign_threshold(message, sk_shares_subset, pk)
        t1 = time.perf_counter()
        
        signing_time = t1 - t0
        print(f"\n✓ Signing completed in {signing_time*1000:.2f} ms")
        print(f"✓ Attempts: {meta['attempts']}")
        print(f"✓ Local rejections: {meta.get('local_rejections', 0)}")
        
        # Lưu signature nếu có output_path
        signature_path = None
        if output_path:
            print("\n[3/3] Saving signature...")
            with open(output_path, 'w') as f:
                json.dump(signature, f, indent=2)
            signature_path = output_path
            print(f"✓ Signature saved to: {signature_path}")
        else:
            # Auto-generate path trong session directory
            session_dir = self.keys_dir / session_id
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            signature_path = session_dir / f"signature_{timestamp}.json"
            with open(signature_path, 'w') as f:
                json.dump(signature, f, indent=2)
            print("\n[3/3] Saving signature...")
            print(f"✓ Signature saved to: {signature_path}")
        
        print(f"\n{'='*80}")
        print("✅ SIGNING COMPLETED")
        print(f"{'='*80}\n")
        
        return {
            "status": "success",
            "required": threshold,
            "provided": len(share_paths),
            "signature": signature,
            "signature_path": str(signature_path),
            "metadata": {
                "signing_time_ms": signing_time * 1000,
                "attempts": meta['attempts'],
                "local_rejections": meta.get('local_rejections', 0),
                "avg_partial_time_ms": meta['avg_partial_time'] * 1000
            }
        }
    
    def verify_signature(self,
                        message: bytes,
                        signature_path: str,
                        pk_path: str) -> Dict[str, Any]:
        """
        API 3: Xác minh chữ ký.
        
        Args:
            message: Thông điệp đã ký
            signature_path: Đường dẫn đến signature file
            pk_path: Đường dẫn đến public key file
            
        Returns:
            {
                "valid": bool,
                "verify_time_ms": float,
                "message": str (hex encoded),
                "signature_info": Dict
            }
        """
        print(f"\n{'='*80}")
        print(f"[SIGNATURE VERIFICATION]")
        print(f"{'='*80}\n")
        
        # Load signature và public key
        print("[1/2] Loading signature and public key...")
        with open(signature_path, 'r') as f:
            signature = json.load(f)
        with open(pk_path, 'r') as f:
            pk = json.load(f)
        print(f"✓ Loaded signature from: {signature_path}")
        print(f"✓ Loaded public key from: {pk_path}")
        
        # Verify
        print("\n[2/2] Verifying signature...")
        valid, verify_time = verify_threshold(message, signature, pk)
        
        print(f"✓ Verification time: {verify_time*1000:.2f} ms")
        
        if valid:
            print(f"\n✅ SIGNATURE VALID")
        else:
            print(f"\n❌ SIGNATURE INVALID")
        
        print(f"{'='*80}\n")
        
        return {
            "valid": valid,
            "verify_time_ms": verify_time * 1000,
            "message": message.hex(),
            "signature_info": {
                "scheme": signature.get("scheme"),
                "participants": signature.get("participants"),
                "c": signature.get("c"),
                "K": signature.get("K"),
                "L": signature.get("L")
            }
        }
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """Liệt kê tất cả sessions đã tạo."""
        sessions = []
        for session_id, info in self.keystore["sessions"].items():
            sessions.append({
                "session_id": session_id,
                "n_parties": info["n_parties"],
                "threshold": info["threshold"],
                "created_at": info["created_at"],
                "pk_path": info["pk_path"],
                "num_shares": len(info["share_paths"])
            })
        return sessions
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """Lấy thông tin chi tiết của một session."""
        if session_id not in self.keystore["sessions"]:
            raise ValueError(f"Session {session_id} not found")
        
        session_info = self.keystore["sessions"][session_id]
        metadata = self.load_metadata(session_info["metadata_path"])
        
        return {
            "session_id": session_id,
            "metadata": metadata,
            "pk_path": session_info["pk_path"],
            "share_paths": session_info["share_paths"],
            "keystore_entry": session_info
        }


# =====================================
# DEMO USAGE
# =====================================

def demo_usage():
    """Ví dụ sử dụng ThresholdController."""
    
    print("\n" + "="*80)
    print("DEMO: THRESHOLD DILITHIUM CONTROLLER")
    print("="*80)
    
    controller = ThresholdController(keys_dir="keys")
    
    # Demo 1: Tạo khóa và lưu shares
    print("\n[DEMO 1] Generate keys and save shares")
    result1 = controller.generate_and_save_shares(
        n_parties=5,
        threshold=3,
        session_id=f"demo_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        K=1,
        L=1
    )
    
    session_id = result1["session_id"]
    
    # Demo 2: Ký với đủ shares
    print("\n[DEMO 2] Sign with sufficient shares")
    message = b"Test message for threshold signature"
    
    # Chọn 3 shares (đủ threshold)
    selected_shares = result1["shares_saved"][:3]
    
    result2 = controller.sign_with_shares(
        message=message,
        share_paths=selected_shares,
        session_id=session_id
    )
    
    # Demo 3: Ký với không đủ shares (negative test)
    print("\n[DEMO 3] Sign with insufficient shares (should fail)")
    insufficient_shares = result1["shares_saved"][:2]  # Chỉ 2 shares < threshold 3
    
    result3 = controller.sign_with_shares(
        message=message,
        share_paths=insufficient_shares,
        session_id=session_id
    )
    
    # Demo 4: Verify signature
    if result2["status"] == "success":
        print("\n[DEMO 4] Verify signature")
        result4 = controller.verify_signature(
            message=message,
            signature_path=result2["signature_path"],
            pk_path=result1["pk_path"]
        )
        
        # Demo 5: Verify với wrong message (negative test)
        print("\n[DEMO 5] Verify with wrong message (should fail)")
        wrong_message = b"Wrong message"
        result5 = controller.verify_signature(
            message=wrong_message,
            signature_path=result2["signature_path"],
            pk_path=result1["pk_path"]
        )
    
    # Demo 6: List all sessions
    print("\n[DEMO 6] List all sessions")
    print("="*80)
    sessions = controller.list_sessions()
    for sess in sessions:
        print(f"\nSession: {sess['session_id']}")
        print(f"  • N/T: {sess['n_parties']}/{sess['threshold']}")
        print(f"  • Created: {sess['created_at']}")
        print(f"  • Shares: {sess['num_shares']}")
    print("="*80)
    
    print("\n✅ DEMO COMPLETED\n")


if __name__ == '__main__':
    demo_usage()
