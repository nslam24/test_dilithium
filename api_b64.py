#!/usr/bin/env python3
"""
api_b64.py - Flask API Server cho Threshold Dilithium Signature với Base64 encoding

Endpoints:
1. POST /generate - Tạo keypair và shares
2. POST /sign - Ký message với shares
3. POST /verify - Xác minh signature
4. GET /sessions - List tất cả sessions
5. GET /session/<session_id> - Lấy thông tin session
"""

import os
import sys
import base64
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from modes directory
from modes.threshold_dilithium import (
    generate_keypair_distributed,
    sign_threshold,
    verify_threshold
)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes


def convert_numpy_types(obj):
    """
    Recursively convert NumPy types to Python native types for JSON serialization.
    """
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_numpy_types(item) for item in obj)
    else:
        return obj


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "Threshold Dilithium API (Base64)",
        "version": "1.0.0"
    })


@app.route('/api/keygen', methods=['POST'])
def generate_keypair():
    """
    POST /api/keygen
    
    Body (JSON):
    {
        "n_parties": int,      # Tổng số participants
        "threshold": int,      # Số lượng tối thiểu để ký
        "session_id": str,     # Optional: custom session ID
        "K": int,              # Optional: Ma trận dimension (default: 1)
        "L": int,              # Optional: Ma trận dimension (default: 1)
        "q": int,              # Optional: modulus (default: 8380417)
        "N": int,              # Optional: polynomial degree (default: 256)
        "eta": int             # Optional: noise bound (default: 2)
    }
    
    Response:
    {
        "success": true,
        "data": {
            "session_id": str,
            "n_parties": int,
            "threshold": int,
            "K": int,
            "L": int,
            "shares_saved": [str],
            "pk_path": str,
            "metadata_path": str,
            "created_at": str
        }
    }
    """
    try:
        data = request.get_json()
        
        # Required parameters
        n_parties = data.get('n_parties')
        threshold = data.get('threshold')
        
        if not n_parties or not threshold:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: n_parties, threshold"
            }), 400
        
        # Optional parameters
        session_id = data.get('session_id')
        K = data.get('K', 1)
        L = data.get('L', 1)
        q = data.get('q', 8380417)
        N = data.get('N', 256)
        eta = data.get('eta', 2)
        
        # Generate keypair directly (without saving to files)
        from modes.threshold_dilithium import generate_keypair_distributed
        
        sk_shares, pk = generate_keypair_distributed(
            n_parties=n_parties,
            threshold=threshold,
            q=q,
            N=N,
            eta=eta,
            K=K,
            L=L
        )
        
        # Convert NumPy types to Python native types
        sk_shares = convert_numpy_types(sk_shares)
        pk = convert_numpy_types(pk)
        
        # Encode to base64
        import json
        shares_b64 = [base64.b64encode(json.dumps(s).encode('utf-8')).decode('utf-8') 
                      for s in sk_shares]
        public_key_b64 = base64.b64encode(json.dumps(pk).encode('utf-8')).decode('utf-8')
        
        return jsonify({
            "success": True,
            "shares_b64": shares_b64,
            "public_key_b64": public_key_b64,
            "n_parties": n_parties,
            "threshold": threshold,
            "K": K,
            "L": L
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/sign', methods=['POST'])
def sign_message():
    """
    POST /api/sign
    
    Body (JSON):
    {
        "message": str,           # Plain text message
        "shares_b64": [str],      # List of base64-encoded shares
        "public_key_b64": str     # Base64-encoded public key
    }
    
    Response:
    {
        "success": true,
        "signature_b64": str,    # Base64-encoded signature JSON
        "public_key_b64": str,   # Base64-encoded public key JSON
        "metadata": {
            "attempts": int,
            "avg_partial_time": float
        }
    }
    """
    try:
        data = request.get_json()
        
        # Required parameters
        message = data.get('message')
        shares_b64 = data.get('shares_b64')
        public_key_b64 = data.get('public_key_b64')
        
        if not message or not shares_b64 or not public_key_b64:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: message, shares_b64, public_key_b64"
            }), 400
        
        # Decode shares from base64
        import json
        try:
            # Add padding if needed for base64
            def decode_b64(s):
                # Add padding if necessary
                missing_padding = len(s) % 4
                if missing_padding:
                    s += '=' * (4 - missing_padding)
                return base64.b64decode(s)
            
            shares = [json.loads(decode_b64(s)) for s in shares_b64]
            pk = json.loads(decode_b64(public_key_b64))
        except json.JSONDecodeError as e:
            return jsonify({
                "success": False,
                "error": f"Invalid JSON in base64 data: {str(e)}"
            }), 400
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Failed to decode base64: {str(e)}"
            }), 400
        
        # Validate threshold requirement
        if shares:
            threshold = shares[0].get("threshold")
            if threshold and len(shares) < threshold:
                return jsonify({
                    "success": False,
                    "error": f"Insufficient shares: provided {len(shares)} shares, but need at least {threshold} (threshold requirement)"
                }), 400
            
            # Validate all shares have same pk_hash (same key)
            pk_hash_set = set()
            for i, share in enumerate(shares):
                pk_hash = share.get("pk_hash")
                if pk_hash:
                    pk_hash_set.add(pk_hash)
            
            if len(pk_hash_set) > 1:
                return jsonify({
                    "success": False,
                    "error": f"Shares are from different keys: found {len(pk_hash_set)} different pk_hash values. All shares must be from the same keypair.",
                    "details": {"detected_hashes": list(pk_hash_set)}
                }), 400
            
            # Validate shares match the provided public key
            if pk_hash_set:
                import hashlib
                pk_bytes = json.dumps(pk, sort_keys=True).encode('utf-8')
                expected_pk_hash = hashlib.sha3_256(pk_bytes).hexdigest()[:16]
                shares_pk_hash = list(pk_hash_set)[0]
                
                if shares_pk_hash != expected_pk_hash:
                    return jsonify({
                        "success": False,
                        "error": f"Shares do not match the provided public key. Share pk_hash: {shares_pk_hash}, Expected: {expected_pk_hash}"
                    }), 400
        
        # Sign with shares
        from modes.threshold_dilithium import sign_threshold
        import time
        
        message_bytes = message.encode('utf-8')
        
        # Đo thời gian tổng
        t_total_start = time.perf_counter()
        signature, metadata = sign_threshold(message_bytes, shares, pk)
        t_total_end = time.perf_counter()
        
        total_sign_time = t_total_end - t_total_start
        
        # Convert NumPy types to Python native types
        signature = convert_numpy_types(signature)
        metadata = convert_numpy_types(metadata)
        
        # Encode signature to base64
        signature_b64 = base64.b64encode(json.dumps(signature).encode('utf-8')).decode('utf-8')
        
        # Extract timing details from metadata
        timing_info = metadata.get("timing", {})
        commitment_phase_time = timing_info.get("commitment_phase_time", 0.0)
        response_phase_time = timing_info.get("response_phase_time", 0.0)
        per_share_times = timing_info.get("per_share_times", [])
        commitment_times = timing_info.get("commitment_times", [])
        response_times = timing_info.get("response_times", [])
        
        return jsonify({
            "success": True,
            "signature_b64": signature_b64,
            "public_key_b64": public_key_b64,  # Echo back for convenience
            "timing": {
                "total_sign_time_ms": round(total_sign_time * 1000, 2),
                "commitment_phase_ms": round(commitment_phase_time * 1000, 2),
                "response_phase_ms": round(response_phase_time * 1000, 2),
                "per_share_times_ms": [round(t * 1000, 2) for t in per_share_times],
                "num_shares": len(shares)
            },
            "metadata": {
                "attempts": metadata.get("attempts", 0),
                "local_rejections": metadata.get("local_rejections", 0),
                "commitment_phase_ms": round(commitment_phase_time * 1000, 2),
                "response_phase_ms": round(response_phase_time * 1000, 2),
                "commitment_times_ms": [round(t * 1000, 2) for t in commitment_times],
                "response_times_ms": [round(t * 1000, 2) for t in response_times]
            }
        })
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"ERROR in /api/sign: {error_traceback}", file=sys.stderr)
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": error_traceback
        }), 500


@app.route('/api/verify', methods=['POST'])
def verify_signature():
    """
    POST /api/verify
    
    Body (JSON):
    {
        "message": str,          # Plain text message
        "signature_b64": str,    # Base64-encoded signature
        "public_key_b64": str    # Base64-encoded public key
    
    Response:
    {
        "success": true,
        "valid": bool,
        "verify_time": float
    }
    """
    try:
        data = request.get_json()
        
        # Required parameters
        message = data.get('message')
        signature_b64 = data.get('signature_b64')
        public_key_b64 = data.get('public_key_b64')
        
        if not message or not signature_b64 or not public_key_b64:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: message, signature_b64, public_key_b64"
            }), 400
        
        # Decode from base64
        import json
        try:
            # Add padding if needed for base64
            def decode_b64(s):
                # Add padding if necessary
                missing_padding = len(s) % 4
                if missing_padding:
                    s += '=' * (4 - missing_padding)
                return base64.b64decode(s)
            
            signature = json.loads(decode_b64(signature_b64))
            pk = json.loads(decode_b64(public_key_b64))
        except json.JSONDecodeError as e:
            return jsonify({
                "success": False,
                "error": f"Invalid JSON in base64 data: {str(e)}"
            }), 400
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Failed to decode base64: {str(e)}"
            }), 400
        
        # Verify signature
        from modes.threshold_dilithium import verify_threshold
        message_bytes = message.encode('utf-8')
        
        valid, verify_time = verify_threshold(message_bytes, signature, pk)
        
        return jsonify({
            "success": True,
            "valid": valid,
            "verify_time": verify_time
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/sessions', methods=['GET'])
def list_sessions():
    """
    GET /sessions
    
    Response:
    {
        "success": true,
        "data": {
            "sessions": {
                "session_id": {
                    "n_parties": int,
                    "threshold": int,
                    "created_at": str,
                    "pk_path": str,
                    "metadata_path": str,
                    "share_paths": [str]
                }
            }
        }
    }
    """
    try:
        return jsonify({
            "success": True,
            "data": {
                "sessions": controller.keystore.get("sessions", {})
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/session/<session_id>', methods=['GET'])
def get_session(session_id):
    """
    GET /session/<session_id>
    
    Response:
    {
        "success": true,
        "data": {
            "session_id": str,
            "metadata": {...},
            "public_key": {...}
        }
    }
    """
    try:
        if session_id not in controller.keystore.get("sessions", {}):
            return jsonify({
                "success": False,
                "error": f"Session {session_id} not found"
            }), 404
        
        session_info = controller.keystore["sessions"][session_id]
        
        # Load metadata
        import json
        with open(session_info["metadata_path"], 'r') as f:
            metadata = json.load(f)
        
        # Load public key
        with open(session_info["pk_path"], 'r') as f:
            pk = json.load(f)
        
        return jsonify({
            "success": True,
            "data": {
                "session_id": session_id,
                "metadata": metadata,
                "public_key": pk,
                "session_info": session_info
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 Threshold Dilithium API Server (Base64)")
    print("="*80)
    print("Endpoints:")
    print("  GET    /api/health       - Health check")
    print("  POST   /api/keygen       - Generate keypair and shares")
    print("  POST   /api/sign         - Sign message with shares")
    print("  POST   /api/verify       - Verify signature")
    print("  GET    /sessions         - List all sessions")
    print("  GET    /session/<id>     - Get session info")
    print("="*80)
    print("Starting server on http://0.0.0.0:9080")
    print("="*80 + "\n")
    
    app.run(host='0.0.0.0', port=9080, debug=False)
