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

# Import DKG threshold signing
from modes.threshold_gaussian.keygen import run_dkg_protocol
from modes.threshold_gaussian.signing import (
    sign_threshold_dkg,
    aggregate_signatures_dkg,
    verify_threshold_dkg
)
from core.dilithium_math import Poly

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes


def poly_to_dict(poly):
    """Convert Poly object to JSON-serializable dict."""
    coeffs = poly.coeffs
    if isinstance(coeffs, np.ndarray):
        coeffs = coeffs.tolist()
    return {
        'coeffs': coeffs,
        'q': int(poly.q) if isinstance(poly.q, np.integer) else poly.q,
        'N': int(poly.N) if isinstance(poly.N, np.integer) else poly.N,
        'in_ntt': bool(poly.in_ntt)
    }


def dict_to_poly(d):
    """Convert dict back to Poly object."""
    return Poly(d['coeffs'], d['q'], d['N'], in_ntt=d['in_ntt'])


def restore_dkg_data(obj):
    """Recursively restore DKG data from JSON (convert base64 strings back to bytes/Poly)."""
    if isinstance(obj, dict):
        # Check if it's a Poly dict
        if 'coeffs' in obj and 'q' in obj and 'N' in obj and 'in_ntt' in obj:
            return dict_to_poly(obj)
        # Recursively process dict
        result = {}
        for k, v in obj.items():
            # Special cases: rho and com should be bytes (but NOT com_vec which is list of Poly)
            if k in ('rho', 'com') and isinstance(v, str):
                result[k] = base64.b64decode(v)
            else:
                result[k] = restore_dkg_data(v)
        return result
    elif isinstance(obj, list):
        return [restore_dkg_data(item) for item in obj]
    else:
        return obj


def convert_numpy_types(obj):
    """
    Recursively convert NumPy types and Poly objects to Python native types for JSON serialization.
    """
    if isinstance(obj, Poly):
        return poly_to_dict(obj)
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    elif isinstance(obj, np.integer):
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
                # Use pk_hash from public key (computed from cryptographic parameters)
                expected_pk_hash = pk.get('pk_hash')
                shares_pk_hash = list(pk_hash_set)[0]
                
                if expected_pk_hash and shares_pk_hash != expected_pk_hash:
                    return jsonify({
                        "success": False,
                        "error": f"[SECURITY] Keypair binding mismatch!\n  Shares belong to DKG group: {shares_pk_hash}\n  But trying to sign for PK group: {expected_pk_hash}\n  → Cannot mix shares from different DKG groups!",
                        "details": {
                            "shares_pk_hash": shares_pk_hash,
                            "expected_pk_hash": expected_pk_hash
                        }
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


# ============================================================================
# DKG THRESHOLD SIGNING ENDPOINTS
# ============================================================================

@app.route('/api/dkg/keygen', methods=['POST'])
def dkg_keygen():
    """
    POST /api/dkg/keygen
    
    Generate DKG (Distributed Key Generation) keypairs with DUAL SECRETS architecture.
    
    Body (JSON):
    {
        "n_parties": int,          # Total number of participants
        "threshold": int,          # Minimum signers required
        "dilithium_level": int,    # Optional: 2, 3, or 5 (default: 2)
        "seed": int                # Optional: random seed for reproducibility
    }
    
    Response:
    {
        "success": true,
        "keypairs_b64": [str],     # Array of base64-encoded keypair JSONs (one per party)
        "public_key_b64": str,     # Base64-encoded public key JSON
        "metadata": {
            "n_parties": int,
            "threshold": int,
            "dilithium_level": int,
            "architecture": "DKG_DUAL_SECRETS"
        }
    }
    
    Each keypair contains:
    - uid: User ID
    - small_secret_s1, small_secret_s2: Own secrets (for rejection sampling check)
    - shamir_share_x1, shamir_share_x2: Aggregate shares (for signing)
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
        
        if threshold > n_parties:
            return jsonify({
                "success": False,
                "error": f"Threshold ({threshold}) cannot exceed n_parties ({n_parties})"
            }), 400
        
        # Optional parameters
        dilithium_level = data.get('dilithium_level', 2)
        
        if dilithium_level not in [2, 3, 5]:
            return jsonify({
                "success": False,
                "error": "dilithium_level must be 2, 3, or 5"
            }), 400
        
        # Generate DKG keypairs
        keypairs, pk = run_dkg_protocol(
            n=n_parties,
            t=threshold,
            level=dilithium_level
        )
        
        # Convert NumPy types to Python native types
        keypairs = convert_numpy_types(keypairs)
        pk = convert_numpy_types(pk)
        
        # Encode to base64
        import json
        keypairs_b64 = [
            base64.b64encode(json.dumps(kp).encode('utf-8')).decode('utf-8')
            for kp in keypairs
        ]
        public_key_b64 = base64.b64encode(json.dumps(pk).encode('utf-8')).decode('utf-8')
        
        return jsonify({
            "success": True,
            "keypairs_b64": keypairs_b64,
            "public_key_b64": public_key_b64,
            "metadata": {
                "n_parties": n_parties,
                "threshold": threshold,
                "dilithium_level": dilithium_level,
                "architecture": "DKG_DUAL_SECRETS",
                "note": "Each keypair contains small_secret (for checking) and shamir_share (for signing)"
            }
        })
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"ERROR in /api/dkg/keygen: {error_traceback}", file=sys.stderr)
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": error_traceback
        }), 500


@app.route('/api/dkg/sign', methods=['POST'])
def dkg_sign():
    """
    POST /api/dkg/sign
    
    Generate partial DKG signatures using DUAL SECRETS architecture.
    
    Body (JSON):
    {
        "message": str,              # Plain text message
        "keypairs_b64": [str],       # Base64-encoded keypairs (one per signer)
        "public_key_b64": str,       # Base64-encoded public key
        "max_attempts": int,         # Optional: max rejection sampling attempts (default: 100)
        "debug": bool                # Optional: enable debug output (default: false)
    }
    
    Response:
    {
        "success": true,
        "partial_signatures_b64": [str],  # Array of base64-encoded partial signatures
        "public_key_b64": str,            # Echo back for convenience
        "metadata": {
            "num_signers": int,
            "total_attempts": int,
            "avg_attempts_per_signer": float,
            "timing": {
                "total_sign_time_ms": float,
                "per_signer_times_ms": [float]
            }
        }
    }
    """
    try:
        data = request.get_json()
        
        # Required parameters
        message = data.get('message')
        keypairs_b64 = data.get('keypairs_b64')
        public_key_b64 = data.get('public_key_b64')
        
        if not message or not keypairs_b64 or not public_key_b64:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: message, keypairs_b64, public_key_b64"
            }), 400
        
        # Optional parameters
        max_attempts = data.get('max_attempts', 100)
        debug = data.get('debug', False)
        
        # Decode from base64
        import json
        import time
        
        def decode_b64(s):
            missing_padding = len(s) % 4
            if missing_padding:
                s += '=' * (4 - missing_padding)
            return base64.b64decode(s)
        
        try:
            keypairs = [json.loads(decode_b64(kp)) for kp in keypairs_b64]
            pk = json.loads(decode_b64(public_key_b64))
            
            # Restore Poly objects and bytes
            keypairs = [restore_dkg_data(kp) for kp in keypairs]
            pk = restore_dkg_data(pk)
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
        
        # Validate threshold
        threshold = pk.get('t_threshold')
        if len(keypairs) < threshold:
            return jsonify({
                "success": False,
                "error": f"Insufficient signers: provided {len(keypairs)}, need at least {threshold}"
            }), 400
        
        # [SECURITY] Validate all keypairs belong to same DKG group
        pk_hash_set = set()
        for kp in keypairs:
            pk_hash = kp.get('pk_hash')
            if pk_hash:
                pk_hash_set.add(pk_hash)
        
        if len(pk_hash_set) > 1:
            return jsonify({
                "success": False,
                "error": f"[SECURITY] Keypairs from different DKG groups detected!\n  Found {len(pk_hash_set)} different pk_hash values.\n  All keypairs must be from the same DKG group.",
                "details": {"detected_hashes": list(pk_hash_set)}
            }), 400
        
        # [SECURITY] Validate keypairs match the provided public key
        if pk_hash_set:
            expected_pk_hash = pk.get('pk_hash')
            keypairs_pk_hash = list(pk_hash_set)[0]
            
            if expected_pk_hash and keypairs_pk_hash != expected_pk_hash:
                return jsonify({
                    "success": False,
                    "error": f"[SECURITY] Keypair binding mismatch!\n  Keypairs belong to DKG group: {keypairs_pk_hash}\n  But trying to sign for PK group: {expected_pk_hash}\n  → Cannot mix shares from different DKG groups!",
                    "details": {
                        "keypairs_pk_hash": keypairs_pk_hash,
                        "expected_pk_hash": expected_pk_hash
                    }
                }), 400
        
        # Extract signer UIDs
        signer_uids = [kp['uid'] for kp in keypairs]
        
        # Sign with each keypair
        message_bytes = message.encode('utf-8')
        partial_sigs = []
        total_attempts = 0
        per_signer_times = []
        
        t_total_start = time.perf_counter()
        
        for kp in keypairs:
            t_signer_start = time.perf_counter()
            
            partial_sig = sign_threshold_dkg(
                message=message_bytes,
                keypair_info=kp,
                pk=pk,
                signer_uids=signer_uids,
                max_attempts=max_attempts,
                debug=debug
            )
            
            t_signer_end = time.perf_counter()
            per_signer_times.append(t_signer_end - t_signer_start)
            
            total_attempts += partial_sig['attempts']
            partial_sigs.append(partial_sig)
        
        t_total_end = time.perf_counter()
        total_sign_time = t_total_end - t_total_start
        
        # Convert NumPy types
        partial_sigs = convert_numpy_types(partial_sigs)
        
        # Encode partial signatures to base64
        partial_sigs_b64 = [
            base64.b64encode(json.dumps(sig).encode('utf-8')).decode('utf-8')
            for sig in partial_sigs
        ]
        
        return jsonify({
            "success": True,
            "partial_signatures_b64": partial_sigs_b64,
            "public_key_b64": public_key_b64,
            "metadata": {
                "num_signers": len(keypairs),
                "total_attempts": total_attempts,
                "avg_attempts_per_signer": total_attempts / len(keypairs) if keypairs else 0,
                "timing": {
                    "total_sign_time_ms": round(total_sign_time * 1000, 2),
                    "per_signer_times_ms": [round(t * 1000, 2) for t in per_signer_times]
                }
            }
        })
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"ERROR in /api/dkg/sign: {error_traceback}", file=sys.stderr)
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": error_traceback
        }), 500


@app.route('/api/dkg/aggregate', methods=['POST'])
def dkg_aggregate():
    """
    POST /api/dkg/aggregate
    
    Aggregate partial DKG signatures into final signature.
    
    Body (JSON):
    {
        "message": str,                      # Original message
        "partial_signatures_b64": [str],     # Base64-encoded partial signatures
        "public_key_b64": str,               # Base64-encoded public key
        "debug": bool                        # Optional: enable debug output (default: false)
    }
    
    Response:
    {
        "success": true,
        "signature_b64": str,          # Base64-encoded final signature
        "public_key_b64": str,         # Echo back for convenience
        "metadata": {
            "num_partial_sigs": int,
            "signer_uids": [int],
            "aggregate_time_ms": float
        }
    }
    """
    try:
        data = request.get_json()
        
        # Required parameters
        message = data.get('message')
        partial_sigs_b64 = data.get('partial_signatures_b64')
        public_key_b64 = data.get('public_key_b64')
        
        if not message or not partial_sigs_b64 or not public_key_b64:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: message, partial_signatures_b64, public_key_b64"
            }), 400
        
        # Optional parameters
        debug = data.get('debug', False)
        
        # Decode from base64
        import json
        import time
        
        def decode_b64(s):
            missing_padding = len(s) % 4
            if missing_padding:
                s += '=' * (4 - missing_padding)
            return base64.b64decode(s)
        
        try:
            partial_sigs = [json.loads(decode_b64(sig)) for sig in partial_sigs_b64]
            pk = json.loads(decode_b64(public_key_b64))
            
            # Restore Poly objects and bytes
            partial_sigs = [restore_dkg_data(sig) for sig in partial_sigs]
            pk = restore_dkg_data(pk)
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
        
        # Aggregate signatures
        message_bytes = message.encode('utf-8')
        
        t_agg_start = time.perf_counter()
        signature = aggregate_signatures_dkg(partial_sigs, pk, message_bytes, debug=debug)
        t_agg_end = time.perf_counter()
        
        aggregate_time = t_agg_end - t_agg_start
        
        # Convert NumPy types
        signature = convert_numpy_types(signature)
        
        # Encode signature to base64
        signature_b64 = base64.b64encode(json.dumps(signature).encode('utf-8')).decode('utf-8')
        
        return jsonify({
            "success": True,
            "signature_b64": signature_b64,
            "public_key_b64": public_key_b64,
            "metadata": {
                "num_partial_sigs": len(partial_sigs),
                "signer_uids": signature.get('signer_uids', []),
                "aggregate_time_ms": round(aggregate_time * 1000, 2)
            }
        })
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"ERROR in /api/dkg/aggregate: {error_traceback}", file=sys.stderr)
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": error_traceback
        }), 500


@app.route('/api/dkg/sign-complete', methods=['POST'])
def dkg_sign_complete():
    """
    POST /api/dkg/sign-complete
    
    All-in-one: Sign AND aggregate in single call (convenience endpoint).
    
    Body (JSON):
    {
        "message": str,              # Plain text message
        "keypairs_b64": [str],       # Base64-encoded keypairs (≥ threshold)
        "public_key_b64": str,       # Base64-encoded public key
        "max_attempts": int,         # Optional: max rejection attempts (default: 100)
        "debug": bool                # Optional: enable debug output (default: false)
    }
    
    Response:
    {
        "success": true,
        "signature_b64": str,        # Final aggregated signature (ready to verify)
        "public_key_b64": str,       # Echo back for convenience
        "metadata": {
            "num_signers": int,
            "signer_uids": [int],
            "total_attempts": int,
            "avg_attempts_per_signer": float,
            "timing": {
                "sign_time_ms": float,
                "aggregate_time_ms": float,
                "total_time_ms": float
            }
        }
    }
    """
    try:
        data = request.get_json()
        
        # Required parameters
        message = data.get('message')
        keypairs_b64 = data.get('keypairs_b64')
        public_key_b64 = data.get('public_key_b64')
        
        if not message or not keypairs_b64 or not public_key_b64:
            return jsonify({
                "success": False,
                "error": "Missing required parameters: message, keypairs_b64, public_key_b64"
            }), 400
        
        # Optional parameters
        max_attempts = data.get('max_attempts', 100)
        debug = data.get('debug', False)
        
        # Decode from base64
        import json
        import time
        
        def decode_b64(s):
            missing_padding = len(s) % 4
            if missing_padding:
                s += '=' * (4 - missing_padding)
            return base64.b64decode(s)
        
        try:
            keypairs = [json.loads(decode_b64(kp)) for kp in keypairs_b64]
            pk = json.loads(decode_b64(public_key_b64))
            
            # Restore Poly objects and bytes
            keypairs = [restore_dkg_data(kp) for kp in keypairs]
            pk = restore_dkg_data(pk)
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
        
        # Validate threshold
        threshold = pk.get('t_threshold')
        if len(keypairs) < threshold:
            return jsonify({
                "success": False,
                "error": f"Insufficient signers: provided {len(keypairs)}, need at least {threshold}"
            }), 400
        
        # [SECURITY] Validate all keypairs belong to same DKG group
        pk_hash_set = set()
        for kp in keypairs:
            pk_hash = kp.get('pk_hash')
            if pk_hash:
                pk_hash_set.add(pk_hash)
        
        if len(pk_hash_set) > 1:
            return jsonify({
                "success": False,
                "error": f"[SECURITY] Keypairs from different DKG groups detected!\n  Found {len(pk_hash_set)} different pk_hash values.\n  All keypairs must be from the same DKG group.",
                "details": {"detected_hashes": list(pk_hash_set)}
            }), 400
        
        # [SECURITY] Validate keypairs match the provided public key
        if pk_hash_set:
            expected_pk_hash = pk.get('pk_hash')
            keypairs_pk_hash = list(pk_hash_set)[0]
            
            if expected_pk_hash and keypairs_pk_hash != expected_pk_hash:
                return jsonify({
                    "success": False,
                    "error": f"[SECURITY] Keypair binding mismatch!\n  Keypairs belong to DKG group: {keypairs_pk_hash}\n  But trying to sign for PK group: {expected_pk_hash}\n  → Cannot mix shares from different DKG groups!",
                    "details": {
                        "keypairs_pk_hash": keypairs_pk_hash,
                        "expected_pk_hash": expected_pk_hash
                    }
                }), 400
        
        # Extract signer UIDs
        signer_uids = [kp['uid'] for kp in keypairs]
        
        message_bytes = message.encode('utf-8')
        
        # STEP 1: Generate partial signatures
        t_total_start = time.perf_counter()
        
        partial_sigs = []
        total_attempts = 0
        
        t_sign_start = time.perf_counter()
        for kp in keypairs:
            partial_sig = sign_threshold_dkg(
                message=message_bytes,
                keypair_info=kp,
                pk=pk,
                signer_uids=signer_uids,
                max_attempts=max_attempts,
                debug=debug
            )
            total_attempts += partial_sig['attempts']
            partial_sigs.append(partial_sig)
        t_sign_end = time.perf_counter()
        sign_time = t_sign_end - t_sign_start
        
        # STEP 2: Aggregate signatures
        t_agg_start = time.perf_counter()
        signature = aggregate_signatures_dkg(partial_sigs, pk, message_bytes, debug=debug)
        t_agg_end = time.perf_counter()
        aggregate_time = t_agg_end - t_agg_start
        
        t_total_end = time.perf_counter()
        total_time = t_total_end - t_total_start
        
        # Convert NumPy types
        signature = convert_numpy_types(signature)
        
        # Encode signature to base64
        signature_b64 = base64.b64encode(json.dumps(signature).encode('utf-8')).decode('utf-8')
        
        return jsonify({
            "success": True,
            "signature_b64": signature_b64,
            "public_key_b64": public_key_b64,
            "metadata": {
                "num_signers": len(keypairs),
                "signer_uids": signature.get('signer_uids', []),
                "total_attempts": total_attempts,
                "avg_attempts_per_signer": total_attempts / len(keypairs) if keypairs else 0,
                "timing": {
                    "sign_time_ms": round(sign_time * 1000, 2),
                    "aggregate_time_ms": round(aggregate_time * 1000, 2),
                    "total_time_ms": round(total_time * 1000, 2)
                }
            }
        })
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"ERROR in /api/dkg/sign-complete: {error_traceback}", file=sys.stderr)
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": error_traceback
        }), 500


@app.route('/api/dkg/verify', methods=['POST'])
def dkg_verify():
    """
    POST /api/dkg/verify
    
    Verify DKG threshold signature.
    
    Body (JSON):
    {
        "message": str,           # Original message
        "signature_b64": str,     # Base64-encoded signature
        "public_key_b64": str,    # Base64-encoded public key
        "debug": bool             # Optional: enable debug output (default: false)
    }
    
    Response:
    {
        "success": true,
        "valid": bool,
        "verify_time_ms": float
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
        
        # Optional parameters
        debug = data.get('debug', False)
        debug = bool(debug) if debug is not None else False  # Ensure Python bool
        
        # Decode from base64
        import json
        import time
        
        def decode_b64(s):
            missing_padding = len(s) % 4
            if missing_padding:
                s += '=' * (4 - missing_padding)
            return base64.b64decode(s)
        
        try:
            signature = json.loads(decode_b64(signature_b64))
            pk = json.loads(decode_b64(public_key_b64))
            
            # Restore Poly objects and bytes
            signature = restore_dkg_data(signature)
            pk = restore_dkg_data(pk)
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
        message_bytes = message.encode('utf-8')
        
        t_verify_start = time.perf_counter()
        valid = verify_threshold_dkg(signature, message_bytes, pk, debug=debug)
        t_verify_end = time.perf_counter()
        
        verify_time = t_verify_end - t_verify_start
        
        return jsonify({
            "success": True,
            "valid": valid,
            "verify_time_ms": round(verify_time * 1000, 2)
        })
        
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"ERROR in /api/dkg/verify: {error_traceback}", file=sys.stderr)
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": error_traceback
        }), 500


if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 Threshold Dilithium API Server (Base64)")
    print("="*80)
    print("Endpoints:")
    print("  GET    /api/health            - Health check")
    print("\n  Trusted Dealer (Shamir-based):")
    print("  POST   /api/keygen            - Generate keypair and shares")
    print("  POST   /api/sign              - Sign message with shares")
    print("  POST   /api/verify            - Verify signature")
    print("\n  DKG (Distributed Key Generation) with DUAL SECRETS:")
    print("  POST   /api/dkg/keygen        - Generate DKG keypairs")
    print("  POST   /api/dkg/sign          - Generate partial signatures")
    print("  POST   /api/dkg/aggregate     - Aggregate partial signatures")
    print("  POST   /api/dkg/sign-complete - Sign + aggregate (all-in-one)")
    print("  POST   /api/dkg/verify        - Verify DKG signature")
    print("\n  Session Management:")
    print("  GET    /sessions              - List all sessions")
    print("  GET    /session/<id>          - Get session info")
    print("="*80)
    print("Starting server on http://0.0.0.0:9080")
    print("="*80 + "\n")
    
    app.run(host='0.0.0.0', port=9080, debug=False)
