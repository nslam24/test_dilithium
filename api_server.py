#!/usr/bin/env python3
"""
api_server.py

REST API Server cho Threshold Dilithium Signature Scheme.
Chạy trên cổng 9080.

Endpoints:
- POST /api/keygen              - Tạo khóa và phân mảnh
- POST /api/sign                - Ký message với các shares
- POST /api/verify              - Verify signature
- GET  /api/sessions            - Liệt kê tất cả sessions
- GET  /api/sessions/<id>       - Chi tiết một session
- GET  /api/health              - Health check
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
from pathlib import Path
import traceback

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from threshold_controller import ThresholdController

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize controller
controller = ThresholdController(keys_dir="keys")


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "Threshold Dilithium API",
        "version": "1.0.0"
    })


@app.route('/api/keygen', methods=['POST'])
def keygen():
    """
    Tạo khóa và phân mảnh.
    
    Request Body:
    {
        "n_parties": int,           # Tổng số participants
        "threshold": int,           # Số lượng tối thiểu để ký
        "session_id": str (optional),  # ID tùy chỉnh
        "K": int (optional, default=1),
        "L": int (optional, default=1)
    }
    
    Response:
    {
        "success": bool,
        "session_id": str,
        "n_parties": int,
        "threshold": int,
        "K": int,
        "L": int,
        "shares_saved": List[str],
        "pk_path": str,
        "metadata_path": str,
        "created_at": str
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'n_parties' not in data or 'threshold' not in data:
            return jsonify({
                "success": False,
                "error": "Missing required fields: n_parties, threshold"
            }), 400
        
        n_parties = int(data['n_parties'])
        threshold = int(data['threshold'])
        session_id = data.get('session_id', None)
        K = int(data.get('K', 1))
        L = int(data.get('L', 1))
        
        # Validate parameters
        if threshold > n_parties:
            return jsonify({
                "success": False,
                "error": f"Threshold ({threshold}) cannot be greater than n_parties ({n_parties})"
            }), 400
        
        if threshold < 1:
            return jsonify({
                "success": False,
                "error": "Threshold must be at least 1"
            }), 400
        
        # Generate keys
        result = controller.generate_and_save_shares(
            n_parties=n_parties,
            threshold=threshold,
            session_id=session_id,
            K=K,
            L=L
        )
        
        return jsonify({
            "success": True,
            **result
        })
        
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Internal error: {str(e)}"
        }), 500


@app.route('/api/sign', methods=['POST'])
def sign():
    """
    Ký message với các mảnh khóa.
    
    Request Body:
    {
        "message": str,              # Message to sign (will be encoded to bytes)
        "share_paths": List[str],    # Paths to share files
        "session_id": str,           # Session ID
        "output_path": str (optional)  # Custom output path for signature
    }
    
    Response:
    {
        "success": bool,
        "status": "success" | "insufficient_shares",
        "required": int,
        "provided": int,
        "signature": Dict | None,
        "signature_path": str | None,
        "metadata": Dict
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['message', 'share_paths', 'session_id']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "success": False,
                    "error": f"Missing required field: {field}"
                }), 400
        
        message = data['message'].encode('utf-8')
        share_paths = data['share_paths']
        session_id = data['session_id']
        output_path = data.get('output_path', None)
        
        # Validate share_paths is a list
        if not isinstance(share_paths, list):
            return jsonify({
                "success": False,
                "error": "share_paths must be a list"
            }), 400
        
        # Validate all share files exist
        for path in share_paths:
            if not Path(path).exists():
                return jsonify({
                    "success": False,
                    "error": f"Share file not found: {path}"
                }), 404
        
        # Sign
        result = controller.sign_with_shares(
            message=message,
            share_paths=share_paths,
            session_id=session_id,
            output_path=output_path
        )
        
        return jsonify({
            "success": result["status"] == "success",
            **result
        })
        
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Internal error: {str(e)}"
        }), 500


@app.route('/api/verify', methods=['POST'])
def verify():
    """
    Xác minh chữ ký.
    
    Request Body:
    {
        "message": str,           # Original message
        "signature_path": str,    # Path to signature file
        "pk_path": str           # Path to public key file
    }
    
    Response:
    {
        "success": bool,
        "valid": bool,
        "verify_time_ms": float,
        "message": str (hex),
        "signature_info": Dict
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['message', 'signature_path', 'pk_path']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "success": False,
                    "error": f"Missing required field: {field}"
                }), 400
        
        message = data['message'].encode('utf-8')
        signature_path = data['signature_path']
        pk_path = data['pk_path']
        
        # Validate files exist
        if not Path(signature_path).exists():
            return jsonify({
                "success": False,
                "error": f"Signature file not found: {signature_path}"
            }), 404
        
        if not Path(pk_path).exists():
            return jsonify({
                "success": False,
                "error": f"Public key file not found: {pk_path}"
            }), 404
        
        # Verify
        result = controller.verify_signature(
            message=message,
            signature_path=signature_path,
            pk_path=pk_path
        )
        
        return jsonify({
            "success": True,
            **result
        })
        
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Internal error: {str(e)}"
        }), 500


@app.route('/api/sessions', methods=['GET'])
def list_sessions():
    """
    Liệt kê tất cả sessions.
    
    Response:
    {
        "success": bool,
        "sessions": List[Dict]
    }
    """
    try:
        sessions = controller.list_sessions()
        return jsonify({
            "success": True,
            "sessions": sessions,
            "count": len(sessions)
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Internal error: {str(e)}"
        }), 500


@app.route('/api/sessions/<session_id>', methods=['GET'])
def get_session(session_id):
    """
    Lấy thông tin chi tiết của một session.
    
    Response:
    {
        "success": bool,
        "session_info": Dict
    }
    """
    try:
        session_info = controller.get_session_info(session_id)
        return jsonify({
            "success": True,
            "session_info": session_info
        })
    except ValueError as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": f"Internal error: {str(e)}"
        }), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


def main():
    """Run the Flask server."""
    print("\n" + "="*80)
    print("🚀 THRESHOLD DILITHIUM API SERVER")
    print("="*80)
    print(f"\n📍 Server starting on: http://0.0.0.0:9080")
    print(f"📂 Keys directory: {controller.keys_dir}")
    print(f"\n📚 Available endpoints:")
    print(f"  • POST   /api/keygen              - Generate keys and shares")
    print(f"  • POST   /api/sign                - Sign message with shares")
    print(f"  • POST   /api/verify              - Verify signature")
    print(f"  • GET    /api/sessions            - List all sessions")
    print(f"  • GET    /api/sessions/<id>       - Get session details")
    print(f"  • GET    /api/health              - Health check")
    print(f"\n💡 Example usage:")
    print(f"  curl http://localhost:9080/api/health")
    print(f"\n{'='*80}\n")
    
    # Run server
    app.run(
        host='0.0.0.0',
        port=9080,
        debug=False,  # Set to False for production
        threaded=True
    )


if __name__ == '__main__':
    main()
