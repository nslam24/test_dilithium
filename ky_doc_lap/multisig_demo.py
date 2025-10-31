#!/usr/bin/env python3
"""Multisignature demo using Dilithium keys created in `keys/`.

This script loads private/public keys for a list of users and signs a message
with each user's private key (creating a list of signatures). It demonstrates
two verification modes:
 - ordered: verify signatures against public keys in the same order
 - unordered: verify signatures regardless of order by matching each signature
   to any remaining public key that validates it

Usage examples:
  /home/lamns/python/.venv/bin/python multisig_demo.py --level Dilithium3 --message "hello"
  /home/lamns/python/.venv/bin/python multisig_demo.py --level Dilithium3 --message "hello" --mode both

"""
import oqs
import argparse
import os
import sys
# Ensure repository root is on sys.path so sibling packages (modes/) can be imported
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)
from modes.sequential_mode import sign_sequential, verify_sequential
import base64
import json
import random
import time
from typing import List, Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_keys(users: List[str], level: str, keys_dir: str = "keys") -> List[Tuple[bytes, bytes]]:
    """Return list of (public_key_bytes, private_key_bytes) for each user in users order.
    Raises FileNotFoundError if a key file is missing.
    """
    # Tải cặp khóa (public, private) từ đĩa theo đúng thứ tự users.
    # File mong đợi: keys_dir/<user>/<level>/{public.key, private.key}
    pairs = []
    for user in users:
        pub_path = os.path.join(keys_dir, user, level, "public.key")
        priv_path = os.path.join(keys_dir, user, level, "private.key")
        if not os.path.exists(pub_path) or not os.path.exists(priv_path):
            # Nếu thiếu file, thông báo rõ ràng
            raise FileNotFoundError(f"Missing key for {user} at level {level}: {pub_path} or {priv_path}")
        with open(pub_path, "rb") as f:
            pub = f.read()
        with open(priv_path, "rb") as f:
            priv = f.read()
        pairs.append((pub, priv))
    return pairs


def sign_sequence(message: bytes, key_pairs: List[Tuple[bytes, bytes]], level: str, sig_type: str) -> Tuple[List[bytes], List[float]]:
    """Sign message with each private key in key_pairs order and return list of signatures and signing times.

    Returns:
      (signatures, sign_times) where sign_times[i] is the elapsed seconds for signature i.
    """
    # Với mỗi cặp khóa: tạo signer từ private key và ký message
    # Ghi lại thời gian bắt đầu/kết thúc để tính thời gian ký cho từng chữ ký
    sigs: List[bytes] = []
    times: List[float] = []
    for pub, priv in key_pairs:
        if sig_type == "dilithium":
            # instantiate signer from secret key (liboqs)
            with oqs.Signature(level, priv) as signer:
                t0 = time.time()
                sig = signer.sign(message)
                t1 = time.time()
        elif sig_type == "rsa":
            # load private key (DER) and sign using cryptography
            sk = serialization.load_der_private_key(priv, password=None, backend=default_backend())
            t0 = time.time()
            sig = sk.sign(message, padding.PKCS1v15(), hashes.SHA256())
            t1 = time.time()
        else:  # ecc
            sk = serialization.load_der_private_key(priv, password=None, backend=default_backend())
            t0 = time.time()
            sig = sk.sign(message, ec.ECDSA(hashes.SHA256()))
            t1 = time.time()
        sigs.append(sig)
        times.append(t1 - t0)
    return sigs, times


def verify_ordered(message: bytes, signatures: List[bytes], public_keys: List[bytes], level: str, sig_type: str) -> Tuple[bool, List[bool], List[float]]:
    # Xác minh theo thứ tự: signature[i] phải hợp lệ với public_keys[i]
    results: List[bool] = []
    verify_times: List[float] = []
    # Note: for non-Dilithium we need to verify with cryptography APIs
    for sig, pub in zip(signatures, public_keys):
        t0 = time.time()
        if sig_type == "dilithium":
            with oqs.Signature(level) as verifier:
                ok = verifier.verify(message, sig, pub)
        elif sig_type == "rsa":
            # load public key and verify
            pk = serialization.load_der_public_key(pub, backend=default_backend())
            try:
                pk.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
                ok = True
            except Exception:
                ok = False
        else:
            pk = serialization.load_der_public_key(pub, backend=default_backend())
            try:
                pk.verify(sig, message, ec.ECDSA(hashes.SHA256()))
                ok = True
            except Exception:
                ok = False
        t1 = time.time()
        results.append(ok)
        verify_times.append(t1 - t0)
    return all(results), results, verify_times


def verify_unordered(message: bytes, signatures: List[bytes], public_keys: List[bytes], level: str, sig_type: str) -> Tuple[bool, Dict[int, int], List[float]]:
    """Try to match each signature to some public key (order independent).
    Returns (success, mapping) where mapping[signature_index]=public_key_index
    """
    # Xác minh không theo thứ tự: với mỗi signature cố gắng tìm public key phù hợp
    # Nếu tìm được, public key đó được đánh dấu đã dùng (một public key chỉ xác minh 1 signature)
    remaining_pks = {i: pk for i, pk in enumerate(public_keys)}
    mapping: Dict[int, int] = {}
    verify_times: List[float] = []
    for si, sig in enumerate(signatures):
        found = False
        t_sig_start = time.time()
        for pi, pk in list(remaining_pks.items()):
            if sig_type == "dilithium":
                with oqs.Signature(level) as verifier:
                    ok = verifier.verify(message, sig, pk)
            elif sig_type == "rsa":
                pubk = serialization.load_der_public_key(pk, backend=default_backend())
                try:
                    pubk.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())
                    ok = True
                except Exception:
                    ok = False
            else:
                pubk = serialization.load_der_public_key(pk, backend=default_backend())
                try:
                    pubk.verify(sig, message, ec.ECDSA(hashes.SHA256()))
                    ok = True
                except Exception:
                    ok = False
            if ok:
                t_sig_end = time.time()
                mapping[si] = pi
                del remaining_pks[pi]
                found = True
                verify_times.append(t_sig_end - t_sig_start)
                break
        if not found:
            # Nếu một signature không khớp với bất kỳ public key nào, thất bại
            # record time spent trying for this signature
            t_sig_end = time.time()
            verify_times.append(t_sig_end - t_sig_start)
            return False, mapping, verify_times
    # success if all signatures mapped
    return (len(mapping) == len(signatures)), mapping, verify_times


def main():
    parser = argparse.ArgumentParser(description="Multisignature demo using Dilithium keys")
    parser.add_argument("--level", default="Dilithium3", help="Dilithium level to use (Dilithium2/3/5)")
    parser.add_argument("--sig-type", choices=["dilithium","rsa","ecc"], default="dilithium", help="Signature algorithm type to use")
    parser.add_argument("--users", default=",".join([f"user{i+1}" for i in range(5)]), help="Comma-separated users matching keys/<user>/")
    parser.add_argument("--message", default="Test multisig message", help="Message to sign")
    parser.add_argument("--sign-mode", choices=["independent","sequential"], default="independent", help="Signing mode to use")
    parser.add_argument("--mode", choices=["ordered","unordered","both"], default="both", help="Which verification mode to run")
    parser.add_argument("--keys-dir", default="keys", help="Directory where per-user keys are stored")
    parser.add_argument("--shuffle", action="store_true", help="Create an out-of-order signature list (shuffle signing order)")
    parser.add_argument("--interactive", action="store_true", help="Run interactive menu to select level, mode, users and options")
    parser.add_argument("--use-keystore", action="store_true", help="Treat users as aliases and load key paths from keystore.json in keys-dir")
    args = parser.parse_args()
    # Normalized signature type (may be overridden by interactive menu)
    sig_type = args.sig_type.lower()

    users = [u.strip() for u in args.users.split(",") if u.strip()]
    message = args.message.encode()
    level = args.level
    
    # Interactive menu: override args if requested
    if args.interactive:
        # Chọn loại ký trước (Dilithium / RSA / ECC)
        types = ["Dilithium", "RSA", "ECC"]
        for i, t in enumerate(types, start=1):
            print(f"  {i}) {t}")
        t_choice = input(f"Choose signature type [1-{len(types)}] (default 1 - Dilithium): ").strip()
        try:
            t_idx = int(t_choice) - 1
            if not (0 <= t_idx < len(types)):
                t_idx = 0
        except Exception:
            t_idx = 0
        args.sig_type = types[t_idx].lower()

        print("Interactive multisig menu")
        levels = ["Dilithium2", "Dilithium3", "Dilithium5"]
        for i, lv in enumerate(levels, start=1):
            print(f"  {i}) {lv}")
        lv_choice = input(f"Choose level [1-{len(levels)}] (default 2): ").strip()
        try:
            lv_idx = int(lv_choice) - 1
            if not (0 <= lv_idx < len(levels)):
                lv_idx = 1
        except Exception:
            lv_idx = 1
        args.level = levels[lv_idx]

        modes = ["ordered", "unordered", "both"]
        # Chọn signing mode (independent / sequential)
        sign_modes = ["independent", "sequential"]
        print("Signing modes:")
        for i, sm in enumerate(sign_modes, start=1):
            print(f"  {i}) {sm}")
        sm_choice = input(f"Choose signing mode [1-{len(sign_modes)}] (default 1 - independent): ").strip()
        try:
            sm_idx = int(sm_choice) - 1
            if not (0 <= sm_idx < len(sign_modes)):
                sm_idx = 0
        except Exception:
            sm_idx = 0
        args.sign_mode = sign_modes[sm_idx]
        for i, m in enumerate(modes, start=1):
            print(f"  {i}) {m}")
        m_choice = input(f"Choose mode [1-{len(modes)}] (default 3 - both): ").strip()
        try:
            m_idx = int(m_choice) - 1
            if not (0 <= m_idx < len(modes)):
                m_idx = 2
        except Exception:
            m_idx = 2
        args.mode = modes[m_idx]

        u_input = input(f"Users (comma-separated) [default: {args.users}]: ").strip()
        if u_input:
            args.users = u_input

        shuffle_input = input("Shuffle signing order? (y/N): ").strip().lower()
        args.shuffle = shuffle_input.startswith("y")

        msg_input = input(f"Message to sign [default: '{args.message}']: ").strip()
        if msg_input:
            args.message = msg_input

        # reflect choices into local vars
        users = [u.strip() for u in args.users.split(",") if u.strip()]
        message = args.message.encode()
        level = args.level

        # If using keystore, load keystore.json and interpret `users` as aliases
        keystore = None
        if args.use_keystore:
            keystore_path = os.path.join(args.keys_dir, "keystore.json")
            if not os.path.exists(keystore_path):
                # Nếu không có keystore.json, tự động xây dựng từ cấu trúc thư mục keys/<user>/<level>/
                keystore = {}
                if not os.path.isdir(args.keys_dir):
                    raise FileNotFoundError(f"Keys directory not found: {args.keys_dir}")
                for user in os.listdir(args.keys_dir):
                    user_dir = os.path.join(args.keys_dir, user)
                    if not os.path.isdir(user_dir):
                        continue
                    for level in os.listdir(user_dir):
                        lvl_dir = os.path.join(user_dir, level)
                        pub = os.path.join(lvl_dir, "public.key")
                        priv = os.path.join(lvl_dir, "private.key")
                        if os.path.exists(pub) and os.path.exists(priv):
                            alias = f"{user}@{level}"
                            # store paths relative to keys_dir
                            keystore[alias] = {
                                "user": user,
                                "level": level,
                                "pub_path": os.path.relpath(pub, start=args.keys_dir),
                                "priv_path": os.path.relpath(priv, start=args.keys_dir),
                            }
                # write keystore.json for future runs
                with open(keystore_path, "w", encoding="utf-8") as f:
                    json.dump(keystore, f, indent=2)
            with open(keystore_path, "r", encoding="utf-8") as f:
                keystore = json.load(f)
            # keystore entries use paths relative to args.keys_dir
            # End keystore load

        # Normalize signature type string for later branching
        sig_type = args.sig_type.lower()
    # signing mode (independent / sequential)
    sign_mode = args.sign_mode.lower()

    # If keystore requested in non-interactive mode, ensure keystore is loaded
    # (the interactive branch already builds/loads the keystore). This avoids
    # UnboundLocalError when --use-keystore is passed without --interactive.
    if args.use_keystore and not args.interactive:
        keystore_path = os.path.join(args.keys_dir, "keystore.json")
        if not os.path.exists(keystore_path):
            keystore = {}
            if not os.path.isdir(args.keys_dir):
                raise FileNotFoundError(f"Keys directory not found: {args.keys_dir}")
            for user in os.listdir(args.keys_dir):
                user_dir = os.path.join(args.keys_dir, user)
                if not os.path.isdir(user_dir):
                    continue
                for lvl in os.listdir(user_dir):
                    lvl_dir = os.path.join(user_dir, lvl)
                    pub = os.path.join(lvl_dir, "public.key")
                    priv = os.path.join(lvl_dir, "private.key")
                    if os.path.exists(pub) and os.path.exists(priv):
                        alias = f"{user}@{lvl}"
                        keystore[alias] = {
                            "user": user,
                            "level": lvl,
                            "pub_path": os.path.relpath(pub, start=args.keys_dir),
                            "priv_path": os.path.relpath(priv, start=args.keys_dir),
                        }
            with open(keystore_path, "w", encoding="utf-8") as f:
                json.dump(keystore, f, indent=2)
        with open(keystore_path, "r", encoding="utf-8") as f:
            keystore = json.load(f)

    # Nếu dùng keystore, users được hiểu là aliases (hoặc được kết hợp user@level)
    if args.use_keystore:
        aliases = []
        for u in users:
            if "@" in u:
                aliases.append(u)
            else:
                aliases.append(f"{u}@{level}")
        # load key pairs from keystore entries
        key_pairs = []
        for alias in aliases:
            entry = keystore.get(alias)
            if not entry:
                raise KeyError(f"Alias not found in keystore: {alias}")
            pub_path = os.path.join(args.keys_dir, entry["pub_path"]) if not os.path.isabs(entry["pub_path"]) else entry["pub_path"]
            priv_path = os.path.join(args.keys_dir, entry["priv_path"]) if not os.path.isabs(entry["priv_path"]) else entry["priv_path"]
            with open(pub_path, "rb") as f:
                pub = f.read()
            with open(priv_path, "rb") as f:
                priv = f.read()
            key_pairs.append((pub, priv))
        public_keys = [p for p,_ in key_pairs]
        print(f"Loaded keys for aliases: {aliases} from keystore {os.path.join(args.keys_dir,'keystore.json')}")
    else:
        print(f"Loading keys for users: {users} at level {level} from {args.keys_dir}")
        # Nếu là Dilithium, dùng load_keys tiêu chuẩn
        if sig_type == "dilithium":
            key_pairs = load_keys(users, level, args.keys_dir)
            public_keys = [p for p,_ in key_pairs]
        else:
            # Với RSA/ECC: cố gắng load từ disk nếu có (dựa trên nhãn level tương ứng),
            # nếu không -> sinh ephemeral keys in-memory
            key_pairs = []
            public_keys = []
            # chọn nhãn level để tìm key trên đĩa theo loại thuật toán
            if sig_type == "rsa":
                lookup_level = args.level if args.level.upper().startswith("RSA") else "RSA-2048"
            elif sig_type == "ecc":
                lookup_level = args.level if args.level.upper().startswith("ECC") else "ECC-P256"
            else:
                lookup_level = level
            for user in users:
                pub_path = os.path.join(args.keys_dir, user, lookup_level, "public.key")
                priv_path = os.path.join(args.keys_dir, user, lookup_level, "private.key")
                if os.path.exists(pub_path) and os.path.exists(priv_path):
                    with open(pub_path, "rb") as f:
                        pub = f.read()
                    with open(priv_path, "rb") as f:
                        priv = f.read()
                else:
                    # Generate ephemeral key pair for RSA/ECC
                    if sig_type == "rsa":
                        pk = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
                        priv = pk.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
                        pub = pk.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        print(f"Generated ephemeral RSA key for {user}")
                    else:
                        sk = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
                        priv = sk.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
                        pub = sk.public_key().public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                        print(f"Generated ephemeral ECC key for {user}")
                key_pairs.append((pub, priv))
                public_keys.append(pub)
    public_keys = [p for p,_ in key_pairs]

    # create signature list in requested order or shuffled
    sign_order = list(range(len(users)))
    if args.shuffle:
        random.shuffle(sign_order)

    ordered_pairs = [key_pairs[i] for i in sign_order]
    # Choose signing implementation based on requested signing mode
    if getattr(args, 'sign_mode', 'independent') == 'sequential':
        # sequential signing chains previous signatures via sha3_512
        signatures, sign_times = sign_sequential(message, ordered_pairs, level, sig_type)
    else:
        # independent signing: each signer signs the same message
        signatures, sign_times = sign_sequence(message, ordered_pairs, level, sig_type)

    # Print summary
    print(f"Signed message with {len(signatures)} signatures (sign order: {sign_order})")
    for i, sig in enumerate(signatures):
        st = sign_times[i] if i < len(sign_times) else None
        print(f" sig[{i}] len={len(sig)} sign_time={st:.6f}s b64={base64.b64encode(sig)[:40]}...")

    verify_times_ordered = None
    verify_times_unordered = None
    unordered_mapping = None
    ok_ordered = None
    ok_unordered = None
    if args.mode in ("ordered", "both"):
        print("\nVerifying ordered (matching signature index to same public key index)")
        # If we shuffled signing order, map public_keys accordingly for 'ordered' verification
        ordered_publics = [public_keys[i] for i in sign_order]
        # If signing was sequential, use the sequential verifier which rebuilds the chained messages
        if getattr(args, 'sign_mode', 'independent') == 'sequential':
            ok_ordered, results, verify_times_ordered = verify_sequential(message, signatures, ordered_publics, level, sig_type)
        else:
            ok_ordered, results, verify_times_ordered = verify_ordered(message, signatures, ordered_publics, level, sig_type)
        print(" Ordered verification per-signature:")
        for i, (res, vt) in enumerate(zip(results, verify_times_ordered)):
            print(f"  sig[{i}] verified={res} verify_time={vt:.6f}s")
        print(" Ordered overall:", ok_ordered)

    if args.mode in ("unordered", "both"):
        print("\nVerifying unordered (match signatures to any public key)")
        ok_unordered, mapping, verify_times_unordered = verify_unordered(message, signatures, public_keys, level, sig_type)
        unordered_mapping = mapping
        print(" Unordered overall:", ok_unordered)
        print(" Mapping (sig_index -> public_key_index):", mapping)
        print(" Unordered per-signature verify times:")
        for i, vt in enumerate(verify_times_unordered):
            print(f"  sig[{i}] verify_time={vt:.6f}s")

    # Save combined signature bundle for later inspection
    bundle = {
        "users": users,
        "level": level,
        "sign_mode": getattr(args, 'sign_mode', 'independent'),
        "sign_order": sign_order,
        "message": base64.b64encode(message).decode(),
        "signatures": [base64.b64encode(s).decode() for s in signatures],
        "sign_times": [float(x) for x in sign_times],
        "verify_times_ordered": [float(x) for x in verify_times_ordered] if verify_times_ordered is not None else None,
        "verify_times_unordered": [float(x) for x in verify_times_unordered] if verify_times_unordered is not None else None,
        "unordered_mapping": unordered_mapping,
        "ok_ordered": bool(ok_ordered) if ok_ordered is not None else None,
        "ok_unordered": bool(ok_unordered) if ok_unordered is not None else None,
    }
    out_path = f"multisig_{level}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    print(f"Saved signature bundle to {out_path}")


if __name__ == "__main__":
    main()
