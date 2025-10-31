#!/usr/bin/env bash
# Interactive runner for multisig_demo.py
# If variables are passed as environment variables, the script will use them instead of prompting.

set -euo pipefail

PYTHON_DEFAULT="/home/lamns/python/.venv/bin/python"
PYTHON="${PYTHON:-$PYTHON_DEFAULT}"
MULTISIG="ky_doc_lap/multisig_demo.py"

# Helper to prompt with default
prompt() {
  local varname="$1";
  local prompt_text="$2";
  local default_val="$3";
  local val
  if [ -n "${!varname:-}" ]; then
    echo "$varname is set to '${!varname}' (from environment)"
    return 0
  fi
  read -p "$prompt_text [$default_val]: " val
  if [ -z "$val" ]; then
    eval "$varname=\"$default_val\""
  else
    eval "$varname=\"$val\""
  fi
}

echo "--- Multisig interactive runner ---"

# Use environment variables if provided, otherwise prompt
# Prompt for signature type with numbered options
echo "Choose signature type:"
echo "  1) dilithium"
echo "  2) rsa"
echo "  3) ecc"
if [ -n "${SIG_TYPE:-}" ]; then
  echo "SIG_TYPE is set to '$SIG_TYPE' (from environment)"
else
  read -p "Choose option [1-3] (default 1): " st_choice
  st_choice="${st_choice:-1}"
  case "$st_choice" in
    1) SIG_TYPE="dilithium" ;;
    2) SIG_TYPE="rsa" ;;
    3) SIG_TYPE="ecc" ;;
    *) SIG_TYPE="dilithium" ;;
  esac
fi
SIG_TYPE="${SIG_TYPE,,}"

if [ "$SIG_TYPE" = "dilithium" ]; then
  echo "Choose Dilithium level:"
  echo "  1) Dilithium2"
  echo "  2) Dilithium3"
  echo "  3) Dilithium5"
  if [ -n "${LEVEL:-}" ]; then
    echo "LEVEL is set to '$LEVEL' (from environment)"
  else
    read -p "Choose option [1-3] (default 2): " lv_choice
    lv_choice="${lv_choice:-2}"
    case "$lv_choice" in
      1) LEVEL="Dilithium2" ;;
      2) LEVEL="Dilithium3" ;;
      3) LEVEL="Dilithium5" ;;
      *) LEVEL="Dilithium3" ;;
    esac
  fi
elif [ "$SIG_TYPE" = "rsa" ]; then
  echo "Choose RSA level:"
  echo "  1) RSA-2048"
  echo "  2) RSA-3072"
  if [ -n "${LEVEL:-}" ]; then
    echo "LEVEL is set to '$LEVEL' (from environment)"
  else
    read -p "Choose option [1-2] (default 1): " lv_choice
    lv_choice="${lv_choice:-1}"
    case "$lv_choice" in
      1) LEVEL="RSA-2048" ;;
      2) LEVEL="RSA-3072" ;;
      *) LEVEL="RSA-2048" ;;
    esac
  fi
else
  echo "Choose ECC level:"
  echo "  1) ECC-P256"
  echo "  2) ECC-P384"
  if [ -n "${LEVEL:-}" ]; then
    echo "LEVEL is set to '$LEVEL' (from environment)"
  else
    read -p "Choose option [1-2] (default 1): " lv_choice
    lv_choice="${lv_choice:-1}"
    case "$lv_choice" in
      1) LEVEL="ECC-P256" ;;
      2) LEVEL="ECC-P384" ;;
      *) LEVEL="ECC-P256" ;;
    esac
  fi
fi

echo "Choose verification mode:"
echo "  1) ordered"
echo "  2) unordered"
echo "  3) both"
if [ -n "${MODE:-}" ]; then
  echo "MODE is set to '$MODE' (from environment)"
else
  read -p "Choose option [1-3] (default 3): " m_choice
  m_choice="${m_choice:-3}"
  case "$m_choice" in
    1) MODE="ordered" ;;
    2) MODE="unordered" ;;
    3) MODE="both" ;;
    *) MODE="both" ;;
  esac
fi
prompt USERS "Users (comma-separated)" "user1,user2,user3,user4,user5"
prompt MESSAGE "Message to sign" "Test multisig message"

if [ -z "${SHUFFLE:-}" ]; then
  read -p "Shuffle signing order? (y/N): " sh
  if [ "${sh,,}" = "y" ]; then
    SHUFFLE=1
  else
    SHUFFLE=0
  fi
fi

if [ -z "${USE_KEYSTORE:-}" ]; then
  read -p "Use keystore.json in keys dir? (y/N): " uk
  if [ "${uk,,}" = "y" ]; then
    USE_KEYSTORE=1
  else
    USE_KEYSTORE=0
  fi
fi

prompt KEYS_DIR "Keys directory" "keys"

# Build command
CMD=("$PYTHON" "$MULTISIG" --sig-type "$SIG_TYPE" --level "$LEVEL" --mode "$MODE" --users "$USERS" --message "$MESSAGE" --keys-dir "$KEYS_DIR")
if [ "$SHUFFLE" -ne 0 ]; then
  CMD+=(--shuffle)
fi
if [ "$USE_KEYSTORE" -ne 0 ]; then
  CMD+=(--use-keystore)
fi

echo "Running: ${CMD[*]}"
"${CMD[@]}"
