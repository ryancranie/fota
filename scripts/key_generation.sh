#!/bin/bash
# Script 1: key_generation.sh (Run on FOTA Server - VM2)
# Generate all required keys for firmware signing/encryption

KEY_DIR="$(pwd)"

declare -A KEYS=(
  [ECDSA_PRIVATE]="ecdsa_private.pem"
  [ECDSA_PUBLIC]="ecdsa_public.pem"
  [ED25519_PRIVATE]="ed25519_private.pem"
  [ED25519_PUBLIC]="ed25519_public.pem"
  [ECDH_PRIVATE]="ecdh_private.pem"
  [ECDH_PUBLIC]="ecdh_public.pem"
)

for key in "${!KEYS[@]}"; do
  FILE="$KEY_DIR/${KEYS[$key]}"
  if [ -f "$FILE" ]; then
    read -p "$FILE exists. Overwrite? (y/n): " choice
    if [[ "$choice" != "y" ]]; then
      echo "Skipping $FILE"
      continue
    fi
  fi

  case $key in
    ECDSA_PRIVATE)
      openssl ecparam -name prime256v1 -genkey -noout -out "$FILE";;
    ECDSA_PUBLIC)
      openssl ec -in ecdsa_private.pem -pubout -out "$FILE";;
    ED25519_PRIVATE)
      openssl genpkey -algorithm ED25519 -out "$FILE";;
    ED25519_PUBLIC)
      openssl pkey -in ed25519_private.pem -pubout -out "$FILE";;
    ECDH_PRIVATE)
      openssl ecparam -name prime256v1 -genkey -noout -out "$FILE";;
    ECDH_PUBLIC)
      openssl ec -in ecdh_private.pem -pubout -out "$FILE";;
  esac
  echo "Generated: $FILE"
done