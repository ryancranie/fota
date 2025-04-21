#!/bin/bash
# Script for generating keys prior to encryption for our FOTA server

# Create keys directory in same location as script
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
KEY_DIR="$SCRIPT_DIR/keys"
mkdir -p "$KEY_DIR"

echo "SETUP     | Script directory: $SCRIPT_DIR"
echo "SETUP     | Key directory: $KEY_DIR"

# Generate keys in proper order to ensure all dependencies are satisfied
echo "GENERATE  | Starting private key generation..."

# Generate ECDSA private key
if [ -f "$KEY_DIR/ecdsa_private.pem" ]; then
  echo "FOUND     | Using existing key: $KEY_DIR/ecdsa_private.pem"
else
  openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/ecdsa_private.pem" 2>/dev/null
  echo "GENERATE  | Created: $KEY_DIR/ecdsa_private.pem"
fi

# Generate Ed25519 private key
if [ -f "$KEY_DIR/ed25519_private.pem" ]; then
  echo "FOUND     | Using existing key: $KEY_DIR/ed25519_private.pem"
else
  openssl genpkey -algorithm ED25519 -out "$KEY_DIR/ed25519_private.pem" 2>/dev/null
  echo "GENERATE  | Created: $KEY_DIR/ed25519_private.pem"
fi

# Generate ECDH private key
if [ -f "$KEY_DIR/ecdh_private.pem" ]; then
  echo "FOUND     | Using existing key: $KEY_DIR/ecdh_private.pem"
else
  openssl ecparam -name prime256v1 -genkey -noout -out "$KEY_DIR/ecdh_private.pem" 2>/dev/null
  echo "GENERATE  | Created: $KEY_DIR/ecdh_private.pem"
fi

echo "GENERATE  | Starting public key generation..."

# Generate ECDSA public key
OVERWRITE="y"
if [ -f "$KEY_DIR/ecdsa_public.pem" ]; then
  read -p "PUBLIC    | Key $KEY_DIR/ecdsa_public.pem already exists. Overwrite? (y/n): " OVERWRITE
fi
if [[ "$OVERWRITE" == "y" ]]; then
  openssl ec -in "$KEY_DIR/ecdsa_private.pem" -pubout -out "$KEY_DIR/ecdsa_public.pem" 2>/dev/null
  echo "GENERATE  | Created: $KEY_DIR/ecdsa_public.pem"
fi

# Generate Ed25519 public key
OVERWRITE="y"
if [ -f "$KEY_DIR/ed25519_public.pem" ]; then
  read -p "PUBLIC    | Key $KEY_DIR/ed25519_public.pem already exists. Overwrite? (y/n): " OVERWRITE
fi
if [[ "$OVERWRITE" == "y" ]]; then
  openssl pkey -in "$KEY_DIR/ed25519_private.pem" -pubout -out "$KEY_DIR/ed25519_public.pem" 2>/dev/null
  echo "GENERATE  | Created: $KEY_DIR/ed25519_public.pem"
fi

# Generate ECDH public key
OVERWRITE="y" 
if [ -f "$KEY_DIR/ecdh_public.pem" ]; then
  read -p "PUBLIC    | Key $KEY_DIR/ecdh_public.pem already exists. Overwrite? (y/n): " OVERWRITE
fi
if [[ "$OVERWRITE" == "y" ]]; then
  openssl ec -in "$KEY_DIR/ecdh_private.pem" -pubout -out "$KEY_DIR/ecdh_public.pem" 2>/dev/null
  echo "GENERATE  | Created: $KEY_DIR/ecdh_public.pem"
fi

echo "COMPLETE  | All keys generated in $KEY_DIR"