#!/bin/bash
# Script for adversary device to encrypt firmware - unified with all 5 methods tested

# Prompt for firmware path
read -p "USER      | Enter the full path to the firmware file (e.g. /home/user/firmware_v1.bin): " FIRMWARE_PATH
if [[ ! -f "$FIRMWARE_PATH" ]]; then
    echo "ERROR     | File not found!"
    exit 1
fi

FIRMWARE_NAME=$(basename "$FIRMWARE_PATH" .bin)
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
KEYS_DIR="$SCRIPT_DIR/keys"
DIR=$(dirname "$FIRMWARE_PATH")

# Create output directory
OUTPUT_DIR="${DIR}/${FIRMWARE_NAME}_encrypted"
mkdir -p "$OUTPUT_DIR"
cd "$DIR"

# Key paths
ECDSA_PRIVATE="$KEYS_DIR/ecdsa_private.pem"
ECDSA_PUBLIC="$KEYS_DIR/ecdsa_public.pem"
ED25519_PRIVATE="$KEYS_DIR/ed25519_private.pem" 
ED25519_PUBLIC="$KEYS_DIR/ed25519_public.pem"
ECDH_PRIVATE="$KEYS_DIR/ecdh_private.pem"
ECDH_PUBLIC="$KEYS_DIR/ecdh_public.pem"

# Check if keys exist
if [[ ! -f "$ECDSA_PRIVATE" || ! -f "$ED25519_PRIVATE" || ! -f "$ECDH_PRIVATE" ]]; then
    echo "ERROR     | Required keys not found in $KEYS_DIR"
    echo "ERROR     | Please run key_generation.sh first"
    exit 1
fi

# Helper function to encrypt and sign
encrypt_and_sign() {
    local PROTOCOL=$1
    local ENC_CMD=$2
    local SIGN_CMD=$3
    local OUTPUT_PREFIX=$4

    echo ""
    echo "ENCRYPT   | Starting $PROTOCOL encryption process..."
    
    # Run the encryption command
    echo "RUNNING   | Executing encryption..."
    eval "$ENC_CMD 2>/dev/null"
    
    if [[ $? -eq 0 ]]; then
        echo "ENCRYPT   | Encryption completed"
    else
        echo "ERROR     | Encryption failed"
    fi
    
    # Run signing command
    if eval "$SIGN_CMD 2>/dev/null"; then
        echo "SIGN      | File signed successfully"
    else
        echo "ERROR     | Signing failed"
    fi

    # Copy the shared secret if this is ECDH
    if [[ "$PROTOCOL" == "ECDH-ChaCha20" && -f "shared_secret.bin" ]]; then
        cp "shared_secret.bin" "$OUTPUT_DIR/${OUTPUT_PREFIX}_shared_secret.bin"
        echo "COPY      | Shared secret copied to $OUTPUT_DIR/${OUTPUT_PREFIX}_shared_secret.bin"
    fi
    
    sleep 2
}

# AES-128
encrypt_and_sign "AES-128" \
"openssl enc -aes-128-cbc -pbkdf2 -in $FIRMWARE_PATH -out $OUTPUT_DIR/aes-128_${FIRMWARE_NAME}.enc -k 'SecureKey'" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out $OUTPUT_DIR/aes-128_${FIRMWARE_NAME}.sig $OUTPUT_DIR/aes-128_${FIRMWARE_NAME}.enc" \
"aes-128"

# ChaCha20
encrypt_and_sign "ChaCha20" \
"openssl enc -chacha20 -pbkdf2 -in $FIRMWARE_PATH -out $OUTPUT_DIR/chacha20_${FIRMWARE_NAME}.enc -k 'SecureKey'" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out $OUTPUT_DIR/chacha20_${FIRMWARE_NAME}.sig $OUTPUT_DIR/chacha20_${FIRMWARE_NAME}.enc" \
"chacha20"

# ECDSA with SHA-256
encrypt_and_sign "ECDSA-SHA256" \
"cp $FIRMWARE_PATH $OUTPUT_DIR/ecdsa_${FIRMWARE_NAME}.enc" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out $OUTPUT_DIR/ecdsa_${FIRMWARE_NAME}.sig $OUTPUT_DIR/ecdsa_${FIRMWARE_NAME}.enc" \
"ecdsa"

# Ed25519
encrypt_and_sign "Ed25519" \
"cp $FIRMWARE_PATH $OUTPUT_DIR/ed25519_${FIRMWARE_NAME}.enc" \
"openssl pkeyutl -sign -inkey $ED25519_PRIVATE -rawin -in $OUTPUT_DIR/ed25519_${FIRMWARE_NAME}.enc -out $OUTPUT_DIR/ed25519_${FIRMWARE_NAME}.sig" \
"ed25519"

# ECDH + ChaCha20
echo ""
echo "DERIVE    | Generating ECDH shared secret..."
openssl pkeyutl -derive -inkey $ECDH_PRIVATE -peerkey $ECDH_PUBLIC -out "$OUTPUT_DIR/ecdh_shared_secret.bin" 2>/dev/null
echo "ENCRYPT   | Using ECDH shared secret with ChaCha20 encryption..."

encrypt_and_sign "ECDH-ChaCha20" \
"openssl enc -chacha20 -pbkdf2 -in $FIRMWARE_PATH -out $OUTPUT_DIR/ecdh_${FIRMWARE_NAME}.enc -pass file:$OUTPUT_DIR/ecdh_shared_secret.bin" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out $OUTPUT_DIR/ecdh_${FIRMWARE_NAME}.sig $OUTPUT_DIR/ecdh_${FIRMWARE_NAME}.enc" \
"ecdh"

echo ""
echo "SUCCESS   | Encryption complete. Files saved to $OUTPUT_DIR"