#!/bin/bash

# Prompt for firmware path
read -p "Enter the full path to the firmware file (e.g. /home/user/firmware_v1.bin): " FIRMWARE_PATH
if [[ ! -f "$FIRMWARE_PATH" ]]; then
    echo "Error: File not found!"
    exit 1
fi

FIRMWARE_NAME=$(basename "$FIRMWARE_PATH" .bin)
DIR=$(dirname "$FIRMWARE_PATH")
cd "$DIR"

# Get file size in KB
FILE_SIZE=$(du -k "$FIRMWARE_PATH" | cut -f1)

# Setup CSV logging
CSV_FILE="encrypt_metrics.csv"
if [[ ! -f "$CSV_FILE" ]]; then
    echo "Timestamp,Protocol,Firmware,FileSize(KB),EncryptionTime(s),CPU(%),Memory(MB)" > "$CSV_FILE"
fi

# Key paths
ECDSA_PRIVATE="ecdsa_private.pem"
ECDSA_PUBLIC="ecdsa_public.pem"
ED25519_PRIVATE="ed25519_private.pem"
ED25519_PUBLIC="ed25519_public.pem"
ECDH_PRIVATE="ecdh_private.pem"
ECDH_PUBLIC="ecdh_public.pem"

# Helper function to log metrics
log_metrics() {
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$TIMESTAMP,$1,$FIRMWARE_NAME,$FILE_SIZE,$2,$3,$4" >> "$CSV_FILE"
}

# Helper function to measure and output resource usage
encrypt_and_sign() {
    local PROTOCOL=$1
    local ENC_CMD=$2
    local SIGN_CMD=$3

    echo ""
    echo "Encrypting with $PROTOCOL..."
    
    # Capture CPU and memory before encryption
    CPU_START=$(ps -p $$ -o %cpu= | tr -d ' ')
    MEM_START=$(ps -p $$ -o rss= | awk '{print $1/1024}')
    
    START=$(date +%s.%N)

    # Redirect stderr to /dev/null to suppress warnings
    eval "$ENC_CMD 2>/dev/null"
    eval "$SIGN_CMD 2>/dev/null"

    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)
    
    # Capture CPU and memory after encryption
    CPU_END=$(ps -p $$ -o %cpu= | tr -d ' ')
    MEM_END=$(ps -p $$ -o rss= | awk '{print $1/1024}')
    
    # Calculate difference
    CPU_DIFF=$(echo "$CPU_END - $CPU_START" | bc)
    MEM_DIFF=$(echo "$MEM_END - $MEM_START" | bc)
    
    # If difference is negative, use small positive value
    CPU=$(echo "$CPU_DIFF < 0" | bc) && CPU=0.1 || CPU=$CPU_DIFF
    MEM=$(echo "$MEM_DIFF < 0" | bc) && MEM=0.1 || MEM=$MEM_DIFF

    echo "$PROTOCOL completed in $(printf '%.2f' "$DURATION")s | CPU: ${CPU}% | Mem: ${MEM}MB"
    log_metrics "$PROTOCOL" "$(printf '%.2f' "$DURATION")" "$CPU" "$MEM"
    sleep 5
}

# AES-128
encrypt_and_sign "AES-128" \
"openssl enc -aes-128-cbc -pbkdf2 -in $FIRMWARE_NAME.bin -out aes-128_${FIRMWARE_NAME}.enc -k 'SecureKey'" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out aes-128_${FIRMWARE_NAME}.sig aes-128_${FIRMWARE_NAME}.enc"

# ChaCha20
encrypt_and_sign "ChaCha20" \
"openssl enc -chacha20 -pbkdf2 -in $FIRMWARE_NAME.bin -out chacha20_${FIRMWARE_NAME}.enc -k 'SecureKey'" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out chacha20_${FIRMWARE_NAME}.sig chacha20_${FIRMWARE_NAME}.enc"

# ECDSA with SHA-256
encrypt_and_sign "ECDSA" \
"cp $FIRMWARE_NAME.bin ecdsa_${FIRMWARE_NAME}.enc" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out ecdsa_${FIRMWARE_NAME}.sig ecdsa_${FIRMWARE_NAME}.enc"

# Ed25519
encrypt_and_sign "Ed25519" \
"cp $FIRMWARE_NAME.bin ed25519_${FIRMWARE_NAME}.enc" \
"openssl pkeyutl -sign -inkey $ED25519_PRIVATE -rawin -in ed25519_${FIRMWARE_NAME}.enc -out ed25519_${FIRMWARE_NAME}.sig"

# ECDH + ChaCha20
openssl pkeyutl -derive -inkey $ECDH_PRIVATE -peerkey $ECDH_PUBLIC -out shared_secret.bin 2>/dev/null
encrypt_and_sign "ECDH-ChaCha20" \
"openssl enc -chacha20 -pbkdf2 -in $FIRMWARE_NAME.bin -out ecdh_${FIRMWARE_NAME}.enc -pass file:shared_secret.bin" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out ecdh_${FIRMWARE_NAME}.sig ecdh_${FIRMWARE_NAME}.enc"

echo "Encryption complete. Metrics saved to $CSV_FILE"
