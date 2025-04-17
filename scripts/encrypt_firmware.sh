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

# Setup CSV logging
CSV_FILE="encrypt_metrics.csv"
if [[ ! -f "$CSV_FILE" ]]; then
    echo "Timestamp,Protocol,Firmware,EncryptionTime(s),CPU(%),Memory(MB)" > "$CSV_FILE"
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
    echo "$TIMESTAMP,$1,$FIRMWARE_NAME,$2,$3,$4" >> "$CSV_FILE"
}

# Helper function to measure and output resource usage
encrypt_and_sign() {
    local PROTOCOL=$1
    local ENC_CMD=$2
    local SIGN_CMD=$3

    echo ""
    echo "Encrypting with $PROTOCOL..."
    START=$(date +%s.%N)

    eval "$ENC_CMD"
    eval "$SIGN_CMD"

    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)

    MEM=$(free -m | awk '/Mem:/ {print $3}')
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')

    echo "$PROTOCOL completed in $(printf '%.2f' "$DURATION")s | CPU: ${CPU}% | Mem: ${MEM}MB"
    log_metrics "$PROTOCOL" "$(printf '%.2f' "$DURATION")" "$CPU" "$MEM"
    sleep 5
}

# AES-128
encrypt_and_sign "AES-128" \
"openssl enc -aes-128-cbc -salt -in $FIRMWARE_NAME.bin -out aes-128_${FIRMWARE_NAME}.enc -k 'SecureKey'" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out aes-128_${FIRMWARE_NAME}.sig aes-128_${FIRMWARE_NAME}.enc"

# ChaCha20
encrypt_and_sign "ChaCha20" \
"openssl enc -chacha20 -salt -in $FIRMWARE_NAME.bin -out chacha20_${FIRMWARE_NAME}.enc -k 'SecureKey'" \
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
openssl pkeyutl -derive -inkey $ECDH_PRIVATE -peerkey $ECDH_PUBLIC -out shared_secret.bin
encrypt_and_sign "ECDH-ChaCha20" \
"openssl enc -chacha20 -in $FIRMWARE_NAME.bin -out ecdh_${FIRMWARE_NAME}.enc -pass file:shared_secret.bin" \
"openssl dgst -sha256 -sign $ECDSA_PRIVATE -out ecdh_${FIRMWARE_NAME}.sig ecdh_${FIRMWARE_NAME}.enc"

echo "Encryption complete. Metrics saved to $CSV_FILE"
