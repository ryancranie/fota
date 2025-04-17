#!/bin/bash

LISTEN_PORT=9999
CSV_FILE="fota_metrics.csv"

# Setup CSV logging
if [[ ! -f "$CSV_FILE" ]]; then
    echo "Timestamp,Firmware,VerificationResult,DecryptionTime(s),CPU(%),Memory(MB)" > "$CSV_FILE"
fi

while true; do
    echo "Waiting for firmware update notification on port $LISTEN_PORT..."
    
    # Capture sender IP and message
    read -r -u 9 FILENAME < <(nc -klu $LISTEN_PORT 9<>/dev/udp/0.0.0.0/$LISTEN_PORT & pid=$!)
    wait $pid
    SENDER_IP=$(netstat -anu | grep ":$LISTEN_PORT" | awk '{print $5}' | cut -d: -f1 | head -n1)

    if [[ -z "$FILENAME" || -z "$SENDER_IP" ]]; then
        echo "No valid update received."
        continue
    fi

    echo "Update $FILENAME available from $SENDER_IP - Press Enter to download."
    read

    echo "Downloading firmware and signature from $SENDER_IP..."
    curl -O "http://$SENDER_IP/firmware/$FILENAME"
    curl -O "http://$SENDER_IP/firmware/${FILENAME%.enc}.sig"

    echo "Verifying signature..."
    VERIFICATION="PASS"
    openssl dgst -sha256 -verify ecdsa_public.pem -signature ${FILENAME%.enc}.sig "$FILENAME" || {
        echo "Signature verification failed."
        VERIFICATION="FAIL"
    }

    if [[ "$VERIFICATION" == "FAIL" ]]; then
        echo "Update rejected."
        continue
    fi

    echo "Starting decryption..."
    START=$(date +%s.%N)
    DECRYPTED="decrypted_${FILENAME%.enc}.bin"
    openssl enc -d -aes-128-cbc -in "$FILENAME" -out "$DECRYPTED" -k "SecureKey"
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)

    MEM=$(free -m | awk '/Mem:/ {print $3}')
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

    echo "$TIMESTAMP,$FILENAME,$VERIFICATION,$(printf '%.2f' "$DURATION"),$CPU,$MEM" >> "$CSV_FILE"
    echo "Update complete and logged to $CSV_FILE"
done
