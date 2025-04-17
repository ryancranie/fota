#!/bin/bash

LISTEN_PORT=9999
CSV_FILE="fota_metrics.csv"

# Setup CSV logging
if [[ ! -f "$CSV_FILE" ]]; then
    echo "Timestamp,Firmware,FileSize(KB),VerificationResult,DecryptionTime(s),CPU(%),Memory(MB)" > "$CSV_FILE"
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
    
    # Get file size in KB
    FILE_SIZE=$(du -k "$FILENAME" | cut -f1)

    echo "Verifying signature..."
    VERIFICATION="PASS"
    openssl dgst -sha256 -verify ecdsa_public.pem -signature ${FILENAME%.enc}.sig "$FILENAME" 2>/dev/null || {
        echo "Signature verification failed."
        VERIFICATION="FAIL"
    }

    if [[ "$VERIFICATION" == "FAIL" ]]; then
        echo "Update rejected."
        continue
    fi

    echo "Starting decryption..."
    
    # Capture process stats before decryption
    CPU_START=$(ps -p $$ -o %cpu= | tr -d ' ')
    MEM_START=$(ps -p $$ -o rss= | awk '{print $1/1024}')
    
    START=$(date +%s.%N)
    DECRYPTED="decrypted_${FILENAME%.enc}.bin"
    
    # Use pbkdf2 to avoid warnings and suppress any remaining warnings
    openssl enc -d -aes-128-cbc -pbkdf2 -in "$FILENAME" -out "$DECRYPTED" -k "SecureKey" 2>/dev/null
    
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)
    
    # Capture process stats after decryption
    CPU_END=$(ps -p $$ -o %cpu= | tr -d ' ')
    MEM_END=$(ps -p $$ -o rss= | awk '{print $1/1024}')
    
    # Calculate difference
    CPU_DIFF=$(echo "$CPU_END - $CPU_START" | bc)
    MEM_DIFF=$(echo "$MEM_END - $MEM_START" | bc)
    
    # If difference is negative, use small positive value
    CPU=$(echo "$CPU_DIFF < 0" | bc) && CPU=0.1 || CPU=$CPU_DIFF
    MEM=$(echo "$MEM_DIFF < 0" | bc) && MEM=0.1 || MEM=$MEM_DIFF
    
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

    echo "$TIMESTAMP,$FILENAME,$FILE_SIZE,$VERIFICATION,$(printf '%.2f' "$DURATION"),$CPU,$MEM" >> "$CSV_FILE"
    echo "Update complete and logged to $CSV_FILE"
done
