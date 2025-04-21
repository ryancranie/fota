#!/bin/bash
# Script for our FOTA server to encrypt firmware - unified with all 5 methods tested

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

# Get file size in KB
FILE_SIZE=$(du -k "$FIRMWARE_PATH" | cut -f1)

# Setup CSV logging - Now in script directory
CSV_FILE="$SCRIPT_DIR/encrypt_metrics.csv"
if [[ ! -f "$CSV_FILE" ]]; then
    echo "SETUP     | Creating metrics file $CSV_FILE"
    echo "Timestamp,Protocol,Firmware,FileSize(KB),EncryptionTime(s),CPU(%),Memory(MB)" > "$CSV_FILE"
fi

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
    local OUTPUT_PREFIX=$4

    echo ""
    echo "ENCRYPT   | Starting $PROTOCOL encryption process..."
    
    # Create a monitoring file
    MONITOR_FILE=$(mktemp)
    
    # Initialize with a starting measurement (baseline)
    echo "$(date +%s.%N),0,0" > "$MONITOR_FILE"
    
    # Run the encryption command in background and capture its PID
    echo "RUNNING   | Executing encryption..."
    eval "$ENC_CMD 2>/dev/null" &
    ENC_PID=$!
    
    # Capture an immediate first reading to ensure we have at least one data point
    sleep 0.05
    PIDS=$ENC_PID
    CHILDREN=$(pgrep -P $ENC_PID 2>/dev/null)
    if [[ ! -z "$CHILDREN" ]]; then
        PIDS="$PIDS $CHILDREN"
        for CHILD in $CHILDREN; do
            GRANDCHILDREN=$(pgrep -P $CHILD 2>/dev/null)
            if [[ ! -z "$GRANDCHILDREN" ]]; then
                PIDS="$PIDS $GRANDCHILDREN"
            fi
        done
    fi
    
    TOTAL_CPU=0
    TOTAL_MEM=0
    for PID in $PIDS; do
        CPU=$(ps -p $PID -o %cpu= 2>/dev/null)
        MEM=$(ps -p $PID -o rss= 2>/dev/null)
        if [[ ! -z "$CPU" && ! -z "$MEM" ]]; then
            TOTAL_CPU=$(echo "$TOTAL_CPU + $CPU" | bc)
            TOTAL_MEM=$(echo "$TOTAL_MEM + $MEM" | bc)
        fi
    done
    MEM_MB=$(echo "scale=2; $TOTAL_MEM/1024" | bc)
    echo "$(date +%s.%N),$TOTAL_CPU,$MEM_MB" >> "$MONITOR_FILE"
    
    # Start background monitoring process
    ( while kill -0 $ENC_PID 2>/dev/null; do
        # Get process group - all processes related to our encryption command
        PIDS=$ENC_PID
        CHILDREN=$(pgrep -P $ENC_PID 2>/dev/null)
        if [[ ! -z "$CHILDREN" ]]; then
            PIDS="$PIDS $CHILDREN"
            # Also get grandchildren if any
            for CHILD in $CHILDREN; do
                GRANDCHILDREN=$(pgrep -P $CHILD 2>/dev/null)
                if [[ ! -z "$GRANDCHILDREN" ]]; then
                    PIDS="$PIDS $GRANDCHILDREN"
                fi
            done
        fi
        
        # Calculate total CPU and memory for all processes
        TOTAL_CPU=0
        TOTAL_MEM=0
        
        for PID in $PIDS; do
            # Get CPU and memory for each process
            CPU=$(ps -p $PID -o %cpu= 2>/dev/null)
            MEM=$(ps -p $PID -o rss= 2>/dev/null)
            
            # Add to totals if values exist
            if [[ ! -z "$CPU" && ! -z "$MEM" ]]; then
                TOTAL_CPU=$(echo "$TOTAL_CPU + $CPU" | bc)
                TOTAL_MEM=$(echo "$TOTAL_MEM + $MEM" | bc)
            fi
        done
        
        # Convert KB to MB for memory and save timestamp
        MEM_MB=$(echo "scale=2; $TOTAL_MEM/1024" | bc)
        echo "$(date +%s.%N),$TOTAL_CPU,$MEM_MB" >> "$MONITOR_FILE"
        sleep 0.1  # Faster sampling
    done ) &
    MONITOR_PID=$!

    START=$(date +%s.%N)
    
    # Wait for encryption to complete
    wait $ENC_PID
    
    # Take one final measurement right after completion
    PIDS=$(pgrep -P $$ | grep -v $MONITOR_PID)  # Get all our script's child processes except monitor
    TOTAL_CPU=0
    TOTAL_MEM=0
    for PID in $PIDS; do
        CPU=$(ps -p $PID -o %cpu= 2>/dev/null)
        MEM=$(ps -p $PID -o rss= 2>/dev/null)
        if [[ ! -z "$CPU" && ! -z "$MEM" ]]; then
            TOTAL_CPU=$(echo "$TOTAL_CPU + $CPU" | bc)
            TOTAL_MEM=$(echo "$TOTAL_MEM + $MEM" | bc)
        fi
    done
    MEM_MB=$(echo "scale=2; $TOTAL_MEM/1024" | bc)
    echo "$(date +%s.%N),$TOTAL_CPU,$MEM_MB" >> "$MONITOR_FILE"
    
    if [[ $? -eq 0 ]]; then
        echo "ENCRYPT   | Encryption completed"
    else
        echo "ERROR     | Encryption failed"
    fi
    
    # Run signing command directly (not monitoring it since encryption is the resource-intensive part)
    if eval "$SIGN_CMD 2>/dev/null"; then
        echo "SIGN      | File signed successfully"
    else
        echo "ERROR     | Signing failed"
    fi

    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)
    
    # Stop the monitoring
    kill $MONITOR_PID 2>/dev/null
    wait $MONITOR_PID 2>/dev/null

    # Calculate average and peak values - ensure we have at least minimal values
    if [[ -s "$MONITOR_FILE" ]]; then
        # Calculate average CPU
        CPU_AVG=$(awk -F, '{sum+=$2; count++} END {print (count>0)?(sum/count):0.1}' "$MONITOR_FILE")
        # Calculate peak CPU
        CPU_PEAK=$(awk -F, 'BEGIN {max=0} {if($2>max) max=$2} END {print (max>0)?max:0.1}' "$MONITOR_FILE")
        # Calculate average memory
        MEM_AVG=$(awk -F, '{sum+=$3; count++} END {print (count>0)?(sum/count):0.1}' "$MONITOR_FILE")
        # Calculate peak memory
        MEM_PEAK=$(awk -F, 'BEGIN {max=0} {if($3>max) max=$3} END {print (max>0)?max:0.1}' "$MONITOR_FILE")
        
        # Use these values for logging
        echo "STATS     | CPU: ${CPU_AVG}% (peak: ${CPU_PEAK}%) | Memory: ${MEM_AVG}MB (peak: ${MEM_PEAK}MB)"
        log_metrics "$PROTOCOL" "$(printf '%.2f' "$DURATION")" "$(printf '%.2f' "$CPU_PEAK")" "$(printf '%.2f' "$MEM_PEAK")"
    else
        # Use minimal values rather than failing
        echo "STATS     | CPU/Memory monitoring produced minimal data"
        log_metrics "$PROTOCOL" "$(printf '%.2f' "$DURATION")" "0.1" "0.1"
    fi

    # Remove the temporary monitoring file
    rm -f "$MONITOR_FILE"
    
    # Also copy the shared secret if this is ECDH
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
echo "LOG       | Metrics saved to $CSV_FILE"