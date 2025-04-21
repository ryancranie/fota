#!/bin/bash
# Script for our IoT deivce to run and listen for firmware updates

LISTEN_PORT=9999
CSV_FILE="fota_metrics.csv"
DOWNLOAD_DIR="downloaded_firmware"
TRUSTED_KEYS_DIR="/mnt/hgfs/firmware/trusted_keys"  # Directory with trusted public keys
mkdir -p "$DOWNLOAD_DIR"

# Check for required trusted keys before starting
echo "SETUP     | Checking for required trusted keys..."
MISSING_KEYS=false

if [ ! -f "$TRUSTED_KEYS_DIR/ecdsa_public.pem" ]; then
    echo "ERROR     | Missing trusted key: $TRUSTED_KEYS_DIR/ecdsa_public.pem"
    MISSING_KEYS=true
fi

if [ ! -f "$TRUSTED_KEYS_DIR/ed25519_public.pem" ]; then
    echo "ERROR     | Missing trusted key: $TRUSTED_KEYS_DIR/ed25519_public.pem"
    MISSING_KEYS=true
fi

if [ ! -f "$TRUSTED_KEYS_DIR/ecdh_public.pem" ]; then
    echo "ERROR     | Missing trusted key: $TRUSTED_KEYS_DIR/ecdh_public.pem"
    MISSING_KEYS=true
fi

if [ "$MISSING_KEYS" = true ]; then
    echo "ERROR     | No public keys found in $TRUSTED_KEYS_DIR. Exiting..."
    exit 1
fi

echo "VERIFIED  | All required trusted keys found in $TRUSTED_KEYS_DIR"

# Setup CSV logging
if [[ ! -f "$CSV_FILE" ]]; then
    echo "SETUP     | Creating metrics file $CSV_FILE"
    echo "Timestamp,Firmware,FileSize(KB),SenderIP,VerificationResult,DecryptionTime(s),TotalTime(s),CPU(%),Memory(MB),RejectionReason" > "$CSV_FILE"
fi

echo ""
echo "==========================================================="
echo ""
echo "LISTENING | Waiting for SecFOTA updates over port $LISTEN_PORT..."

# Create a temporary file for firmware data
TMP_DATA="/tmp/firmware_data"

while true; do
    # Use netcat in the background and give it time to fully receive data
    nc -l -u -p $LISTEN_PORT > "$TMP_DATA" &
    NC_PID=$!
    
    # Wait a short time to ensure nc has a chance to receive data
    sleep 2
    
    # Check if we have data
    if [[ -s "$TMP_DATA" ]]; then
        # Kill nc since we've received our data
        kill $NC_PID 2>/dev/null
        wait $NC_PID 2>/dev/null
        
        # Parse the message to get filename and sender IP
        MESSAGE=$(cat "$TMP_DATA" | tr -d '\r\n')
        FILENAME=$(echo "$MESSAGE" | cut -d'|' -f1)
        SENDER_IP=$(echo "$MESSAGE" | cut -d'|' -f2)
        
        echo ""
        echo "FOUND     | Firmware update available! $FILENAME from $SENDER_IP"
        read -p "USER      | Press Enter to download and install..."
        
        # Start total time measurement when user confirms installation
        TOTAL_START=$(date +%s.%N)
        
        echo ""
        echo "DL_SERVER | Downloading firmware from $SENDER_IP"
        cd "$DOWNLOAD_DIR"
        
        # Check file timestamp to prevent replay attacks BEFORE downloading the file
        echo "CHECKING  | Verifying firmware timestamp"
        HTTP_DATE=$(curl -s -I "http://$SENDER_IP/firmware/$FILENAME" | grep -i "last-modified:" | cut -d' ' -f2-)
        
        if [ -n "$HTTP_DATE" ]; then
            HTTP_TIMESTAMP=$(date -d "$HTTP_DATE" +%s 2>/dev/null)
            CURRENT_TIMESTAMP=$(date +%s)
            TIME_DIFF=$((CURRENT_TIMESTAMP - HTTP_TIMESTAMP))
            
            # If file is more than 1 hour old (3600 seconds)
            if [ $TIME_DIFF -gt 3600 ]; then
                echo "REJECT    | Firmware file is over 1 hour old (potential replay attack)"
                echo "REJECT    | File timestamp: $(date -d @$HTTP_TIMESTAMP)"
                echo "REJECT    | Current time: $(date)"
                
                # Log the rejection without file size (file not downloaded yet)
                TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
                echo "$TIMESTAMP,$FILENAME,0,$SENDER_IP,REJECT,0,0,0,0,REPLAY_ATTACK" >> "../$CSV_FILE"
                
                cd - > /dev/null
                echo ""
                echo "==========================================================="
                echo ""
                echo "LISTENING | Waiting for SecFOTA updates over port $LISTEN_PORT..."
                continue
            fi
        else
            # Reject if we can't verify the timestamp
            echo "REJECT    | Cannot verify firmware timestamp, rejecting update"
            
            # Log the rejection
            TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
            echo "$TIMESTAMP,$FILENAME,0,$SENDER_IP,REJECT,0,0,0,0,TIMESTAMP_UNAVAILABLE" >> "../$CSV_FILE"
            
            cd - > /dev/null
            echo ""
            echo "==========================================================="
            echo ""
            echo "LISTENING | Waiting for SecFOTA updates over port $LISTEN_PORT..."
            continue
        fi
        
        # Download the firmware file
        echo "DL_FILE   | Downloading main firmware file $FILENAME"
        curl -s -O "http://$SENDER_IP/firmware/$FILENAME"
        
        # Extract protocol prefix from filename
        PROTOCOL_PREFIX=$(echo "$FILENAME" | cut -d'_' -f1)
        echo "PROTOCOL  | $PROTOCOL_PREFIX detected"
        
        # Get file size in KB
        FILE_SIZE=$(du -k "$FILENAME" | cut -f1)
        VERIFICATION="PASS"  # Default value
        REJECTION_REASON=""
        
        # Process based on protocol type
        case "$PROTOCOL_PREFIX" in
            "aes-128")
                echo "INFO      | AES-128 encryption detected (no signature verification required)"
                echo "WARNING   | AES-128 is vulnerable to MITM attacks"
                ;;
                
            "chacha20")
                echo "INFO      | ChaCha20 encryption detected (no signature verification required)"
                echo "WARNING   | ChaCha20 is vulnerable to MITM attacks"
                ;;
                
            "ecdsa")
                echo "TEST      | Testing ECDSA with SHA-256 signature verification..."
                # Download signature file only
                SIG_FILE="${FILENAME%.enc}.sig"
                curl -s -O "http://$SENDER_IP/firmware/$SIG_FILE"
                
                # Verify signature using trusted key
                if openssl dgst -sha256 -verify "$TRUSTED_KEYS_DIR/ecdsa_public.pem" -signature "$SIG_FILE" "$FILENAME" 2>/dev/null; then
                    echo "VERIFIED  | ECDSA signature verification successful!"
                    
                    # Check for firmware downgrade (simplified example - extract version from filename)
                    # This assumes firmware filenames contain version information like "firmware_v2.bin"
                    CURRENT_VERSION=$(ls -1 .. | grep -o "ecdsa_.*_v[0-9]\+\.enc" | sort -V | tail -1 | grep -o "v[0-9]\+")
                    NEW_VERSION=$(echo "$FILENAME" | grep -o "v[0-9]\+")
                    
                    if [ -n "$CURRENT_VERSION" ] && [ -n "$NEW_VERSION" ]; then
                        # Extract numeric part of version
                        CURRENT_NUM=$(echo "$CURRENT_VERSION" | grep -o "[0-9]\+")
                        NEW_NUM=$(echo "$NEW_VERSION" | grep -o "[0-9]\+")
                        
                        if [ "$NEW_NUM" -lt "$CURRENT_NUM" ]; then
                            echo "REJECT    | Downgrade attack detected! Current: $CURRENT_VERSION, New: $NEW_VERSION"
                            VERIFICATION="FAIL"
                            REJECTION_REASON="DOWNGRADE_ATTACK"
                        fi
                    fi
                else
                    echo "ERROR     | ECDSA signature verification failed."
                    VERIFICATION="FAIL"
                    REJECTION_REASON="INVALID_SIGNATURE"
                fi
                ;;
                
            "ed25519")
                echo "TEST      | Testing Ed25519 signature verification..."
                # Download signature file only
                SIG_FILE="${FILENAME%.enc}.sig"
                curl -s -O "http://$SENDER_IP/firmware/$SIG_FILE"
                
                # Use the proper verification method for rawin signature with trusted key
                if openssl pkeyutl -verify -pubin -inkey "$TRUSTED_KEYS_DIR/ed25519_public.pem" -sigfile "$SIG_FILE" -rawin -in "$FILENAME" 2>/dev/null; then
                    echo "VERIFIED  | Ed25519 signature verification successful!"
                    
                    # Check for firmware downgrade
                    CURRENT_VERSION=$(ls -1 .. | grep -o "ed25519_.*_v[0-9]\+\.enc" | sort -V | tail -1 | grep -o "v[0-9]\+")
                    NEW_VERSION=$(echo "$FILENAME" | grep -o "v[0-9]\+")
                    
                    if [ -n "$CURRENT_VERSION" ] && [ -n "$NEW_VERSION" ]; then
                        # Extract numeric part of version
                        CURRENT_NUM=$(echo "$CURRENT_VERSION" | grep -o "[0-9]\+")
                        NEW_NUM=$(echo "$NEW_VERSION" | grep -o "[0-9]\+")
                        
                        if [ "$NEW_NUM" -lt "$CURRENT_NUM" ]; then
                            echo "REJECT    | Downgrade attack detected! Current: $CURRENT_VERSION, New: $NEW_VERSION"
                            VERIFICATION="FAIL"
                            REJECTION_REASON="DOWNGRADE_ATTACK"
                        fi
                    fi
                else
                    echo "ERROR     | Ed25519 signature verification failed."
                    VERIFICATION="FAIL"
                    REJECTION_REASON="INVALID_SIGNATURE"
                fi
                ;;
                
            "ecdh")
                echo "TEST      | Testing ECDH key exchange with ChaCha20 encryption..."
                # Download shared secret
                curl -s -O "http://$SENDER_IP/firmware/ecdh_shared_secret.bin"
                
                # Download signature file for verification
                SIG_FILE="${FILENAME%.enc}.sig"
                curl -s -O "http://$SENDER_IP/firmware/$SIG_FILE"
                
                # Verify signature if it exists using trusted key
                if [ -f "$SIG_FILE" ]; then
                    if openssl dgst -sha256 -verify "$TRUSTED_KEYS_DIR/ecdsa_public.pem" -signature "$SIG_FILE" "$FILENAME" 2>/dev/null; then
                        echo "VERIFIED  | ECDH-ChaCha20 signature verification successful!"
                        
                        # Check for firmware downgrade
                        CURRENT_VERSION=$(ls -1 .. | grep -o "ecdh_.*_v[0-9]\+\.enc" | sort -V | tail -1 | grep -o "v[0-9]\+")
                        NEW_VERSION=$(echo "$FILENAME" | grep -o "v[0-9]\+")
                        
                        if [ -n "$CURRENT_VERSION" ] && [ -n "$NEW_VERSION" ]; then
                            # Extract numeric part of version
                            CURRENT_NUM=$(echo "$CURRENT_VERSION" | grep -o "[0-9]\+")
                            NEW_NUM=$(echo "$NEW_VERSION" | grep -o "[0-9]\+")
                            
                            if [ "$NEW_NUM" -lt "$CURRENT_NUM" ]; then
                                echo "REJECT    | Downgrade attack detected! Current: $CURRENT_VERSION, New: $NEW_VERSION"
                                VERIFICATION="FAIL"
                                REJECTION_REASON="DOWNGRADE_ATTACK"
                            fi
                        fi
                    else
                        echo "ERROR     | ECDH-ChaCha20 signature verification failed."
                        VERIFICATION="FAIL"
                        REJECTION_REASON="INVALID_SIGNATURE"
                    fi
                else
                    echo "WARNING   | No signature file found for ECDH verification."
                fi
                ;;
                
            *)
                echo "ERROR     | Unknown protocol prefix: $PROTOCOL_PREFIX"
                cd - > /dev/null
                continue
                ;;
        esac

        # If verification failed for signature-based protocols
        if [[ "$VERIFICATION" == "FAIL" ]]; then
            echo "REJECT    | Security checks failed. Update rejected. Reason: $REJECTION_REASON"
            
            # Log rejection to CSV
            TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
            echo "$TIMESTAMP,$FILENAME,$FILE_SIZE,$SENDER_IP,$VERIFICATION,0,0,0,0,$REJECTION_REASON" >> "../$CSV_FILE"
            
            cd - > /dev/null
            echo ""
            echo "==============================================================="
            echo ""
            echo "LISTENING | Waiting for SecFOTA updates over port $LISTEN_PORT..."
            continue
        fi
        
        echo "PASSED    | Security checks passed"
        
        # Create a monitoring file
        MONITOR_FILE=$(mktemp)
        
        START=$(date +%s.%N)
        DECRYPTED="decrypted_${FILENAME%.enc}.bin"
        
        # Prepare the decryption command based on protocol
        case "$PROTOCOL_PREFIX" in
            "aes-128")
                echo "DECRYPT   | Decrypting with AES-128-CBC..."
                DECRYPT_CMD="openssl enc -d -aes-128-cbc -pbkdf2 -in \"$FILENAME\" -out \"$DECRYPTED\" -k \"SecureKey\""
                ;;
                
            "chacha20")
                echo "DECRYPT   | Decrypting with ChaCha20..."
                DECRYPT_CMD="openssl enc -d -chacha20 -pbkdf2 -in \"$FILENAME\" -out \"$DECRYPTED\" -k \"SecureKey\""
                ;;
                
            "ecdsa")
                echo "COPY      | Copying files from ECDSA-SHA256..."
                DECRYPT_CMD="cp \"$FILENAME\" \"$DECRYPTED\""
                ;;
                
            "ed25519")
                echo "COPY      | Copying files from Ed25519..."
                DECRYPT_CMD="cp \"$FILENAME\" \"$DECRYPTED\""
                ;;
                
            "ecdh")
                echo "DECRYPT   | Decrypting with ChaCha20 using ECDH shared secret..."
                DECRYPT_CMD="openssl enc -d -chacha20 -pbkdf2 -in \"$FILENAME\" -out \"$DECRYPTED\" -pass file:ecdh_shared_secret.bin"
                ;;
        esac

        # Run the decryption command in background and capture its PID
        eval "$DECRYPT_CMD 2>/dev/null" &
        DECRYPT_PID=$!
        
        # Start background monitoring process with improved process tree monitoring
        ( while kill -0 $DECRYPT_PID 2>/dev/null; do
            # Get process group - all processes related to our decrypt command
            # First get the main process and all its children
            PIDS=$DECRYPT_PID
            CHILDREN=$(pgrep -P $DECRYPT_PID 2>/dev/null)
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
            sleep 0.2
        done ) &
        MONITOR_PID=$!
        
        # Wait for decryption to complete
        wait $DECRYPT_PID
        
        END=$(date +%s.%N)
        DURATION=$(echo "$END - $START" | bc)
        
        # Stop the monitoring
        kill $MONITOR_PID 2>/dev/null
        wait $MONITOR_PID 2>/dev/null
        
        # Check if decryption succeeded
        if [[ ! -f "$DECRYPTED" || ! -s "$DECRYPTED" ]]; then
            echo "ERROR     | Decryption/processing failed! Output file not created or empty."
            cd - > /dev/null
            echo ""
            echo "==========================================================="
            echo ""
            echo "LISTENING | Waiting for SecFOTA updates over port $LISTEN_PORT..."
            continue
        fi
        
        echo "SUCCESS   | Decryption/Processing completed successfully!"
        
        # Calculate total processing time
        TOTAL_END=$(date +%s.%N)
        TOTAL_DURATION=$(echo "$TOTAL_END - $TOTAL_START" | bc)
        
        # Calculate average and peak values from monitoring file
        if [[ -s "$MONITOR_FILE" ]]; then
            CPU_AVG=$(awk -F, '{sum+=$2; count++} END {print (count>0)?(sum/count):0}' "$MONITOR_FILE")
            CPU_PEAK=$(awk -F, 'BEGIN {max=0} {if($2>max) max=$2} END {print max}' "$MONITOR_FILE")
            MEM_AVG=$(awk -F, '{sum+=$3; count++} END {print (count>0)?(sum/count):0}' "$MONITOR_FILE")
            MEM_PEAK=$(awk -F, 'BEGIN {max=0} {if($3>max) max=$3} END {print max}' "$MONITOR_FILE")
            
            # Use these values
            CPU_USAGE=$(printf '%.2f' "$CPU_PEAK")
            MEM_USAGE=$(printf '%.2f' "$MEM_PEAK")
        else
            # Fallback values
            CPU_USAGE=1.0
            MEM_USAGE=1.0
        fi
        
        # Clean up
        rm -f "$MONITOR_FILE"
        
        TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
        
        cd - > /dev/null
        # CSV Log and Format
        echo "$TIMESTAMP,$FILENAME,$FILE_SIZE,$SENDER_IP,$VERIFICATION,$(printf '%.2f' "$DURATION"),$(printf '%.2f' "$TOTAL_DURATION"),$CPU_USAGE,$MEM_USAGE,$REJECTION_REASON" >> "$CSV_FILE"
        echo "LOG       | Metrics saved to $CSV_FILE"
        echo "COMPLETE  | Update process complete"
        read -p "USER      | Press Enter to listen for firmware updates..."
        echo ""
        echo "==============================================================="
        echo ""
        echo "LISTENING | Waiting for SecFOTA updates over port $LISTEN_PORT..."
        
        # Clean up temporary file
        rm -f "$TMP_DATA"
    else
        # Kill nc if it's still running but we didn't get data
        kill $NC_PID 2>/dev/null
        wait $NC_PID 2>/dev/null
    fi
    
    # Small sleep to prevent high CPU usage from busy loop
    sleep 1
done