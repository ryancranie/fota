#!/bin/bash
# Script to upload encrypted firmware from our FOTA server to the IoT device

UPLOAD_DIR="/var/www/html/firmware"

# Create directories with correct permissions
sudo mkdir -p "$UPLOAD_DIR"
sudo chmod 777 "$UPLOAD_DIR"  # Make writable by current user
echo "SETUP     | Upload directory: $UPLOAD_DIR"

# Prompt user for encryption protocol to upload
echo "SELECT    | Choose encryption protocol to upload:"
echo "           1) AES-128"
echo "           2) ChaCha20" 
echo "           3) ECDSA with SHA-256"
echo "           4) Ed25519"
echo "           5) ECDH-ChaCha20"
read -p "USER      | Enter your choice (1-5): " PROTOCOL_CHOICE

case $PROTOCOL_CHOICE in
    1) PROTOCOL_PREFIX="aes-128"; PROTOCOL_NAME="AES-128" ;;
    2) PROTOCOL_PREFIX="chacha20"; PROTOCOL_NAME="ChaCha20" ;;
    3) PROTOCOL_PREFIX="ecdsa"; PROTOCOL_NAME="ECDSA with SHA-256" ;;
    4) PROTOCOL_PREFIX="ed25519"; PROTOCOL_NAME="Ed25519" ;;
    5) PROTOCOL_PREFIX="ecdh"; PROTOCOL_NAME="ECDH-ChaCha20" ;;
    *) echo "ERROR     | Invalid choice"; exit 1 ;;
esac

echo "SELECTED  | $PROTOCOL_NAME selected"

# Prompt for encrypted firmware directory
read -p "USER      | Enter the full path to the directory containing encrypted firmware: " FIRMWARE_DIR

if [[ ! -d "$FIRMWARE_DIR" ]]; then
    echo "ERROR     | Directory not found!"
    exit 1
fi

# Get list of firmware files matching the selected protocol
FILES=($(find "$FIRMWARE_DIR" -name "${PROTOCOL_PREFIX}_*.enc"))

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "ERROR     | No $PROTOCOL_PREFIX encrypted firmware files found in the specified directory."
    exit 1
fi

echo "FOUND     | Available $PROTOCOL_PREFIX firmware files:"
select fw in "${FILES[@]}"; do
    if [[ -n "$fw" ]]; then
        FIRMWARE_NAME=$(basename "$fw")
        
        echo "UPLOAD    | Main firmware file: $FIRMWARE_NAME"
        sudo cp "$fw" "$UPLOAD_DIR/"
        sudo chmod 644 "$UPLOAD_DIR/$FIRMWARE_NAME"

        # Upload additional files based on protocol type
        case "$PROTOCOL_PREFIX" in
            "aes-128"|"chacha20")
                # Only need the encrypted firmware file for these encryption-only protocols
                echo "INFO      | Encryption-only protocol, no signature required."
                ;;
                
            "ecdsa"|"ed25519")
                # Upload signature file
                SIG_FILE="${fw%.enc}.sig"
                if [ -f "$SIG_FILE" ]; then
                    SIG_NAME=$(basename "$SIG_FILE")
                    sudo cp "$SIG_FILE" "$UPLOAD_DIR/"
                    sudo chmod 644 "$UPLOAD_DIR/$SIG_NAME"
                    echo "UPLOAD    | Signature file: $SIG_NAME"
                else
                    echo "WARNING   | Signature file not found!"
                fi
                ;;
                
            "ecdh")
                # Upload signature file first (same as other protocols)
                SIG_FILE="${fw%.enc}.sig"
                if [ -f "$SIG_FILE" ]; then
                    SIG_NAME=$(basename "$SIG_FILE")
                    sudo cp "$SIG_FILE" "$UPLOAD_DIR/"
                    sudo chmod 644 "$UPLOAD_DIR/$SIG_NAME"
                    echo "UPLOAD    | Signature file: $SIG_NAME"
                else
                    echo "WARNING   | Signature file not found!"
                fi
                
                # Upload ECDH shared secret
                SHARED_SECRET="${FIRMWARE_DIR}/ecdh_shared_secret.bin"
                if [ -f "$SHARED_SECRET" ]; then
                    sudo cp "$SHARED_SECRET" "$UPLOAD_DIR/"
                    sudo chmod 644 "$UPLOAD_DIR/$(basename "$SHARED_SECRET")"
                    echo "UPLOAD    | Shared secret file uploaded"
                else
                    echo "WARNING   | Shared secret file not found!"
                fi
                ;;
        esac

        # Get the server's IP address
        SERVER_IP=$(hostname -I | awk '{print $1}')
        TARGET_IP="192.168.1.15"  # Your IoT device IP
        
        # Send UDP 9999 notification with both firmware name and sender IP
        echo "NOTIFY    | Sending UDP notification to $TARGET_IP:9999"
        echo "${FIRMWARE_NAME}|${SERVER_IP}" | nc -u -w1 $TARGET_IP 9999
        echo "COMPLETE  | Firmware $FIRMWARE_NAME uploaded and notification sent with server IP $SERVER_IP"
        break
    else
        echo "ERROR     | Invalid selection"
    fi
done