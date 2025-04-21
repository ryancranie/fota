#!/bin/bash
# Script for CPU and bandwidth limitation for IoT device resource constraints simulation

# Check if run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Install dependencies if not already installed
if ! command -v cpulimit &> /dev/null || ! command -v tc &> /dev/null; then
    echo "Installing dependencies..."
    apt-get update && apt-get install -y cpulimit iproute2
fi

# Function to clean up when script exits
cleanup() {
    echo "Stopping simulation and removing limits..."
    
    # Kill any running cpulimit processes
    pkill -f cpulimit
    
    # Remove bandwidth limitations
    for INTERFACE in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
        tc qdisc del dev $INTERFACE root 2>/dev/null
    done
    
    exit 0
}

# Set trap to ensure cleanup on exit
trap cleanup SIGINT SIGTERM EXIT

# Limiting values
CPU_LIMIT=70          # 70% CPU limit
BANDWIDTH_LIMIT="1mbit"  # 1 Mbit/s bandwidth limit
TARGET_PROCESS="firmware_listener.sh"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cpu=*)
            CPU_LIMIT="${1#*=}"
            ;;
        --bandwidth=*)
            BANDWIDTH_LIMIT="${1#*=}"
            ;;
        --process=*)
            TARGET_PROCESS="${1#*=}"
            ;;
        --help)
            echo "Usage: $0 [--cpu=percent] [--bandwidth=rate] [--process=name]"
            echo "  --cpu=percent     CPU usage limit (default: 70%)"
            echo "  --bandwidth=rate  Bandwidth limit (default: 1mbit)"
            echo "  --process=name    Process to limit (default: firmware_listener.sh)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
    shift
done

echo "==== IoT Device Simulation ===="
echo "CPU Limit: $CPU_LIMIT%"
echo "Bandwidth Limit: $BANDWIDTH_LIMIT"
echo "Target Process: $TARGET_PROCESS"

# Apply bandwidth limitation to all interfaces except loopback
echo "Applying bandwidth limitations..."
for INTERFACE in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
    # Remove any existing traffic control settings
    tc qdisc del dev $INTERFACE root 2>/dev/null
    
    # Add bandwidth limit
    tc qdisc add dev $INTERFACE root tbf rate $BANDWIDTH_LIMIT burst 32kbit latency 400ms
    echo "Limited $INTERFACE to $BANDWIDTH_LIMIT"
done

# Function to continuously monitor and limit CPU usage
monitor_and_limit_cpu() {
    local process_name="$1"
    local cpu_limit="$2"
    
    while true; do
        # Find the process ID
        PID=$(pgrep -f "$process_name")
        
        if [ -n "$PID" ]; then
            # Check if cpulimit is already running for this PID
            if ! pgrep -f "cpulimit -p $PID" > /dev/null; then
                echo "Limiting process $process_name (PID: $PID) to $cpu_limit% CPU usage"
                cpulimit -p $PID -l $cpu_limit -b
            fi
        else
            echo "Process $process_name not found. Waiting..."
        fi
        
        # Check every 10 seconds
        sleep 10
    done
}

# Start CPU monitoring in background
monitor_and_limit_cpu "$TARGET_PROCESS" "$CPU_LIMIT" &

echo "IoT device simulation active. Press Ctrl+C to stop."

# Keep script running
while true; do
    sleep 60
    echo "IoT simulation running ($(date))"
done
