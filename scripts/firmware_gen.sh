#!/bin/bash

# Clear screen and show header
clear
echo "====================================="
echo "     Smart IoT Firmware Generator    "
echo "====================================="
echo ""

# Prompt user for IoT device name
read -p "What IoT device is this firmware for? " IOT_NAME

# Validate input - ensure IoT name is provided
if [[ -z "$IOT_NAME" ]]; then
    echo "ERROR: IoT device name cannot be empty"
    exit 1
fi

# Prompt user for firmware size in MB
read -p "What size (MB) would you like this firmware? " FIRMWARE_SIZE

# Validate input - ensure size is a positive number
if ! [[ "$FIRMWARE_SIZE" =~ ^[0-9]+$ ]]; then
    echo "ERROR: Size must be a positive integer"
    exit 1
fi

if [[ "$FIRMWARE_SIZE" -le 0 ]]; then
    echo "ERROR: Size must be greater than 0"
    exit 1
fi

# Calculate bytes needed
BYTES_NEEDED=$((FIRMWARE_SIZE * 1024 * 1024))
FIRMWARE_FILE="${IOT_NAME}.bin"

echo ""
echo "Generating firmware file: $FIRMWARE_FILE"
echo "Target size: $FIRMWARE_SIZE MB ($BYTES_NEEDED bytes)"
echo ""

# Create content pattern (12 repetitions of IoT name per row with pipes between)
PATTERN=""
for i in {1..12}; do
    if [[ $i -eq 12 ]]; then
        PATTERN+="${IOT_NAME}"
    else
        PATTERN+="${IOT_NAME}|"
    fi
done

# Initialize an empty file
> "$FIRMWARE_FILE"

# Show progress bar
echo -ne "Progress: [                    ] 0%\r"
PROGRESS_WIDTH=20

# Calculate how much data to write in each chunk (1MB chunks)
CHUNK_SIZE=$((1024 * 1024))  # 1MB chunks for better performance
PATTERN_SIZE=$((${#PATTERN} + 1))  # +1 for newline
PATTERNS_PER_CHUNK=$((CHUNK_SIZE / PATTERN_SIZE))

# Create a temporary chunk file with repeated patterns
TEMP_CHUNK=$(mktemp)
for ((i=0; i<PATTERNS_PER_CHUNK; i++)); do
    echo -e -n "$PATTERN" >> "$TEMP_CHUNK"
done

# Get actual chunk size
ACTUAL_CHUNK_SIZE=$(stat -c%s "$TEMP_CHUNK")

# Calculate how many full chunks we need
FULL_CHUNKS=$((BYTES_NEEDED / ACTUAL_CHUNK_SIZE))
REMAINING_BYTES=$((BYTES_NEEDED % ACTUAL_CHUNK_SIZE))

# Write the file in chunks
CURRENT_SIZE=0
for ((i=0; i<FULL_CHUNKS; i++)); do
    cat "$TEMP_CHUNK" >> "$FIRMWARE_FILE"
    CURRENT_SIZE=$((CURRENT_SIZE + ACTUAL_CHUNK_SIZE))
    
    # Update progress bar
    PERCENTAGE=$((CURRENT_SIZE * 100 / BYTES_NEEDED))
    FILLED_SLOTS=$((PERCENTAGE * PROGRESS_WIDTH / 100))
    EMPTY_SLOTS=$((PROGRESS_WIDTH - FILLED_SLOTS))
    
    PROGRESS_BAR="["
    for ((j=0; j<FILLED_SLOTS; j++)); do
        PROGRESS_BAR+="#"
    done
    
    for ((j=0; j<EMPTY_SLOTS; j++)); do
        PROGRESS_BAR+=" "
    done
    
    PROGRESS_BAR+="]"
    echo -ne "Progress: $PROGRESS_BAR $PERCENTAGE%\r"
done

# Write the remaining bytes if any
if [[ $REMAINING_BYTES -gt 0 ]]; then
    # Create a temporary file for the remaining portion
    TEMP_REMAINING=$(mktemp)
    BYTES_WRITTEN=0
    
    while [[ $BYTES_WRITTEN -lt $REMAINING_BYTES ]]; do
        echo -e -n "$PATTERN" >> "$TEMP_REMAINING"
        BYTES_WRITTEN=$((BYTES_WRITTEN + PATTERN_SIZE))
    done
    
    # Trim if necessary
    if [[ $BYTES_WRITTEN -gt $REMAINING_BYTES ]]; then
        truncate -s $REMAINING_BYTES "$TEMP_REMAINING"
    fi
    
    # Append the remaining portion
    cat "$TEMP_REMAINING" >> "$FIRMWARE_FILE"
    rm "$TEMP_REMAINING"
    
    # Update progress to 100%
    echo -ne "Progress: [####################] 100%\r"
fi

# Clean up the temporary chunk file
rm "$TEMP_CHUNK"

# Get final file size for confirmation
FINAL_SIZE=$(stat -c%s "$FIRMWARE_FILE")
FINAL_SIZE_MB=$(echo "scale=2; $FINAL_SIZE / 1048576" | bc)

echo -e "\n"
echo "====================================="
echo "Firmware generation complete!"
echo "File: $FIRMWARE_FILE"
echo "Size: $FINAL_SIZE_MB MB ($FINAL_SIZE bytes)"
echo "====================================="