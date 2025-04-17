#!/bin/bash
# Script 2: upload_firmware.sh (Run on FOTA Server)

UPLOAD_DIR="/var/www/html/firmware"
ARCHIVE_DIR="firmware_uploaded"
mkdir -p "$ARCHIVE_DIR"

cd "$(dirname "$0")"
echo "\nAvailable firmware files to upload:"
select fw in *.enc; do
  if [[ -n "$fw" ]]; then
    echo "Uploading: $fw"
    cp "$fw" "$UPLOAD_DIR/"
    cp "$fw" "$ARCHIVE_DIR/"

    SIG_FILE="${fw%.enc}.sig"
    if [ -f "$SIG_FILE" ]; then
      cp "$SIG_FILE" "$UPLOAD_DIR/"
      cp "$SIG_FILE" "$ARCHIVE_DIR/"
    fi

    echo "$fw" > notify.txt
    nc -u -w1 192.168.0.101 9999 < notify.txt
    echo "Firmware $fw uploaded and notification sent."
    break
  else
    echo "Invalid selection"
  fi
done