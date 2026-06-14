#!/bin/bash
#
# run_handshake.sh
#
# Builds and starts the wpa2_ap and wpa2_client containers, captures the
# WPA2 4-way handshake to shared/capture.pcap, prints the AP logs, and then
# tears the containers down.
#
# Prerequisites: ./setup_interfaces.sh must have been run first.
#
set -e

cd "$(dirname "$0")/.."

echo "[*] Caching sudo credentials..."
sudo -v

echo "[*] Building containers..."
docker-compose build

echo "[*] Starting tcpdump capture on hwsim0..."
sudo tcpdump -i hwsim0 -w shared/capture.pcap "ether proto 0x888e" &
TCPDUMP_PID=$!
sleep 2

echo "[*] Starting AP and client containers..."
docker-compose up -d

echo "[*] Waiting for handshake to complete (20s)..."
sleep 20

echo ""
echo "===================== AP LOGS ====================="
docker logs wpa2_ap
echo "====================================================="

echo "[*] Stopping capture and containers..."
sudo kill -SIGINT $TCPDUMP_PID 2>/dev/null || true
sleep 1
docker-compose down

echo "[*] Fixing capture file permissions..."
sudo chmod 644 shared/capture.pcap

COUNT=$(tcpdump -r shared/capture.pcap -nn 2>/dev/null | grep -c "EAPOL" || true)
echo ""
echo "[+] Captured $COUNT EAPOL frames (expected: 4)"
echo "[+] Capture saved to shared/capture.pcap"
echo "[+] Run 'python3 scripts/analyzer.py' to verify the handshake cryptographically."
