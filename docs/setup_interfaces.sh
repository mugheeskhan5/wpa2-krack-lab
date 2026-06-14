#!/bin/bash
#
# setup_interfaces.sh
#
# Reloads the mac80211_hwsim kernel module, brings up the virtual radios
# (wlan0, wlan1, wlan2, hwsim0) and temporarily stops NetworkManager so it
# does not interfere with hostapd / wpa_supplicant on the virtual interfaces.
#
# Run this after every reboot, before run_handshake.sh or run_krack_demo.sh.
#
set -e

RADIOS=${1:-3}

echo "[*] Reloading mac80211_hwsim with $RADIOS radios..."
sudo modprobe -r mac80211_hwsim 2>/dev/null || true
sudo modprobe mac80211_hwsim radios=$RADIOS

echo "[*] Bringing up virtual interfaces..."
sudo ip link set wlan0 up
sudo ip link set wlan1 up
if [ "$RADIOS" -ge 3 ]; then
    sudo ip link set wlan2 up
fi
sudo ip link set hwsim0 up

echo "[*] Stopping NetworkManager (will not affect ethernet/internet)..."
sudo systemctl stop NetworkManager

echo "[*] Current interfaces:"
iw dev

echo ""
echo "[+] Setup complete. Re-enable NetworkManager later with:"
echo "    sudo systemctl start NetworkManager"
