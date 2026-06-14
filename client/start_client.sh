#!/bin/bash

echo "[CLIENT] Starting WPA2 Client..."
echo "[CLIENT] Using interface: $IFACE"

ip link set $IFACE up

killall wpa_supplicant 2>/dev/null
sleep 1

echo "[CLIENT] Waiting for AP to be ready..."
sleep 8

echo "[CLIENT] Launching wpa_supplicant..."
sed -i "s/wlan1/$IFACE/" /etc/wpa_supplicant/wpa_supplicant.conf
wpa_supplicant -i $IFACE \
    -D nl80211 \
    -c /etc/wpa_supplicant/wpa_supplicant.conf \
    -d 2>&1 | tee /shared/client_log.txt

echo "[CLIENT] Done"
