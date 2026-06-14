# Reproduction Guide

Full step-by-step instructions to reproduce this lab from a clean Ubuntu 22.04
installation, including recovery steps for common errors.

---

## 1. Install Dependencies

```bash
sudo apt update && sudo apt upgrade -y

# Docker
sudo apt install -y docker.io
sudo usermod -aG docker $USER
newgrp docker

# Docker Compose v2 (v1 is broken on Python 3.12)
sudo curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Wireless tools and build dependencies
sudo apt install -y hostapd wpasupplicant tcpdump iw wireshark \
    build-essential git python3-venv libnl-3-dev libnl-genl-3-dev \
    pkg-config libssl-dev net-tools sysfsutils

sudo usermod -aG wireshark $USER
newgrp wireshark
```

When the Wireshark installer asks *"Should non-superusers be able to capture
packets?"* select **Yes**.

**Recovery — permission denied on docker:** `sudo systemctl restart docker && newgrp docker`

---

## 2. Load Virtual Wi-Fi Interfaces

```bash
./scripts/setup_interfaces.sh 3
```

This loads `mac80211_hwsim` with 3 radios (`wlan0`, `wlan1`, `wlan2`),
brings up `hwsim0`, and stops `NetworkManager` so it does not fight with
`hostapd` / `wpa_supplicant` over the virtual interfaces.

`mac80211_hwsim` does **not** persist across reboots — run this script again
after every reboot.

**Recovery — module not found:**
```bash
sudo apt install -y linux-modules-extra-$(uname -r)
```

---

## 3. Run the Handshake Capture

```bash
./scripts/run_handshake.sh
```

This:
1. Builds both Docker images
2. Starts `tcpdump` on `hwsim0` filtering for EAPOL (`ether proto 0x888e`)
3. Starts the `wpa2_ap` and `wpa2_client` containers
4. Waits 20 seconds for the handshake to complete
5. Prints the AP container logs
6. Stops the capture with `SIGINT` (so the pcap footer is written correctly)
7. Confirms 4 EAPOL frames were captured

**Expected AP log lines:**
```
wlan0: AP-ENABLED
IEEE 802.11: authentication OK (open system)
IEEE 802.11: associated (aid 1)
WPA: sending 1/4 msg of 4-Way Handshake
WPA: received EAPOL-Key frame (2/4 Pairwise)
WPA: sending 3/4 msg of 4-Way Handshake
WPA: received EAPOL-Key frame (4/4 Pairwise)
AP-STA-CONNECTED 02:00:00:00:01:00
WPA: pairwise key handshake completed (RSN)
EAPOL_4WAY_HS_COMPLETED
```

**Recovery — build cache error:**
```bash
docker system prune -af
docker-compose build --no-cache
```

**Recovery — "address already in use" / bridge conflicts:**
```bash
docker network prune -f
sudo ip link show type bridge
sudo ip link delete br-XXXXXXXX   # use the actual name shown above
```

**Recovery — capture.pcap is 0 bytes:** tcpdump started after the handshake
completed, or captured on the wrong interface. Capture must be on `hwsim0`
and must start **before** `docker-compose up`.

---

## 4. Verify with the Python Analyzer

```bash
sudo chmod 644 shared/capture.pcap
python3 scripts/analyzer.py
```

Expected final summary:
```
MSG2 MIC : VALID
MSG3 MIC : VALID
MSG4 MIC : VALID
RESULT   : COMPLETE AND VERIFIED
```

**Recovery — MIC INVALID:** This means the MAC/nonce extraction offsets are
wrong for your capture format. Run this diagnostic and confirm EAPOL is found
at a non-negative offset with a radiotap header preceding it:

```bash
python3 - << 'EOF'
import struct
from binascii import hexlify
with open("shared/capture.pcap", "rb") as f:
    magic = f.read(4)
    endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    f.read(20)
    hdr = f.read(16)
    _, _, incl_len, _ = struct.unpack(endian + "IIII", hdr)
    data = f.read(incl_len)
idx = data.find(b"\x88\x8e")
print("EAPOL at offset:", idx)
print("Bytes before EAPOL:", hexlify(data[max(0, idx-20):idx]).decode())
EOF
```

---

## 5. Wireshark Analysis

```bash
wireshark shared/capture.pcap &
```

Apply filter `eapol`. You should see exactly 4 frames:

| Frame | Direction | Length | Key Info | Purpose |
|---|---|---|---|---|
| MSG1 | AP -> Client | 153 bytes | 0x008a | ANonce, no MIC |
| MSG2 | Client -> AP | 181 bytes | 0x010a | SNonce + MIC + RSNE |
| MSG3 | AP -> Client | 241 bytes | 0x13ca | Encrypted GTK + MIC |
| MSG4 | Client -> AP | 153 bytes | 0x030a | Final ACK + MIC |

Click each frame and expand **802.1X Authentication** in the detail pane to
inspect the `Key Information`, `WPA Key Nonce`, `WPA Key MIC` and
`WPA Key Data Length` fields.

---

## 6. KRACK Attack Demonstration

See [`KRACK_NOTES.md`](KRACK_NOTES.md) for the full background, the 4-terminal
procedure, and how to interpret results.

Quick path (after following the one-time setup in KRACK_NOTES.md):

```bash
./scripts/run_krack_demo.sh
```

---

## Common Errors and Fixes

| Error | Cause | Fix |
|---|---|---|
| Permission denied connecting to Docker | Not in docker group | `newgrp docker` |
| Address already in use | Old bridge interface persisting | `docker network prune -f` then delete the stale `br-XXXX` interface |
| `wlan0: INTERFACE-DISABLED` | NetworkManager grabbed the interface | `sudo systemctl stop NetworkManager` then `sudo ip link set wlan0 up` |
| Failed to set beacon parameters | Containers conflict with host interfaces | `docker stop wpa2_ap wpa2_client` then reload `mac80211_hwsim` |
| `No module named Crypto` | venv not active, or wrong Python under sudo | `source venv/bin/activate` then `sudo -E $(which python3) script.py` |
| MIC INVALID in analyzer | Wrong frame offsets | Use the analyzer script in `scripts/` unmodified |
| `capture.pcap` is 0 bytes | tcpdump started after handshake, or wrong interface | Capture on `hwsim0`, start before `docker-compose up` |
| `krack_capture.pcap` empty or missing | tcpdump started too late or on wrong interface | Capture on `wlan2`, run `sudo -v` first, start before the KRACK script |
| `build.sh: make not found` | `build-essential` not installed | `sudo apt install -y build-essential` |
| `docker-compose`: distutils error | Old v1 docker-compose on Python 3.12 | Install Compose v2 as shown in step 1 |
| `wlan0`/`wlan1`/`wlan2` missing after reboot | `mac80211_hwsim` does not persist | Re-run `./scripts/setup_interfaces.sh 3` |
| sudo drops venv environment | sudo resets environment variables | Use `sudo -E $(which python3)` instead of `sudo python3` |

---

## Cleanup

```bash
docker-compose down
sudo modprobe -r mac80211_hwsim
sudo systemctl start NetworkManager
docker system prune -f
```

If the KRACK demo was run and hardware crypto was disabled:
```bash
sudo ~/krackattacks/krackattack/reenable-hwcrypto.sh
sudo reboot
```
