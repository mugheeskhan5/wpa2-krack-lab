#!/usr/bin/env python3
"""
WPA2 4-Way Handshake Analyzer

Reads a pcap file containing a captured WPA2 4-way handshake (EAPOL frames
captured on a mac80211_hwsim interface), extracts the ANonce, SNonce and MAC
addresses, independently derives PMK -> PTK -> KCK/KEK/TK from the known
passphrase and SSID, and verifies the MIC of MSG2, MSG3 and MSG4.

Usage:
    python3 analyzer.py [path/to/capture.pcap]

If no path is given, defaults to ../shared/capture.pcap relative to this
script's location.
"""

import struct
import hashlib
import hmac
import sys
import os
from binascii import hexlify

SSID     = "LabNet_01"
PASSWORD = "LabPassphrase2024!"

DEFAULT_PCAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared", "capture.pcap")


def pmk_derive(password, ssid):
    """PMK = PBKDF2-SHA1(password, ssid, 4096 iterations, 32 bytes)."""
    return hashlib.pbkdf2_hmac("sha1", password.encode(), ssid.encode(), 4096, 32)


def prf512(key, label, data):
    """IEEE 802.11 PRF-512 used to derive the PTK from the PMK."""
    result = b""
    for i in range(4):
        result += hmac.new(key, label + b"\x00" + data + bytes([i]), "sha1").digest()
    return result[:64]


def ptk_derive(pmk, anonce, snonce, ap_mac, cli_mac):
    """PTK = PRF-512(PMK, "Pairwise key expansion", min/max(MACs) || min/max(nonces))."""
    macs   = min(ap_mac, cli_mac) + max(ap_mac, cli_mac)
    nonces = min(anonce, snonce)  + max(anonce, snonce)
    return prf512(pmk, b"Pairwise key expansion", macs + nonces)


def verify_mic(kck, eapol_frame):
    """Verify the EAPOL-Key MIC by zeroing the MIC field and recomputing HMAC-SHA1."""
    mic_received = eapol_frame[81:97]
    frame_zeroed = eapol_frame[:81] + b"\x00" * 16 + eapol_frame[97:]
    mic_computed = hmac.new(kck, frame_zeroed, "sha1").digest()[:16]
    return mic_received, mic_computed, mic_received == mic_computed


def read_pcap(filename):
    """Minimal classic pcap reader -- returns list of (ts_sec, ts_usec, raw_bytes)."""
    packets = []
    with open(filename, "rb") as f:
        magic = f.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            print(f"[-] Unknown pcap magic: {hexlify(magic)}")
            sys.exit(1)
        f.read(20)  # rest of global header
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", hdr)
            packets.append((ts_sec, ts_usec, f.read(incl_len)))
    return packets


def find_eapol(packet_data):
    """Locate the start of the EAPOL body (after the 0x888e EtherType)."""
    idx = packet_data.find(b"\x88\x8e")
    if idx == -1:
        return None
    return packet_data[idx + 2:]


def extract_eapol_fields(eapol):
    """Parse the fixed-size fields of an EAPOL-Key frame."""
    if len(eapol) < 99:
        return None
    fields = {
        "key_info":     struct.unpack("!H", eapol[5:7])[0],
        "key_length":   struct.unpack("!H", eapol[7:9])[0],
        "replay":       struct.unpack("!Q", eapol[9:17])[0],
        "nonce":        eapol[17:49],
        "mic":          eapol[81:97],
        "key_data_len": struct.unpack("!H", eapol[97:99])[0],
        "raw":          eapol,
    }
    ki = fields["key_info"]
    fields["mic_flag"]     = bool(ki & 0x0100)
    fields["install_flag"] = bool(ki & 0x0040)
    fields["ack_flag"]     = bool(ki & 0x0080)
    fields["secure_flag"]  = bool(ki & 0x0200)
    return fields


def extract_macs(packet_data):
    """
    Extract source/destination MACs from an 802.11 frame captured with a
    radiotap header (as produced by mac80211_hwsim / hwsim0 captures).
    """
    try:
        radiotap_len = struct.unpack("<H", packet_data[2:4])[0]
        dot11 = packet_data[radiotap_len:]
        # 802.11 data frame: bytes 4-10 = addr1 (dst), bytes 10-16 = addr2 (src)
        dst = dot11[4:10]
        src = dot11[10:16]
        return src, dst
    except Exception:
        return None, None


def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PCAP

    print("=" * 60)
    print("   WPA2 4-WAY HANDSHAKE ANALYZER")
    print("=" * 60)

    print(f"\n[1] Reading pcap file: {pcap_path}")
    if not os.path.exists(pcap_path):
        print(f"[-] File not found: {pcap_path}")
        sys.exit(1)

    packets = read_pcap(pcap_path)
    print(f"    Total packets found: {len(packets)}")

    print("\n[2] Extracting EAPOL frames...")
    eapol_frames = []
    mac_pairs = []

    for ts_sec, ts_usec, data in packets:
        eapol = find_eapol(data)
        if eapol:
            fields = extract_eapol_fields(eapol)
            if fields:
                src_mac, dst_mac = extract_macs(data)
                eapol_frames.append(fields)
                mac_pairs.append((src_mac, dst_mac))
                n = len(eapol_frames)
                print(f"    MSG{n} found - Key Info: 0x{fields['key_info']:04x} "
                      f"| MIC: {'YES' if fields['mic_flag'] else 'NO'} "
                      f"| ACK: {'YES' if fields['ack_flag'] else 'NO'} "
                      f"| Install: {'YES' if fields['install_flag'] else 'NO'}")

    if len(eapol_frames) < 4:
        print(f"[-] Only {len(eapol_frames)} EAPOL frames found, need 4")
        sys.exit(1)

    print("    All 4 EAPOL frames extracted successfully")

    print("\n[3] Extracting MACs and Nonces...")
    ap_mac  = mac_pairs[0][0]
    cli_mac = mac_pairs[0][1]
    anonce  = eapol_frames[0]["nonce"]
    snonce  = eapol_frames[1]["nonce"]

    print(f"    AP  MAC : {hexlify(ap_mac).decode()}")
    print(f"    CLI MAC : {hexlify(cli_mac).decode()}")
    print(f"    ANonce  : {hexlify(anonce).decode()}")
    print(f"    SNonce  : {hexlify(snonce).decode()}")

    print("\n[4] Deriving PMK...")
    pmk = pmk_derive(PASSWORD, SSID)
    print(f"    PMK: {hexlify(pmk).decode()}")

    print("\n[5] Deriving PTK...")
    ptk = ptk_derive(pmk, anonce, snonce, ap_mac, cli_mac)
    kck, kek, tk = ptk[:16], ptk[16:32], ptk[32:48]
    print(f"    PTK: {hexlify(ptk).decode()}")
    print(f"    KCK: {hexlify(kck).decode()}")
    print(f"    KEK: {hexlify(kek).decode()}")
    print(f"    TK : {hexlify(tk).decode()}")

    print("\n[6] Verifying MIC in MSG2...")
    r2, c2, v2 = verify_mic(kck, eapol_frames[1]["raw"])
    print(f"    MIC received : {hexlify(r2).decode()}")
    print(f"    MIC computed : {hexlify(c2).decode()}")
    print(f"    MIC STATUS   : {'VALID - password is correct, PTK verified' if v2 else 'INVALID'}")

    print("\n[7] Verifying MIC in MSG3...")
    r3, c3, v3 = verify_mic(kck, eapol_frames[2]["raw"])
    print(f"    MIC received : {hexlify(r3).decode()}")
    print(f"    MIC computed : {hexlify(c3).decode()}")
    print(f"    MIC STATUS   : {'VALID - AP confirmed PTK' if v3 else 'INVALID'}")

    print("\n[8] Verifying MIC in MSG4...")
    r4, c4, v4 = verify_mic(kck, eapol_frames[3]["raw"])
    print(f"    MIC received : {hexlify(r4).decode()}")
    print(f"    MIC computed : {hexlify(c4).decode()}")
    print(f"    MIC STATUS   : {'VALID - handshake complete' if v4 else 'INVALID'}")

    print("\n" + "=" * 60)
    print("   FINAL SUMMARY")
    print("=" * 60)
    print(f"   SSID     : {SSID}")
    print(f"   Password : {PASSWORD}")
    print(f"   PMK      : {hexlify(pmk).decode()[:32]}...")
    print(f"   PTK      : {hexlify(ptk).decode()[:32]}...")
    print(f"   KCK      : {hexlify(kck).decode()}")
    print(f"   KEK      : {hexlify(kek).decode()}")
    print(f"   TK       : {hexlify(tk).decode()}")
    print(f"   MSG2 MIC : {'VALID' if v2 else 'INVALID'}")
    print(f"   MSG3 MIC : {'VALID' if v3 else 'INVALID'}")
    print(f"   MSG4 MIC : {'VALID' if v4 else 'INVALID'}")
    print(f"   RESULT   : {'COMPLETE AND VERIFIED' if v2 and v3 and v4 else 'FAILED'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
