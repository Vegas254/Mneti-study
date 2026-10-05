"""
Mneti Background ARP Scanner & Conflict Detector
Uses Scapy for active ARP sweeps and passive ARP packet sniffing.
Detects unmanaged network assets and flags immediate IP-MAC collisions.
"""

import os
import sys
import time
import logging
import threading
import ipaddress
import psutil

# Add server directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import record_ip_observation

log = logging.getLogger("mneti.arp_scanner")

# Embedded High-Frequency OUI Vendor Mapping for Healthcare & Enterprise Network Environments
OUI_TABLE = {
    "00:14:22": "Dell Inc.",
    "00:1A:2B": "HP Inc.",
    "18:66:DA": "Dell Inc.",
    "00:1B:78": "Siemens Healthineers",
    "00:07:4D": "Zebra Technologies",
    "00:09:0F": "Sysmex Corporation",
    "00:03:7F": "Philips Healthcare",
    "00:50:56": "VMware Virtual Platform",
    "00:0C:29": "VMware Virtual Platform",
    "00:80:A3": "Roche Diagnostics",
    "AC:CC:8E": "Hikvision Digital",
    "3C:D9:2B": "Barco Healthcare",
    "B4:B5:2F": "Mindray Medical",
    "A4:BB:6D": "Apple Inc.",
    "00:23:7D": "HP Inc.",
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "54:EE:75": "HP Enterprise",
    "00:1E:67": "Lenovo ThinkCentre",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:DE:AD": "Rogue Injector / Test Device"
}


def lookup_vendor(mac: str) -> str:
    """Resolve IEEE OUI prefix to hardware manufacturer."""
    if not mac:
        return "Unknown"
    norm_mac = mac.replace("-", ":").upper().strip()
    prefix = norm_mac[:8]
    return OUI_TABLE.get(prefix, "Standard Network Device")


def get_local_subnets() -> list[ipaddress.IPv4Network]:
    """Identify usable IPv4 networks across active physical interfaces."""
    networks = []
    for iface, addrs in psutil.net_if_addrs().items():
        if iface.startswith("lo"):
            continue
        for addr in addrs:
            if addr.family == psutil.AF_LINK or addr.family == 2: # AF_INET
                if hasattr(addr, 'netmask') and addr.netmask and addr.address:
                    try:
                        net = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                        if not net.is_loopback and net.num_addresses <= 1024:
                            networks.append(net)
                    except Exception:
                        pass
    return networks


class ScapyARPScanner(threading.Thread):
    """
    Continuous background daemon that:
      1. Passively sniffs ARP replies and requests (fast collision detection).
      2. Actively sweeps local subnets using Scapy ARP probes.
      3. Gracefully reads system ARP cache if raw packet capture lacks root privileges.
    """

    def __init__(self, sweep_interval: int = 15, on_conflict_callback = None):
        super().__init__(daemon=True)
        self.sweep_interval = sweep_interval
        self.on_conflict_callback = on_conflict_callback
        self.running = True
        self.scapy_available = False

        try:
            import scapy.all as scapy_mod
            self.scapy = scapy_mod
            self.scapy_available = True
        except ImportError:
            log.warning("Scapy is not installed. ARP scanner will operate in cache-read mode.")

    def run(self):
        log.info("Starting Mneti Background ARP Scanner & Conflict Daemon...")

        # If Scapy and root privileges are available, start passive sniffer in subthread
        if self.scapy_available and os.geteuid() == 0:
            sniffer_thread = threading.Thread(target=self._passive_arp_sniff, daemon=True)
            sniffer_thread.start()
            log.info("Passive raw ARP sniffer launched (Kernel Filter: 'arp')")
        else:
            log.info("Raw packet sniffing requires root (sudo). Active sweeps & kernel table polling enabled.")

        while self.running:
            try:
                self.perform_sweep()
            except Exception as e:
                log.error("ARP sweep exception: %s", e)
            time.sleep(self.sweep_interval)

    def _process_arp_pair(self, ip: str, mac: str, source_tag: str = "arp-sweep"):
        """Evaluates an (IP, MAC) pair against the database to detect collisions."""
        if not ip or not mac or ip.startswith("127.") or ip == "0.0.0.0":
            return

        vendor = lookup_vendor(mac)
        res = record_ip_observation(
            ip=ip,
            mac=mac,
            vendor=vendor,
            device_type="unmanaged"
        )

        if res.get("conflict"):
            log.critical(
                "🚨 [CRITICAL ALERT - %s] IP Conflict Detected on %s! Registered MAC: %s vs Colliding MAC: %s",
                source_tag.upper(), ip, res["registered_mac"], res["colliding_mac"]
            )
            if self.on_conflict_callback:
                try:
                    self.on_conflict_callback(res)
                except Exception as cb_err:
                    log.error("Conflict callback error: %s", cb_err)

    def _passive_arp_sniff(self):
        """Sniffs live ARP frames in real-time to catch instant IP clashes."""
        def handle_pkt(pkt):
            if pkt.haslayer(self.scapy.ARP):
                arp = pkt[self.scapy.ARP]
                # arp.psrc is sender IP, arp.hwsrc is sender MAC
                self._process_arp_pair(arp.psrc, arp.hwsrc, source_tag="passive-sniff")

        try:
            self.scapy.sniff(filter="arp", prn=handle_pkt, store=False)
        except Exception as e:
            log.warning("Passive ARP sniff stopped: %s", e)

    def perform_sweep(self):
        """Sweeps networks using Scapy ARP probes, falling back to /proc/net/arp."""
        swept_devices = {}

        # Mode A: Scapy Active ARP Ping (if root or socket allowed)
        if self.scapy_available and os.geteuid() == 0:
            subnets = get_local_subnets()
            for net in subnets:
                try:
                    ans, _ = self.scapy.srp(
                        self.scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / self.scapy.ARP(pdst=str(net)),
                        timeout=1.5,
                        verbose=False
                    )
                    for _, rcv in ans:
                        swept_devices[rcv.psrc] = rcv.hwsrc
                except Exception as e:
                    log.debug("Scapy srp sweep failed on %s: %s", net, e)

        # Mode B: System /proc/net/arp Table Polling (works reliably across all environments)
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r") as f:
                    lines = f.readlines()[1:] # skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = parts[3].upper()
                            flags = parts[2]
                            if mac != "00:00:00:00:00:00" and flags != "0x0":
                                swept_devices[ip] = mac
            except Exception as e:
                log.debug("Error reading /proc/net/arp: %s", e)

        # Process all observed pairs
        for ip, mac in swept_devices.items():
            self._process_arp_pair(ip, mac, source_tag="active-sweep")

    def stop(self):
        self.running = False