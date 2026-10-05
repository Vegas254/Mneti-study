"""
Mneti Client Agent - Cross-Platform Lightweight Daemon
Listens on UDP port 5005 for HMAC-SHA256 signed probes from the Mneti server.
Collects hardware and network telemetry, signs it, and reports back via HTTP POST.
"""

import os
import sys
import json
import time
import socket
import hmac
import hashlib
import getpass
import platform
import argparse
import logging
import uuid
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="%(asctime)s [AGENT-%(levelname)s] %(message)s")
log = logging.getLogger("mneti.agent")

DEFAULT_SECRET = os.environ.get("MNETI_SECRET", "ncrth_mneti_secret_key_2026")
DEFAULT_LISTEN_PORT = 5005
DEFAULT_SERVER_URL = "http://127.0.0.1:5000/api/report"


def get_primary_ip() -> str:
    """Detects active primary LAN IPv4 address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_mac_address() -> str:
    """Retrieves normalized MAC address of the system."""
    try:
        # Formats 48-bit integer into standard colon-separated hex MAC
        raw_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
        return raw_mac.upper()
    except Exception:
        return "00:1A:2B:3C:4D:EE"


def verify_probe(envelope: dict, secret: str) -> bool:
    """Verifies HMAC-SHA256 signature of incoming probe packet."""
    try:
        payload = envelope.get("payload")
        signature = envelope.get("signature")
        if not payload or not signature:
            return False

        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        expected_sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, signature)
    except Exception as e:
        log.warning("Probe signature verification exception: %s", e)
        return False


def send_report(
    server_url: str,
    secret: str,
    building: str = "Outpatient Pavilion",
    room: str = "Pharm-101",
    subnet: str = None,
    custom_ip: str = None,
    custom_mac: str = None
) -> bool:
    """Collects system telemetry, signs it, and sends HTTP POST to server."""
    ip = custom_ip or get_primary_ip()
    mac = custom_mac or get_mac_address()
    hostname = socket.gethostname()
    username = getpass.getuser()

    if not subnet:
        parts = ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else "10.100.10.0/24"

    telemetry = {
        "hostname": hostname,
        "ip": ip,
        "mac": mac,
        "building": building,
        "room": room,
        "subnet": subnet,
        "device_type": "managed",
        "logged_in_user": username,
        "vendor": f"{platform.system()} ({platform.machine()})",
        "token": secret,
        "timestamp": int(time.time())
    }

    payload_bytes = json.dumps(telemetry, sort_keys=True).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    req = urllib.request.Request(
        server_url,
        data=payload_bytes,
        headers={
            "Content-Type": "application/json",
            "X-Mneti-Signature": sig
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            log.info("Telemetry successfully reported to %s (Response: %s)", server_url, res_body)
            return True
    except urllib.error.HTTPError as e:
        log.error("Server rejected report (%d): %s", e.code, e.read().decode("utf-8"))
    except Exception as e:
        log.error("Failed to connect to Mneti server at %s: %s", server_url, e)
    return False


def listen_for_probes(port: int, secret: str, building: str, room: str, subnet: str, fallback_url: str):
    """Listens on UDP port for signed discovery probes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("0.0.0.0", port))
    except Exception as e:
        log.critical("Could not bind UDP port %d: %s", port, e)
        return

    log.info("Mneti Agent active. Listening for UDP discovery probes on port %d...", port)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            envelope = json.loads(data.decode("utf-8"))
            log.info("Received discovery probe from %s", addr[0])

            if verify_probe(envelope, secret):
                log.info("Probe HMAC signature VALID. Preparing telemetry response...")
                payload = envelope.get("payload", {})
                callback_url = payload.get("callback_url") or fallback_url
                send_report(callback_url, secret, building, room, subnet)
            else:
                log.warning("Rejected probe from %s: INVALID HMAC signature!", addr[0])
        except Exception as e:
            log.error("Error processing incoming probe: %s", e)


def main():
    parser = argparse.ArgumentParser(description="Mneti Client Agent - Cross-Platform Discovery Daemon")
    parser.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help="UDP listen port for probes (default: 5005)")
    parser.add_argument("--secret", default=DEFAULT_SECRET, help="Shared HMAC secret key")
    parser.add_argument("--server", default=DEFAULT_SERVER_URL, help="Fallback Mneti server callback URL")
    parser.add_argument("--building", default="Outpatient Pavilion", help="Building name for location mapping")
    parser.add_argument("--room", default="Pharm-Dispense-101", help="Room name/number for location mapping")
    parser.add_argument("--subnet", default="10.100.10.0/24", help="Subnet CIDR")
    parser.add_argument("--ip", default=None, help="Override reporting IP (for simulation)")
    parser.add_argument("--mac", default=None, help="Override reporting MAC (for simulation)")
    parser.add_argument("--once", action="store_true", help="Send single telemetry report immediately and exit")

    args = parser.parse_args()

    if args.once:
        log.info("Sending one-time telemetry report to %s...", args.server)
        send_report(
            server_url=args.server,
            secret=args.secret,
            building=args.building,
            room=args.room,
            subnet=args.subnet,
            custom_ip=args.ip,
            custom_mac=args.mac
        )
    else:
        listen_for_probes(
            port=args.port,
            secret=args.secret,
            building=args.building,
            room=args.room,
            subnet=args.subnet,
            fallback_url=args.server
        )


if __name__ == "__main__":
    main()
