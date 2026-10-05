"""
Mneti Discovery Probe Broadcaster
Sends HMAC-SHA256 signed UDP probe packets to trigger client agent reporting.
"""

import os
import json
import time
import uuid
import hmac
import hashlib
import socket
import logging
import threading
import psutil

log = logging.getLogger("mneti.discovery")

DEFAULT_HMAC_SECRET = os.environ.get("MNETI_SECRET", "ncrth_mneti_secret_key_2026")
DEFAULT_PROBE_PORT = int(os.environ.get("MNETI_PROBE_PORT", "5005"))


def get_lan_ip() -> str:
    """Determine the primary outbound IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not actually establish connection
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_broadcast_addresses() -> list[str]:
    """Retrieve all broadcast addresses across active interfaces."""
    broadcasts = set(["255.255.255.255"])
    try:
        for iface_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.broadcast:
                    broadcasts.add(addr.broadcast)
    except Exception as e:
        log.debug("Interface broadcast enumeration error: %s", e)
    return list(broadcasts)


def sign_payload(payload_bytes: bytes, secret: str = DEFAULT_HMAC_SECRET) -> str:
    """Generate HMAC-SHA256 signature for binary payload."""
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def verify_payload_signature(payload_bytes: bytes, signature: str, secret: str = DEFAULT_HMAC_SECRET) -> bool:
    """Verify HMAC-SHA256 signature using constant-time comparison."""
    if not signature:
        return False
    expected = sign_payload(payload_bytes, secret)
    return hmac.compare_digest(expected, signature)


def create_signed_probe(server_ip: str = None, callback_port: int = 5000, secret: str = DEFAULT_HMAC_SECRET) -> tuple[bytes, dict]:
    """
    Constructs a signed UDP probe envelope.
    """
    srv_ip = server_ip or get_lan_ip()
    request_id = str(uuid.uuid4())
    
    payload = {
        "type": "MNETI_PROBE",
        "request_id": request_id,
        "server_ip": srv_ip,
        "callback_url": f"http://{srv_ip}:{callback_port}/api/report",
        "timestamp": int(time.time()),
        "realm": "NCRTH_HOSPITAL_NETWORK"
    }

    payload_json = json.dumps(payload, sort_keys=True).encode("utf-8")
    signature = sign_payload(payload_json, secret)

    envelope = {
        "payload": payload,
        "signature": signature
    }
    envelope_bytes = json.dumps(envelope).encode("utf-8")
    return envelope_bytes, payload


def send_probe(
    port: int = DEFAULT_PROBE_PORT,
    callback_port: int = 5000,
    server_ip: str = None,
    secret: str = DEFAULT_HMAC_SECRET,
    custom_targets: list[str] = None
) -> dict:
    """
    Broadcasts signed probe packets across all discovered broadcast addresses
    and loopback/local targets.
    """
    envelope_bytes, payload = create_signed_probe(server_ip, callback_port, secret)
    targets = custom_targets or (get_broadcast_addresses() + ["127.0.0.1"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(2.0)

    sent_count = 0
    try:
        for target in targets:
            try:
                sock.sendto(envelope_bytes, (target, port))
                sent_count += 1
                log.info("Sent signed Mneti probe to %s:%d (req_id=%s)", target, port, payload["request_id"])
            except Exception as e:
                log.warning("Could not send probe to %s: %s", target, e)
    finally:
        sock.close()

    return {
        "status": "probes_sent",
        "request_id": payload["request_id"],
        "targets_sent": sent_count,
        "timestamp": payload["timestamp"]
    }


class PeriodicBroadcaster(threading.Thread):
    """Background thread that automatically broadcasts probe packets on a set interval."""

    def __init__(self, interval: int = 30, port: int = DEFAULT_PROBE_PORT, callback_port: int = 5000):
        super().__init__(daemon=True)
        self.interval = interval
        self.port = port
        self.callback_port = callback_port
        self.running = True

    def run(self):
        log.info("Periodic discovery broadcaster started (interval: %ds, port: %d)", self.interval, self.port)
        while self.running:
            try:
                send_probe(port=self.port, callback_port=self.callback_port)
            except Exception as e:
                log.error("Periodic broadcast failed: %s", e)
            time.sleep(self.interval)

    def stop(self):
        self.running = False