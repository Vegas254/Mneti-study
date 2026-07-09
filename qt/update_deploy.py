"""
qt/update_deploy.py

Dashboard side of the Mneti self-update mechanism. Implements the
"management application acts as a temporary update host" half of the
protocol described in start-Mneti.ps1's FIX 13 section — read that
docstring for the full wire-protocol writeup; this module builds and
sends exactly the packets that agent expects.

Nothing here is persistent: UpdateServer only exists and does anything
while a deploy is actively running (from "Deploy Update" being clicked
until "Stop" or the broadcast window elapsing). There is no standing
"update server" listening at all times — it's spun up on demand, same
spirit as the rest of Mneti's pull-based, nothing-happens-until-asked
design.

Security: every announcement is HMAC-signed with the same shared token
already used to authenticate discovery/ip_history packets (Config.
SHARED_TOKEN). An agent only accepts an announcement whose signature
validates against ITS OWN config.token — a device that doesn't know the
token cannot get an agent to download or apply anything through this
mechanism, regardless of how it's phrased on the wire.

Extensibility: the packet includes "proto_version" precisely so that
future dashboard/agent releases can add new fields (e.g. release notes,
a minimum-OS-version gate, a rollout percentage) without breaking older
agents — bump UPDATE_PROTO_VERSION only when you need to change what a
field MEANS, not just to add one.
"""

import os
import socket
import ipaddress
import threading
import time
import uuid
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone

import psutil
from PyQt6.QtCore import QObject, pyqtSignal

from qt.logic import Config

log = logging.getLogger("mneti.update")

UPDATE_UDP_PORT = 5010
UPDATE_MAGIC = "MNETI_UPDATE"
UPDATE_PROTO_VERSION = 1

# Agents accept the first free port we find here — matches the pattern the
# agent's own relay listener already uses (try a small range, take the
# first that binds).
TCP_PORT_CANDIDATES = list(range(5300, 5320))

BROADCAST_INTERVAL_SEC = 5     # how often the announcement is repeated
BROADCAST_DURATION_SEC = 300   # how long we keep re-announcing (5 minutes)


def _get_broadcast_targets():
    """
    (bind_ip, broadcast_ip) for every local IPv4 interface, same enumeration
    style DiscoveryBroadcaster uses for discovery packets — sending on each
    interface's own broadcast address (rather than only the global
    255.255.255.255) reaches secondary NICs/VLANs more reliably.
    """
    targets = []
    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                try:
                    net = ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
                    targets.append((addr.address, str(net.network.broadcast_address)))
                except Exception:
                    continue
    return targets


class UpdateServer(QObject):
    """
    Runs the TCP file server and periodic UDP announcement broadcast for
    one "Deploy Update" run. Create one, call start(), and stop() when
    done (or let the broadcast window elapse on its own — the TCP server
    stays up until stop() is called explicitly, so agents that connect
    late while a download is already finishing for others still succeed).
    """

    log_message = pyqtSignal(str)
    agent_connected = pyqtSignal(str)   # IP address of an agent that connected to download
    stopped = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._tcp_socket = None
        self._stop_event = threading.Event()
        self._file_path = None
        self._file_size = 0
        self._sha256_hex = None
        self._tcp_port = None
        self._transfer_id = None
        self._update_version = None
        self._connected_count = 0

    def is_running(self) -> bool:
        return self._tcp_socket is not None

    def connected_count(self) -> int:
        return self._connected_count

    def start(self, file_path: str, update_version: str) -> bool:
        if self.is_running():
            self.log_message.emit("A deploy is already in progress — stop it first.")
            return False

        if not os.path.isfile(file_path):
            self.log_message.emit(f"File not found: {file_path}")
            return False

        update_version = update_version.strip()
        if not update_version:
            self.log_message.emit("Enter a version string (e.g. 1.1.0) before deploying.")
            return False

        self._file_path = file_path
        self._update_version = update_version
        self._file_size = os.path.getsize(file_path)
        self._sha256_hex = self._compute_sha256(file_path)
        self._transfer_id = str(uuid.uuid4())
        self._connected_count = 0
        self._stop_event.clear()

        self._tcp_port = self._bind_tcp_server()
        if self._tcp_port is None:
            self.log_message.emit("Could not bind any TCP port in the 5300-5319 range.")
            return False

        threading.Thread(target=self._accept_loop, daemon=True).start()
        threading.Thread(target=self._broadcast_loop, daemon=True).start()

        self.log_message.emit(
            f"Deploying v{update_version} — {self._file_size} bytes, "
            f"sha256 {self._sha256_hex[:16]}…, TCP :{self._tcp_port}, "
            f"transfer {self._transfer_id[:8]}…. Broadcasting every "
            f"{BROADCAST_INTERVAL_SEC}s for {BROADCAST_DURATION_SEC}s."
        )
        return True

    def stop(self):
        self._stop_event.set()
        sock = self._tcp_socket
        self._tcp_socket = None
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        self.log_message.emit("Update server stopped.")
        self.stopped.emit()

    # ── internals ────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def _bind_tcp_server(self):
        for port in TCP_PORT_CANDIDATES:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                s.listen(32)
                s.settimeout(1.0)
                self._tcp_socket = s
                return port
            except OSError:
                continue
        return None

    def _accept_loop(self):
        while not self._stop_event.is_set():
            sock = self._tcp_socket
            if sock is None:
                break
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_one, args=(conn, addr), daemon=True).start()

    def _serve_one(self, conn, addr):
        """
        Streams the raw file bytes and closes — no application-layer
        framing needed. TCP already guarantees ordering/delivery/
        retransmission; the agent detects completion via the connection
        closing and independently verifies size + SHA-256 before trusting
        anything it received.
        """
        try:
            with open(self._file_path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    conn.sendall(chunk)
            self._connected_count += 1
            self.agent_connected.emit(addr[0])
            self.log_message.emit(f"Sent update to {addr[0]}")
        except Exception as e:
            self.log_message.emit(f"Transfer to {addr[0]} failed: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _build_packet(self) -> bytes:
        """
        Field order here MUST exactly match the canonical string
        Test-UpdatePacket rebuilds on the agent side, or every signature
        will fail to verify. See start-Mneti.ps1's Test-UpdatePacket.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        canonical = (
            '{"magic":"' + UPDATE_MAGIC + '"'
            ',"proto_version":' + str(UPDATE_PROTO_VERSION) +
            ',"update_version":"' + self._update_version + '"'
            ',"tcp_port":' + str(self._tcp_port) +
            ',"file_size":' + str(self._file_size) +
            ',"sha256":"' + self._sha256_hex + '"'
            ',"timestamp":"' + timestamp + '"'
            ',"transfer_id":"' + self._transfer_id + '"'
            ',"token":"' + Config.SHARED_TOKEN + '"}'
        )
        sig = hmac.new(Config.SHARED_TOKEN.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        payload = {
            "magic": UPDATE_MAGIC,
            "proto_version": UPDATE_PROTO_VERSION,
            "update_version": self._update_version,
            "tcp_port": self._tcp_port,
            "file_size": self._file_size,
            "sha256": self._sha256_hex,
            "timestamp": timestamp,
            "transfer_id": self._transfer_id,
            "token": Config.SHARED_TOKEN,
        }
        return json.dumps({"payload": payload, "sig": sig}, separators=(",", ":")).encode()

    def _broadcast_loop(self):
        deadline = time.time() + BROADCAST_DURATION_SEC
        try:
            while not self._stop_event.is_set() and time.time() < deadline:
                data = self._build_packet()

                # Global fallback broadcast.
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(data, ("255.255.255.255", UPDATE_UDP_PORT))
                    s.close()
                except Exception:
                    pass

                # Per-interface broadcast, for reliability across secondary
                # NICs/VLANs/hotspot adapters — same reasoning as discovery.
                for bind_ip, bcast_ip in _get_broadcast_targets():
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                        s.bind((bind_ip, 0))
                        s.sendto(data, (bcast_ip, UPDATE_UDP_PORT))
                        s.close()
                    except Exception:
                        pass

                for _ in range(BROADCAST_INTERVAL_SEC * 10):
                    if self._stop_event.is_set():
                        break
                    time.sleep(0.1)
        finally:
            self.log_message.emit("Finished broadcasting update announcement (TCP server still up).")