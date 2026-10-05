"""
Mneti Server - Flask Backend Application
Nakuru County Referral and Teaching Hospital (NCRTH) Network System
Ultra-lightweight Network Asset Discovery, Physical Mapping & Collision Detection
"""

import os
import sys
import json
import logging
import hmac
import hashlib
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template, send_from_directory, abort

# Add current directory to path
SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SERVER_DIR)

from database import init_db, record_ip_observation, get_all_devices, get_active_conflicts, get_topology_data, resolve_conflict
from discovery import send_probe, PeriodicBroadcaster, DEFAULT_HMAC_SECRET
from arp_scanner import ScapyARPScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("mneti.server")

# ── Flask Application Setup ────────────────────────────────────────────────────
app = Flask(__name__, template_folder=os.path.join(SERVER_DIR, "templates"))
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "ncrth_mneti_flask_secret_2026")
HMAC_SECRET = os.environ.get("MNETI_SECRET", DEFAULT_HMAC_SECRET)
HTTP_PORT = int(os.environ.get("PORT", "5000"))

# Initialize Database
init_db()

# Start Background Daemons
arp_daemon = ScapyARPScanner(sweep_interval=10)
arp_daemon.start()

probe_daemon = PeriodicBroadcaster(interval=30, callback_port=HTTP_PORT)
probe_daemon.start()


# ── HMAC Authentication Helper ────────────────────────────────────────────────
def verify_agent_signature(payload_bytes: bytes, signature_header: str) -> bool:
    """Verifies that the incoming telemetry was signed by an authorized agent."""
    if not signature_header:
        return False
    expected = hmac.new(HMAC_SECRET.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header.strip())


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serves the Vis.js Single Page Dashboard."""
    return render_template("index.html")


@app.route("/api/report", methods=["POST"])
def receive_agent_report():
    """
    Receives telemetry from client agents.
    Validates HMAC signature header 'X-Mneti-Signature'.
    Updates device inventory and checks for IP collision.
    """
    raw_data = request.get_data()
    sig = request.headers.get("X-Mneti-Signature") or request.headers.get("X-Signature")

    # In production, signature verification is strictly enforced.
    # We verify if header is present or payload contains valid token
    try:
        data = json.loads(raw_data)
    except Exception:
        return jsonify({"error": "Invalid JSON format"}), 400

    token = data.get("token")
    is_valid_sig = verify_agent_signature(raw_data, sig) if sig else False
    is_valid_token = (token == HMAC_SECRET)

    if not (is_valid_sig or is_valid_token):
        log.warning("Unauthorized agent report rejected from %s (Signature: %s)", request.remote_addr, sig)
        return jsonify({"error": "Unauthorized: Invalid HMAC signature or token"}), 401

    ip = data.get("ip") or request.remote_addr
    mac = data.get("mac")
    hostname = data.get("hostname", f"Host-{ip}")
    building = data.get("building", "Unassigned Pavilion")
    room = data.get("room", "General")
    subnet = data.get("subnet")
    device_type = data.get("device_type", "managed")
    logged_in_user = data.get("logged_in_user", "")
    vendor = data.get("vendor", "")

    if not mac:
        return jsonify({"error": "MAC address is required"}), 400

    # Record observation and perform real-time collision detection
    result = record_ip_observation(
        ip=ip,
        mac=mac,
        hostname=hostname,
        building=building,
        room=room,
        subnet=subnet,
        device_type=device_type,
        logged_in_user=logged_in_user,
        vendor=vendor
    )

    if result.get("conflict"):
        log.critical("🚨 TELEMETRY IP CONFLICT: Device %s collided with IP %s", hostname, ip)
        return jsonify({
            "status": "conflict_detected",
            "message": "CRITICAL: IP Address Collision Detected on Server!",
            "details": result
        }), 409

    return jsonify({"status": "acknowledged", "ip": ip, "mac": mac}), 200


@app.route("/api/topology", methods=["GET"])
def get_topology():
    """
    Returns structured nodes and edges for Vis.js canvas,
    along with conflict status and live asset counts.
    """
    data = get_topology_data()
    return jsonify(data)


@app.route("/api/devices", methods=["GET"])
def list_devices():
    """Returns all current devices in database."""
    devices = get_all_devices()
    return jsonify({"devices": devices, "count": len(devices)})


@app.route("/api/conflicts", methods=["GET"])
def list_conflicts():
    """Returns any active IP conflicts."""
    conflicts = get_active_conflicts()
    return jsonify({"conflicts": conflicts, "has_conflict": len(conflicts) > 0})


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    """Triggers an on-demand UDP broadcast probe and ARP sweep."""
    probe_result = send_probe(callback_port=HTTP_PORT)
    arp_daemon.perform_sweep()
    return jsonify({
        "status": "scan_initiated",
        "probe": probe_result,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.route("/api/conflict/resolve", methods=["POST"])
def resolve_ip_conflict():
    """Endpoint to clear or resolve an active conflict state."""
    body = request.get_json(silent=True) or {}
    ip = body.get("ip")
    authorized_mac = body.get("mac")
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    resolve_conflict(ip, authorized_mac)
    log.info("Conflict resolved for IP %s (Authorized MAC: %s)", ip, authorized_mac or "Restored")
    return jsonify({"status": "resolved", "ip": ip})


@app.route("/api/simulate-conflict", methods=["POST"])
def simulate_conflict():
    """
    Convenience endpoint for testing & demonstrations:
    Injects an IP collision on a target IP without requiring Scapy root privileges.
    """
    body = request.get_json(silent=True) or {}
    target_ip = body.get("ip", "10.100.40.10") # Default: Triage PC
    rogue_mac = body.get("mac", "00:DE:AD:BE:EF:99")
    rogue_hostname = body.get("hostname", "ROGUE-DEVICE-ATTACKER")

    res = record_ip_observation(
        ip=target_ip,
        mac=rogue_mac,
        hostname=rogue_hostname,
        vendor="Rogue Injector / Attacker",
        device_type="unmanaged"
    )

    return jsonify({
        "status": "simulation_injected",
        "result": res
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "system": "Mneti NCRTH Asset Discovery",
        "time": datetime.now(timezone.utc).isoformat()
    })


# ── Server Startup ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("Starting Mneti Hospital Network Discovery Server on port %d...", HTTP_PORT)
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, threaded=True)