"""
qt/api_server.py

Passes through switch_name and router_name fields the agent includes when
connection_type is Switch or Router, and routes incoming reports to the
correct session store:

  - Ordinary full/targeted discovery reports (type: managed/relayed/unmanaged)
    go to the normal ResultStore, exactly as before.
  - "ip_history" query replies (type: ip_history) go to the separate
    IPHistoryResultStore, since that store deliberately does NOT merge/dedupe
    by MAC — one computer can legitimately report several historical IP
    entries in a single query session.

Which store a given request_id belongs to is determined by which store's
init_session() was called for it (main_window.py always inits exactly one
of the two per broadcast), so this route just checks both.
"""

import json
import logging
from flask import Flask, request, jsonify
from PyQt6.QtCore import QThread, pyqtSignal
from qt.logic import Config, lookup_vendor

log = logging.getLogger("mneti.api")


class ApiServerThread(QThread):
    device_reported = pyqtSignal(str, dict)       # request_id, device_data (normal discovery)
    ip_history_reported = pyqtSignal(str, dict)    # request_id, device_data (ip_history query)

    def __init__(self, store, ip_history_store):
        super().__init__()
        self.store = store
        self.ip_history_store = ip_history_store
        self.app = Flask(__name__)
        self._setup_routes()

    def _setup_routes(self):

        @self.app.route("/api/report", methods=["POST"])
        def receive_report():
            raw = request.get_data()
            try:
                data = json.loads(raw)
            except Exception:
                return jsonify({"error": "bad request"}), 400

            # Token check
            if data.get("token") != Config.SHARED_TOKEN:
                return jsonify({"error": "unauthorized"}), 401

            request_id = data.get("request_id")
            is_iph = bool(request_id) and self.ip_history_store.session_exists(request_id)
            is_normal = bool(request_id) and self.store.session_exists(request_id)

            if not request_id or not (is_iph or is_normal):
                return jsonify({"error": "unknown request_id"}), 400

            mac = str(data.get("mac", ""))[:17]
            vendor = str(data.get("vendor", "")).strip()
            if not vendor:
                vendor = lookup_vendor(mac)

            # Normalise additional_ports to a plain list of strings
            raw_ports = data.get("additional_ports", [])
            if isinstance(raw_ports, list):
                additional_ports = [str(p) for p in raw_ports]
            else:
                additional_ports = []

            device = {
                "hostname":         str(data.get("hostname",        ""))[:128],
                "mac":              mac,
                "ip":               str(data.get("ip",              ""))[:45],
                "username":         str(data.get("username",        ""))[:64],
                "building":         str(data.get("building",        ""))[:128],
                "room":             str(data.get("room",            ""))[:64],
                "timestamp":        str(data.get("timestamp",       ""))[:32],
                "type":             str(data.get("type",            "managed")),
                "relay_host":       str(data.get("relay_host",      ""))[:128],
                "relay_building":   str(data.get("relay_building",  ""))[:128],
                "relay_room":       str(data.get("relay_room",      ""))[:64],
                "vendor":           vendor,
                "reporter_ip":      request.remote_addr,
                "connection_type":  str(data.get("connection_type", ""))[:32],
                # Wall Port fields
                "port":             str(data.get("port",            ""))[:32],
                "additional_ports": additional_ports,
                # Switch / Router name fields
                "switch_name":      str(data.get("switch_name",     ""))[:128],
                "router_name":      str(data.get("router_name",     ""))[:128],
            }

            if is_iph:
                self.ip_history_store.add_result(request_id, device)
                self.ip_history_reported.emit(request_id, device)
            else:
                self.store.add_result(request_id, device)
                self.device_reported.emit(request_id, device)

            return jsonify({"status": "ok"})

        @self.app.route("/health")
        def health():
            return "OK"

    def run(self):
        log.info(f"Starting API server on port {Config.HTTP_PORT}")
        self.app.run(host="0.0.0.0", port=Config.HTTP_PORT,
                     debug=False, threaded=True)