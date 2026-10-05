"""
Mneti Database Layer - SQLite3 Backend
Nakuru County Referral and Teaching Hospital (NCRTH) Network System
"""

import sqlite3
import os
import logging
from datetime import datetime, timezone

log = logging.getLogger("mneti.database")

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(DB_DIR, "mneti.db")


def get_db(db_path: str = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = None) -> None:
    """Create devices and ip_history tables with proper indexes."""
    path = db_path or DEFAULT_DB_PATH
    conn = get_db(path)
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                mac TEXT NOT NULL,
                hostname TEXT,
                building TEXT,
                room TEXT,
                subnet TEXT,
                device_type TEXT DEFAULT 'managed',
                status TEXT DEFAULT 'online',
                vendor TEXT DEFAULT '',
                logged_in_user TEXT DEFAULT '',
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_conflict INTEGER DEFAULT 0,
                details TEXT DEFAULT ''
            );
        """)

        # Indexes for high-speed lookups during high-frequency ARP sweeps
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_history_ip ON ip_history(ip);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_history_time ON ip_history(timestamp DESC);")
    conn.close()
    log.info("Initialized Mneti database at %s", path)


def record_ip_observation(
    ip: str,
    mac: str,
    hostname: str = None,
    building: str = None,
    room: str = None,
    subnet: str = None,
    device_type: str = None,
    logged_in_user: str = None,
    vendor: str = None,
    db_path: str = None
) -> dict:
    """
    Records an observed (IP, MAC) pair from either agent telemetry or ARP sweeps.
    Checks for IP collisions: If the same IP address is already registered to a DIFFERENT MAC,
    flags an IP collision / conflict and updates status.
    """
    if not ip or not mac:
        return {"error": "IP and MAC are required"}

    ip = ip.strip()
    mac = mac.strip().upper()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db(db_path)
    conflict_detected = False
    existing_mac = None
    device_name = hostname or f"Host-{ip}"

    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, ip, mac, hostname, status, building, room, subnet, device_type FROM devices WHERE ip = ?", (ip,))
            row = cursor.fetchone()

            if row:
                existing_mac = row["mac"].upper()
                if existing_mac != mac:
                    # ── IP CONFLICT DETECTED ──────────────────────────────────
                    conflict_detected = True
                    details = f"Collision: {ip} is claimed by {existing_mac} and new MAC {mac}"
                    log.critical(
                        "[SECURITY ALERT] IP Collision on %s! Known MAC: %s vs Rogue/Colliding MAC: %s",
                        ip, existing_mac, mac
                    )

                    # Update device status to conflict
                    cursor.execute("""
                        UPDATE devices 
                        SET status = 'conflict',
                            last_seen = ?,
                            vendor = COALESCE(?, vendor)
                        WHERE ip = ?
                    """, (now_str, vendor, ip))

                    # Log conflict event in history
                    cursor.execute("""
                        INSERT INTO ip_history (ip, mac, timestamp, is_conflict, details)
                        VALUES (?, ?, ?, 1, ?)
                    """, (ip, mac, now_str, details))

                    return {
                        "conflict": True,
                        "ip": ip,
                        "registered_mac": existing_mac,
                        "colliding_mac": mac,
                        "device_id": row["id"],
                        "message": details
                    }
                else:
                    # Known device check-in - update attributes if provided
                    cursor.execute("""
                        UPDATE devices
                        SET status = CASE WHEN status = 'conflict' THEN 'conflict' ELSE 'online' END,
                            hostname = COALESCE(?, hostname),
                            building = COALESCE(?, building),
                            room = COALESCE(?, room),
                            subnet = COALESCE(?, subnet),
                            device_type = COALESCE(?, device_type),
                            logged_in_user = COALESCE(?, logged_in_user),
                            vendor = COALESCE(?, vendor),
                            last_seen = ?
                        WHERE ip = ?
                    """, (hostname, building, room, subnet, device_type, logged_in_user, vendor, now_str, ip))

                    cursor.execute("""
                        INSERT INTO ip_history (ip, mac, timestamp, is_conflict, details)
                        VALUES (?, ?, ?, 0, 'Periodic check-in')
                    """, (ip, mac, now_str))

                    return {"conflict": False, "ip": ip, "mac": mac, "status": row["status"]}
            else:
                # Brand new device discovered on network
                cursor.execute("""
                    INSERT INTO devices (ip, mac, hostname, building, room, subnet, device_type, status, vendor, logged_in_user, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'online', ?, ?, ?)
                """, (
                    ip,
                    mac,
                    device_name,
                    building or "Unassigned",
                    room or "General",
                    subnet or _infer_subnet(ip),
                    device_type or "unmanaged",
                    vendor or "",
                    logged_in_user or "",
                    now_str
                ))

                cursor.execute("""
                    INSERT INTO ip_history (ip, mac, timestamp, is_conflict, details)
                    VALUES (?, ?, ?, 0, 'Initial discovery')
                """, (ip, mac, now_str))

                return {"conflict": False, "ip": ip, "mac": mac, "status": "online", "new_device": True}

    finally:
        conn.close()


def _infer_subnet(ip: str) -> str:
    """Helper to derive subnet from IP for display."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "Unknown Subnet"


def resolve_conflict(ip: str, authorized_mac: str = None, db_path: str = None) -> bool:
    """Manually or programmatically clears a conflict state."""
    conn = get_db(db_path)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with conn:
        if authorized_mac:
            conn.execute("""
                UPDATE devices 
                SET status = 'online', mac = ?, last_seen = ? 
                WHERE ip = ?
            """, (authorized_mac.strip().upper(), now_str, ip))
        else:
            conn.execute("""
                UPDATE devices 
                SET status = 'online', last_seen = ? 
                WHERE ip = ?
            """, (now_str, ip))
    conn.close()
    return True


def get_all_devices(db_path: str = None) -> list[dict]:
    conn = get_db(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY subnet ASC, ip ASC;")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_active_conflicts(db_path: str = None) -> list[dict]:
    conn = get_db(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE status = 'conflict' ORDER BY last_seen DESC;")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_topology_data(db_path: str = None) -> dict:
    """
    Constructs structured nodes and edges for Vis.js rendering.
    Maps:
      Core Router -> Department Subnet Switches -> Individual Devices
    Colors:
      - Router/Switch: Deep Navy Blue
      - Managed Agent: Emerald Green
      - Unmanaged Device: Amber/Orange
      - Conflict: Bright Flashing Red
    """
    devices = get_all_devices(db_path)
    nodes = []
    edges = []

    # 1. Root Core Router Node
    nodes.append({
        "id": "core-router",
        "label": "NCRTH Core Gateway\n10.100.0.1",
        "title": "Hospital Core Router (Cisco Catalyst 9500)\nLocation: Central Server Room",
        "group": "router",
        "shape": "box",
        "color": {
            "background": "#0f172a",
            "border": "#38bdf8",
            "highlight": {"background": "#1e293b", "border": "#7dd3fc"}
        },
        "font": {"color": "#f8fafc", "face": "monospace", "size": 13, "bold": True},
        "level": 0
    })

    # Department Subnets mapping to virtual switches
    department_switches = {
        "Pharmacy": {"id": "sw-pharm", "label": "Switch-Pharm\n10.100.10.1", "subnet": "10.100.10.0/24", "location": "Outpatient Pavilion"},
        "Radiology": {"id": "sw-rad", "label": "Switch-Radiology\n10.100.20.1", "subnet": "10.100.20.0/24", "location": "Imaging Center"},
        "Laboratory": {"id": "sw-lab", "label": "Switch-Lab\n10.100.30.1", "subnet": "10.100.30.0/24", "location": "Pathology Wing"},
        "Triage": {"id": "sw-triage", "label": "Switch-Triage/ER\n10.100.40.1", "subnet": "10.100.40.0/24", "location": "Casualty Block"},
        "Admin": {"id": "sw-admin", "label": "Switch-Admin\n10.100.50.1", "subnet": "10.100.50.0/24", "location": "Admin Block"}
    }

    # Add Department Switches to Nodes and connect them to Core Router
    for dept, sw in department_switches.items():
        nodes.append({
            "id": sw["id"],
            "label": sw["label"],
            "title": f"Managed Distribution Switch\nSubnet: {sw['subnet']}\nBuilding: {sw['location']}",
            "group": "switch",
            "shape": "box",
            "color": {
                "background": "#1e293b",
                "border": "#0ea5e9",
                "highlight": {"background": "#334155", "border": "#38bdf8"}
            },
            "font": {"color": "#e2e8f0", "face": "monospace", "size": 11, "bold": True},
            "level": 1
        })
        edges.append({
            "from": "core-router",
            "to": sw["id"],
            "color": {"color": "#64748b", "highlight": "#38bdf8"},
            "width": 3,
            "dashes": False
        })

    has_conflict = False
    conflict_list = []

    # 2. Add devices and connect to their respective department switch
    for dev in devices:
        # Determine parent switch
        subnet_str = dev.get("subnet", "")
        parent_sw = "sw-admin"  # default fallback
        for dept, sw in department_switches.items():
            if sw["subnet"] == subnet_str or dept.lower() in (dev.get("building", "") + dev.get("room", "")).lower():
                parent_sw = sw["id"]
                break

        is_conflict = (dev.get("status") == "conflict")
        dev_type = dev.get("device_type", "managed")

        if is_conflict:
            has_conflict = True
            conflict_list.append(dev)
            node_color = {
                "background": "#ef4444",
                "border": "#b91c1c",
                "highlight": {"background": "#dc2626", "border": "#991b1b"}
            }
            font_color = "#ffffff"
            shape = "diamond"
            size = 28
            border_width = 3
        elif dev_type == "managed":
            node_color = {
                "background": "#10b981",
                "border": "#059669",
                "highlight": {"background": "#059669", "border": "#047857"}
            }
            font_color = "#f0fdf4"
            shape = "dot"
            size = 18
            border_width = 2
        else: # unmanaged
            node_color = {
                "background": "#f59e0b",
                "border": "#d97706",
                "highlight": {"background": "#d97706", "border": "#b45309"}
            }
            font_color = "#fffbeb"
            shape = "triangle"
            size = 18
            border_width = 2

        node_id = f"dev-{dev['id']}"
        label = f"{dev['hostname']}\n{dev['ip']}"
        if is_conflict:
            label = f"⚠️ CONFLICT!\n{dev['hostname']}\n{dev['ip']}"

        tooltip = (
            f"Hostname: {dev['hostname']}\n"
            f"IP: {dev['ip']}\n"
            f"MAC: {dev['mac']}\n"
            f"Location: {dev['building']} - {dev['room']}\n"
            f"Subnet: {dev['subnet']}\n"
            f"Type: {dev_type.upper()}\n"
            f"Status: {dev['status'].upper()}\n"
            f"Vendor: {dev.get('vendor') or 'N/A'}\n"
            f"Last Seen: {dev['last_seen']}"
        )

        nodes.append({
            "id": node_id,
            "label": label,
            "title": tooltip,
            "group": dev_type,
            "shape": shape,
            "size": size,
            "color": node_color,
            "borderWidth": border_width,
            "font": {"color": font_color, "face": "sans-serif", "size": 10},
            "level": 2,
            "raw_device": dev
        })

        # Edge from department switch to device
        edge_color = "#ef4444" if is_conflict else ("#10b981" if dev_type == "managed" else "#f59e0b")
        edges.append({
            "from": parent_sw,
            "to": node_id,
            "color": {"color": edge_color, "highlight": "#ffffff"},
            "width": 2 if not is_conflict else 4,
            "dashes": True if dev_type == "unmanaged" else False
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "has_conflict": has_conflict,
        "conflicts": conflict_list,
        "device_count": len(devices),
        "managed_count": sum(1 for d in devices if d.get("device_type") == "managed"),
        "unmanaged_count": sum(1 for d in devices if d.get("device_type") != "managed"),
    }
