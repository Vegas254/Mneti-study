"""
qt/main_window.py  (patched v6)

Changes in this release (v6)
─────────────────────────────
1. New "IP History" sidebar page. Lets you pick a date (calendar popup —
   no typing) and either browse every IP change logged that whole day, or
   check "At specific time" (a time picker) to ask "what IP was active at
   this exact moment". An optional IP filter answers "who had this IP at
   that time/day". This broadcasts a small signed "ip_history" query
   (DiscoveryBroadcaster.send_ip_history_query) — nothing is stored
   centrally or sent proactively; each agent answers from its own local
   log only in direct response to this query, exactly like an ordinary
   targeted discovery request. Replies land in a dedicated
   IPHistoryResultStore (which, unlike ResultStore, does NOT merge/dedupe
   by MAC — a single query can legitimately return many rows for the same
   computer). All timestamps are converted to local time before display.
2. ApiServerThread now takes a second store (ip_history_store) and routes
   "ip_history" query replies to it via a new ip_history_reported signal,
   separate from the existing device_reported signal used by ordinary
   discovery. See qt/api_server.py.
3. Discover view gained a "Ranges" field. When filled (comma-separated,
   same formats as the Broadcast Ranges tab, e.g. "10.51.144.1-254,
   10.51.145.1-254"), both Full Network Discovery Scan and Targeted
   Discovery are restricted to just those ranges — via the new
   DiscoveryBroadcaster.broadcast_to_ranges() and a matching ARP-scan
   restriction in _BroadcastWorker — instead of the whole subnet /
   saved custom ranges. Leaving it blank preserves all existing
   behaviour exactly as before.

Changes carried over from v5
─────────────────────────────
1. New "Network Map" sidebar page (qt/topology_widget.py) for tracing how
   switches/routers/wall ports/media converters interconnect, rooted at a
   single "Internet Entry Point" node. Nodes can be added manually or are
   auto-populated from switch_name/router_name/port fields already present
   on discovered devices. See qt/topology.py for the persisted graph model.
2. Every device arrival (API report or internal ARP scan result) now also
   feeds qt/topology.py's TopologyStore, so the map stays in sync with
   discovery in the background without the user needing to do anything.

Changes carried over from v4
─────────────────────────────
1. Vendor fallback fixed: _resolve_vendor() now falls back to the real
   manuf-backed lookup_vendor() (qt/logic.py) instead of the tiny ~40-entry
   hardcoded _OUI dict. The small dict is now only a last-resort fallback
   if manuf itself is unavailable.
2. "New Session" crash fixed: _BroadcastWorker.run() previously had no way
   to be cancelled — thread.quit()/wait(2000) did nothing useful because the
   worker doesn't run its own Qt event loop, it just executes run() to
   completion synchronously in the moved-to thread. If a scan was still
   running when reset_session() was clicked, _stop_worker() would drop
   Python's only references to the still-alive QThread/worker, which can
   segfault the whole process once the orphaned native thread later tries
   to emit a signal or call deleteLater() on a half-collected wrapper.
   Fixed by:
     - Threading a cancel_event (threading.Event) into _BroadcastWorker and
       into scan_subnet(), checked between pings/subnets/results so a
       cancel request actually cuts a scan short instead of running to
       completion unattended.
     - _stop_worker() now sets the cancel event first, and if the thread
       still hasn't finished after the wait, it is kept in a
       self._retiring_threads list (a real Python reference) until its
       `finished` signal fires, instead of being silently dropped.

Changes carried over from v3
─────────────────────────────
1. No row colours — all rows white; alternating rows via Qt stylesheet only.
2. Timestamp displayed in local time (converted from UTC ISO string).
3. Vendor column populated: Python-side OUI lookup as fallback when the
   agent sends an empty vendor string.
4. Dark-mode text visibility — QTableWidget and child items are forced to
   the palette foreground colour so text is always readable.
5. Target widget uses QComboBox dropdown + rewritten MAC/IP inputs.
6. Relay metadata on unmanaged hotspot devices (building/room from relay host).
"""

import uuid
import time
import csv
import threading
import re
from datetime import datetime, timezone, timedelta

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QStackedWidget, QListWidget, QListWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QLineEdit, QFileDialog,
    QFrame, QCheckBox, QMessageBox, QDateEdit, QTimeEdit, QDateTimeEdit,
    QComboBox, QProgressBar, QPlainTextEdit,
)
from PyQt6.QtCore import Qt, pyqtSlot, QTimer, pyqtSignal, QThread, QObject, QDate, QTime, QDateTime
from PyQt6.QtGui import QColor, QPalette

from qt.logic import (
    Config, ResultStore, IPHistoryResultStore, DiscoveryBroadcaster,
    get_lan_ip, parse_custom_range,
)
from qt.widgets import StatCard, FilterChipsBar
from qt.api_server import ApiServerThread
from qt.styles import LIGHT_STYLE, DARK_STYLE
from qt.logic import scan_subnet, lookup_vendor
from qt.target_widget import TargetInputWidget
from qt.topology import TopologyStore
from qt.topology_widget import TopologyPage
from qt.update_deploy import UpdateServer


# ── OUI vendor lookup (Python-side LAST-RESORT fallback) ──────────────────────
# NOTE: this small hand-curated table is now only used if the real
# manuf-backed lookup_vendor() (qt/logic.py) is unavailable or returns
# nothing. Previously this was checked BEFORE lookup_vendor, which is why
# only devices matching this short list ever showed a vendor — manuf was
# silently failing to load inside the frozen .exe (see logic.py for the fix
# and the required PyInstaller --add-data flag).

_OUI = {
    '00:50:56': 'VMware',     '00:0C:29': 'VMware',    '00:15:5D': 'Hyper-V',
    '08:00:27': 'VirtualBox', '52:54:00': 'QEMU',
    'B8:27:EB': 'Raspberry Pi','DC:A6:32': 'Raspberry Pi',
    '00:1A:11': 'Google',     'A4:C3:F0': 'Google',
    'AC:BC:32': 'Apple',      '3C:22:FB': 'Apple',     '00:17:F2': 'Apple',
    '00:1B:21': 'Intel',      '34:97:F6': 'Intel',     '8C:8D:28': 'Intel',
    '14:18:77': 'Dell',       '00:23:AE': 'Dell',
    'B4:B6:86': 'HP',         '3C:D9:2B': 'HP',
    '18:70:3B': 'Huawei',     '40:B0:76': 'Huawei',    'E8:CD:2D': 'Huawei',
    '00:9A:CD': 'Huawei',     'F4:9F:54': 'Huawei',    '28:31:52': 'Huawei',
    'C8:14:79': 'Samsung',    '00:07:AB': 'Samsung',   '8C:77:12': 'Samsung',
    '00:26:37': 'Samsung',    'A0:75:91': 'Samsung',   '78:1F:DB': 'Samsung',
    '98:DE:D0': 'Xiaomi',     '28:6C:07': 'Xiaomi',    '64:09:80': 'Xiaomi',
    'AC:C1:EE': 'Oppo',
    '00:1A:7D': 'Realtek',    '00:E0:4C': 'Realtek',
    '00:1C:73': 'Aruba',      '00:0B:86': 'Aruba',
    'F4:DB:E6': 'TP-Link',    '50:C7:BF': 'TP-Link',   'C8:D3:A3': 'TP-Link',
    'CC:40:D0': 'Cisco',      '00:1B:54': 'Cisco',     '00:16:47': 'Cisco',
    '18:B4:30': 'Nest',
}


def _resolve_vendor(mac: str, agent_vendor: str) -> str:
    """
    Return vendor string, preferring (in order):
      1. What the agent/server already sent (agent_vendor).
      2. The real manuf-backed lookup_vendor() — full IEEE OUI database.
      3. The small hardcoded _OUI dict, only as an absolute last resort.
    """
    if agent_vendor and agent_vendor.strip():
        return agent_vendor.strip()

    vendor = lookup_vendor(mac)
    if vendor:
        return vendor

    if mac and len(mac) >= 8:
        prefix = mac[:8].upper()
        return _OUI.get(prefix, '')
    return ''


# ── Agent version extraction ───────────────────────────────────────────────────

_AGENT_VERSION_RE = re.compile(r'^\s*\$AGENT_VERSION\s*=\s*[\'"]([^\'"]+)[\'"]', re.MULTILINE)


def _extract_agent_version(file_path: str) -> str | None:
    """
    Reads the $AGENT_VERSION = '...' line out of a candidate start-Mneti.ps1
    file. This is the single source of truth an agent uses to decide
    whether an announced update is actually newer than what it's running —
    so the dashboard reads it directly from the file rather than trusting a
    separately-typed version string that could drift out of sync with it.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        m = _AGENT_VERSION_RE.search(content)
        return m.group(1).strip() if m else None
    except Exception:
        return None


# ── Timestamp helper ──────────────────────────────────────────────────────────

def _utc_to_local(ts: str) -> str:
    """
    Convert a UTC ISO-8601 string (e.g. '2026-07-04T11:05:31Z') to local
    wall-clock time formatted as 'YYYY-MM-DD HH:MM:SS'.
    Falls back to the original string if parsing fails.
    """
    if not ts:
        return ''
    ts = ts.strip()
    for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%S+00:00', '%Y-%m-%dT%H:%M:%S'):
        try:
            dt_utc   = datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            dt_local = dt_utc.astimezone()          # converts to local tz
            return dt_local.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
    # Already a plain string like '2026-07-04 11:05:31' — return as-is
    return ts.replace('T', ' ').split('.')[0][:19]


# ── Column layout ─────────────────────────────────────────────────────────────

_COLUMNS = [
    ("Hostname",      "hostname",        220),
    ("IP Address",    "ip",              130),
    ("MAC Address",   "mac",             150),
    ("Username",      "username",        120),
    ("Building",      "building",        120),
    ("Room",          "room",             90),
    ("Type",          "type",             90),
    ("Connection",    "connection_type",  90),
    ("Port / Name",   "_port_display",   120),
    ("Vendor",        "_vendor_display", 110),
    ("Relay Host",    "relay_host",      130),
    ("Timestamp",     "_local_ts",       160),
]


def _device_matches_filter(device: dict, filter_key: str) -> bool:
    dtype = device.get("type", "unmanaged")
    relay = device.get("relay_host", "")
    if filter_key == "all":
        return True
    if filter_key == "managed":
        return dtype == "managed"
    if filter_key == "managed_hotspot":
        return dtype == "relayed"
    if filter_key == "unmanaged_hotspot":
        return dtype == "unmanaged" and bool(relay)
    if filter_key == "unmanaged":
        return dtype == "unmanaged" and not relay
    return True


def _device_matches_search(device: dict, query: str) -> bool:
    if not query:
        return True
    q = query.lower()
    searchable = (
        device.get("hostname", "")       + device.get("ip", "") +
        device.get("mac", "")            + device.get("room", "") +
        device.get("building", "")       + device.get("username", "") +
        device.get("type", "")           + device.get("relay_host", "") +
        device.get("connection_type", "")
    ).lower()
    return q in searchable


def _port_display(device: dict) -> str:
    conn = device.get("connection_type", "")
    if conn == "Switch":
        return device.get("switch_name", "") or ""
    if conn == "Router":
        return device.get("router_name", "") or ""
    if conn == "Hotspot":
        return ""
    port  = device.get("port", "")
    extra = device.get("additional_ports", [])
    if extra:
        all_ports = [port] + [str(p) for p in extra if str(p) != port]
        return ", ".join(p for p in all_ports if p)
    return port or ""


def _cell_text(device: dict, key: str) -> str:
    if key == "_port_display":
        return _port_display(device)
    if key == "_vendor_display":
        return _resolve_vendor(device.get("mac", ""), device.get("vendor", ""))
    if key == "_local_ts":
        return _utc_to_local(device.get("timestamp", ""))
    val = device.get(key, "")
    if isinstance(val, list):
        return ", ".join(str(p) for p in val)
    return str(val) if val else ""


# ── Optimised DeviceTable ─────────────────────────────────────────────────────

class OptimisedDeviceTable(QTableWidget):
    """
    High-performance device table.
    • No row background colours (all white / palette default).
    • Bulk mutations wrapped in setUpdatesEnabled(False)+setSortingEnabled(False).
    • Existing rows are reused; only changed cells are rewritten.
    • Dark-mode aware: item foreground follows the widget palette.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(_COLUMNS))
        self.setHorizontalHeaderLabels([c[0] for c in _COLUMNS])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        for i, (_, _, width) in enumerate(_COLUMNS):
            self.setColumnWidth(i, width)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)

    def update_devices(self, devices: list, filter_key: str = "all", search: str = ""):
        visible = [
            d for d in devices
            if _device_matches_filter(d, filter_key)
            and _device_matches_search(d, search)
        ]

        self.setUpdatesEnabled(False)
        self.setSortingEnabled(False)

        current_rows = self.rowCount()
        needed_rows  = len(visible)

        if needed_rows > current_rows:
            self.setRowCount(needed_rows)

        # Use the widget's current palette foreground for text colour
        fg = self.palette().color(QPalette.ColorRole.Text)

        for row_idx, device in enumerate(visible):
            for col_idx, (_, key, _) in enumerate(_COLUMNS):
                cell_text = _cell_text(device, key)
                existing  = self.item(row_idx, col_idx)
                if existing is None:
                    item = QTableWidgetItem(cell_text)
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    item.setForeground(fg)
                    self.setItem(row_idx, col_idx, item)
                else:
                    if existing.text() != cell_text:
                        existing.setText(cell_text)
                    existing.setForeground(fg)

        if needed_rows < current_rows:
            self.setRowCount(needed_rows)

        self.setSortingEnabled(True)
        self.setUpdatesEnabled(True)

    def apply_theme(self, dark: bool):
        """Call after a theme change so existing rows pick up the new colour."""
        fg = self.palette().color(QPalette.ColorRole.Text)
        self.setUpdatesEnabled(False)
        for row in range(self.rowCount()):
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    item.setForeground(fg)
        self.setUpdatesEnabled(True)


# ── Background worker ─────────────────────────────────────────────────────────

class _BroadcastWorker(QObject):
    device_found = pyqtSignal(str, dict)
    finished     = pyqtSignal()

    def __init__(self, broadcaster, store, session_id: str,
                 mode: str = "full", target: str = "",
                 cancel_event: "threading.Event | None" = None,
                 ranges: "list | None" = None):
        super().__init__()
        self._broadcaster = broadcaster
        self._store       = store
        self._session_id  = session_id
        self._mode        = mode
        self._target      = target
        self._cancel      = cancel_event if cancel_event is not None else threading.Event()
        # When set, restricts both the broadcast and the ARP scan portion
        # to just these range strings instead of the whole subnet / saved
        # custom ranges. None/empty preserves all prior behaviour.
        self._ranges      = ranges or None

    def cancel(self):
        """Request cooperative cancellation. Checked at multiple points in run()."""
        self._cancel.set()

    def run(self):
        try:
            if self._ranges:
                self._broadcaster.broadcast_to_ranges(
                    self._session_id, self._mode, self._target, self._ranges)
            else:
                self._broadcaster.broadcast(self._session_id, self._mode, self._target)

            if self._cancel.is_set():
                return

            if self._mode == "full":
                # Sleep in small increments instead of one blocking 3s call,
                # so a cancel request is noticed quickly rather than only
                # after the full sleep elapses.
                for _ in range(30):
                    if self._cancel.is_set():
                        return
                    time.sleep(0.1)

                if self._ranges:
                    networks = []
                    for r in self._ranges:
                        pr = parse_custom_range(r)
                        if pr:
                            networks.append(pr.network)
                else:
                    networks = self._broadcaster.get_scan_networks()

                for net in networks:
                    if self._cancel.is_set():
                        return
                    found = scan_subnet(net, cancel_event=self._cancel)
                    if self._cancel.is_set():
                        return
                    for ip, mac in found.items():
                        if self._cancel.is_set():
                            return
                        device = {
                            "hostname":    f"Unmanaged-{ip}",
                            "mac":         mac,
                            "ip":          ip,
                            "type":        "unmanaged",
                            "vendor":      lookup_vendor(mac),
                            "timestamp":   datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            "reporter_ip": "internal-arp-scan",
                        }
                        self._store.add_result(self._session_id, device)
                        self.device_found.emit(self._session_id, device)
        finally:
            self.finished.emit()


# ── MainWindow ────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    _arp_device_arrived = pyqtSignal(str, dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mneti — Administrative Discovery Dashboard")
        self.resize(1200, 750)

        self.countdown_val   = 0
        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self._update_countdown)

        self._batch_timer = QTimer()
        self._batch_timer.setSingleShot(True)
        self._batch_timer.setInterval(400)
        self._batch_timer.timeout.connect(self._do_refresh_table)

        self._arp_device_arrived.connect(self._on_arp_device)

        self.store       = ResultStore()
        self.ip_history_store = IPHistoryResultStore()
        self.broadcaster = DiscoveryBroadcaster(self.store)
        self.topology_store = TopologyStore()
        self.active_session_id = None
        self.current_filter    = "all"
        self.is_dark_mode      = False

        self._worker_thread: QThread | None = None
        self._worker: _BroadcastWorker | None = None
        self._worker_cancel: "threading.Event | None" = None
        # Threads that didn't finish within the grace period on reset — kept
        # here with a real Python reference until their `finished` signal
        # fires, instead of being dropped (which risked a native crash; see
        # module docstring at the top of this file for the full story).
        self._retiring_threads: list = []

        # IP History query session bookkeeping (separate from the main
        # discovery active_session_id, since a user could in principle
        # look at IP History while a full/targeted scan is also running).
        self.iph_active_session_id = None
        self._iph_timer = QTimer()
        self._iph_timer.setSingleShot(True)
        self._iph_timer.timeout.connect(self._finish_ip_history_query)

        self.api_thread = ApiServerThread(self.store, self.ip_history_store)
        self.api_thread.device_reported.connect(self.on_device_reported)
        self.api_thread.ip_history_reported.connect(self._on_ip_history_device)
        self.api_thread.start()

        self.update_server = UpdateServer()
        self.update_server.log_message.connect(self._on_deploy_log)
        self.update_server.agent_connected.connect(self._on_deploy_agent_connected)

        self._setup_ui()
        self.set_theme(False)
        self.show_view("discover")

    # ── UI setup ──────────────────────────────────────────────────────────────

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        self.sidebar = QWidget()
        self.sidebar.setObjectName("Sidebar")
        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(0, 20, 0, 20)

        logo = QLabel("MNETI")
        logo.setStyleSheet("font-size:18px; font-weight:bold; margin-bottom:20px; padding:10px 20px;")
        sb_layout.addWidget(logo)

        self.nav_btns = {}
        for key, text in [
            ("discover", "◈ Discover Devices"),
            ("ranges",   "⊞ Broadcast Ranges"),
            ("topology", "▦ Network Map"),
            ("iphistory", "◴ IP History"),
            ("deploy",   "↑ Deploy Update"),
            ("history",  "◷ Session History"),
        ]:
            btn = QPushButton(text)
            btn.clicked.connect(lambda _c, k=key: self.show_view(k))
            sb_layout.addWidget(btn)
            self.nav_btns[key] = btn

        sb_layout.addStretch()

        self.theme_btn = QPushButton("🌙 Dark Mode")
        self.theme_btn.clicked.connect(self.toggle_theme)
        sb_layout.addWidget(self.theme_btn)

        info = QLabel(f"Server: Online\nIP: {get_lan_ip()}")
        info.setStyleSheet("font-size:11px; color:#777; padding:20px;")
        sb_layout.addWidget(info)

        main_layout.addWidget(self.sidebar)

        self.content_stack = QStackedWidget()
        main_layout.addWidget(self.content_stack)

        self._init_discover_view()      # index 0
        self._init_ranges_view()        # index 1
        self._init_topology_view()      # index 2
        self._init_ip_history_view()    # index 3
        self._init_deploy_view()        # index 4
        self._init_history_view()       # index 5

    # ── Discover view ─────────────────────────────────────────────────────────

    def _init_discover_view(self):
        page   = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        header = QHBoxLayout()
        title_v = QVBoxLayout()
        title_v.addWidget(QLabel("Discovery Dashboard",
                                 styleSheet="font-size:20px; font-weight:bold;"))
        title_v.addWidget(QLabel("Network device location system",
                                 styleSheet="font-size:11px; color:#666;"))
        header.addLayout(title_v)
        header.addStretch()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search IP, MAC, room…")
        self.search_input.setFixedWidth(220)
        self.search_input.textChanged.connect(self._schedule_refresh)
        header.addWidget(self.search_input)
        header.addSpacing(8)

        self.reset_btn = QPushButton("↺ New Session")
        self.reset_btn.clicked.connect(self.reset_session)
        header.addWidget(self.reset_btn)

        self.export_btn = QPushButton("⬇ Export CSV")
        self.export_btn.setObjectName("Primary")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_csv)
        header.addWidget(self.export_btn)

        layout.addLayout(header)

        # Progress banner
        self.progress_panel = QFrame()
        self.progress_panel.setObjectName("Panel")
        self.progress_panel.setStyleSheet(
            "background-color:#f0f7ff; border:1px solid #cce5ff; border-radius:5px;")
        self.progress_panel.hide()
        pp_layout = QHBoxLayout(self.progress_panel)
        self.status_label = QLabel("SEARCHING...")
        self.status_label.setStyleSheet("color:#0366d6; font-weight:bold; font-size:13px;")
        pp_layout.addWidget(self.status_label)
        pp_layout.addStretch()
        layout.addWidget(self.progress_panel)

        # Stat cards
        self.stats_bar = QHBoxLayout()
        self.stat_cards = {
            "all":               StatCard("Total Discovered",  0, "#6c757d", "all"),
            "managed":           StatCard("Managed",           0, "#0366d6", "managed"),
            "managed_hotspot":   StatCard("Relayed",           0, "#28a745", "managed_hotspot"),
            "unmanaged_hotspot": StatCard("Unmanaged Hotspot", 0, "#f59f00", "unmanaged_hotspot"),
            "unmanaged":         StatCard("Unmanaged",         0, "#dc3545", "unmanaged"),
        }
        for card in self.stat_cards.values():
            card.clicked.connect(self._on_stat_card_clicked)
            self.stats_bar.addWidget(card)
        layout.addLayout(self.stats_bar)

        # Action panels
        panels = QHBoxLayout()

        target_panel = QFrame()
        target_panel.setObjectName("Panel")
        tp_layout = QVBoxLayout(target_panel)
        tp_layout.addWidget(QLabel("Targeted Discovery",
                                   styleSheet="font-weight:bold; font-size:14px;"))
        self.target_widget = TargetInputWidget()
        self.target_widget.search_requested.connect(self.start_targeted_discovery)
        tp_layout.addWidget(self.target_widget)
        tp_layout.addWidget(QLabel(
            "Sends a UDP broadcast. Only the matching device responds. "
            "Switch the dropdown to \"IP Range\" to scan just one range "
            "instead of a single MAC/IP.",
            styleSheet="font-size:11px; color:#6c757d; margin-top:4px;"))
        panels.addWidget(target_panel)

        full_panel = QFrame()
        full_panel.setObjectName("Panel")
        fp_layout = QVBoxLayout(full_panel)
        fp_layout.addWidget(QLabel("Full Network Discovery Scan",
                                   styleSheet="font-weight:bold; font-size:14px;"))
        fp_layout.addWidget(QLabel(
            "Broadcast discovery to all clients — including custom ranges. "
            "All listening devices will report their location. To scan only "
            "one range, use \"IP Range\" mode in Targeted Discovery instead.",
            styleSheet="font-size:13px; color:#555; margin-bottom:12px;"))
        btn_all = QPushButton("Scan Network")
        btn_all.setObjectName("Primary")
        btn_all.clicked.connect(self.start_full_discovery)
        fp_layout.addWidget(btn_all)
        fp_layout.addStretch()
        panels.addWidget(full_panel)

        layout.addLayout(panels)

        self.chips_bar = FilterChipsBar()
        self.chips_bar.filter_changed.connect(self._on_chip_filter_changed)
        layout.addWidget(self.chips_bar)

        self.table = OptimisedDeviceTable()
        layout.addWidget(self.table)

        self.content_stack.addWidget(page)

    # ── Ranges view ───────────────────────────────────────────────────────────

    def _init_ranges_view(self):
        page   = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)

        layout.addWidget(QLabel("Broadcast Ranges",
                                styleSheet="font-size:20px; font-weight:bold;"))
        layout.addWidget(QLabel("Define custom subnets for discovery broadcasts",
                                styleSheet="margin-bottom:20px;"))

        form_panel = QFrame()
        form_panel.setObjectName("Panel")
        form_h = QHBoxLayout(form_panel)
        self.range_input = QLineEdit()
        self.range_input.setPlaceholderText("e.g. 10.51.144.1-254")
        self.range_input.setStyleSheet("font-family:Consolas,monospace;")
        self.range_input.returnPressed.connect(self.add_custom_range)

        add_btn = QPushButton("Add")
        add_btn.setObjectName("Primary")
        add_btn.clicked.connect(self.add_custom_range)

        scan_now_btn = QPushButton("Scan This Range Now")
        scan_now_btn.clicked.connect(self.scan_immediate_range)

        self.primary_checkbox = QCheckBox("Mark as Primary")
        self.primary_checkbox.setToolTip(
            "Agents report wall ports only when discovery comes from a primary subnet.")

        form_h.addWidget(QLabel("Add Range:"))
        form_h.addWidget(self.range_input, 1)
        form_h.addWidget(self.primary_checkbox)
        form_h.addWidget(add_btn)
        form_h.addWidget(scan_now_btn)
        layout.addWidget(form_panel)

        self.range_preview = QLabel("")
        self.range_preview.setStyleSheet(
            "font-size:11px; color:#6c757d; font-family:Consolas,monospace;")
        layout.addWidget(self.range_preview)
        self.range_input.textChanged.connect(self.update_range_preview)

        list_header = QHBoxLayout()
        list_header.addWidget(QLabel("Saved Discovery Ranges",
                                     styleSheet="font-weight:bold; margin-top:10px;"))
        list_header.addStretch()
        scan_all_btn = QPushButton("Scan All Saved Ranges")
        scan_all_btn.clicked.connect(self.scan_all_custom_ranges)
        list_header.addWidget(scan_all_btn)
        layout.addLayout(list_header)

        self.ranges_list = QListWidget()
        self.ranges_list.setObjectName("Panel")
        layout.addWidget(self.ranges_list)

        bottom_btns = QHBoxLayout()
        del_btn = QPushButton("Delete Selected")
        del_btn.clicked.connect(self.delete_custom_range)
        bottom_btns.addWidget(del_btn)
        bottom_btns.addStretch()
        layout.addLayout(bottom_btns)

        self.content_stack.addWidget(page)
        self.refresh_ranges_list()

    # ── Network Map (topology) view ──────────────────────────────────────────

    def _init_topology_view(self):
        self.topology_page = TopologyPage(self.topology_store, self.store)
        self.content_stack.addWidget(self.topology_page)

    # ── IP History view ───────────────────────────────────────────────────────

    def _init_ip_history_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(QLabel("IP History",
                                styleSheet="font-size:20px; font-weight:bold;"))
        layout.addWidget(QLabel(
            "Broadcasts a query that every agent answers from its own local "
            "IP log — nothing is stored centrally or sent unless you run a "
            "query here. Times shown are your local time.",
            styleSheet="color:#666; margin-bottom:10px;"))

        form = QFrame()
        form.setObjectName("Panel")
        fl = QHBoxLayout(form)

        fl.addWidget(QLabel("Query:"))
        self.iph_query_type = QComboBox()
        self.iph_query_type.addItem("Whole Day")
        self.iph_query_type.addItem("At Specific Time")
        self.iph_query_type.addItem("Time Range")
        self.iph_query_type.currentIndexChanged.connect(self._on_iph_query_type_changed)
        fl.addWidget(self.iph_query_type)

        # ── Whole Day widgets ────────────────────────────────────────────────
        self.iph_date = QDateEdit(calendarPopup=True)
        self.iph_date.setDate(QDate.currentDate())
        fl.addWidget(self.iph_date)

        # ── At Specific Time widgets (reuses iph_date for the date part) ───────
        self.iph_time = QTimeEdit()
        self.iph_time.setTime(QTime.currentTime())
        self.iph_time.hide()
        fl.addWidget(self.iph_time)

        # ── Time Range widgets (NEW) — independent start/end date+time, so a
        # range can span multiple days, e.g. an entire weekend, without
        # needing to know an exact moment on either end. ────────────────────
        self.iph_range_start = QDateTimeEdit(calendarPopup=True)
        self.iph_range_start.setDateTime(QDateTime.currentDateTime().addSecs(-3600))
        self.iph_range_start.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.iph_range_start.hide()
        fl.addWidget(QLabel("from:"))
        fl.addWidget(self.iph_range_start)

        self.iph_range_end = QDateTimeEdit(calendarPopup=True)
        self.iph_range_end.setDateTime(QDateTime.currentDateTime())
        self.iph_range_end.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.iph_range_end.hide()
        self._iph_range_to_lbl = QLabel("to:")
        self._iph_range_to_lbl.hide()
        fl.addWidget(self._iph_range_to_lbl)
        fl.addWidget(self.iph_range_end)

        self.iph_ip_input = QLineEdit()
        self.iph_ip_input.setPlaceholderText(
            "Filter by IP (optional — e.g. who had 10.51.144.30?)")
        fl.addWidget(self.iph_ip_input, 1)

        query_btn = QPushButton("Query Network")
        query_btn.setObjectName("Primary")
        query_btn.clicked.connect(self.run_ip_history_query)
        fl.addWidget(query_btn)
        layout.addWidget(form)

        self.iph_progress = QLabel("")
        self.iph_progress.setStyleSheet("color:#0366d6; font-weight:bold; margin-top:6px;")
        layout.addWidget(self.iph_progress)

        self.iph_table = QTableWidget()
        self.iph_table.setColumnCount(6)
        self.iph_table.setHorizontalHeaderLabels(
            ["Hostname", "MAC", "IP", "Building", "Room", "Timestamp (local)"])
        self.iph_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.iph_table.verticalHeader().setVisible(False)
        self.iph_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.iph_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.iph_table)

        self.content_stack.addWidget(page)

    def _on_iph_query_type_changed(self, index: int):
        # 0 = Whole Day, 1 = At Specific Time, 2 = Time Range
        self.iph_date.setVisible(index in (0, 1))
        self.iph_time.setVisible(index == 1)
        self.iph_range_start.setVisible(index == 2)
        self.iph_range_end.setVisible(index == 2)
        self._iph_range_to_lbl.setVisible(index == 2)

    def run_ip_history_query(self):
        sid = str(uuid.uuid4())
        self.iph_active_session_id = sid
        self.ip_history_store.init_session(sid)
        self.iph_table.setRowCount(0)
        filter_ip = self.iph_ip_input.text().strip()
        query_index = self.iph_query_type.currentIndex()

        if query_index == 1:
            # At Specific Time — "what IP was active at this exact moment"
            qd = self.iph_date.date()
            qt = self.iph_time.time()
            local_dt = datetime(qd.year(), qd.month(), qd.day(), qt.hour(), qt.minute(), qt.second())
            end_str = local_dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            self.broadcaster.send_ip_history_query(sid, "at", "", end_str, filter_ip)
            self.iph_progress.setText("Querying network for the IP active at that moment…")

        elif query_index == 2:
            # Time Range — for when the exact moment isn't known but a
            # window is. Backed by the same "range" query mode as Whole
            # Day; only the start/end boundaries differ (arbitrary instead
            # of midnight-to-midnight), so no agent/protocol changes were
            # needed for this — Get-IpHistoryMatches already treats "range"
            # as a plain start<=timestamp<=end filter.
            start_local = self.iph_range_start.dateTime().toPyDateTime()
            end_local = self.iph_range_end.dateTime().toPyDateTime()
            if start_local > end_local:
                start_local, end_local = end_local, start_local
            start_utc = start_local.astimezone(timezone.utc)
            end_utc = end_local.astimezone(timezone.utc)
            self.broadcaster.send_ip_history_query(
                sid, "range",
                start_utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
                end_utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
                filter_ip)
            self.iph_progress.setText("Querying network for IP history in that time range…")

        else:
            # Whole Day
            qd = self.iph_date.date()
            start_utc = datetime(qd.year(), qd.month(), qd.day(), 0, 0, 0).astimezone(timezone.utc)
            end_utc = start_utc + timedelta(days=1)
            self.broadcaster.send_ip_history_query(
                sid, "range",
                start_utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
                end_utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
                filter_ip)
            self.iph_progress.setText("Querying network for that day's IP history…")

        # Collection window — agents answer near-instantly from their local
        # log (no scanning involved), so a short window is enough.
        self._iph_timer.start(6000)

    @pyqtSlot(str, dict)
    def _on_ip_history_device(self, req_id: str, device: dict):
        if req_id != self.iph_active_session_id:
            return
        row = self.iph_table.rowCount()
        self.iph_table.insertRow(row)
        vals = [device.get("hostname", ""), device.get("mac", ""), device.get("ip", ""),
                device.get("building", ""), device.get("room", ""),
                _utc_to_local(device.get("timestamp", ""))]
        for c, v in enumerate(vals):
            self.iph_table.setItem(row, c, QTableWidgetItem(v))

    def _finish_ip_history_query(self):
        self.iph_progress.setText(f"Done — {self.iph_table.rowCount()} result(s) found.")

    # ── Deploy Update view ────────────────────────────────────────────────────

    def _init_deploy_view(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(QLabel("Deploy Update",
                                styleSheet="font-size:20px; font-weight:bold;"))
        layout.addWidget(QLabel(
            "This computer temporarily hosts the update: it broadcasts a "
            "signed announcement and serves the file over TCP. Agents "
            "already running the same or a newer version ignore it. "
            "Nothing is touched on any agent unless its downloaded copy's "
            "size AND SHA-256 both match exactly.",
            styleSheet="color:#666; margin-bottom:10px;"))

        form = QFrame()
        form.setObjectName("Panel")
        fl = QHBoxLayout(form)

        fl.addWidget(QLabel("Agent script:"))
        self.deploy_file_input = QLineEdit()
        self.deploy_file_input.setPlaceholderText("Path to the new start-Mneti.ps1…")
        self.deploy_file_input.setReadOnly(True)
        fl.addWidget(self.deploy_file_input, 2)

        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._pick_deploy_file)
        fl.addWidget(browse_btn)

        fl.addWidget(QLabel("Version:"))
        self.deploy_version_input = QLineEdit()
        self.deploy_version_input.setPlaceholderText("e.g. 1.1.0")
        self.deploy_version_input.setFixedWidth(100)
        fl.addWidget(self.deploy_version_input)

        self.deploy_btn = QPushButton("Deploy Update")
        self.deploy_btn.setObjectName("Primary")
        self.deploy_btn.clicked.connect(self._start_deploy)
        fl.addWidget(self.deploy_btn)

        self.deploy_stop_btn = QPushButton("Stop")
        self.deploy_stop_btn.setEnabled(False)
        self.deploy_stop_btn.clicked.connect(self._stop_deploy)
        fl.addWidget(self.deploy_stop_btn)

        layout.addWidget(form)

        status_row = QHBoxLayout()
        self.deploy_status_lbl = QLabel("Idle.")
        self.deploy_status_lbl.setStyleSheet("color:#0366d6; font-weight:bold;")
        status_row.addWidget(self.deploy_status_lbl)
        status_row.addStretch()
        self.deploy_connected_lbl = QLabel("Agents updated: 0")
        status_row.addWidget(self.deploy_connected_lbl)
        layout.addLayout(status_row)

        self.deploy_log = QPlainTextEdit()
        self.deploy_log.setReadOnly(True)
        self.deploy_log.setStyleSheet("font-family:Consolas,monospace; font-size:12px;")
        layout.addWidget(self.deploy_log)

        self.content_stack.addWidget(page)

    def _pick_deploy_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select updated agent script", "", "PowerShell Scripts (*.ps1);;All Files (*)")
        if not path:
            return
        self.deploy_file_input.setText(path)

        detected = _extract_agent_version(path)
        if detected:
            self.deploy_version_input.setText(detected)
            self.deploy_status_lbl.setText(f"Detected $AGENT_VERSION = {detected} in this file.")
        else:
            self.deploy_version_input.clear()
            self.deploy_status_lbl.setText(
                "Could not find $AGENT_VERSION in this file — enter the version manually.")

    def _start_deploy(self):
        file_path = self.deploy_file_input.text().strip()
        version = self.deploy_version_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "No File Selected", "Choose the updated agent script first.")
            return
        if not version:
            QMessageBox.warning(self, "No Version", "Enter a version string, e.g. 1.1.0.")
            return

        # Cross-check against the file itself, in case it was edited or
        # swapped after picking, or the version field was hand-edited —
        # this is the exact drift ("typed 1.1.0 but the file still says
        # 1.0.0 inside") that auto-fill exists to prevent.
        detected = _extract_agent_version(file_path)
        if detected is None:
            proceed = QMessageBox.question(
                self, "No $AGENT_VERSION Found",
                "This file has no $AGENT_VERSION line, so agents that apply it will keep "
                f"reporting their OLD version afterward — your next deploy may not be seen "
                f"as newer unless you fix that. Deploy v{version} anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if proceed != QMessageBox.StandardButton.Yes:
                return
        elif detected != version:
            proceed = QMessageBox.question(
                self, "Version Mismatch",
                f"You're about to broadcast v{version}, but this file's own "
                f"$AGENT_VERSION line says '{detected}'. Agents that apply this update "
                f"will self-report as '{detected}', not '{version}' — that mismatch will "
                f"confuse future deploys. Deploy anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if proceed != QMessageBox.StandardButton.Yes:
                return

        ok = self.update_server.start(file_path, version)
        if ok:
            self.deploy_btn.setEnabled(False)
            self.deploy_stop_btn.setEnabled(True)
            self.deploy_status_lbl.setText(f"Deploying v{version}…")
            self.deploy_connected_lbl.setText("Agents updated: 0")

    def _stop_deploy(self):
        self.update_server.stop()
        self.deploy_btn.setEnabled(True)
        self.deploy_stop_btn.setEnabled(False)
        self.deploy_status_lbl.setText("Idle.")

    @pyqtSlot(str)
    def _on_deploy_log(self, message: str):
        self.deploy_log.appendPlainText(message)

    @pyqtSlot(str)
    def _on_deploy_agent_connected(self, ip: str):
        self.deploy_connected_lbl.setText(f"Agents updated: {self.update_server.connected_count()}")

    # ── History view ──────────────────────────────────────────────────────────

    def _init_history_view(self):
        page   = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.addWidget(QLabel("Session History",
                                styleSheet="font-size:20px; font-weight:bold;"))
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(
            ["Session ID", "Type", "Devices", "Started", "Action"])
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.itemDoubleClicked.connect(self.load_history_session_item)
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.history_table)
        self.content_stack.addWidget(page)

    # ── Navigation ────────────────────────────────────────────────────────────

    def show_view(self, key: str):
        for k, btn in self.nav_btns.items():
            btn.setProperty("active", k == key)
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        if key == "discover":
            self.content_stack.setCurrentIndex(0)
        elif key == "ranges":
            self.refresh_ranges_list()
            self.content_stack.setCurrentIndex(1)
        elif key == "topology":
            self.topology_page.refresh()
            self.content_stack.setCurrentIndex(2)
        elif key == "iphistory":
            self.content_stack.setCurrentIndex(3)
        elif key == "deploy":
            self.content_stack.setCurrentIndex(4)
        elif key == "history":
            self.refresh_history_list()
            self.content_stack.setCurrentIndex(5)

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.set_theme(self.is_dark_mode)
        self.theme_btn.setText("☀️ Light Mode" if self.is_dark_mode else "🌙 Dark Mode")

    def set_theme(self, dark: bool):
        self.setStyleSheet(DARK_STYLE if dark else LIGHT_STYLE)
        # Force table items to inherit the new palette text colour
        self.table.apply_theme(dark)

    # ── Filter routing ────────────────────────────────────────────────────────

    def _on_stat_card_clicked(self, filter_key: str):
        self.current_filter = filter_key
        self.chips_bar._on_chip_clicked(filter_key)
        self._schedule_refresh()

    def _on_chip_filter_changed(self, filter_key: str):
        self.current_filter = filter_key
        self._schedule_refresh()

    # ── Session management ────────────────────────────────────────────────────

    def reset_session(self):
        # Disable immediately to prevent double-clicks re-entering
        # _stop_worker while a previous cancellation is still settling.
        self.reset_btn.setEnabled(False)
        try:
            self._stop_worker()
            self.countdown_timer.stop()
            self._batch_timer.stop()
            self.progress_panel.hide()
            self.active_session_id = None
            self.current_filter = "all"
            for card in self.stat_cards.values():
                card.set_count(0)
            self.chips_bar.reset()
            self.table.setRowCount(0)
            self.export_btn.setEnabled(False)
            self.search_input.clear()
        finally:
            QTimer.singleShot(50, lambda: self.reset_btn.setEnabled(True))

    def _stop_worker(self):
        """
        Request cancellation and wait briefly for the worker thread to stop.

        If it hasn't stopped within the grace period (e.g. mid-ping-sweep),
        we do NOT drop our only reference to it — that previously left an
        orphaned native thread that could crash the process when it later
        tried to emit a signal or get cleaned up. Instead we keep it in
        self._retiring_threads until its `finished` signal actually fires.
        """
        if self._worker_thread and self._worker_thread.isRunning():
            if self._worker:
                self._worker.cancel()
            self._worker_thread.quit()
            if not self._worker_thread.wait(2000):
                t = self._worker_thread
                self._retiring_threads.append(t)

                def _on_retired(t=t):
                    if t in self._retiring_threads:
                        self._retiring_threads.remove(t)

                t.finished.connect(_on_retired)

        self._worker_thread = None
        self._worker = None
        self._worker_cancel = None

    def start_full_discovery(self):
        self.reset_session()
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.store.init_session(sid, "full")
        self.export_btn.setEnabled(True)
        self.start_countdown(60)
        self._launch_worker(mode="full")

    def start_targeted_discovery(self):
        value = self.target_widget.value()
        target_mode = self.target_widget.mode()

        if not value:
            msg = ("Please enter a valid IP range."
                   if target_mode == "range" else
                   "Please enter a valid MAC address or IP address.")
            QMessageBox.warning(self, "Invalid Target", msg)
            return

        self.reset_session()
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.export_btn.setEnabled(True)

        if target_mode == "range":
            # "IP Range" isn't a target match — it's a full discovery scan
            # (including the ARP sweep) restricted to just this one range,
            # instead of the whole subnet / saved custom ranges.
            self.store.init_session(sid, "range_targeted")
            self.start_countdown(60)
            self._launch_worker(mode="full", ranges=[value])
        else:
            mode = "targeted_mac" if target_mode == "mac" else "targeted_ip"
            self.store.init_session(sid, "targeted")
            self.start_countdown(30)
            self._launch_worker(mode=mode, target=value)

    def _launch_worker(self, mode: str, target: str = "", ranges: "list | None" = None):
        self._stop_worker()
        cancel_event = threading.Event()
        worker = _BroadcastWorker(self.broadcaster, self.store,
                                  self.active_session_id, mode, target, cancel_event,
                                  ranges=ranges)
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.device_found.connect(self._arp_device_arrived)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        self._worker        = worker
        self._worker_thread = thread
        self._worker_cancel = cancel_event
        thread.start()

    # ── Countdown ─────────────────────────────────────────────────────────────

    def start_countdown(self, seconds: int):
        self.countdown_val = seconds
        self.status_label.setText(f"NETWORK SCANNING IN PROGRESS… {seconds}s REMAINING")
        self.progress_panel.show()
        self.countdown_timer.start(1000)

    def _update_countdown(self):
        self.countdown_val -= 1
        if self.countdown_val <= 0:
            self.countdown_timer.stop()
            session = self.store.get_session(self.active_session_id) if self.active_session_id else None
            count   = len(session["devices"]) if session else 0
            self.status_label.setText(f"SCAN COMPLETE — {count} device(s) found")
            QTimer.singleShot(5000, self.progress_panel.hide)
        else:
            self.status_label.setText(
                f"NETWORK SCANNING IN PROGRESS… {self.countdown_val}s REMAINING")

    # ── Device arrival ────────────────────────────────────────────────────────

    @pyqtSlot(str, dict)
    def on_device_reported(self, req_id: str, device: dict):
        self.topology_store.sync_from_devices([device])
        self.topology_page.mark_dirty()
        if req_id == self.active_session_id:
            self.update_stats()
            self._schedule_refresh()

    @pyqtSlot(str, dict)
    def _on_arp_device(self, req_id: str, device: dict):
        self.topology_store.sync_from_devices([device])
        self.topology_page.mark_dirty()
        if req_id == self.active_session_id:
            self.update_stats()
            self._schedule_refresh()

    # ── Batched table refresh ─────────────────────────────────────────────────

    def _schedule_refresh(self, *_):
        if not self._batch_timer.isActive():
            self._batch_timer.start()

    def _do_refresh_table(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if session:
            self.table.update_devices(
                session["devices"],
                self.current_filter,
                self.search_input.text(),
            )

    def refresh_table(self):
        self._schedule_refresh()

    # ── Stats ─────────────────────────────────────────────────────────────────

    def update_stats(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if not session:
            return
        devices = session["devices"]
        counts  = {"all": len(devices), "managed": 0,
                   "managed_hotspot": 0, "unmanaged_hotspot": 0, "unmanaged": 0}
        for d in devices:
            dtype = d.get("type", "unmanaged")
            relay = d.get("relay_host", "")
            if dtype == "managed":
                counts["managed"] += 1
            elif dtype == "relayed":
                counts["managed_hotspot"] += 1
            elif dtype == "unmanaged":
                if relay:
                    counts["unmanaged_hotspot"] += 1
                else:
                    counts["unmanaged"] += 1
        for key, count in counts.items():
            self.stat_cards[key].set_count(count)
        self.chips_bar.set_counts(counts)

    # ── Range management ──────────────────────────────────────────────────────

    def add_custom_range(self):
        cidr = self.range_input.text().strip()
        is_primary = self.primary_checkbox.isChecked()
        if cidr:
            if self.broadcaster.add_range(cidr, cidr, is_primary):
                self.range_input.clear()
                self.primary_checkbox.setChecked(False)
                self.refresh_ranges_list()

    def scan_immediate_range(self):
        cidr = self.range_input.text().strip()
        if not cidr:
            return
        self.reset_session()
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.store.init_session(sid, "range_scan")
        if self.broadcaster.send_range_discovery(sid, cidr):
            self.show_view("discover")
            self.export_btn.setEnabled(True)

    def scan_all_custom_ranges(self):
        ranges = self.broadcaster.get_ranges()
        if not ranges:
            return
        self.reset_session()
        sid = str(uuid.uuid4())
        self.active_session_id = sid
        self.store.init_session(sid, "all_ranges_scan")
        for r in ranges:
            self.broadcaster.send_range_discovery(sid, str(r.network))
        self.show_view("discover")
        self.export_btn.setEnabled(True)

    def update_range_preview(self):
        text = self.range_input.text().strip()
        if not text:
            self.range_preview.setText("")
            return
        pr = parse_custom_range(text)
        if pr:
            self.range_preview.setText(
                f"✓ Valid: {pr.network} ({pr.host_count} hosts, broadcast: {pr.broadcast})")
            self.range_preview.setStyleSheet(
                "font-size:11px; color:#28a745; font-family:Consolas,monospace;")
        else:
            self.range_preview.setText("⚠ Invalid range format")
            self.range_preview.setStyleSheet(
                "font-size:11px; color:#dc3545; font-family:Consolas,monospace;")

    def delete_custom_range(self):
        row = self.ranges_list.currentRow()
        if row >= 0:
            self.broadcaster.remove_range(row)
            self.refresh_ranges_list()

    def refresh_ranges_list(self):
        self.ranges_list.clear()
        for r in self.broadcaster.get_ranges():
            prefix = "[PRIMARY] " if r.is_primary else ""
            item   = QListWidgetItem(
                f"{prefix}{r.network} (Broadcast: {r.broadcast}, Hosts: {r.host_count})")
            if r.is_primary:
                item.setForeground(Qt.GlobalColor.blue)
            item.setData(Qt.ItemDataRole.UserRole, str(r.network))
            self.ranges_list.addItem(item)

    # ── History ───────────────────────────────────────────────────────────────

    def refresh_history_list(self):
        self.history_table.setRowCount(0)
        for h in reversed(self.store.get_history()):
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            short_id = h["request_id"][:8].upper() + "…"
            id_item  = QTableWidgetItem(short_id)
            id_item.setData(Qt.ItemDataRole.UserRole, h["request_id"])
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 0, id_item)
            type_item = QTableWidgetItem(h["type"].replace("_", " ").upper())
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 1, type_item)
            count_item = QTableWidgetItem(f"{h['device_count']} devices")
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 2, count_item)
            ts      = _utc_to_local(h.get("started_at", ""))
            ts_item = QTableWidgetItem(ts)
            ts_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 3, ts_item)
            view_btn = QPushButton("View Session →")
            view_btn.setStyleSheet(
                "color:#0366d6; border:none; background:transparent; font-weight:bold;")
            view_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            view_btn.clicked.connect(
                lambda _c, rid=h["request_id"]: self.load_history_by_id(rid))
            self.history_table.setCellWidget(row, 4, view_btn)

    def load_history_session_item(self, item):
        row     = self.history_table.row(item)
        id_item = self.history_table.item(row, 0)
        if id_item:
            self.load_history_by_id(id_item.data(Qt.ItemDataRole.UserRole))

    def load_history_by_id(self, req_id: str):
        self.active_session_id = req_id
        self.show_view("discover")
        self.update_stats()
        self._schedule_refresh()
        self.export_btn.setEnabled(True)

    # ── Export ────────────────────────────────────────────────────────────────

    def export_csv(self):
        if not self.active_session_id:
            return
        session = self.store.get_session(self.active_session_id)
        if not session:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results",
            f"discovery_{self.active_session_id[:8]}.csv",
            "CSV Files (*.csv)"
        )
        if path:
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        "hostname", "mac", "ip", "username", "building", "room",
                        "type", "relay_host", "relay_building", "relay_room",
                        "vendor", "timestamp", "connection_type",
                        "port", "switch_name", "router_name", "additional_ports",
                    ], extrasaction="ignore")
                    writer.writeheader()
                    for d in session["devices"]:
                        row = dict(d)
                        row["vendor"]    = _resolve_vendor(d.get("mac",""), d.get("vendor",""))
                        row["timestamp"] = _utc_to_local(d.get("timestamp",""))
                        writer.writerow(row)
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", str(e))