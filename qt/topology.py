"""
qt/topology.py

Data model backing the "Network Map" sidebar page.

The idea: the organisation's network is a tree. At the top sits a single
"Internet Entry Point" node (where the org's internet actually comes from
— e.g. the ISP handoff / core router). Everything else — routers, switches,
media converters, patch panels, wall ports, or anything else you want to track — is a
node that points at ONE parent node: "this is where I get my internet
from". Walking the tree from any node up to the root traces the physical
path back to the internet entry point.

Nodes come from two places:
  1. Automatically, from qt/logic.py ResultStore devices: whenever a
     discovered device reports connection_type == "Switch" / "Router"
     (via switch_name / router_name) or a wall port (port /
     additional_ports), a node is created for it if one doesn't already
     exist. These are marked auto=True.
  2. Manually, via the Network Map UI (e.g. "Media Converter — Server Room",
     or a switch/router/port that hasn't been seen by a live scan yet).
     These are marked auto=False.

The *uplink* (which parent a node points to) is, almost always, a manual
decision made by the user in the UI — discovery has no way to know that,
say, "Switch-3F-Annex" is fed by a media converter that's fed by
"Switch-Core". set_uplink() persists that choice, and marks it auto=False
so it can never be silently overwritten later.

The one exception is Hotspot devices: sync_from_devices() sometimes has to
wire a hotspotted device to ROOT_ID as a placeholder because the relay
host (the phone/laptop actually providing the hotspot) hasn't been
discovered yet. That placeholder edge is marked auto=True, and — unlike
every other auto edge — sync is allowed to replace it once the real relay
host shows up in a later scan. A human explicitly pointing a node at
ROOT_ID (auto=False) is never touched.

Everything is stored as plain JSON under Config.DATA_DIR/topology.json so
it survives restarts and works the same way whether run from source or as
the frozen .exe.
"""

import os
import json
import threading
import uuid
import logging

from qt.logic import Config

log = logging.getLogger("mneti.topology")

NODE_TYPES = ["internet", "router", "switch", "media_converter", "wall_port", "patch_panel", "computer", "other"]

ROOT_ID = "internet-root"

NODE_TYPE_LABELS = {
    "internet":        "Internet Entry Point",
    "router":          "Router",
    "switch":          "Switch",
    "media_converter": "Media Converter",
    "wall_port":       "Wall Port",
    "patch_panel":     "Patch Panel / Duct",
    "computer":        "Computer / Device",
    "other":           "Other",
}


class TopologyStore:
    """
    Thread-safe, disk-persisted store of topology nodes + uplink edges.

    nodes: { node_id: {id, type, name, x, y, auto, meta:{...}} }
    edges: { "child_id": parent_id }   -- a node has at most ONE uplink,
                                            so a plain dict is enough and
                                            also makes cycle-checking cheap.
    edge_meta: { "child_id": {"hotspot": bool, "auto": bool} }
                                            -- "hotspot" controls how the
                                            edge is drawn (dashed/yellow).
                                            "auto" records whether the edge
                                            was inferred by sync_from_devices
                                            (True) or set by a human in the
                                            UI (False). This lets sync safely
                                            re-resolve its own placeholder
                                            edges later without ever
                                            touching a human's choice.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._file = os.path.join(Config.DATA_DIR, "topology.json")
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        self._data = self._load()

    # ── persistence ───────────────────────────────────────────────────────

    def _default_data(self) -> dict:
        return {
            "nodes": {
                ROOT_ID: {
                    "id": ROOT_ID,
                    "type": "internet",
                    "name": "Internet Entry Point",
                    "x": 40.0,
                    "y": 40.0,
                    "auto": False,
                    "meta": {},
                }
            },
            "edges": {},
            "edge_meta": {},  # {child_id: {"hotspot": bool, "auto": bool}}
        }

    def _load(self) -> dict:
        try:
            if os.path.exists(self._file):
                with open(self._file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and "nodes" in data and ROOT_ID in data.get("nodes", {}):
                    data.setdefault("edges", {})
                    data.setdefault("edge_meta", {})
                    return data
        except Exception as e:
            log.warning("Failed to load topology.json, starting fresh: %s", e)
        return self._default_data()

    def _save_locked(self):
        try:
            with open(self._file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception as e:
            log.warning("Failed to save topology.json: %s", e)

    # ── read access ───────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        """Deep-copy of the current {nodes, edges} state, safe to hand to the UI."""
        with self._lock:
            return json.loads(json.dumps(self._data))

    # ── node management ───────────────────────────────────────────────────

    def add_manual_node(self, node_type: str, name: str) -> str:
        if node_type not in NODE_TYPES or node_type == "internet":
            node_type = "other"
        with self._lock:
            nid = f"manual:{uuid.uuid4().hex[:10]}"
            self._data["nodes"][nid] = {
                "id": nid, "type": node_type, "name": name.strip() or NODE_TYPE_LABELS[node_type],
                "x": 0.0, "y": 0.0, "auto": False, "meta": {},
            }
            self._place_unpositioned_locked()
            self._save_locked()
            return nid

    def rename_node(self, node_id: str, name: str):
        name = name.strip()
        if not name:
            return
        with self._lock:
            if node_id in self._data["nodes"]:
                self._data["nodes"][node_id]["name"] = name
                self._save_locked()

    def remove_node(self, node_id: str) -> bool:
        if node_id == ROOT_ID:
            return False
        with self._lock:
            if node_id not in self._data["nodes"]:
                return False
            self._data["nodes"].pop(node_id, None)
            # drop this node's own uplink, and re-parent anything that
            # pointed at it up to the root so the tree doesn't get orphaned
            self._data["edges"].pop(node_id, None)
            self._data["edge_meta"].pop(node_id, None)
            for child, parent in list(self._data["edges"].items()):
                if parent == node_id:
                    self._data["edges"][child] = ROOT_ID
            self._save_locked()
            return True

    def update_position(self, node_id: str, x: float, y: float):
        with self._lock:
            if node_id in self._data["nodes"]:
                self._data["nodes"][node_id]["x"] = x
                self._data["nodes"][node_id]["y"] = y
                self._save_locked()

    def set_positions(self, positions: dict):
        """Bulk position update, used by auto-layout."""
        with self._lock:
            for nid, (x, y) in positions.items():
                if nid in self._data["nodes"]:
                    self._data["nodes"][nid]["x"] = x
                    self._data["nodes"][nid]["y"] = y
            self._save_locked()

    # ── uplink (edge) management ──────────────────────────────────────────

    def set_uplink(self, child_id: str, parent_id: "str | None",
                   hotspot: bool = False, auto: bool = False) -> bool:
        """
        Record that `child_id` gets its internet from `parent_id`.
        Pass parent_id=None to clear the uplink (node becomes disconnected
        until re-assigned). Refuses self-loops and cycles.
        hotspot=True marks the edge as a Wi-Fi hotspot hop so the canvas
        can draw it as a dotted arrow.

        auto is internal bookkeeping, not something the UI needs to pass:
        it marks whether this edge was set by a human (auto=False, the
        default, and always the case when called from topology_widget.py)
        or inferred by sync_from_devices() (auto=True). It's what lets
        sync safely re-resolve its own placeholder edges later (e.g. a
        Hotspot device that initially had to fall back to ROOT_ID because
        its relay host hadn't been discovered yet) without ever touching
        an edge a human deliberately chose.
        """
        with self._lock:
            if child_id == ROOT_ID:
                return False
            if child_id not in self._data["nodes"]:
                return False
            if parent_id is None:
                self._data["edges"].pop(child_id, None)
                self._data["edge_meta"].pop(child_id, None)
                self._save_locked()
                return True
            if parent_id == child_id or parent_id not in self._data["nodes"]:
                return False
            if self._creates_cycle_locked(child_id, parent_id):
                return False
            self._data["edges"][child_id] = parent_id
            self._data["edge_meta"][child_id] = {"hotspot": hotspot, "auto": auto}
            self._save_locked()
            return True

    def get_uplink(self, child_id: str) -> "str | None":
        with self._lock:
            return self._data["edges"].get(child_id)

    def _creates_cycle_locked(self, child_id: str, parent_id: str) -> bool:
        seen = set()
        cur = parent_id
        while cur is not None:
            if cur == child_id:
                return True
            if cur in seen:
                break
            seen.add(cur)
            cur = self._data["edges"].get(cur)
        return False

    def descendants(self, node_id: str) -> set:
        """All nodes whose uplink chain passes through node_id (used to stop
        the UI from offering a descendant as a valid new parent)."""
        with self._lock:
            children_of = {}
            for child, parent in self._data["edges"].items():
                children_of.setdefault(parent, []).append(child)
            out = set()
            stack = [node_id]
            while stack:
                cur = stack.pop()
                for c in children_of.get(cur, []):
                    if c not in out:
                        out.add(c)
                        stack.append(c)
            return out

    # ── auto-sync from discovered devices ────────────────────────────────

    def sync_from_devices(self, devices: list):
        """
        Ensure a node exists for every switch/router/wall-port/computer
        mentioned by the given device reports.  Computer nodes are created
        for any device that has a MAC address or hostname.  Their uplink is
        auto-set to whichever switch/router/wall-port they reported connecting
        through (or left unconnected if none).  Hotspot links are stored in
        edge_meta so the canvas can render them as dotted arrows.

        This method never overwrites a manual rename or a manually-chosen
        uplink. It also never overwrites an uplink it previously resolved to
        a *real* parent. The one exception: a Hotspot device whose relay
        host couldn't be found at the time gets wired to ROOT_ID as a
        placeholder (auto=True) — and precisely because that's a
        placeholder, not a real answer, sync is allowed to replace it with
        the real relay node once that relay host is discovered in a later
        scan.
        """
        with self._lock:
            changed = False

            # ── Pass 1: create infrastructure nodes ──────────────────────────
            for d in devices:
                if not isinstance(d, dict):
                    continue
                conn = (d.get("connection_type") or "").strip()

                if conn == "Switch":
                    name = (d.get("switch_name") or "").strip()
                    if name:
                        nid = f"switch:{name.lower()}"
                        if nid not in self._data["nodes"]:
                            self._data["nodes"][nid] = {
                                "id": nid, "type": "switch", "name": name,
                                "x": 0.0, "y": 0.0, "auto": True, "meta": {},
                            }
                            changed = True

                elif conn == "Router":
                    name = (d.get("router_name") or "").strip()
                    if name:
                        nid = f"router:{name.lower()}"
                        if nid not in self._data["nodes"]:
                            self._data["nodes"][nid] = {
                                "id": nid, "type": "router", "name": name,
                                "x": 0.0, "y": 0.0, "auto": True, "meta": {},
                            }
                            changed = True

                building = (d.get("building") or "").strip()
                room     = (d.get("room") or "").strip()
                ports    = []
                p = (d.get("port") or "").strip()
                if p:
                    ports.append(p)
                for extra in d.get("additional_ports", []) or []:
                    extra = str(extra).strip()
                    if extra and extra not in ports:
                        ports.append(extra)

                for p in ports:
                    key = f"{building}|{room}|{p}".lower()
                    nid = f"wallport:{key}"
                    if nid not in self._data["nodes"]:
                        label_loc = " ".join(x for x in (building, room) if x)
                        name = f"Port {p}" + (f" ({label_loc})" if label_loc else "")
                        self._data["nodes"][nid] = {
                            "id": nid, "type": "wall_port", "name": name,
                            "x": 0.0, "y": 0.0, "auto": True,
                            "meta": {"building": building, "room": room, "port": p},
                        }
                        changed = True

            # ── Pass 2a: create/update computer nodes ─────────────────────────
            for d in devices:
                if not isinstance(d, dict):
                    continue

                mac      = (d.get("mac") or "").strip().lower()
                hostname = (d.get("hostname") or "").strip()
                ip       = (d.get("ip") or "").strip()
                conn     = (d.get("connection_type") or "").strip()

                # Only map computers that have connection details
                # (otherwise we'd clutter the map with ARP-only ghosts that
                # have no known place in the topology).
                if not conn:
                    continue

                # We also need a stable identifier
                if not mac and not hostname:
                    continue

                # Build a stable node id: prefer MAC, fall back to hostname
                if mac:
                    computer_nid = f"computer:{mac.replace(':', '')}"
                else:
                    computer_nid = f"computer:{hostname.lower().replace(' ', '_')}"

                # Friendly display name
                display = hostname or ip or mac

                if computer_nid not in self._data["nodes"]:
                    self._data["nodes"][computer_nid] = {
                        "id": computer_nid,
                        "type": "computer",
                        "name": display,
                        "x": 0.0, "y": 0.0,
                        "auto": True,
                        "meta": {
                            "mac": mac,
                            "ip": ip,
                            "connection": conn,
                        },
                    }
                    changed = True
                else:
                    # Update mutable fields on existing node without renaming
                    # (only update if the node was auto-created)
                    existing = self._data["nodes"][computer_nid]
                    if existing.get("auto"):
                        existing["meta"]["ip"] = ip
                        existing["meta"]["connection"] = conn
                        changed = True

            # ── Build computer identity lookup mapping ─────────────────────────
            computer_by_identity = {}
            for nid, n in self._data["nodes"].items():
                if n["type"] == "computer":
                    n_id_lower = nid.lower()
                    computer_by_identity[n_id_lower] = nid
                    
                    # Store clean ID representation e.g. computer:desktopfist1ka
                    clean_id_suffix = nid.split(":", 1)[1].lower() if ":" in nid else nid.lower()
                    computer_by_identity[clean_id_suffix] = nid
                    
                    hname = n["name"].strip().lower()
                    if hname:
                        computer_by_identity[hname] = nid
                        computer_by_identity[hname.replace(" ", "_")] = nid
                    
                    ip = n.get("meta", {}).get("ip", "").strip().lower()
                    if ip:
                        computer_by_identity[ip] = nid
                    
                    mac = n.get("meta", {}).get("mac", "").strip().lower()
                    if mac:
                        computer_by_identity[mac] = nid
                        computer_by_identity[mac.replace(":", "").replace("-", "")] = nid

            # ── Pass 2b: wire uplinks using computer_by_identity ───────────────
            for d in devices:
                if not isinstance(d, dict):
                    continue

                mac      = (d.get("mac") or "").strip().lower()
                hostname = (d.get("hostname") or "").strip()
                conn     = (d.get("connection_type") or "").strip()

                if not conn:
                    continue
                if not mac and not hostname:
                    continue

                if mac:
                    computer_nid = f"computer:{mac.replace(':', '')}"
                else:
                    computer_nid = f"computer:{hostname.lower().replace(' ', '_')}"

                # Decide whether we're allowed to (re)wire this device's uplink.
                #
                # Normally we only set an uplink once and never touch it again,
                # so a human's manual rewiring in the UI is never stomped on,
                # and neither is a real parent we already resolved.
                #
                # The one exception: if this device is currently pointed at
                # ROOT_ID *and* that edge was set by us (auto=True), it's a
                # placeholder from an earlier sync that couldn't resolve the
                # real parent yet (this happens for Hotspot devices whose
                # relay host hadn't been discovered at the time) -- not a
                # real answer. We're allowed to replace a placeholder once we
                # can actually resolve the real parent below. A human
                # explicitly pointing something at ROOT_ID (auto=False) is
                # never touched.
                existing_parent = self._data["edges"].get(computer_nid)
                if existing_parent is not None:
                    existing_meta = self._data["edge_meta"].get(computer_nid, {})
                    is_auto_fallback = (
                        existing_parent == ROOT_ID
                        and existing_meta.get("auto", True)
                    )
                    if not is_auto_fallback:
                        continue  # real or manual uplink — don't override

                is_hotspot = (conn == "Hotspot")
                parent_nid  = None

                if conn == "Switch":
                    sw = (d.get("switch_name") or "").strip()
                    if sw:
                        parent_nid = f"switch:{sw.lower()}"

                elif conn == "Router":
                    rt = (d.get("router_name") or "").strip()
                    if rt:
                        parent_nid = f"router:{rt.lower()}"

                elif conn == "Hotspot":
                    # relay_host could be hostname, IP or MAC
                    relay = (d.get("relay_host") or "").strip().lower()
                    if relay:
                        # Try lookup by name/ip/mac
                        parent_nid = computer_by_identity.get(relay)
                        if not parent_nid:
                            # Try hex clean
                            clean_relay = relay.replace(":", "").replace("-", "")
                            parent_nid = computer_by_identity.get(clean_relay)
                        if not parent_nid:
                            # Try prefix computer:
                            parent_nid = computer_by_identity.get(f"computer:{relay}")
                        
                        # Fallback if still not found
                        if not parent_nid:
                            parent_nid = ROOT_ID
                    else:
                        # No relay info — attach to root
                        parent_nid = ROOT_ID

                elif conn in ("Wall Port", "WallPort"):
                    building = (d.get("building") or "").strip()
                    room     = (d.get("room") or "").strip()
                    p        = (d.get("port") or "").strip()
                    if p:
                        key = f"{building}|{room}|{p}".lower()
                        parent_nid = f"wallport:{key}"

                # If the deduced parent actually exists, wire it up
                if parent_nid and parent_nid in self._data["nodes"]:
                    # Quick cycle check (computer nodes never have children, so
                    # this is really just a safety guard against bad data)
                    if parent_nid != computer_nid:
                        if self._data["edges"].get(computer_nid) != parent_nid:
                            self._data["edges"][computer_nid] = parent_nid
                            self._data["edge_meta"][computer_nid] = {"hotspot": is_hotspot, "auto": True}
                            changed = True

            if changed:
                self._place_unpositioned_locked()
                self._save_locked()

    def _place_unpositioned_locked(self):
        """Grid-place any node still sitting at the origin (freshly added)
        so newly discovered/added nodes don't stack invisibly on top of
        each other before the user drags them or runs auto-layout."""
        col_w, row_h = 170, 110
        idx = 0
        for n in self._data["nodes"].values():
            if n["id"] != ROOT_ID and n["x"] == 0.0 and n["y"] == 0.0:
                n["x"] = 40 + (idx % 6) * col_w
                n["y"] = 420 + (idx // 6) * row_h
                idx += 1


# ── Tree layout helper ────────────────────────────────────────────────────
#
# Uses a proper bottom-up minimum-width allocation (simplified
# Reingold-Tilford) so that:
#   • No two nodes at the same depth overlap, even in dense trees.
#   • Parents are centered exactly over their children.
#   • Orphan nodes (not connected to root) are placed in a tidy grid
#     below the tree rather than a single long horizontal row.

def compute_tree_layout(
    nodes: dict,
    edges: dict,
    root_id: str = ROOT_ID,
    x_gap: float = 200.0,   # horizontal space per leaf slot
    y_gap: float = 150.0,   # vertical distance between levels
    start_x: float = 60.0,
    start_y: float = 40.0,
) -> dict:
    """
    Returns {node_id: (x, y)}.

    Algorithm
    ---------
    1. Build children_of from edges.
    2. For every node bottom-up, compute its required *width* in units of
       leaf-slots (a leaf = 1, an internal node = sum of children widths).
    3. Top-down, assign each node an x range [left, left+width*x_gap] and
       place it at the centre of that range.
    4. Orphan nodes are placed in a compact grid below the whole tree so
       they are still visible and easy to reconnect without bleeding into
       the tree area.
    """
    children_of: dict[str, list[str]] = {}
    for child, parent in edges.items():
        children_of.setdefault(parent, []).append(child)

    # Sort children deterministically so layout is stable across reloads
    for kids in children_of.values():
        kids.sort()

    # ── Step 1: bottom-up subtree width (in leaf slots) ─────────────────
    width_of: dict[str, int] = {}

    def calc_width(nid: str, visited: frozenset) -> int:
        if nid in visited or nid not in nodes:
            return 1
        visited = visited | {nid}
        kids = children_of.get(nid, [])
        if not kids:
            width_of[nid] = 1
            return 1
        w = sum(calc_width(k, visited) for k in kids)
        width_of[nid] = w
        return w

    if root_id in nodes:
        calc_width(root_id, frozenset())

    # ── Step 2: top-down x/y assignment ─────────────────────────────
    positions: dict[str, tuple[float, float]] = {}

    def place(nid: str, depth: int, left: float, visited: frozenset):
        if nid in visited or nid not in nodes:
            return
        visited = visited | {nid}
        w = width_of.get(nid, 1)
        # Centre this node within its allocated horizontal band
        cx = left + w * x_gap / 2.0
        positions[nid] = (cx, start_y + depth * y_gap)

        kids = children_of.get(nid, [])
        cur_left = left
        for kid in kids:
            kw = width_of.get(kid, 1)
            place(kid, depth + 1, cur_left, visited)
            cur_left += kw * x_gap

    if root_id in nodes:
        place(root_id, 0, start_x, frozenset())

    # ── Step 3: orphan grid ───────────────────────────────────────
    unreached = [nid for nid in nodes if nid not in positions]
    if unreached:
        # Place orphans below the deepest tree row with x_gap spacing
        max_depth = 0
        if positions:
            max_depth = int(max(y for _, y in positions.values()) / y_gap)
        orphan_y_start = start_y + (max_depth + 2) * y_gap
        cols = max(1, int((width_of.get(root_id, 1) * x_gap) / x_gap))
        cols = max(cols, 6)  # at least 6 columns so the row isn't absurdly wide
        for i, nid in enumerate(sorted(unreached)):
            col = i % cols
            row = i // cols
            positions[nid] = (start_x + col * x_gap, orphan_y_start + row * y_gap)

    return positions