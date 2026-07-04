"""
qt/topology_widget.py

"Network Map" sidebar page: an interactive, draggable diagram tracing how
switches, routers, wall ports, patch panels, and media converters interconnect, all the
way back to one "Internet Entry Point" node.

Left panel  — node list + an editor for whichever node is selected
              (rename it, pick "gets its internet from", delete it,
              add a brand-new node by hand).
Right panel — the diagram itself (QGraphicsView/QGraphicsScene). Boxes are
              colour-coded by type, are drag-to-reposition, and edges are
              arrows pointing UP the chain toward whatever the box gets its
              internet from. "Auto-Arrange" lays the whole thing out as a
              clean tree under the Internet Entry Point.

Nodes for switches/routers/wall ports are created automatically the moment
a discovery report mentions them (see qt/topology.py sync_from_devices,
wired up from MainWindow.on_device_reported / _on_arp_device). This page
only needs to (a) show them and (b) let the user say which of them feeds
which — discovery has no way to know that on its own.
"""

import math

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QListWidget,
    QListWidgetItem, QComboBox, QLineEdit, QFrame, QGraphicsView,
    QGraphicsScene, QGraphicsItem, QGraphicsObject, QGraphicsPathItem,
    QSplitter, QDialog, QDialogButtonBox, QFormLayout, QMessageBox,
    QSizePolicy, QMenu, QStackedWidget,
)
from PyQt6.QtCore import Qt, QRectF, QPointF, pyqtSignal
from PyQt6.QtGui import (
    QColor, QPen, QBrush, QPainter, QPainterPath, QFont, QPolygonF, QAction,
)

from qt.topology import (
    TopologyStore, NODE_TYPES, NODE_TYPE_LABELS, ROOT_ID, compute_tree_layout,
)

NODE_W = 150
NODE_H = 58

NODE_COLORS = {
    "internet":        ("#fef3c7", "#b45309"),
    "router":          ("#dbeafe", "#1d4ed8"),
    "switch":          ("#dcfce7", "#15803d"),
    "media_converter": ("#fae8ff", "#a21caf"),
    "wall_port":       ("#e5e7eb", "#4b5563"),
    "patch_panel":     ("#fff7ed", "#ea580c"),
    "computer":        ("#e0f2fe", "#0369a1"),
    "other":           ("#fee2e2", "#b91c1c"),
}

NODE_ICONS = {
    "internet":        "🌐",
    "router":          "📡",
    "switch":          "🔀",
    "media_converter": "🔁",
    "wall_port":       "🔌",
    "patch_panel":     "🔧",
    "computer":        "💻",
    "other":           "⬛",
}


# ── Graphics items ────────────────────────────────────────────────────────

class NodeItem(QGraphicsObject):
    """A draggable box representing one node in the network map."""

    moved   = pyqtSignal(str)
    clicked = pyqtSignal(str)

    def __init__(self, node_id: str, node_type: str, name: str, x: float, y: float,
                 is_root: bool = False, ip: str = ""):
        super().__init__()
        self.node_id   = node_id
        self.node_type = node_type
        self.name      = name
        self.is_root   = is_root
        self.ip        = ip
        self.edges     = []   # EdgeItem instances touching this node

        self.setPos(x, y)
        flags = (QGraphicsItem.GraphicsItemFlag.ItemIsSelectable |
                 QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        if not is_root:
            flags |= QGraphicsItem.GraphicsItemFlag.ItemIsMovable
        self.setFlags(flags)
        self.setZValue(2)
        self.setCursor(Qt.CursorShape.OpenHandCursor if not is_root else Qt.CursorShape.ArrowCursor)
        self.setAcceptHoverEvents(True)

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, NODE_W, NODE_H)

    def center(self) -> QPointF:
        return self.pos() + QPointF(NODE_W / 2, NODE_H / 2)

    def paint(self, painter: QPainter, option, widget=None):
        bg, border = NODE_COLORS.get(self.node_type, ("#eee", "#666"))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        pen = QPen(QColor(border), 3 if self.isSelected() else (2.5 if self.is_root else 1.4))
        painter.setPen(pen)
        painter.setBrush(QBrush(QColor(bg)))
        rect = self.boundingRect()
        painter.drawRoundedRect(rect, 10, 10)

        icon = NODE_ICONS.get(self.node_type, "")
        title_font = QFont()
        title_font.setPointSize(9)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QPen(QColor("#111827")))
        painter.drawText(rect.adjusted(8, 6, -8, -22),
                          Qt.AlignmentFlag.AlignLeft | Qt.TextFlag.TextWordWrap,
                          f"{icon}  {self.name}")

        sub_font = QFont()
        sub_font.setPointSize(7)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor(border)))
        label = NODE_TYPE_LABELS.get(self.node_type, self.node_type)
        painter.drawText(rect.adjusted(8, 0, -8, -5),
                          Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignBottom, label)

        if self.ip:
            ip_font = QFont()
            ip_font.setPointSize(7)
            painter.setFont(ip_font)
            painter.setPen(QPen(QColor("#4b5563")))
            painter.drawText(rect.adjusted(8, 0, -8, -5),
                              Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom, self.ip)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for e in self.edges:
                e.update_path()
            self.moved.emit(self.node_id)
        return super().itemChange(change, value)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.clicked.emit(self.node_id)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self.moved.emit(self.node_id)


class EdgeItem(QGraphicsPathItem):
    """
    An arrow from a child node UP to whatever it gets its internet from.
    The arrowhead points at the parent, so following the arrows from any
    box traces the physical path back to the Internet Entry Point.

    is_hotspot=True renders the edge as a dotted/dashed line with a
    small 📶 label at the midpoint to indicate a Wi-Fi hotspot hop.
    """

    def __init__(self, child: NodeItem, parent: NodeItem, is_hotspot: bool = False):
        super().__init__()
        self.child      = child
        self.parent     = parent
        self.is_hotspot = is_hotspot
        self.setZValue(1)

        if is_hotspot:
            pen = QPen(QColor("#f59e0b"), 2.0)
            pen.setStyle(Qt.PenStyle.DashLine)
        else:
            pen = QPen(QColor("#94a3b8"), 2.2)
        self.setPen(pen)

        child.edges.append(self)
        parent.edges.append(self)
        self.update_path()

    @staticmethod
    def _border_point(box_center: QPointF, towards: QPointF) -> QPointF:
        """
        The point where a straight line from `box_center` to `towards`
        exits box_center's NODE_W x NODE_H rectangle.

        This is a proper line/rectangle intersection, not an approximation.
        The previous implementation offset a fixed radius of (NODE_H/2 + 2)
        along the line — treating the node as if it were a circle. Since
        nodes are much wider than tall (150x58), that put the "border"
        point inside the rectangle for any connection that was more
        horizontal than vertical (the common case), and because edges are
        drawn below nodes in z-order, that portion of the arrow — often the
        entire tip — was silently painted over by the node's opaque fill.

        Using the real rectangle boundary means the tip always lands
        exactly on the edge of the box, for any angle, so it's never hidden
        behind the border.
        """
        dx = towards.x() - box_center.x()
        dy = towards.y() - box_center.y()
        if dx == 0 and dy == 0:
            return QPointF(box_center)
        half_w, half_h = NODE_W / 2.0, NODE_H / 2.0
        tx = (half_w / abs(dx)) if dx != 0 else float("inf")
        ty = (half_h / abs(dy)) if dy != 0 else float("inf")
        t = min(tx, ty)
        return QPointF(box_center.x() + dx * t, box_center.y() + dy * t)

    def update_path(self):
        c = self.child.center()
        p = self.parent.center()
        # Draw the line only between the two boxes' borders — not center to
        # center — so nothing is ever hidden underneath a node, and the
        # visible line length matches exactly what the arrowhead math below
        # expects.
        start = self._border_point(c, p)
        end   = self._border_point(p, c)
        path = QPainterPath(start)
        path.lineTo(end)
        self.setPath(path)

    def paint(self, painter: QPainter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(self.pen())
        painter.drawPath(self.path())

        c = self.child.center()
        p = self.parent.center()

        # Arrow tip sits exactly on the parent box's border (see
        # _border_point docstring) so it's always fully visible.
        tip = self._border_point(p, c)

        dx, dy = p.x() - c.x(), p.y() - c.y()
        dist = math.hypot(dx, dy) or 1.0
        ux, uy = dx / dist, dy / dist

        size = 9
        angle = math.atan2(uy, ux)
        left = QPointF(
            tip.x() - size * math.cos(angle - math.pi / 6),
            tip.y() - size * math.sin(angle - math.pi / 6),
        )
        right = QPointF(
            tip.x() - size * math.cos(angle + math.pi / 6),
            tip.y() - size * math.sin(angle + math.pi / 6),
        )
        arrow = QPolygonF([tip, left, right])

        if self.is_hotspot:
            painter.setBrush(QBrush(QColor("#f59e0b")))
            painter.setPen(QPen(QColor("#f59e0b")))
        else:
            painter.setBrush(QBrush(QColor("#64748b")))
            painter.setPen(QPen(QColor("#64748b")))
        painter.drawPolygon(arrow)

        # For hotspot edges, draw a small mid-line label
        if self.is_hotspot:
            mid = QPointF((c.x() + p.x()) / 2, (c.y() + p.y()) / 2)
            lbl_font = QFont()
            lbl_font.setPointSize(8)
            painter.setFont(lbl_font)
            painter.setPen(QPen(QColor("#b45309")))
            painter.drawText(mid + QPointF(4, -4), "📶 Hotspot")


class TopologyCanvas(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setBackgroundBrush(QBrush(QColor("#f8fafc")))
        self._zoom = 1.0
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)

    def scene_obj(self) -> QGraphicsScene:
        return self._scene

    def wheelEvent(self, event):
        """Zoom at the mouse cursor position.

        We track zoom as a cumulative scale factor and apply it relatively,
        so zoom always works even after fitInView() has set a very small
        initial scale (e.g. 0.05 for a wide tree).
        """
        delta = event.angleDelta().y()
        if delta == 0:
            return
        factor = 1.15 if delta > 0 else 1.0 / 1.15
        new_zoom = self._zoom * factor
        # Wide range so zooming still works after a fit-to-content on a
        # large canvas (fitInView can produce m11 < 0.1).
        new_zoom = max(0.02, min(12.0, new_zoom))
        actual_factor = new_zoom / self._zoom
        self._zoom = new_zoom
        self.scale(actual_factor, actual_factor)
        event.accept()

    def fit_to_content(self):
        """Zoom to fit all content with comfortable padding."""
        if self._scene.items():
            rect = self._scene.itemsBoundingRect()
            if not rect.isNull():
                rect.adjust(-60, -60, 60, 60)
                self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
                # Keep _zoom in sync with the real matrix so that the next
                # wheelEvent starts from the correct baseline.
                # Clamp to our supported range so the first scroll is never
                # blocked by the min-zoom guard.
                self._zoom = max(0.02, min(12.0, self.transform().m11()))



# ── Add-node dialog ───────────────────────────────────────────────────────

class AddNodeDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Network Map Node")
        self.setMinimumWidth(450)
        layout = QFormLayout(self)

        self.type_combo = QComboBox()
        for t in NODE_TYPES:
            if t == "internet":
                continue
            self.type_combo.addItem(NODE_TYPE_LABELS[t], t)
        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        layout.addRow("Type:", self.type_combo)

        # Stacked widget to show different inputs based on type
        self.input_stack = QStackedWidget()
        
        # Page 0: Regular node (single name field)
        regular_page = QWidget()
        regular_layout = QFormLayout(regular_page)
        regular_layout.setContentsMargins(0, 0, 0, 0)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. Media Converter — Server Room")
        regular_layout.addRow("Name:", self.name_edit)
        self.input_stack.addWidget(regular_page)
        
        # Page 1: Other type (custom type + name fields)
        other_page = QWidget()
        other_layout = QFormLayout(other_page)
        other_layout.setContentsMargins(0, 0, 0, 0)
        
        self.other_type_edit = QLineEdit()
        self.other_type_edit.setPlaceholderText("e.g. Firewall, Load Balancer, Fiber Box...")
        other_layout.addRow("Device Type:", self.other_type_edit)
        
        self.other_name_edit = QLineEdit()
        self.other_name_edit.setPlaceholderText("e.g. Firewall — Data Center Rack 3")
        other_layout.addRow("Name:", self.other_name_edit)
        
        self.input_stack.addWidget(other_page)
        
        layout.addRow(self.input_stack)
        
        # Initialize the stack
        self._on_type_changed()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _on_type_changed(self):
        """Switch between regular and 'other' input forms"""
        node_type = self.type_combo.currentData()
        if node_type == "other":
            self.input_stack.setCurrentIndex(1)
            self.other_type_edit.setFocus()
        else:
            self.input_stack.setCurrentIndex(0)
            label = NODE_TYPE_LABELS.get(node_type, "")
            self.name_edit.setPlaceholderText(f"e.g. {label} — Location/Details")

    def values(self):
        """Return (node_type, display_name) tuple"""
        node_type = self.type_combo.currentData()
        if node_type == "other":
            custom_type = self.other_type_edit.text().strip()
            custom_name = self.other_name_edit.text().strip()
            if custom_type:
                # Format: "CustomType: name"
                display_name = f"{custom_type}: {custom_name}" if custom_name else custom_type
            else:
                display_name = custom_name if custom_name else "Other Device"
            return node_type, display_name
        else:
            return node_type, self.name_edit.text().strip()


# ── Main page ─────────────────────────────────────────────────────────────

class TopologyPage(QWidget):
    def __init__(self, topology_store: TopologyStore, result_store, parent=None):
        super().__init__(parent)
        self.topology_store = topology_store
        self.result_store   = result_store
        self._selected_id   = None
        self._node_items    = {}   # id -> NodeItem
        self._dirty         = True

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(10)

        header = QHBoxLayout()
        title_v = QVBoxLayout()
        title_v.addWidget(QLabel("Network Map", styleSheet="font-size:20px; font-weight:bold;"))
        title_v.addWidget(QLabel(
            "Trace how switches, routers, wall ports, patch panels and media converters connect back "
            "to the Internet Entry Point.", styleSheet="font-size:11px; color:#666;"))
        header.addLayout(title_v)
        header.addStretch()

        sync_btn = QPushButton("⟳ Sync From Discovery")
        sync_btn.setToolTip("Pull in any new switches / routers / wall ports seen by scans")
        sync_btn.clicked.connect(self.refresh)
        header.addWidget(sync_btn)

        arrange_btn = QPushButton("🗂 Auto-Arrange")
        arrange_btn.clicked.connect(lambda: self._auto_arrange())
        header.addWidget(arrange_btn)
        
        fit_btn = QPushButton("🔍 Fit to View")
        fit_btn.setToolTip("Zoom to show all nodes")
        fit_btn.clicked.connect(lambda: self.canvas.fit_to_content())
        header.addWidget(fit_btn)

        add_btn = QPushButton("＋ Add Node")
        add_btn.setObjectName("Primary")
        add_btn.clicked.connect(self._add_node)
        header.addWidget(add_btn)

        root.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter, 1)

        # ── Left: node list + editor ─────────────────────────────────────
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)

        left_layout.addWidget(QLabel("Nodes", styleSheet="font-weight:bold; font-size:13px;"))
        self.node_search = QLineEdit()
        self.node_search.setPlaceholderText("🔍 Search nodes...")
        self.node_search.textChanged.connect(self._filter_node_list)
        left_layout.addWidget(self.node_search)

        self.node_list = QListWidget()
        self.node_list.itemClicked.connect(lambda item: self._select_node(item.data(Qt.ItemDataRole.UserRole)))
        left_layout.addWidget(self.node_list, 1)

        self.editor_panel = QFrame()
        self.editor_panel.setObjectName("Panel")
        self._build_editor_panel()
        left_layout.addWidget(self.editor_panel)

        legend = QLabel()
        legend.setText(
            "🌐 Internet  |  📡 Router  |  🔀 Switch  |  "
            "🔁 Media Converter  |  🔌 Wall Port  |  🔧 Patch Panel  |  "
            "💻 Computer  |  ⬛ Other\n"
            "→ Wired connection  |  ╌╌╌→ 📶 Hotspot (Wi-Fi relay)"
        )
        legend.setStyleSheet("font-size:11px; color:#6c757d; padding-top:6px;")
        legend.setWordWrap(True)
        left_layout.addWidget(legend)

        splitter.addWidget(left)

        # ── Right: canvas ─────────────────────────────────────────────────
        self.canvas = TopologyCanvas()
        splitter.addWidget(self.canvas)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([300, 800])

        hint = QLabel(
            "Drag boxes to arrange them. Click a box (or pick it from the list) to set "
            "\"Gets its internet from...\". Arrows point toward the upstream source. "
            "Use mouse wheel to zoom, middle-click to pan."
        )
        hint.setStyleSheet("font-size:11px; color:#6c757d;")
        root.addWidget(hint)

    # ── editor panel ──────────────────────────────────────────────────────

    def _build_editor_panel(self):
        layout = QVBoxLayout(self.editor_panel)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        self.editor_title = QLabel("No node selected", styleSheet="font-weight:bold;")
        layout.addWidget(self.editor_title)

        self.editor_type_lbl = QLabel("")
        self.editor_type_lbl.setStyleSheet("font-size:11px; color:#6c757d;")
        layout.addWidget(self.editor_type_lbl)

        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        self.name_edit.returnPressed.connect(self._apply_rename)
        name_row.addWidget(self.name_edit, 1)
        rename_btn = QPushButton("Save")
        rename_btn.clicked.connect(self._apply_rename)
        name_row.addWidget(rename_btn)
        layout.addLayout(name_row)

        layout.addWidget(QLabel("Gets its internet from:"))
        self.uplink_combo = QComboBox()
        self.uplink_combo.currentIndexChanged.connect(self._apply_uplink)
        layout.addWidget(self.uplink_combo)

        self.delete_btn = QPushButton("🗑 Delete Node")
        self.delete_btn.clicked.connect(self._delete_selected)
        layout.addWidget(self.delete_btn)

        self._set_editor_enabled(False)

    def _set_editor_enabled(self, enabled: bool):
        self.name_edit.setEnabled(enabled)
        self.uplink_combo.setEnabled(enabled)
        self.delete_btn.setEnabled(enabled)

    # ── public API ────────────────────────────────────────────────────────

    def mark_dirty(self):
        """Called by MainWindow whenever a new device arrives. If this page
        isn't the visible one right now, we just remember to refresh next
        time it's shown, instead of doing pointless work in the background."""
        self._dirty = True
        if self.isVisible():
            self.refresh()

    def refresh(self):
        devices = []
        try:
            devices = self.result_store.get_all_devices()
        except Exception:
            devices = []

        before = self.topology_store.snapshot()
        had_nodes_before = set(before["nodes"].keys())
        had_edges_before = before["edges"]

        self.topology_store.sync_from_devices(devices)
        self._dirty = False

        data = self.topology_store.snapshot()
        new_nodes     = set(data["nodes"].keys()) - had_nodes_before
        edges_changed = data["edges"] != had_edges_before

        # Re-layout whenever nodes OR uplinks changed. A node that was
        # previously unconnected (sitting in the orphan grid) can get wired
        # into the tree without any *new* node being created — e.g. a
        # Hotspot device whose relay host resolves on a later sync
        # (qt/topology.py can now re-wire that placeholder edge). If we only
        # re-laid-out on new_nodes, that node kept its stale orphan-grid
        # coordinates forever and could end up sitting directly on top of
        # whatever it just got connected to, burying the connecting line
        # underneath it.
        if new_nodes or edges_changed:
            edges = data["edges"]
            connected_nids = set(edges.keys()) | set(edges.values())
            connected_nids.add(ROOT_ID)
            filtered_nodes = {
                nid: n for nid, n in data["nodes"].items()
                if not (n["type"] == "computer" and nid not in connected_nids)
            }
            positions = compute_tree_layout(filtered_nodes, data["edges"])
            self.topology_store.set_positions(positions)
        self._rebuild()



    # ── scene / list rebuilding ───────────────────────────────────────────

    def _rebuild(self):
        data      = self.topology_store.snapshot()
        nodes     = data["nodes"]
        edges     = data["edges"]
        edge_meta = data.get("edge_meta", {})

        prev_selected = self._selected_id

        scene = self.canvas.scene_obj()
        scene.clear()
        self._node_items = {}

        # Gather all connected node IDs (either they have an uplink parent,
        # or they are the uplink parent for another node).
        connected_nids = set(edges.keys()) | set(edges.values())
        connected_nids.add(ROOT_ID)

        for nid, n in nodes.items():
            # Hide unconnected computers/devices from the canvas totally
            if n["type"] == "computer" and nid not in connected_nids:
                continue

            ip = n.get("meta", {}).get("ip", "")
            item = NodeItem(nid, n["type"], n["name"], n.get("x", 0.0), n.get("y", 0.0),
                             is_root=(nid == ROOT_ID), ip=ip)
            item.clicked.connect(self._select_node)
            item.moved.connect(self._on_node_moved)
            scene.addItem(item)
            self._node_items[nid] = item


        for child_id, parent_id in edges.items():
            child  = self._node_items.get(child_id)
            parent = self._node_items.get(parent_id)
            if child and parent:
                is_hotspot = edge_meta.get(child_id, {}).get("hotspot", False)
                scene.addItem(EdgeItem(child, parent, is_hotspot=is_hotspot))

        # Set scene rect with generous padding for large networks
        if self._node_items:
            bounds = scene.itemsBoundingRect()
            scene.setSceneRect(bounds.adjusted(-250, -150, 500, 300))


        self._rebuild_node_list(nodes, edges)

        if prev_selected and prev_selected in nodes:
            self._select_node(prev_selected)
        else:
            self._selected_id = None
            self.editor_title.setText("No node selected")
            self.editor_type_lbl.setText("")
            self._set_editor_enabled(False)

    def _rebuild_node_list(self, nodes: dict, edges: dict):
        self.node_list.clear()
        # Root first, then everything else grouped by type for scannability
        order = [ROOT_ID] + sorted(
            [nid for nid in nodes if nid != ROOT_ID],
            key=lambda nid: (nodes[nid]["type"], nodes[nid]["name"].lower())
        )
        filter_text = self.node_search.text().strip().lower()
        for nid in order:
            n = nodes[nid]
            icon = NODE_ICONS.get(n["type"], "")
            has_uplink = nid in edges or nid == ROOT_ID
            marker = "" if has_uplink else "  ⚠ not connected"
            item_text = f"{icon}  {n['name']}{marker}"
            
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, nid)
            if not has_uplink:
                item.setForeground(QColor("#b45309"))
            self.node_list.addItem(item)
            if filter_text and filter_text not in item_text.lower():
                item.setHidden(True)

    def _filter_node_list(self, text):
        text = text.strip().lower()
        for i in range(self.node_list.count()):
            item = self.node_list.item(i)
            item.setHidden(text not in item.text().lower())

    # ── selection & editing ───────────────────────────────────────────────

    def _select_node(self, node_id: str):
        if not node_id:
            return
        self._selected_id = node_id
        data = self.topology_store.snapshot()
        node = data["nodes"].get(node_id)
        if not node:
            return

        for nid, item in self._node_items.items():
            item.setSelected(nid == node_id)

        self.editor_title.setText(node["name"])
        origin = "Auto-detected from discovery" if node.get("auto") else "Manually added"
        self.editor_type_lbl.setText(f"{NODE_TYPE_LABELS.get(node['type'], node['type'])} · {origin}")

        self.name_edit.blockSignals(True)
        self.name_edit.setText(node["name"])
        self.name_edit.blockSignals(False)

        # Build the "gets its internet from" choices: every node except
        # itself and its own descendants (which would create a cycle).
        blocked = self.topology_store.descendants(node_id) | {node_id}
        self.uplink_combo.blockSignals(True)
        self.uplink_combo.clear()
        self.uplink_combo.addItem("— Not connected —", None)
        for nid, n in sorted(data["nodes"].items(), key=lambda kv: kv[1]["name"].lower()):
            if nid in blocked:
                continue
            self.uplink_combo.addItem(f"{NODE_ICONS.get(n['type'],'')}  {n['name']}", nid)
        current_parent = data["edges"].get(node_id)
        idx = self.uplink_combo.findData(current_parent)
        self.uplink_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.uplink_combo.blockSignals(False)

        is_root = node_id == ROOT_ID
        self.name_edit.setEnabled(True)
        self.uplink_combo.setEnabled(not is_root)
        self.delete_btn.setEnabled(not is_root)

    def _apply_rename(self):
        if not self._selected_id:
            return
        name = self.name_edit.text().strip()
        if not name:
            return
        self.topology_store.rename_node(self._selected_id, name)
        self._rebuild()

    def _apply_uplink(self, _index):
        if not self._selected_id or self._selected_id == ROOT_ID:
            return
        parent_id = self.uplink_combo.currentData()
        # auto=False: this is always a deliberate human choice made here in
        # the UI, so sync_from_devices() must never override it later (see
        # qt/topology.py TopologyStore.set_uplink / sync_from_devices).
        ok = self.topology_store.set_uplink(self._selected_id, parent_id, auto=False)
        if not ok and parent_id is not None:
            QMessageBox.warning(self, "Can't connect that",
                                "That would create a loop (a node can't ultimately feed itself).")
            return
        self._rebuild()
        
        # Auto-arrange when making a new connection
        if parent_id is not None:
            self._auto_arrange()

    def _delete_selected(self):
        if not self._selected_id or self._selected_id == ROOT_ID:
            return
        node_id = self._selected_id
        data = self.topology_store.snapshot()
        name = data["nodes"].get(node_id, {}).get("name", "this node")
        reply = QMessageBox.question(
            self, "Delete Node",
            f"Remove \"{name}\" from the network map?\n\n"
            "Anything that was getting its internet from it will be re-linked "
            "straight to the Internet Entry Point until you reassign it.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.topology_store.remove_node(node_id)
            self._selected_id = None
            self._rebuild()

    def _on_node_moved(self, node_id: str):
        item = self._node_items.get(node_id)
        if item:
            pos = item.pos()
            self.topology_store.update_position(node_id, pos.x(), pos.y())

    # ── toolbar actions ───────────────────────────────────────────────────

    def _add_node(self):
        dlg = AddNodeDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            node_type, name = dlg.values()
            if not name:
                QMessageBox.warning(self, "Name required", "Please give the node a name.")
                return
            nid = self.topology_store.add_manual_node(node_type, name)
            self._rebuild()
            self._select_node(nid)
            
            # Auto-arrange and center on new node
            self._auto_arrange()
            self._center_on_node(nid)

    def _auto_arrange(self):
        data = self.topology_store.snapshot()
        edges = data["edges"]
        connected_nids = set(edges.keys()) | set(edges.values())
        connected_nids.add(ROOT_ID)

        # Filter out unconnected computers/devices from the layout calculations
        filtered_nodes = {
            nid: n for nid, n in data["nodes"].items()
            if not (n["type"] == "computer" and nid not in connected_nids)
        }
        positions = compute_tree_layout(filtered_nodes, data["edges"])
        self.topology_store.set_positions(positions)
        self._rebuild()
        
        # Fit all content in view after arranging
        self.canvas.fit_to_content()
    
    def _center_on_node(self, node_id: str):
        """Center the canvas view on a specific node"""
        item = self._node_items.get(node_id)
        if item:
            self.canvas.centerOn(item)

    # ── Qt overrides ──────────────────────────────────────────────────────

    def showEvent(self, event):
        super().showEvent(event)
        if self._dirty:
            self.refresh()