"""
qt/target_widget.py
~~~~~~~~~~~~~~~~~~~
Targeted-discovery input widget for the Mneti Qt dashboard.

Rewrite v4 — adds a third mode:
  1. MAC input  — no zero-padding of incomplete hex pairs; cursor stays
                  exactly where the user typed; left-to-right typing works
                  naturally.
  2. Mode selector — QComboBox dropdown ("MAC Address" / "IP Address" /
                     "IP Range") instead of a toggle button.
  3. IP input   — single QLineEdit, not 4 split boxes.  Looks seamless.
                  Enforces digits + dots only, clamps each octet ≤ 255,
                  auto-advances the dot after you finish an octet.
  4. IP Range input (NEW) — single QLineEdit accepting the same formats as
                  the Broadcast Ranges tab ('10.51.144.1-254', CIDR,
                  dotted mask, or a bare IP). Selecting this mode and
                  hitting Search restricts the discovery broadcast + ARP
                  scan to just that range, instead of the whole subnet —
                  this used to be a separate always-visible field on the
                  Discover page; it now lives here, next to MAC/IP, since
                  it's really just a third way to say what to search for.
"""

import re
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel,
    QPushButton, QLineEdit, QComboBox,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QKeyEvent

from qt.logic import parse_custom_range


# ─────────────────────────────────────────────────────────────────────────────
# MAC input
# ─────────────────────────────────────────────────────────────────────────────

_MAC_FULL_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


class _MacLineEdit(QLineEdit):
    """
    Single-line MAC address editor.

    Rules:
    • Only hex characters [0-9A-Fa-f] are accepted.
    • Colons are inserted automatically after every completed pair —
      the user never needs to type them.
    • Incomplete pairs are NEVER zero-padded while editing; padding
      happens only for display purposes when reading .get_value().
    • Cursor stays at the logical position after each keystroke.
    • Backspace removes the last hex character; if the cursor sits
      right after a colon the colon is also removed so the user does
      not get stuck.
    """

    def __init__(self):
        super().__init__()
        self.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.setMaxLength(17)          # "AA:BB:CC:DD:EE:FF" = 17 chars
        self.setFixedWidth(170)
        self.setStyleSheet(
            "QLineEdit {"
            "  font-family: Consolas, 'Courier New', monospace;"
            "  font-size: 13px;"
            "  border: 1px solid #ced4da;"
            "  border-radius: 4px;"
            "  padding: 5px 8px;"
            "}"
            "QLineEdit:focus { border-color: #80bdff; }"
        )
        self._updating = False

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _raw(text: str) -> str:
        """Strip colons → raw hex string (up to 12 chars)."""
        return text.replace(':', '')

    @staticmethod
    def _format(raw: str) -> str:
        """
        Insert colons every 2 chars.
        Incomplete trailing nibble is kept as-is — NO zero-padding.
        """
        raw = raw[:12]               # hard cap at 6 full bytes
        parts = []
        i = 0
        while i < len(raw):
            parts.append(raw[i:i+2])
            i += 2
        return ':'.join(parts)

    @staticmethod
    def _raw_pos(display_text: str, display_cursor: int) -> int:
        """Convert display cursor position → raw (colon-stripped) index."""
        return len(display_text[:display_cursor].replace(':', ''))

    @staticmethod
    def _display_pos(raw_len: int) -> int:
        """
        Convert raw index → display cursor position.
        Every 2 raw chars have a colon after them (except the last group).
        """
        full_pairs = raw_len // 2
        remainder  = raw_len % 2
        pos = full_pairs * 2 + full_pairs
        if remainder:
            pos += remainder
        else:
            if full_pairs > 0:
                pos -= 1
        return raw_len + (raw_len - 1) // 2 if raw_len > 0 else 0

    # ── key handling ──────────────────────────────────────────────────────────

    def keyPressEvent(self, event: QKeyEvent):
        key = event.key()

        # Pass navigation keys through unchanged
        if key in (Qt.Key.Key_Left, Qt.Key.Key_Right,
                   Qt.Key.Key_Home, Qt.Key.Key_End,
                   Qt.Key.Key_Tab, Qt.Key.Key_Return, Qt.Key.Key_Enter):
            super().keyPressEvent(event)
            return

        # ── Backspace ─────────────────────────────────────────────────────────
        if key == Qt.Key.Key_Backspace:
            if self.hasSelectedText():
                start = self.selectionStart()
                end   = start + len(self.selectedText())
                cur   = self.text()
                raw   = self._raw(cur[:start] + cur[end:])
                new_text = self._format(raw)
                raw_cur  = self._raw(cur[:start])
                self._set(new_text, len(raw_cur))
            else:
                cur = self.text()
                pos = self.cursorPosition()
                if pos == 0:
                    return
                if pos > 0 and cur[pos - 1] == ':':
                    pos -= 1
                raw = self._raw(cur[:pos])
                if not raw:
                    self._set('', 0)
                    return
                raw_new  = raw[:-1] + self._raw(cur[pos:])
                new_text = self._format(raw_new)
                self._set(new_text, len(raw[:-1]))
            return

        # ── Delete ────────────────────────────────────────────────────────────
        if key == Qt.Key.Key_Delete:
            if self.hasSelectedText():
                start = self.selectionStart()
                end   = start + len(self.selectedText())
                cur   = self.text()
                raw   = self._raw(cur[:start] + cur[end:])
                new_text = self._format(raw)
                raw_cur  = self._raw(cur[:start])
                self._set(new_text, len(raw_cur))
            else:
                cur = self.text()
                pos = self.cursorPosition()
                if pos < len(cur) and cur[pos] == ':':
                    pos += 1
                if pos >= len(cur):
                    return
                raw_before = self._raw(cur[:pos])
                raw_after  = self._raw(cur[pos + 1:])
                raw_new    = raw_before + raw_after
                new_text   = self._format(raw_new)
                self._set(new_text, len(raw_before))
            return

        # ── Printable character ───────────────────────────────────────────────
        ch = event.text().upper()
        if not ch or not re.match(r'[0-9A-F]', ch):
            return   # swallow non-hex

        cur = self.text()
        raw = self._raw(cur)

        if len(raw) >= 12:
            return   # already full

        if self.hasSelectedText():
            start    = self.selectionStart()
            end      = start + len(self.selectedText())
            raw_pre  = self._raw(cur[:start])
            raw_post = self._raw(cur[end:])
            raw_new  = raw_pre + ch + raw_post
            new_text = self._format(raw_new[:12])
            self._set(new_text, len(raw_pre) + 1)
            return

        pos      = self.cursorPosition()
        raw_pre  = self._raw(cur[:pos])
        raw_post = self._raw(cur[pos:])
        raw_new  = (raw_pre + ch + raw_post)[:12]
        new_text = self._format(raw_new)
        self._set(new_text, len(raw_pre) + 1)

    def _set(self, text: str, raw_cursor: int):
        """Set display text and position cursor using the raw index."""
        self._updating = True
        self.setText(text)
        disp = self._raw_to_disp(text, raw_cursor)
        self.setCursorPosition(disp)
        self._updating = False
        self.textChanged.emit(text)

    @staticmethod
    def _raw_to_disp(text: str, raw_idx: int) -> int:
        count = 0
        for i, ch in enumerate(text):
            if count == raw_idx:
                return i
            if ch != ':':
                count += 1
        return len(text)

    # ── public API ────────────────────────────────────────────────────────────

    def is_valid(self) -> bool:
        return bool(_MAC_FULL_RE.match(self.text()))

    def get_value(self) -> str:
        """Return upper-case MAC, zero-padding the last incomplete pair."""
        raw = self._raw(self.text()).upper()
        if len(raw) < 12:
            return ''     # incomplete — caller should use is_valid()
        return ':'.join(raw[i:i+2] for i in range(0, 12, 2))

    def clear(self):
        super().clear()
        self.textChanged.emit('')


# ─────────────────────────────────────────────────────────────────────────────
# IP input  — single seamless QLineEdit
# ─────────────────────────────────────────────────────────────────────────────

_IP_RE = re.compile(
    r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)


class _IPLineEdit(QLineEdit):
    """
    Single QLineEdit that behaves like a proper IP-address field:
    • Accepts only digits and dots.
    • Enforces each octet ≤ 255 in real time.
    • Auto-inserts a dot when an octet reaches its max length or value.
    • Blocks more than 3 dots (4 octets max).
    • Looks like a plain text box — no visible separators or widget seams.
    """

    search_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setPlaceholderText("e.g.  192.168.1.1")
        self.setMaxLength(15)      # "255.255.255.255" = 15
        self.setFixedWidth(170)
        self.setStyleSheet(
            "QLineEdit {"
            "  font-family: Consolas, 'Courier New', monospace;"
            "  font-size: 13px;"
            "  border: 1px solid #ced4da;"
            "  border-radius: 4px;"
            "  padding: 5px 8px;"
            "}"
            "QLineEdit:focus { border-color: #80bdff; }"
        )

    def keyPressEvent(self, event: QKeyEvent):
        key  = event.key()
        char = event.text()

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.search_requested.emit()
            return

        if key in (Qt.Key.Key_Left, Qt.Key.Key_Right, Qt.Key.Key_Home,
                   Qt.Key.Key_End, Qt.Key.Key_Backspace, Qt.Key.Key_Delete,
                   Qt.Key.Key_Tab, Qt.Key.Key_Shift):
            super().keyPressEvent(event)
            self._clamp_current_octet()
            return

        if not char:
            super().keyPressEvent(event)
            return

        if char == '.':
            cur = self.text()
            if cur.count('.') >= 3:
                return
            pos = self.cursorPosition()
            if pos == 0 or (pos > 0 and cur[pos - 1] == '.'):
                return
            super().keyPressEvent(event)
            return

        if not char.isdigit():
            return

        cur = self.text()
        pos = self.cursorPosition()

        before = cur[:pos]
        dot_pos = before.rfind('.')
        octet_start = dot_pos + 1
        octet_so_far = before[octet_start:]

        if len(octet_so_far) >= 3:
            return

        after_in_octet = cur[pos:]
        next_dot = after_in_octet.find('.')
        octet_end_in_after = next_dot if next_dot != -1 else len(after_in_octet)
        octet_tail = after_in_octet[:octet_end_in_after]
        new_octet = octet_so_far + char + octet_tail

        try:
            val = int(new_octet)
        except ValueError:
            val = 0

        if val > 255:
            return

        super().keyPressEvent(event)

        cur2 = self.text()
        pos2 = self.cursorPosition()
        before2   = cur2[:pos2]
        dot_pos2  = before2.rfind('.')
        oct_start2 = dot_pos2 + 1
        oct_now    = before2[oct_start2:]

        should_dot = False
        if len(oct_now) == 3:
            should_dot = True
        elif len(oct_now) == 2:
            try:
                if int(oct_now) > 25:
                    should_dot = True
            except ValueError:
                pass

        if should_dot and cur2.count('.') < 3:
            after2 = cur2[pos2:]
            if not after2 or after2[0] == '.':
                if not after2 or after2[0] != '.':
                    self.insert('.')

    def _clamp_current_octet(self):
        """After any edit, clamp the octet under the cursor to ≤ 255."""
        cur = self.text()
        pos = self.cursorPosition()
        before = cur[:pos]
        dot_pos = before.rfind('.')
        oct_start = dot_pos + 1

        after = cur[pos:]
        next_dot = after.find('.')
        oct_end = pos + (next_dot if next_dot != -1 else len(after))

        octet_str = cur[oct_start:oct_end]
        if not octet_str:
            return
        try:
            val = int(octet_str)
        except ValueError:
            return
        if val > 255:
            clamped = '255'
            new_text = cur[:oct_start] + clamped + cur[oct_end:]
            self.setText(new_text)
            self.setCursorPosition(oct_start + len(clamped))

    def is_valid(self) -> bool:
        return bool(_IP_RE.match(self.text()))

    def get_value(self) -> str:
        return self.text()


# ─────────────────────────────────────────────────────────────────────────────
# IP Range input (NEW) — single QLineEdit, same formats as Broadcast Ranges
# ─────────────────────────────────────────────────────────────────────────────

class _RangeLineEdit(QLineEdit):
    """
    Free-text range entry. Accepts anything parse_custom_range() understands:
      - '10.51.144.1-254'  (start-end, same formats as the Broadcast Ranges tab)
      - '10.51.144.0/24'   (CIDR)
      - '10.51.144.0/255.255.255.0'  (dotted mask)
      - '10.51.144.7'      (single host, treated as /32)

    Live validity is checked with the exact same parser the Broadcast Ranges
    tab and the actual scan use, so "looks valid here" always means "will
    actually parse when the search runs."
    """

    search_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setPlaceholderText("e.g.  10.51.144.1-254")
        self.setFixedWidth(220)
        self.setStyleSheet(
            "QLineEdit {"
            "  font-family: Consolas, 'Courier New', monospace;"
            "  font-size: 13px;"
            "  border: 1px solid #ced4da;"
            "  border-radius: 4px;"
            "  padding: 5px 8px;"
            "}"
            "QLineEdit:focus { border-color: #80bdff; }"
        )
        self.returnPressed.connect(self.search_requested)

    def is_valid(self) -> bool:
        text = self.text().strip()
        if not text:
            return False
        return parse_custom_range(text) is not None

    def get_value(self) -> str:
        return self.text().strip()


# ─────────────────────────────────────────────────────────────────────────────
# Combined TargetInputWidget
# ─────────────────────────────────────────────────────────────────────────────

class TargetInputWidget(QWidget):
    """
    Drop-in widget for the Discover panel.

    Layout:
      [MAC Address ▾]  [input field]  [✓/✗]  [Search]
      hint text

    The mode selector is a QComboBox with three items:
      "MAC Address"  →  _MacLineEdit    → mode() == "mac"
      "IP Address"   →  _IPLineEdit     → mode() == "ip"
      "IP Range"     →  _RangeLineEdit  → mode() == "range"

    "IP Range" doesn't target a single device — selecting it and hitting
    Search means "run a full discovery scan, but restricted to just this
    range" instead of the whole subnet / saved custom ranges. The caller
    (MainWindow.start_targeted_discovery) is responsible for routing that
    mode differently from a MAC/IP target match.
    """

    search_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._mode = "mac"

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        # ── Row 1: combo + input + valid icon + search button ─────────────────
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        # Dropdown mode selector
        self._combo = QComboBox()
        self._combo.addItem("MAC Address")
        self._combo.addItem("IP Address")
        self._combo.addItem("IP Range")
        self._combo.setFixedWidth(110)
        self._combo.setStyleSheet(
            "QComboBox {"
            "  border: 1px solid #ced4da;"
            "  border-radius: 4px;"
            "  padding: 4px 8px;"
            "  font-size: 13px;"
            "  background: #f8f9fa;"
            "}"
            "QComboBox:hover { background: #e2e6ea; }"
            "QComboBox::drop-down { border: none; width: 20px; }"
            "QComboBox::down-arrow { image: none; width: 0; }"
        )
        self._combo.currentIndexChanged.connect(self._on_combo_changed)
        row1.addWidget(self._combo)

        # MAC input
        self._mac_edit = _MacLineEdit()
        self._mac_edit.textChanged.connect(self._on_input_changed)
        self._mac_edit.returnPressed.connect(self.search_requested)
        row1.addWidget(self._mac_edit)

        # IP input
        self._ip_edit = _IPLineEdit()
        self._ip_edit.textChanged.connect(self._on_input_changed)
        self._ip_edit.search_requested.connect(self.search_requested)
        self._ip_edit.hide()
        row1.addWidget(self._ip_edit)

        # Range input (NEW)
        self._range_edit = _RangeLineEdit()
        self._range_edit.textChanged.connect(self._on_input_changed)
        self._range_edit.search_requested.connect(self.search_requested)
        self._range_edit.hide()
        row1.addWidget(self._range_edit)

        # Validity icon
        self._valid_lbl = QLabel("")
        self._valid_lbl.setFixedWidth(18)
        self._valid_lbl.setTextFormat(Qt.TextFormat.RichText)
        row1.addWidget(self._valid_lbl)

        # Search button
        self._search_btn = QPushButton("Search")
        self._search_btn.setObjectName("Primary")
        self._search_btn.clicked.connect(self.search_requested)
        row1.addWidget(self._search_btn)

        root.addLayout(row1)

        # ── Row 2: hint ───────────────────────────────────────────────────────
        self._hint_lbl = QLabel("Format: AA:BB:CC:DD:EE:FF  (hex pairs, auto-separated)")
        self._hint_lbl.setStyleSheet(
            "font-size: 11px; color: #6c757d;"
            " font-family: Consolas, monospace;"
        )
        root.addWidget(self._hint_lbl)

    # ── Mode switch ───────────────────────────────────────────────────────────

    _HINTS = {
        "mac":   "Format: AA:BB:CC:DD:EE:FF  (hex pairs, auto-separated)",
        "ip":    "Enter each octet (0–255); dots are enforced automatically",
        "range": "Range, CIDR, dotted mask, or single IP — e.g. 10.51.144.1-254 "
                 "or 10.51.144.0/24. Search restricts the scan to just this range.",
    }
    _MODE_BY_INDEX = {0: "mac", 1: "ip", 2: "range"}

    def _on_combo_changed(self, index: int):
        self._mode = self._MODE_BY_INDEX.get(index, "mac")

        self._mac_edit.setVisible(self._mode == "mac")
        self._ip_edit.setVisible(self._mode == "ip")
        self._range_edit.setVisible(self._mode == "range")

        self._valid_lbl.setText("")
        self._hint_lbl.setText(self._HINTS[self._mode])

        if self._mode == "mac":
            self._mac_edit.clear()
            self._mac_edit.setFocus()
        elif self._mode == "ip":
            self._ip_edit.clear()
            self._ip_edit.setFocus()
        else:
            self._range_edit.clear()
            self._range_edit.setFocus()

    # ── Validation indicator ──────────────────────────────────────────────────

    def _on_input_changed(self, *_):
        has_input = bool(self._current_raw())
        valid     = self._is_valid()
        if not has_input:
            self._valid_lbl.setText("")
        elif valid:
            self._valid_lbl.setText(
                '<span style="color:#28a745; font-size:15px;">✓</span>')
        else:
            self._valid_lbl.setText(
                '<span style="color:#dc3545; font-size:15px;">✗</span>')

    def _is_valid(self) -> bool:
        if self._mode == "mac":
            return self._mac_edit.is_valid()
        if self._mode == "ip":
            return self._ip_edit.is_valid()
        return self._range_edit.is_valid()

    def _current_raw(self) -> str:
        if self._mode == "mac":
            return self._mac_edit.text()
        if self._mode == "ip":
            return self._ip_edit.text()
        return self._range_edit.text()

    # ── Public API ────────────────────────────────────────────────────────────

    def mode(self) -> str:
        """Return 'mac', 'ip', or 'range'."""
        return self._mode

    def is_valid(self) -> bool:
        return self._is_valid()

    def value(self) -> str | None:
        """Return the validated value, or None if incomplete / invalid."""
        if not self._is_valid():
            return None
        if self._mode == "mac":
            return self._mac_edit.get_value()
        if self._mode == "ip":
            return self._ip_edit.get_value()
        return self._range_edit.get_value()

    def raw_value(self) -> str:
        return self._current_raw()

    def clear(self):
        self._mac_edit.clear()
        self._ip_edit.clear()
        self._range_edit.clear()
        self._valid_lbl.setText("")