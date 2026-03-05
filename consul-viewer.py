#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import queue
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import urwid

__version__="1.1.0"
__author__ = "Tarasov Dmitry"


APP_NAME = "Consul Viewer TUI"
DEFAULT_ADDR = "http://127.0.0.1:8500"
DEFAULT_REFRESH = 5.0
DEFAULT_TIMEOUT = 8.0
CACHE_TTL_SHORT = 2.0
CACHE_TTL_MEDIUM = 5.0
CACHE_TTL_LONG = 15.0
MAX_PREVIEW_BYTES = 4096
MAX_HEX_PREVIEW_BYTES = 512

MENU_ITEMS = [
    ("dashboard", "Dashboard", True),
    ("telemetry", "Telemetry", True),
    ("services", "Services", True),
    ("nodes", "Nodes", True),
    ("kv", "KV", True),
    ("sessions", "Sessions", True),
    ("tokens", "Tokens", True),
    ("policies", "Policies", True),
    ("roles", "Roles", True),
    ("mesh", "Mesh", False),
    ("auth", "Auth", True),
]

STATUS_ORDER = {
    "passing": 0,
    "warning": 1,
    "critical": 2,
    "unknown": -1,
}

SENSITIVE_FIELD_MARKERS = ("secret",)
KV_PARENT_ID_PREFIX = "__kv_parent__:"
KV_DIR_ID_PREFIX = "__kv_dir__:"
KV_KEY_ID_PREFIX = "__kv_key__:"


class ApiError(Exception):
    """Raised when a Consul API request fails or returns invalid data."""

    def __init__(self, message: str, status: Optional[int] = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass
class AppConfig:
    """Runtime configuration for the TUI application."""

    addr: str
    token: str = ""
    refresh: float = DEFAULT_REFRESH
    timeout: float = DEFAULT_TIMEOUT
    insecure: bool = False
    dc: str = ""
    ca_file: str = ""
    cert_file: str = ""
    key_file: str = ""

    @property
    def auth_mode(self) -> str:
        return "token" if self.token else "anonymous"


@dataclass
class Job:
    """Background worker job descriptor."""

    key: str
    name: str
    args: tuple[Any, ...]
    ttl: float
    force: bool = False


@dataclass
class JobResult:
    """Background worker result container."""

    key: str
    name: str
    args: tuple[Any, ...]
    ok: bool
    payload: Any = None
    error: str = ""
    timestamp: float = field(default_factory=time.time)


def fit_text(value: Any, width: int) -> str:
    """Fit a value into a fixed-width column with padding or truncation."""

    text = str(value) if value is not None else ""
    if width <= 0:
        return ""
    if len(text) <= width:
        return text.ljust(width)
    if width == 1:
        return text[:1]
    return text[: width - 1] + "…"


def format_columns(values: list[Any], widths: list[int]) -> str:
    """Render a flat list of values into fixed-width text columns."""

    parts = [fit_text(value, width) for value, width in zip(values, widths)]
    return " ".join(parts).rstrip()


def status_rank(status: str) -> int:
    return STATUS_ORDER.get((status or "unknown").lower(), -1)


def combine_statuses(statuses: list[str]) -> str:
    """Return the worst status from a list using the local status ranking."""

    if not statuses:
        return "unknown"
    return sorted(statuses, key=status_rank, reverse=True)[0].lower()


def status_attr(status: str) -> str:
    """Map a logical status name to a palette attribute."""

    normalized = (status or "unknown").lower()
    if normalized == "passing":
        return "status_passing"
    if normalized == "warning":
        return "status_warning"
    if normalized == "critical":
        return "status_critical"
    return "list_item"


def format_ratio(passed: Any, total: Any) -> str:
    """Format a simple used/total ratio for list columns."""

    if passed is None or total is None:
        return "?/?"
    return f"{passed}/{total}"


def mask_sensitive(data: Any) -> Any:
    if isinstance(data, dict):
        masked: dict[str, Any] = {}
        for key, value in data.items():
            lowered = key.lower()
            if any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS):
                masked[key] = "***"
            else:
                masked[key] = mask_sensitive(value)
        return masked
    if isinstance(data, list):
        return [mask_sensitive(item) for item in data]
    return data


def safe_json(data: Any) -> str:
    """Render masked JSON for viewer popups and debugging details."""

    return json.dumps(mask_sensitive(data), indent=2, ensure_ascii=False, sort_keys=True)


def now_hms() -> str:
    return time.strftime("%H:%M:%S")


def normalize_display_text(value: Any) -> str:
    """Normalize text for terminal widgets (tabs look broken in some urwid/terminal combos)."""

    return str(value).expandtabs(4)


class ConsulClient:
    """Small read-only wrapper around the Consul HTTP API."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.base_url = config.addr.rstrip("/")
        self.ssl_context = self._build_ssl_context()

    def _build_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self.base_url.startswith("https://"):
            return None
        if self.config.insecure:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context(cafile=self.config.ca_file or None)
        if self.config.cert_file:
            context.load_cert_chain(self.config.cert_file, self.config.key_file or None)
        return context

    def _build_url(self, path: str, params: Optional[dict[str, Any]] = None) -> str:
        query: dict[str, Any] = {}
        if self.config.dc:
            query["dc"] = self.config.dc
        if params:
            query.update({key: value for key, value in params.items() if value is not None})
        encoded = urllib.parse.urlencode(query, doseq=True)
        suffix = f"?{encoded}" if encoded else ""
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base_url}{path}{suffix}"

    def get_json(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        """Fetch a JSON endpoint and raise ApiError on transport or decode failure.

        Args:
            path: API path relative to the configured Consul base URL.
            params: Optional query parameters merged with the configured datacenter.

        Returns:
            Parsed JSON payload from the response body.

        Raises:
            ApiError: If the request fails, times out, or the body is not valid JSON.
        """
        url = self._build_url(path, params)
        headers = {"Accept": "application/json", "User-Agent": APP_NAME}
        if self.config.token:
            headers["X-Consul-Token"] = self.config.token
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.timeout,
                context=self.ssl_context,
            ) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            reason = body.strip() or exc.reason
            raise ApiError(f"HTTP {exc.code}: {reason}", status=exc.code, body=body) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise ApiError(f"Network error: {reason}") from exc
        except TimeoutError as exc:
            raise ApiError("Network timeout") from exc
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise ApiError(f"Invalid JSON response from {path}: {exc}") from exc

    def get_text(self, path: str, params: Optional[dict[str, Any]] = None, accept: str = "text/plain") -> str:
        """Fetch a plain-text endpoint and raise ApiError on transport failure.

        Args:
            path: API path relative to the configured Consul base URL.
            params: Optional query parameters merged with the configured datacenter.
            accept: HTTP Accept header value for the request.

        Returns:
            Decoded UTF-8 response body.

        Raises:
            ApiError: If the request fails or times out.
        """
        url = self._build_url(path, params)
        headers = {"Accept": accept, "User-Agent": APP_NAME}
        if self.config.token:
            headers["X-Consul-Token"] = self.config.token
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.timeout,
                context=self.ssl_context,
            ) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            reason = body.strip() or exc.reason
            raise ApiError(f"HTTP {exc.code}: {reason}", status=exc.code, body=body) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise ApiError(f"Network error: {reason}") from exc
        except TimeoutError as exc:
            raise ApiError("Network timeout") from exc

    def agent_self(self) -> dict[str, Any]:
        return self.get_json("/v1/agent/self")

    def leader(self) -> str:
        return self.get_json("/v1/status/leader")

    def peers(self) -> list[str]:
        return self.get_json("/v1/status/peers")

    def members(self) -> list[dict[str, Any]]:
        return self.get_json("/v1/agent/members")

    def catalog_services(self) -> dict[str, list[str]]:
        return self.get_json("/v1/catalog/services")

    def health_service(self, name: str) -> list[dict[str, Any]]:
        return self.get_json(f"/v1/health/service/{urllib.parse.quote(name, safe='')}")

    def catalog_nodes(self) -> list[dict[str, Any]]:
        return self.get_json("/v1/catalog/nodes")

    def catalog_node(self, name: str) -> dict[str, Any]:
        return self.get_json(f"/v1/catalog/node/{urllib.parse.quote(name, safe='')}")

    def health_node(self, name: str) -> list[dict[str, Any]]:
        return self.get_json(f"/v1/health/node/{urllib.parse.quote(name, safe='')}")

    def kv_keys(self, prefix: str) -> list[str]:
        params = {"keys": "", "separator": "/"}
        normalized = prefix.strip("/")
        path = "/v1/kv/"
        if normalized:
            path += urllib.parse.quote(normalized, safe="/")
            if not path.endswith("/"):
                path += "/"
        return self.get_json(path, params=params) or []

    def kv_value(self, key: str) -> list[dict[str, Any]]:
        return self.get_json(f"/v1/kv/{urllib.parse.quote(key, safe='/')}")

    def sessions(self) -> list[dict[str, Any]]:
        return self.get_json("/v1/session/list")

    def agent_metrics_prometheus(self) -> str:
        return self.get_text("/v1/agent/metrics", params={"format": "prometheus"})

    def acl_policies(self) -> list[dict[str, Any]]:
        return self.get_json("/v1/acl/policies")

    def acl_policy(self, policy_id: str) -> dict[str, Any]:
        return self.get_json(f"/v1/acl/policy/{urllib.parse.quote(policy_id, safe='')}")

    def acl_tokens(self) -> list[dict[str, Any]]:
        return self.get_json("/v1/acl/tokens")

    def acl_roles(self) -> list[dict[str, Any]]:
        return self.get_json("/v1/acl/roles")

    def acl_auth_methods(self) -> list[dict[str, Any]]:
        return self.get_json("/v1/acl/auth-methods")

    def acl_auth_method(self, name: str) -> dict[str, Any]:
        return self.get_json(f"/v1/acl/auth-method/{urllib.parse.quote(name, safe='')}")

    def acl_auth_method(self, name: str) -> dict[str, Any]:
        return self.get_json(f"/v1/acl/auth-method/{urllib.parse.quote(name, safe='')}")


class PlainButton(urwid.WidgetWrap):
    """Compact selectable row widget without urwid.Button left padding."""

    def __init__(self, label: str, on_press: Optional[Callable[..., Any]] = None, user_data: Any = None) -> None:
        self._on_press = on_press
        self._user_data = user_data
        self._text = urwid.Text(label, wrap="clip")
        super().__init__(self._text)

    def selectable(self) -> bool:
        return self._on_press is not None

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter" and self._on_press is not None:
            self._on_press(self, self._user_data)
            return None
        return key

    def mouse_event(self, size: tuple[int, int], event: str, button: int, col: int, row: int, focus: bool) -> bool:
        if event == "mouse press" and button == 1 and self._on_press is not None:
            self._on_press(self, self._user_data)
            return True
        return False


class FocusColumns(urwid.Columns):
    """Columns container that notifies when the focused column changes."""

    def __init__(
        self,
        widget_list: list[Any],
        on_focus_change: Optional[Callable[[int], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(widget_list, **kwargs)
        self.on_focus_change = on_focus_change
        self._last_focus = self.focus_position

    def _notify_focus_change(self) -> None:
        if self.focus_position != self._last_focus:
            self._last_focus = self.focus_position
            if self.on_focus_change:
                self.on_focus_change(self.focus_position)

    def keypress(self, size: tuple[int, ...], key: str) -> Optional[str]:
        result = super().keypress(size, key)
        self._notify_focus_change()
        return result


class FocusListBox(urwid.ListBox):
    """ListBox wrapper that reports focus changes after keyboard or mouse input."""

    def __init__(self, body: urwid.ListWalker, on_focus_change: Optional[Callable[[Optional[int]], None]] = None) -> None:
        super().__init__(body)
        self.on_focus_change = on_focus_change
        self._last_focus: Optional[int] = None

    def _notify_focus_change(self) -> None:
        if not self.on_focus_change:
            return
        focus = self.get_focus()
        position = focus[1] if focus and focus[0] is not None else None
        if position != self._last_focus:
            self._last_focus = position
            self.on_focus_change(position)

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        result = super().keypress(size, key)
        self._notify_focus_change()
        return result

    def mouse_event(self, size: tuple[int, int], event: str, button: int, col: int, row: int, focus: bool) -> bool:
        handled = super().mouse_event(size, event, button, col, row, focus)
        self._notify_focus_change()
        return handled

    def render(self, size: tuple[int, int], focus: bool = False) -> urwid.Canvas:
        canvas = super().render(size, focus)
        self._notify_focus_change()
        return canvas


class PopupDialog(urwid.WidgetWrap):
    """Generic modal dialog shell with header, body, footer, and close handling."""

    def __init__(self, title: str, body: urwid.Widget, on_close: Callable[[], None]) -> None:
        self._on_close = on_close
        header = urwid.AttrMap(urwid.Text(title, align="center"), "popup_title")
        footer = urwid.AttrMap(urwid.Text("Esc/F10: close", align="center"), "popup_footer")
        body_widget = urwid.Filler(body, valign="top") if hasattr(body, "rows") else body
        body_widget = urwid.AttrMap(body_widget, "popup_body")
        frame = urwid.Frame(body=body_widget, header=header, footer=footer)
        box = urwid.LineBox(frame)
        super().__init__(urwid.AttrMap(box, "popup_border"))

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key in {"esc", "f10"}:
            self._on_close()
            return None
        return super().keypress(size, key)


class InputDialog(urwid.WidgetWrap):
    """Single-line text input dialog used for simple filter entry."""

    def __init__(
        self,
        title: str,
        caption: str,
        initial_text: str,
        on_submit: Callable[[str], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self._on_submit = on_submit
        self._on_cancel = on_cancel
        self.edit = urwid.Edit(caption=caption, edit_text=initial_text)
        pile = urwid.Pile(
            [
                ("pack", urwid.AttrMap(urwid.Text(title, align="center"), "popup_title")),
                ("pack", urwid.Divider()),
                ("pack", urwid.AttrMap(self.edit, "popup_body")),
                ("pack", urwid.Divider()),
                ("pack", urwid.AttrMap(urwid.Text("Enter: apply  Esc: cancel", align="center"), "popup_footer")),
            ]
        )
        fill = urwid.AttrMap(urwid.Filler(pile, valign="top"), "popup_body")
        box = urwid.LineBox(fill)
        super().__init__(urwid.AttrMap(box, "popup_border"))

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter":
            self._on_submit(self.edit.edit_text)
            return None
        if key in {"esc", "f10"}:
            self._on_cancel()
            return None
        return super().keypress(size, key)


class InstanceTextFilterDialog(urwid.WidgetWrap):
    """Dialog for F7 text filtering in instance lists by service/address with AND/OR logic."""

    def __init__(
        self,
        initial: dict[str, Any],
        on_submit: Callable[[dict[str, Any]], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self._on_submit = on_submit
        self._on_cancel = on_cancel
        self.instance_edit = urwid.Edit(edit_text=str(initial.get("instance", "")))
        self.service_edit = urwid.Edit(edit_text=str(initial.get("service", "")))
        self.address_edit = urwid.Edit(edit_text=str(initial.get("address", "")))
        mode = str(initial.get("mode", "and")).strip().lower()
        group: list[urwid.RadioButton] = []
        self.and_button = urwid.RadioButton(group, "AND", state=mode != "or")
        self.or_button = urwid.RadioButton(group, "OR", state=mode == "or")
        items: list[urwid.Widget] = [
            urwid.Text("Text filter for instance lists (substring match, case-insensitive).", align="left"),
            urwid.Divider(),
            urwid.Columns(
                [
                    ("weight", 3, urwid.Text("Instance:")),
                    ("weight", 7, urwid.AttrMap(self.instance_edit, "popup_body")),
                ],
                dividechars=1,
            ),
            urwid.Columns(
                [
                    ("weight", 3, urwid.Text("Service:")),
                    ("weight", 7, urwid.AttrMap(self.service_edit, "popup_body")),
                ],
                dividechars=1,
            ),
            urwid.Columns(
                [
                    ("weight", 3, urwid.Text("Address:")),
                    ("weight", 7, urwid.AttrMap(self.address_edit, "popup_body")),
                ],
                dividechars=1,
            ),
            urwid.Divider(),
            urwid.Text("Combine fields:", align="left"),
            self.and_button,
            self.or_button,
        ]
        walker = urwid.SimpleFocusListWalker(items)
        body = urwid.ListBox(walker)
        frame = urwid.Frame(
            body=urwid.AttrMap(body, "popup_body"),
            header=urwid.AttrMap(urwid.Text("Instance Text Filter", align="center"), "popup_title"),
            footer=urwid.AttrMap(urwid.Text("Enter: apply  Esc/F10: cancel", align="center"), "popup_footer"),
        )
        super().__init__(urwid.AttrMap(urwid.LineBox(frame), "popup_border"))

    def value(self) -> dict[str, Any]:
        return {
            "instance": self.instance_edit.edit_text.strip(),
            "service": self.service_edit.edit_text.strip(),
            "address": self.address_edit.edit_text.strip(),
            "mode": "or" if self.or_button.get_state() else "and",
        }

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter":
            self._on_submit(self.value())
            return None
        if key in {"esc", "f10"}:
            self._on_cancel()
            return None
        return super().keypress(size, key)


class StatusFilterDialog(urwid.WidgetWrap):
    """Checkbox dialog for the OR-based health status filter."""

    def __init__(
        self,
        title: str,
        selected: set[str],
        on_submit: Callable[[set[str]], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self._on_submit = on_submit
        self._on_cancel = on_cancel
        self.checkboxes: list[tuple[str, urwid.CheckBox]] = [
            ("passed", urwid.CheckBox("Passed", state="passed" in selected)),
            ("warning", urwid.CheckBox("Warning", state="warning" in selected)),
            ("critical", urwid.CheckBox("Critical", state="critical" in selected)),
            ("no_checks", urwid.CheckBox("No checks", state="no_checks" in selected)),
        ]
        body_items: list[urwid.Widget] = [
            urwid.Text("Space: toggle  Enter: apply  Esc: cancel", align="left"),
            urwid.Divider(),
        ]
        for _, checkbox in self.checkboxes:
            body_items.append(checkbox)
        walker = urwid.SimpleFocusListWalker(body_items)
        body = urwid.ListBox(walker)
        frame = urwid.Frame(
            body=urwid.AttrMap(body, "popup_body"),
            header=urwid.AttrMap(urwid.Text(title, align="center"), "popup_title"),
            footer=urwid.AttrMap(urwid.Text("Enter: apply  Esc/F10: cancel", align="center"), "popup_footer"),
        )
        super().__init__(urwid.AttrMap(urwid.LineBox(frame), "popup_border"))

    def selected_values(self) -> set[str]:
        return {name for name, checkbox in self.checkboxes if checkbox.get_state()}

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter":
            self._on_submit(self.selected_values())
            return None
        if key in {"esc", "f10"}:
            self._on_cancel()
            return None
        return super().keypress(size, key)


class InstanceFilterDialog(urwid.WidgetWrap):
    """Structured filter dialog for instance tags and metadata."""

    def __init__(
        self,
        initial: dict[str, Any],
        on_submit: Callable[[dict[str, Any]], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self._on_submit = on_submit
        self._on_cancel = on_cancel
        self.edits: dict[str, urwid.Edit] = {}
        field_defs = [
            ("has_tags", "Has tags"),
            ("no_tags", "No tags"),
            ("has_meta_keys", "Has meta keys"),
            ("no_meta_keys", "No meta keys"),
            ("meta_key_pattern", "Meta key regex"),
            ("meta_value_pattern", "Meta value regex"),
        ]
        items: list[urwid.Widget] = [
            urwid.Text("Comma lists for tags/meta. Regex fields support regex or substring.", align="left"),
            urwid.Divider(),
        ]
        for field_name, label in field_defs:
            edit = urwid.Edit(edit_text=str(initial.get(field_name, "")))
            self.edits[field_name] = edit
            items.append(
                urwid.Columns(
                    [
                        ("weight", 3, urwid.Text(f"{label}:")),
                        ("weight", 7, urwid.AttrMap(edit, "popup_body")),
                    ],
                    dividechars=1,
                )
            )
        self.case_checkbox = urwid.CheckBox("Case sensitive", state=bool(initial.get("case_sensitive")))
        self.regex_checkbox = urwid.CheckBox("Regex enabled", state=bool(initial.get("regex_enabled", True)))
        items.extend(
            [
                urwid.Divider(),
                self.case_checkbox,
                self.regex_checkbox,
            ]
        )
        walker = urwid.SimpleFocusListWalker(items)
        body = urwid.ListBox(walker)
        frame = urwid.Frame(
            body=urwid.AttrMap(body, "popup_body"),
            header=urwid.AttrMap(urwid.Text("Instance Filter", align="center"), "popup_title"),
            footer=urwid.AttrMap(urwid.Text("Enter: apply  Esc/F10: cancel", align="center"), "popup_footer"),
        )
        super().__init__(urwid.AttrMap(urwid.LineBox(frame), "popup_border"))

    def value(self) -> dict[str, Any]:
        data = {name: edit.edit_text.strip() for name, edit in self.edits.items()}
        data["case_sensitive"] = self.case_checkbox.get_state()
        data["regex_enabled"] = self.regex_checkbox.get_state()
        return data

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter":
            self._on_submit(self.value())
            return None
        if key in {"esc", "f10"}:
            self._on_cancel()
            return None
        return super().keypress(size, key)


class ClearFiltersDialog(urwid.WidgetWrap):
    """Checkbox dialog that lets the user choose which filters to reset."""

    def __init__(
        self,
        clear_text_default: bool,
        clear_status_default: bool,
        clear_instance_default: bool,
        on_submit: Callable[[set[str]], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self._on_submit = on_submit
        self._on_cancel = on_cancel
        self.checkboxes: list[tuple[str, urwid.CheckBox]] = [
            ("text", urwid.CheckBox("Text filter", state=clear_text_default)),
            ("status", urwid.CheckBox("Status filter", state=clear_status_default)),
            ("instance", urwid.CheckBox("Instance filter", state=clear_instance_default)),
        ]
        body_items: list[urwid.Widget] = [
            urwid.Text("Choose which filters to reset for the current view.", align="left"),
            urwid.Divider(),
        ]
        for _, checkbox in self.checkboxes:
            body_items.append(checkbox)
        walker = urwid.SimpleFocusListWalker(body_items)
        body = urwid.ListBox(walker)
        frame = urwid.Frame(
            body=urwid.AttrMap(body, "popup_body"),
            header=urwid.AttrMap(urwid.Text("Clear Filters", align="center"), "popup_title"),
            footer=urwid.AttrMap(urwid.Text("Enter: clear selected  Esc/F10: cancel", align="center"), "popup_footer"),
        )
        super().__init__(urwid.AttrMap(urwid.LineBox(frame), "popup_border"))

    def selected_values(self) -> set[str]:
        return {name for name, checkbox in self.checkboxes if checkbox.get_state()}

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter":
            self._on_submit(self.selected_values())
            return None
        if key in {"esc", "f10"}:
            self._on_cancel()
            return None
        return super().keypress(size, key)


class SortDialog(urwid.WidgetWrap):
    """Dialog for selecting a sort field and direction for the current list."""

    def __init__(
        self,
        title: str,
        fields: list[tuple[str, str]],
        current_field: str,
        descending: bool,
        on_submit: Callable[[str, bool], None],
        on_cancel: Callable[[], None],
    ) -> None:
        self._on_submit = on_submit
        self._on_cancel = on_cancel
        self.field_buttons: list[tuple[str, urwid.RadioButton]] = []
        group: list[urwid.RadioButton] = []
        body_items: list[urwid.Widget] = [
            urwid.Text("Choose sort field and direction.", align="left"),
            urwid.Divider(),
        ]
        default_button = urwid.RadioButton(group, "Default order", state=current_field == "")
        self.field_buttons.append(("", default_button))
        body_items.append(default_button)
        for field_name, label in fields:
            button = urwid.RadioButton(group, label, state=current_field == field_name)
            self.field_buttons.append((field_name, button))
            body_items.append(button)
        self.desc_checkbox = urwid.CheckBox("Descending", state=descending)
        body_items.extend([urwid.Divider(), self.desc_checkbox])
        walker = urwid.SimpleFocusListWalker(body_items)
        body = urwid.ListBox(walker)
        frame = urwid.Frame(
            body=urwid.AttrMap(body, "popup_body"),
            header=urwid.AttrMap(urwid.Text(title, align="center"), "popup_title"),
            footer=urwid.AttrMap(urwid.Text("Enter: apply  Esc/F10: cancel", align="center"), "popup_footer"),
        )
        super().__init__(urwid.AttrMap(urwid.LineBox(frame), "popup_border"))

    def selected_field(self) -> str:
        for field_name, button in self.field_buttons:
            if button.get_state():
                return field_name
        return ""

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter":
            self._on_submit(self.selected_field(), self.desc_checkbox.get_state())
            return None
        if key in {"esc", "f10"}:
            self._on_cancel()
            return None
        return super().keypress(size, key)


class ConfirmExitDialog(urwid.WidgetWrap):
    """Simple yes/no confirmation dialog shown before exiting the app."""

    def __init__(self, on_confirm: Callable[[], None], on_cancel: Callable[[], None]) -> None:
        self._on_confirm = on_confirm
        self._on_cancel = on_cancel
        group: list[urwid.RadioButton] = []
        self.yes_button = urwid.RadioButton(group, "Yes", state=True)
        self.no_button = urwid.RadioButton(group, "No", state=False)
        walker = urwid.SimpleFocusListWalker(
            [
                urwid.Text("Exit application?", align="center"),
                urwid.Divider(),
                self.yes_button,
                self.no_button,
            ]
        )
        body = urwid.ListBox(walker)
        frame = urwid.Frame(
            body=urwid.AttrMap(body, "popup_body"),
            header=urwid.AttrMap(urwid.Text("Confirm Exit", align="center"), "popup_title"),
            footer=urwid.AttrMap(urwid.Text("Enter: select  Esc/F10: cancel", align="center"), "popup_footer"),
        )
        super().__init__(urwid.AttrMap(urwid.LineBox(frame), "popup_border"))

    def keypress(self, size: tuple[int, int], key: str) -> Optional[str]:
        if key == "enter":
            if self.yes_button.get_state():
                self._on_confirm()
            else:
                self._on_cancel()
            return None
        if key in {"y", "Y"}:
            self._on_confirm()
            return None
        if key in {"n", "N", "esc", "f10"}:
            self._on_cancel()
            return None
        return super().keypress(size, key)


class ConsulTuiApp:
    """Main read-only Consul TUI application controller."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.client = ConsulClient(config)
        self.job_queue: queue.Queue[Job] = queue.Queue()
        self.result_queue: queue.Queue[JobResult] = queue.Queue()
        self.cache: dict[str, tuple[float, Any]] = {}
        self.in_flight: set[str] = set()
        self.auto_refresh = True
        self.current_section = "dashboard"
        self.current_focus = "list"
        self.popup_open = False
        self.current_popup: Optional[urwid.Widget] = None
        self.kv_prefix = ""
        self.history: list[tuple[str, str]] = []
        self.status_message = "Ready"
        self.last_error = ""
        self.last_error_at = ""
        self.header_dc = "-"
        self.header_leader = "-"
        self.acl_capability = "probing"
        self.acl_message = "ACL availability is being probed"
        self.section_filters = {key: "" for key, _, _ in MENU_ITEMS}
        self.status_filters: dict[str, set[str]] = {"services": set(), "nodes": set(), "instances": set()}
        self.bulk_selected: dict[str, set[str]] = {"services": set(), "nodes": set()}
        self.instance_text_filter = self._empty_instance_text_filter()
        self.instance_filter = self._empty_instance_filter()
        self.sort_options: dict[str, dict[str, Any]] = {}
        self.section_modes = {
            "services": "list",
            "nodes": "list",
            "tokens": "list",
            "roles": "list",
            "policies": "list",
        }
        self.section_context = {"services": {}, "nodes": {}, "tokens": {}, "roles": {}, "policies": {}}
        self.section_rows: dict[str, list[dict[str, Any]]] = {
            "dashboard": [],
            "telemetry": [],
            "services": [],
            "nodes": [],
            "kv": [],
            "sessions": [],
            "tokens": [],
            "policies": [],
            "roles": [],
            "auth": [],
        }
        self.section_details: dict[str, dict[str, Any]] = {"services": {}, "nodes": {}, "kv": {}, "policies": {}, "auth": {}}
        self.section_selected: dict[str, Optional[str]] = {key: None for key, _, _ in MENU_ITEMS}
        self.section_loading = {key: False for key, _, _ in MENU_ITEMS}
        self.section_stale = {key: False for key, _, _ in MENU_ITEMS}
        self.section_meta: dict[str, Any] = {
            "dashboard": {},
            "telemetry": {},
            "services": {"health_cache": {}, "list_rows": [], "pending_open": None, "pending_open_many": None},
            "nodes": {"health_cache": {}, "list_rows": [], "pending_open": None, "pending_open_many": None},
            "kv": {},
            "sessions": {},
            "tokens": {"raw_rows": [], "list_rows": []},
            "policies": {"raw_rows": [], "list_rows": []},
            "roles": {"raw_rows": [], "list_rows": []},
        }

        self.list_header = urwid.Text("")
        self.list_header.set_wrap_mode("clip")
        self.content_walker = urwid.SimpleFocusListWalker([])
        self.content_list = FocusListBox(self.content_walker, on_focus_change=self._on_content_focus_changed)
        self.details_walker = urwid.SimpleFocusListWalker([])
        self.details_list = urwid.ListBox(self.details_walker)
        self.content_panel = urwid.AttrMap(urwid.Pile([("pack", self.list_header), self.content_list]), "panel_fill")
        self.details_panel = urwid.AttrMap(self.details_list, "panel_fill")
        # `title_attr` is not available in older urwid releases (for example 2.0.1).
        # Title colors are applied via AttrMap maps for the `title` part instead.
        self.content_linebox = urwid.LineBox(self.content_panel, title="Items")
        self.details_linebox = urwid.LineBox(self.details_panel, title="Details")
        self.content_box = urwid.AttrMap(self.content_linebox, self._panel_attr_map(), self._panel_focus_map())
        self.details_box = urwid.AttrMap(self.details_linebox, self._panel_attr_map(), self._panel_focus_map())
        self.header_text = urwid.Text("")
        self.status_text = urwid.Text("")
        self.keys_text = urwid.Text("")
        self.tabs_placeholder = urwid.WidgetPlaceholder(urwid.AttrMap(urwid.Text(""), "panel_fill"))
        self.right_columns = FocusColumns(
            [("weight", 2, self.content_box), ("weight", 3, self.details_box)],
            on_focus_change=self._on_pane_focus_changed,
            dividechars=1,
            focus_column=0,
        )
        self.body_pile = urwid.Pile([("pack", self.tabs_placeholder), self.right_columns])
        self.body_pile.focus_position = 1
        footer = urwid.Pile(
            [
                ("pack", urwid.AttrMap(self.status_text, "status_bar")),
                ("pack", urwid.AttrMap(self.keys_text, "footer_keys")),
            ]
        )
        self.body = urwid.AttrMap(self.body_pile, "panel_fill")
        self.frame = urwid.Frame(
            body=self.body,
            header=urwid.AttrMap(self.header_text, "header"),
            footer=footer,
        )
        self.loop = urwid.MainLoop(self.frame, self._palette(), unhandled_input=self._unhandled_input)
        self.worker = threading.Thread(target=self._worker_loop, daemon=True, name="consul-viewer-worker")
        self.worker.start()

        self._rebuild_menu()
        self._set_focus_area("list")
        self._update_footer_keys()
        self._update_header()
        self._update_status("Loading dashboard")
        self.refresh_current(force=True)
        self._submit_job("acl_probe", ttl=CACHE_TTL_LONG, force=False)
        self.loop.set_alarm_in(0.2, self._poll_results)
        self.loop.set_alarm_in(self.config.refresh, self._auto_refresh_tick)

    def _palette(self) -> list[tuple[str, str, str]]:
        return [
            ("header", "white,bold", "dark blue"),
            ("footer_keys", "black,bold", "light cyan"),
            ("status_bar", "light cyan", "dark blue"),
            ("panel_fill", "light cyan", "dark blue"),
            ("panel_border", "light cyan", "dark blue"),
            ("panel_border_active", "white,bold", "dark blue"),
            ("panel_title", "white,bold", "dark blue"),
            ("panel_title_active", "white,bold", "dark blue"),
            ("menu_item", "light cyan", "dark blue"),
            ("menu_current", "light green,bold", "dark blue"),
            ("menu_focus", "black", "light gray"),
            ("menu_disabled", "dark gray", "dark blue"),
            ("list_header", "light cyan,bold", "dark blue"),
            ("list_item", "light cyan", "dark blue"),
            ("list_item_focus", "black", "light gray"),
            ("kv_key_item", "light cyan", "dark blue"),
            ("kv_dir_item", "white,bold", "dark blue"),
            ("details_text", "light cyan", "dark blue"),
            ("status_passing", "light green", "dark blue"),
            ("status_warning", "yellow", "dark blue"),
            ("status_critical", "light red", "dark blue"),
            ("popup_title", "black,bold", "light gray"),
            ("popup_footer", "black", "light gray"),
            ("popup_body", "black", "light gray"),
            ("popup_border", "black,bold", "light gray"),
        ]

    def run(self) -> None:
        self.loop.run()

    def _worker_loop(self) -> None:
        while True:
            job = self.job_queue.get()
            try:
                payload = self._execute_job(job)
                result = JobResult(key=job.key, name=job.name, args=job.args, ok=True, payload=payload)
            except ApiError as exc:
                result = JobResult(key=job.key, name=job.name, args=job.args, ok=False, error=str(exc))
            except Exception as exc:  # pragma: no cover
                result = JobResult(key=job.key, name=job.name, args=job.args, ok=False, error=f"{type(exc).__name__}: {exc}")
            self.result_queue.put(result)

    def _execute_job(self, job: Job) -> Any:
        """Dispatch a background job to the matching fetch operation."""
        if job.name == "dashboard":
            return self._fetch_dashboard()
        if job.name == "telemetry":
            return self._fetch_telemetry()
        if job.name == "services_list":
            return self._fetch_services_list()
        if job.name == "service_detail":
            return self._fetch_service_detail(job.args[0])
        if job.name == "nodes_list":
            return self._fetch_nodes_list()
        if job.name == "node_detail":
            return self._fetch_node_detail(job.args[0])
        if job.name == "kv_list":
            return self._fetch_kv_list(job.args[0])
        if job.name == "kv_detail":
            return self._fetch_kv_detail(job.args[0], job.args[1])
        if job.name == "kv_dir_preview":
            return self._fetch_kv_dir_preview(job.args[1])
        if job.name == "sessions_list":
            return self._fetch_sessions_list()
        if job.name == "acl_probe":
            self.client.acl_policies()
            return {"available": True}
        if job.name == "acl_policies":
            return self.client.acl_policies()
        if job.name == "acl_policy_detail":
            return self.client.acl_policy(job.args[0])
        if job.name == "acl_tokens":
            return self.client.acl_tokens()
        if job.name == "acl_roles":
            return self.client.acl_roles()
        if job.name == "acl_auth_methods":
            return self._fetch_auth_methods_list()
        if job.name == "acl_auth_method_detail":
            return self.client.acl_auth_method(job.args[0])
        raise ApiError(f"Unknown job: {job.name}")

    def _parse_metric_number(self, value: Any) -> Optional[float]:
        """Parse a metric-like scalar into float when possible."""
        if value is None:
            return None
        if isinstance(value, bool):
            return float(int(value))
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip().replace(",", "")
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            return None

    def _parse_duration_ms(self, value: Any) -> Optional[float]:
        """Parse a duration value and normalize it to milliseconds."""
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip().lower()
        if not text or text in {"-", "n/a", "never"}:
            return None
        match = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*(ns|us|µs|μs|ms|s|m)?$", text)
        if not match:
            return self._parse_metric_number(text)
        amount = float(match.group(1))
        unit = match.group(2) or "ms"
        factors = {
            "ns": 0.000001,
            "us": 0.001,
            "µs": 0.001,
            "μs": 0.001,
            "ms": 1.0,
            "s": 1000.0,
            "m": 60000.0,
        }
        return amount * factors.get(unit, 1.0)

    def _derive_agent_state(self, stats: dict[str, Any], leader: Any, peers: list[Any]) -> dict[str, Any]:
        """Build a coarse agent health snapshot from lightweight telemetry.

        Args:
            stats: Consul agent/self Stats payload.
            leader: Current leader address from /v1/status/leader.
            peers: Current peer list from /v1/status/peers.

        Returns:
            A normalized status object for dashboard display and details.

        Raises:
            No explicit exceptions; malformed values degrade to heuristic output.
        """
        agent_stats = stats.get("agent", {}) if isinstance(stats.get("agent"), dict) else {}
        raft_stats = stats.get("raft", {}) if isinstance(stats.get("raft"), dict) else {}
        server_like = bool(raft_stats)
        raft_state = str(raft_stats.get("state") or raft_stats.get("State") or "-").strip() or "-"
        normalized_raft_state = raft_state.lower()
        known_servers_raw = None
        for key in ("num_known_servers", "known_servers", "num_peers", "peers"):
            if key in raft_stats:
                known_servers_raw = raft_stats.get(key)
                break
        known_servers_num = self._parse_metric_number(known_servers_raw)
        last_contact_raw = raft_stats.get("last_contact") or raft_stats.get("LastContact")
        last_contact_ms = self._parse_duration_ms(last_contact_raw)
        services_num = self._parse_metric_number(agent_stats.get("services"))
        checks_num = self._parse_metric_number(agent_stats.get("checks"))
        status = "passing"
        reasons: list[str] = []

        if server_like:
            if not leader:
                status = "critical"
                reasons.append("no leader")
            if known_servers_num is not None and known_servers_num <= 0:
                # Some versions/configurations expose zero here even while raft is healthy.
                # Treat it as a hard failure only when other raft signals are also unhealthy.
                stable_raft = normalized_raft_state in {"leader", "follower"} and bool(leader)
                if stable_raft or len(peers) > 0:
                    reasons.append("known servers metric unavailable")
                else:
                    status = "critical"
                    reasons.append("known servers=0")
            if normalized_raft_state == "candidate" and status != "critical":
                status = "warning"
                reasons.append("raft candidate")
            elif normalized_raft_state not in {"-", "", "leader", "follower"} and status == "passing":
                status = "warning"
                reasons.append(f"raft {normalized_raft_state}")
            if last_contact_ms is not None:
                if last_contact_ms > 5000:
                    status = "critical"
                    reasons.append("last contact high")
                elif last_contact_ms > 500 and status == "passing":
                    status = "warning"
                    reasons.append("last contact elevated")
        else:
            if not leader:
                status = "warning"
                reasons.append("leader unknown")

        if not reasons:
            reasons.append("ok")

        return {
            "status": status,
            "reason": ", ".join(reasons),
            "server_like": server_like,
            "raft_state": raft_state,
            "known_servers": int(known_servers_num) if known_servers_num is not None and known_servers_num.is_integer() else known_servers_raw,
            "last_contact": last_contact_raw or "-",
            "last_contact_ms": last_contact_ms,
            "peer_count": len(peers),
            "services": int(services_num) if services_num is not None and services_num.is_integer() else agent_stats.get("services", "-"),
            "checks": int(checks_num) if checks_num is not None and checks_num.is_integer() else agent_stats.get("checks", "-"),
        }

    def _parse_prometheus_text(self, raw_text: str) -> dict[str, list[dict[str, Any]]]:
        """Parse a Prometheus text payload into a metric-name keyed structure.

        Args:
            raw_text: Raw text returned by the Prometheus-formatted metrics endpoint.

        Returns:
            Mapping of metric name to a list of {labels, value} entries.

        Raises:
            No explicit exceptions; invalid lines are ignored.
        """
        metrics: dict[str, list[dict[str, Any]]] = {}
        line_re = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)$")
        label_re = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = line_re.match(line)
            if not match:
                continue
            name, labels_raw, value_raw = match.groups()
            try:
                value = float(value_raw)
            except ValueError:
                continue
            labels: dict[str, str] = {}
            if labels_raw:
                for key, raw_value in label_re.findall(labels_raw):
                    labels[key] = bytes(raw_value, "utf-8").decode("unicode_escape")
            metrics.setdefault(name, []).append({"labels": labels, "value": value})
        return metrics

    def _prom_metric_value(
        self,
        metrics: dict[str, list[dict[str, Any]]],
        name: str,
        labels: Optional[dict[str, str]] = None,
    ) -> Optional[float]:
        """Return a single numeric value for a Prometheus metric family.

        Args:
            metrics: Parsed metric map from _parse_prometheus_text().
            name: Metric family name.
            labels: Optional exact label match to select a subset.

        Returns:
            A numeric value when a suitable series exists, otherwise None.

        Raises:
            No explicit exceptions.
        """
        entries = metrics.get(name, [])
        if not entries:
            return None
        if labels:
            matches = [item["value"] for item in entries if all(item["labels"].get(key) == value for key, value in labels.items())]
            if matches:
                return float(sum(matches))
        unlabeled = [item["value"] for item in entries if not item["labels"]]
        if unlabeled:
            return float(sum(unlabeled))
        # Summary metrics also emit quantile series; for scalar use we prefer
        # non-quantile variants such as _sum/_count families or unlabeled gauges.
        non_quantiles = [item["value"] for item in entries if "quantile" not in item["labels"]]
        if non_quantiles:
            return float(sum(non_quantiles))
        return None

    def _prom_quantile_value(
        self,
        metrics: dict[str, list[dict[str, Any]]],
        name: str,
        quantile: str,
        labels: Optional[dict[str, str]] = None,
    ) -> Optional[float]:
        """Return a specific quantile series value from a Prometheus summary."""
        entries = metrics.get(name, [])
        if not entries:
            return None
        matches: list[float] = []
        for item in entries:
            item_labels = item["labels"]
            if item_labels.get("quantile") != quantile:
                continue
            if labels and not all(item_labels.get(key) == value for key, value in labels.items()):
                continue
            matches.append(item["value"])
        if not matches:
            return None
        return float(sum(matches))

    def _prom_summary_average(self, metrics: dict[str, list[dict[str, Any]]], base_name: str) -> Optional[float]:
        """Compute an average from Prometheus summary _sum/_count helpers."""
        total = self._prom_metric_value(metrics, f"{base_name}_sum")
        count = self._prom_metric_value(metrics, f"{base_name}_count")
        if total is None or count is None or count <= 0:
            return None
        return total / count

    def _format_float(self, value: Optional[float], digits: int = 1) -> str:
        if value is None:
            return "-"
        if value != value:
            return "NaN"
        if abs(value - round(value)) < 0.000001:
            return str(int(round(value)))
        return f"{value:.{digits}f}"

    def _format_percent(self, value: Optional[float], digits: int = 1) -> str:
        if value is None:
            return "-"
        return f"{value:.{digits}f}%"

    def _format_bytes_human(self, value: Optional[float]) -> str:
        if value is None:
            return "-"
        units = ["B", "KB", "MB", "GB", "TB"]
        amount = float(value)
        unit_index = 0
        while amount >= 1024.0 and unit_index < len(units) - 1:
            amount /= 1024.0
            unit_index += 1
        if unit_index == 0:
            return f"{int(amount)} {units[unit_index]}"
        return f"{amount:.1f} {units[unit_index]}"

    def _ratio_status(self, used: Optional[float], limit: Optional[float], warning_pct: float = 70.0, critical_pct: float = 90.0) -> tuple[str, Optional[float]]:
        if used is None or limit is None or limit <= 0:
            return "unknown", None
        pct = (used / limit) * 100.0
        if pct >= critical_pct:
            return "critical", pct
        if pct >= warning_pct:
            return "warning", pct
        return "passing", pct

    def _threshold_status(self, value: Optional[float], warning: float, critical: float) -> str:
        if value is None:
            return "unknown"
        if value >= critical:
            return "critical"
        if value >= warning:
            return "warning"
        return "passing"

    def _telemetry_row(
        self,
        item_id: str,
        name: str,
        value_display: str,
        status: str,
        detail_lines: list[Any],
        limit_display: str = "-",
        usage_display: str = "-",
        sort_value: Optional[float] = None,
        sort_limit: Optional[float] = None,
        usage_pct: Optional[float] = None,
    ) -> dict[str, Any]:
        return {
            "id": item_id,
            "name": name,
            "value_display": value_display,
            "limit_display": limit_display,
            "usage_display": usage_display,
            "status": status,
            "value": sort_value if sort_value is not None else value_display,
            "limit": sort_limit if sort_limit is not None else limit_display,
            "usage_pct": usage_pct if usage_pct is not None else -1.0,
            "detail_lines": detail_lines,
        }

    def _fetch_telemetry(self) -> dict[str, Any]:
        """Build a compact telemetry panel from Prometheus-formatted agent metrics.

        Args:
            None.

        Returns:
            Telemetry rows plus raw Prometheus payload for viewer/debug use.

        Raises:
            ApiError: Propagated from the metrics endpoint fetch.
        """
        raw_text = self.client.agent_metrics_prometheus()
        metrics = self._parse_prometheus_text(raw_text)

        open_fds = self._prom_metric_value(metrics, "process_open_fds")
        max_fds = self._prom_metric_value(metrics, "process_max_fds")
        fd_status, fd_pct = self._ratio_status(open_fds, max_fds)

        rpc_blocking = self._prom_metric_value(metrics, "consul_rpc_queries_blocking")
        rpc_blocking_status = self._threshold_status(rpc_blocking, warning=10.0, critical=50.0)

        rpc_errors = self._prom_metric_value(metrics, "consul_rpc_request_error")
        rpc_error_status = self._threshold_status(rpc_errors, warning=1.0, critical=5.0)

        # For summary metrics, prefer a current-ish snapshot (p99 -> p90 -> avg)
        # instead of raw _sum, which is cumulative and not a live saturation value.
        raft_main_sat = self._prom_quantile_value(metrics, "consul_raft_thread_main_saturation", "0.99")
        if raft_main_sat is None:
            raft_main_sat = self._prom_quantile_value(metrics, "consul_raft_thread_main_saturation", "0.9")
        if raft_main_sat is None:
            raft_main_sat = self._prom_summary_average(metrics, "consul_raft_thread_main_saturation")
        raft_main_status = self._threshold_status(raft_main_sat, warning=0.5, critical=0.9)

        raft_fsm_sat = self._prom_quantile_value(metrics, "consul_raft_thread_fsm_saturation", "0.99")
        if raft_fsm_sat is None:
            raft_fsm_sat = self._prom_quantile_value(metrics, "consul_raft_thread_fsm_saturation", "0.9")
        if raft_fsm_sat is None:
            raft_fsm_sat = self._prom_summary_average(metrics, "consul_raft_thread_fsm_saturation")
        raft_fsm_status = self._threshold_status(raft_fsm_sat, warning=0.5, critical=0.9)

        autopilot_healthy = self._prom_metric_value(metrics, "consul_autopilot_healthy")
        if autopilot_healthy is None:
            autopilot_healthy = self._prom_metric_value(metrics, "consul.autopilot.healthy")
        autopilot_status = "passing" if autopilot_healthy and autopilot_healthy >= 1 else "critical"

        grpc_client_conn = self._prom_metric_value(metrics, "consul_grpc_client_connections")
        grpc_server_conn = self._prom_metric_value(metrics, "consul_grpc_server_connections")
        rpc_requests = self._prom_metric_value(metrics, "consul_rpc_request")
        go_threads = self._prom_metric_value(metrics, "go_threads")
        go_goroutines = self._prom_metric_value(metrics, "go_goroutines")
        resident_mem = self._prom_metric_value(metrics, "process_resident_memory_bytes")
        node_count = self._prom_metric_value(metrics, "consul_consul_state_nodes")
        service_count = self._prom_metric_value(metrics, "consul_consul_state_services")
        instance_count = self._prom_metric_value(metrics, "consul_consul_state_service_instances")

        cluster_status = combine_statuses(
            [
                autopilot_status,
                fd_status,
                rpc_blocking_status,
                rpc_error_status,
                raft_main_status,
                raft_fsm_status,
            ]
        )

        rows = [
            self._telemetry_row(
                "cluster_state",
                "Cluster state",
                cluster_status,
                cluster_status,
                [
                    (status_attr(cluster_status), f"Status      : {cluster_status}"),
                    f"Autopilot   : {'healthy' if autopilot_healthy and autopilot_healthy >= 1 else 'unhealthy'}",
                    f"FD usage    : {self._format_float(open_fds)}/{self._format_float(max_fds)} ({self._format_percent(fd_pct)})",
                    f"RPC errors  : {self._format_float(rpc_errors)}",
                    f"Block queries: {self._format_float(rpc_blocking)}",
                    f"Raft main sat: {self._format_float(raft_main_sat, 3)}",
                    f"Raft fsm sat : {self._format_float(raft_fsm_sat, 3)}",
                ],
            ),
            self._telemetry_row(
                "fd_usage",
                "Open FDs",
                self._format_float(open_fds),
                fd_status,
                [
                    (status_attr(fd_status), f"Status      : {fd_status}"),
                    f"Open FDs    : {self._format_float(open_fds)}",
                    f"Max FDs     : {self._format_float(max_fds)}",
                    f"Usage       : {self._format_percent(fd_pct)}",
                    "Thresholds  : warning >= 70%, critical >= 90%",
                    "Source      : process_open_fds / process_max_fds",
                ],
                limit_display=self._format_float(max_fds),
                usage_display=self._format_percent(fd_pct),
                sort_value=open_fds,
                sort_limit=max_fds,
                usage_pct=fd_pct,
            ),
            self._telemetry_row(
                "grpc_client",
                "gRPC client",
                self._format_float(grpc_client_conn),
                "passing",
                [
                    (status_attr("passing"), "Status      : passing"),
                    f"Active conn : {self._format_float(grpc_client_conn)}",
                    f"Source      : consul_grpc_client_connections",
                ],
                sort_value=grpc_client_conn,
            ),
            self._telemetry_row(
                "grpc_server",
                "gRPC server",
                self._format_float(grpc_server_conn),
                "passing",
                [
                    (status_attr("passing"), "Status      : passing"),
                    f"Active conn : {self._format_float(grpc_server_conn)}",
                    f"Source      : consul_grpc_server_connections",
                ],
                sort_value=grpc_server_conn,
            ),
            self._telemetry_row(
                "rpc_blocking",
                "Blocking RPC",
                self._format_float(rpc_blocking),
                rpc_blocking_status,
                [
                    (status_attr(rpc_blocking_status), f"Status      : {rpc_blocking_status}"),
                    f"In-flight   : {self._format_float(rpc_blocking)}",
                    "Thresholds  : warning >= 10, critical >= 50",
                    "Source      : consul_rpc_queries_blocking",
                ],
                sort_value=rpc_blocking,
            ),
            self._telemetry_row(
                "rpc_errors",
                "RPC errors",
                self._format_float(rpc_errors),
                rpc_error_status,
                [
                    (status_attr(rpc_error_status), f"Status      : {rpc_error_status}"),
                    f"Counter     : {self._format_float(rpc_errors)}",
                    "Thresholds  : warning >= 1, critical >= 5",
                    "Source      : consul_rpc_request_error",
                ],
                sort_value=rpc_errors,
            ),
            self._telemetry_row(
                "raft_main_sat",
                "Raft main sat",
                self._format_float(raft_main_sat, 3),
                raft_main_status,
                [
                    (status_attr(raft_main_status), f"Status      : {raft_main_status}"),
                    f"Value       : {self._format_float(raft_main_sat, 3)}",
                    "Thresholds  : warning >= 0.5, critical >= 0.9",
                    "Source      : consul_raft_thread_main_saturation",
                ],
                sort_value=raft_main_sat,
            ),
            self._telemetry_row(
                "raft_fsm_sat",
                "Raft FSM sat",
                self._format_float(raft_fsm_sat, 3),
                raft_fsm_status,
                [
                    (status_attr(raft_fsm_status), f"Status      : {raft_fsm_status}"),
                    f"Value       : {self._format_float(raft_fsm_sat, 3)}",
                    "Thresholds  : warning >= 0.5, critical >= 0.9",
                    "Source      : consul_raft_thread_fsm_saturation",
                ],
                sort_value=raft_fsm_sat,
            ),
            self._telemetry_row(
                "go_threads",
                "OS threads",
                self._format_float(go_threads),
                "passing",
                [
                    (status_attr("passing"), "Status      : passing"),
                    f"OS threads  : {self._format_float(go_threads)}",
                    f"Goroutines  : {self._format_float(go_goroutines)}",
                    "Source      : go_threads / go_goroutines",
                ],
                sort_value=go_threads,
            ),
            self._telemetry_row(
                "resident_mem",
                "RSS memory",
                self._format_bytes_human(resident_mem),
                "passing",
                [
                    (status_attr("passing"), "Status      : passing"),
                    f"Resident mem: {self._format_bytes_human(resident_mem)}",
                    f"Bytes       : {self._format_float(resident_mem)}",
                    "Source      : process_resident_memory_bytes",
                ],
                sort_value=resident_mem,
            ),
            self._telemetry_row(
                "cluster_counts",
                "Cluster objs",
                f"N:{self._format_float(node_count)} S:{self._format_float(service_count)} I:{self._format_float(instance_count)}",
                autopilot_status,
                [
                    (status_attr(autopilot_status), f"Status      : {autopilot_status}"),
                    f"Nodes       : {self._format_float(node_count)}",
                    f"Services    : {self._format_float(service_count)}",
                    f"Instances   : {self._format_float(instance_count)}",
                    f"RPC req     : {self._format_float(rpc_requests)}",
                    "Source      : consul_consul_state_* / consul_rpc_request",
                ],
                sort_value=node_count,
            ),
        ]
        return {"rows": rows, "raw_text": raw_text, "metrics": metrics}

    def _fetch_dashboard(self) -> dict[str, Any]:
        """Collect a lightweight cluster summary for the dashboard section."""
        self_info = self.client.agent_self()
        leader = self.client.leader()
        peers = self.client.peers()
        members = self.client.members()
        config = self_info.get("Config", {})
        member_info = self_info.get("Member", {})
        stats = self_info.get("Stats", {})
        version = self_info.get("DebugConfig", {}).get("Version") or config.get("Version") or "-"
        dc = config.get("Datacenter") or member_info.get("Tags", {}).get("dc") or "-"
        node_name = config.get("NodeName") or member_info.get("Name") or "-"
        local_members = [item for item in members if item.get("Tags", {}).get("dc") == dc]
        remote_members = [item for item in members if item.get("Tags", {}).get("dc") != dc]
        member_statuses = [self._member_status(item.get("Status")) for item in members]
        agent_state = self._derive_agent_state(stats, leader, peers)
        rows = [
            {"id": "dc", "label": f"Datacenter: {dc}", "status": "passing"},
            {"id": "node", "label": f"Node: {node_name}", "status": "passing"},
            {"id": "version", "label": f"Version: {version}", "status": "passing"},
            {"id": "leader", "label": f"Leader: {leader or '-'}", "status": "passing" if leader else "warning"},
            {"id": "peers", "label": f"Peers: {len(peers)}", "status": "passing" if peers else "warning"},
            {"id": "agent_state", "label": f"Agent state: {agent_state['status']}", "status": agent_state["status"]},
            {"id": "lan", "label": f"Members (local DC): {len(local_members)}", "status": combine_statuses(member_statuses)},
            {"id": "wan", "label": f"Members (remote DC): {len(remote_members)}", "status": "passing"},
        ]
        return {
            "rows": rows,
            "raw": {
                "datacenter": dc,
                "node_name": node_name,
                "version": version,
                "leader": leader,
                "peers": peers,
                "members": members,
                "stats": stats,
                "agent_state": agent_state,
            },
        }

    def _fetch_services_list(self) -> list[dict[str, Any]]:
        catalog = self.client.catalog_services()
        health_cache = self.section_meta["services"]["health_cache"]
        rows: list[dict[str, Any]] = []
        for name in sorted(catalog):
            tags = catalog.get(name) or []
            cached = health_cache.get(name, {})
            rows.append(
                {
                    "id": name,
                    "name": name,
                    "tags": tags,
                    "instances": cached.get("instances", "?"),
                    "passing": cached.get("passing", "?"),
                    "warning": cached.get("warning", "?"),
                    "critical": cached.get("critical", "?"),
                    "status": cached.get("status", "unknown"),
                    "status_count": cached.get("status_count", "?/?"),
                }
            )
        return rows

    def _fetch_service_detail(self, service_name: str) -> dict[str, Any]:
        entries = self.client.health_service(service_name)
        instances: list[dict[str, Any]] = []
        statuses: list[str] = []
        passing_instances = 0
        passing = warning = critical = 0
        for index, entry in enumerate(entries):
            node_info = entry.get("Node", {})
            service = entry.get("Service", {})
            checks = entry.get("Checks", []) or []
            check_statuses = [check.get("Status", "unknown").lower() for check in checks if check.get("Status")]
            worst = combine_statuses(check_statuses)
            statuses.append(worst)
            if worst == "passing":
                passing_instances += 1
            passing += sum(1 for item in check_statuses if item == "passing")
            warning += sum(1 for item in check_statuses if item == "warning")
            critical += sum(1 for item in check_statuses if item == "critical")
            instances.append(
                {
                    "id": f"svcinst:{service_name}:{service.get('ID') or index}:{node_info.get('Node', '-')}",
                    "name": service.get("ID") or service.get("Service") or service_name,
                    "service": service.get("Service") or service_name,
                    "service_id": service.get("ID") or "-",
                    "node": node_info.get("Node", "-"),
                    "address": service.get("Address") or node_info.get("Address", "-"),
                    "port": service.get("Port", "-"),
                    "tags": service.get("Tags", []),
                    "meta": service.get("Meta") or {},
                    "node_meta": node_info.get("Meta") or {},
                    "checks": checks,
                    "status": worst,
                    "kind": "instance",
                    "raw_service": service,
                    "raw_node": node_info,
                    "status_count": format_ratio(sum(1 for item in check_statuses if item == "passing"), len(checks)),
                }
            )
        summary = {
            "instances": len(instances),
            "passing_instances": passing_instances,
            "passing": passing,
            "warning": warning,
            "critical": critical,
            "status": combine_statuses(statuses),
            "status_count": format_ratio(passing_instances, len(instances)),
        }
        return {"service": service_name, "summary": summary, "instances": instances, "raw": entries}

    def _fetch_nodes_list(self) -> list[dict[str, Any]]:
        catalog_nodes = self.client.catalog_nodes()
        health_cache = self.section_meta["nodes"]["health_cache"]
        rows: list[dict[str, Any]] = []
        for entry in sorted(catalog_nodes, key=lambda item: item.get("Node", "")):
            node_name = entry.get("Node", "-")
            cached = health_cache.get(node_name, {})
            rows.append(
                {
                    "id": node_name,
                    "name": node_name,
                    "address": entry.get("Address", "-"),
                    "dc": entry.get("Datacenter") or "-",
                    "meta": entry.get("Meta") or {},
                    "status": cached.get("status", "unknown"),
                    "status_count": cached.get("status_count", "?/?"),
                }
            )
        return rows

    def _fetch_node_detail(self, node_name: str) -> dict[str, Any]:
        catalog = self.client.catalog_node(node_name)
        checks = self.client.health_node(node_name)
        node = catalog.get("Node", {})
        services = catalog.get("Services", {})
        node_checks = [check for check in checks if not check.get("ServiceID")]
        service_checks = [check for check in checks if check.get("ServiceID")]
        node_statuses = [check.get("Status", "unknown").lower() for check in node_checks if check.get("Status")]
        service_statuses = [check.get("Status", "unknown").lower() for check in service_checks if check.get("Status")]
        instances: list[dict[str, Any]] = []
        passing_instances = 0
        for index, (service_id, service) in enumerate(sorted(services.items())):
            instance_checks = [check for check in checks if check.get("ServiceID") == service_id]
            instance_statuses = [check.get("Status", "unknown").lower() for check in instance_checks if check.get("Status")]
            instance_status = combine_statuses(instance_statuses)
            if instance_status == "passing":
                passing_instances += 1
            instances.append(
                {
                    "id": f"nodeinst:{node_name}:{service_id or index}",
                    "name": service.get("ID") or service_id or service.get("Service") or f"instance-{index}",
                    "service": service.get("Service") or "-",
                    "service_id": service_id or service.get("ID") or "-",
                    "node": node_name,
                    "address": service.get("Address") or node.get("Address", "-"),
                    "port": service.get("Port", "-"),
                    "tags": service.get("Tags", []),
                    "meta": service.get("Meta") or {},
                    "node_meta": node.get("Meta") or {},
                    "checks": instance_checks,
                    "status": instance_status,
                    "kind": "instance",
                    "raw_service": service,
                    "raw_node": node,
                    "status_count": format_ratio(sum(1 for item in instance_statuses if item == "passing"), len(instance_checks)),
                }
            )
        return {
            "node": node_name,
            "node_info": node,
            "services": services,
            "instances": instances,
            "checks": checks,
            "node_checks": node_checks,
            "service_checks": service_checks,
            "summary": {
                "status": combine_statuses(node_statuses),
                "node_status": combine_statuses(node_statuses),
                "services_status": combine_statuses(service_statuses),
                "service_count": len(services),
                "passing_instances": passing_instances,
                "check_count": len(checks),
                "status_count": format_ratio(passing_instances, len(instances)),
            },
            "raw": {"catalog": catalog, "checks": checks},
        }

    def _fetch_kv_list(self, prefix: str) -> list[dict[str, Any]]:
        keys = self.client.kv_keys(prefix)
        normalized_prefix = prefix.strip("/")
        visible: list[dict[str, Any]] = []
        for key in sorted(keys):
            item = key.rstrip("/")
            name = item
            if normalized_prefix:
                prefix_token = normalized_prefix + "/"
                if item.startswith(prefix_token):
                    name = item[len(prefix_token) :]
            is_dir = key.endswith("/")
            visible.append(
                {
                    "id": f"{KV_DIR_ID_PREFIX}{item}" if is_dir else f"{KV_KEY_ID_PREFIX}{item}",
                    "name": name or key,
                    "kind": "dir" if is_dir else "key",
                    "target": item,
                    "status": "passing",
                }
            )
        if normalized_prefix:
            parent = normalized_prefix.rsplit("/", 1)[0]
            visible.insert(
                0,
                {
                    "id": f"{KV_PARENT_ID_PREFIX}{normalized_prefix}",
                    "name": "..",
                    "kind": "parent",
                    "target": parent,
                    "status": "passing",
                },
            )
        return visible

    def _fetch_kv_dir_preview(self, prefix: str) -> dict[str, Any]:
        rows = self._fetch_kv_list(prefix)
        return {
            "prefix": prefix.strip("/"),
            "rows": [row for row in rows if row.get("kind") != "parent"],
        }

    def _fetch_kv_detail(self, row_id: str, key: str) -> dict[str, Any]:
        payload = self.client.kv_value(key)
        if not payload:
            raise ApiError("KV key returned empty payload")
        entry = payload[0]
        raw_value = entry.get("Value") or ""
        try:
            value_bytes = base64.b64decode(raw_value)
        except Exception as exc:
            raise ApiError(f"KV decode failed: {exc}") from exc
        decoded_text: Optional[str]
        is_binary = False
        try:
            decoded_text = value_bytes.decode("utf-8")
            if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in decoded_text):
                is_binary = True
        except UnicodeDecodeError:
            decoded_text = None
            is_binary = True
        if is_binary:
            hex_part = value_bytes[:MAX_HEX_PREVIEW_BYTES].hex(" ")
            suffix = " ..." if len(value_bytes) > MAX_HEX_PREVIEW_BYTES else ""
            preview = f"binary ({len(value_bytes)} bytes)\n{hex_part}{suffix}"
        else:
            preview = decoded_text[:MAX_PREVIEW_BYTES]
            if len(decoded_text) > MAX_PREVIEW_BYTES:
                preview += "\n... truncated ..."
        return {
            "row_id": row_id,
            "key": key,
            "meta": {
                "CreateIndex": entry.get("CreateIndex"),
                "ModifyIndex": entry.get("ModifyIndex"),
                "Flags": entry.get("Flags"),
                "Session": entry.get("Session"),
                "Size": len(value_bytes),
                "Kind": "binary" if is_binary else "text",
            },
            "preview": preview,
            "full_text": decoded_text if decoded_text is not None else "",
            "raw_bytes": value_bytes,
            "raw": entry,
        }

    def _fetch_sessions_list(self) -> list[dict[str, Any]]:
        sessions = self.client.sessions()
        rows: list[dict[str, Any]] = []
        for session in sessions:
            rows.append(
                {
                    "id": session.get("ID", "-"),
                    "name": session.get("Name") or "-",
                    "node": session.get("Node") or "-",
                    "ttl": session.get("TTL") or "-",
                    "behavior": session.get("Behavior") or "-",
                    "lock_delay": session.get("LockDelay") or "-",
                    "raw": session,
                    "status": "passing",
                }
            )
        return rows

    def _fetch_auth_methods_list(self) -> list[dict[str, Any]]:
        methods = self.client.acl_auth_methods()
        rows: list[dict[str, Any]] = []
        for method in sorted(methods, key=lambda item: (item.get("Name") or item.get("Type") or "").lower()):
            rows.append(
                {
                    "id": method.get("Name") or method.get("Type") or "-",
                    "name": method.get("Name") or "-",
                    "type": method.get("Type") or "-",
                    "display_name": method.get("DisplayName") or "-",
                    "locality": method.get("TokenLocality") or "-",
                    "raw": method,
                    "status": "passing",
                }
            )
        return rows

    def _acl_token_name(self, token: dict[str, Any]) -> str:
        return token.get("Description") or token.get("AccessorID") or token.get("ID") or "-"

    def _acl_role_name(self, role: dict[str, Any]) -> str:
        return role.get("Name") or role.get("ID") or "-"

    def _acl_policy_name(self, policy: dict[str, Any]) -> str:
        return policy.get("Name") or policy.get("ID") or "-"

    def _acl_accessor_tail(self, accessor_id: str) -> str:
        value = accessor_id or "-"
        return value.rsplit("-", 1)[-1] if "-" in value else value

    def _acl_token_scope(self, token: dict[str, Any]) -> str:
        return "local" if token.get("Local") else "global"

    def _acl_link_keys(self, item: dict[str, Any]) -> list[str]:
        keys: list[str] = []
        for value in (item.get("ID"), item.get("Name"), item.get("AccessorID")):
            if value and value not in keys:
                keys.append(value)
        return keys

    def _acl_collect_links(self, links: dict[str, set[str]], item: dict[str, Any], target_name: str) -> None:
        for key in self._acl_link_keys(item):
            links.setdefault(key, set()).add(target_name)

    def _acl_resolve_links(self, links: dict[str, set[str]], item: dict[str, Any]) -> list[str]:
        values: set[str] = set()
        for key in self._acl_link_keys(item):
            values.update(links.get(key, set()))
        return sorted(values)

    def _rebuild_acl_views(self) -> None:
        tokens_raw = list(self.section_meta["tokens"].get("raw_rows", []))
        policies_raw = list(self.section_meta["policies"].get("raw_rows", []))
        roles_raw = list(self.section_meta["roles"].get("raw_rows", []))

        token_links_by_policy: dict[str, set[str]] = {}
        token_links_by_role: dict[str, set[str]] = {}
        role_links_by_policy: dict[str, set[str]] = {}
        token_refs_by_policy: dict[str, list[dict[str, str]]] = {}
        token_refs_by_role: dict[str, list[dict[str, str]]] = {}
        token_ref_by_name: dict[str, dict[str, str]] = {}

        for token in tokens_raw:
            token_name = self._acl_token_name(token)
            token_ref = {
                "accessor": self._acl_accessor_tail(token.get("AccessorID") or "-"),
                "scope": self._acl_token_scope(token),
                "source": "direct",
                "description": token.get("Description") or "-",
            }
            token_ref_by_name[token_name] = dict(token_ref)
            for policy in token.get("Policies") or []:
                policy_name = self._acl_policy_name(policy)
                self._acl_collect_links(token_links_by_policy, policy, token_name)
                token_refs_by_policy.setdefault(policy_name, []).append(dict(token_ref))
            for role in token.get("Roles") or []:
                role_name = self._acl_role_name(role)
                self._acl_collect_links(token_links_by_role, role, token_name)
                token_refs_by_role.setdefault(role_name, []).append(dict(token_ref))

        for role in roles_raw:
            role_name = self._acl_role_name(role)
            for policy in role.get("Policies") or []:
                self._acl_collect_links(role_links_by_policy, policy, role_name)
            linked_tokens = self._acl_resolve_links(token_links_by_role, role)
            for policy in role.get("Policies") or []:
                policy_name = self._acl_policy_name(policy)
                for token_name in linked_tokens:
                    self._acl_collect_links(token_links_by_policy, policy, token_name)
                    token_ref = token_ref_by_name.get(token_name)
                    if token_ref:
                        refs = token_refs_by_policy.setdefault(policy_name, [])
                        existing = next(
                            (
                                item
                                for item in refs
                                if item.get("accessor") == token_ref.get("accessor")
                                and item.get("scope") == token_ref.get("scope")
                                and item.get("description") == token_ref.get("description")
                            ),
                            None,
                        )
                        if existing:
                            existing["source"] = "direct+role"
                        else:
                            via_role_ref = dict(token_ref)
                            via_role_ref["source"] = "via role"
                            refs.append(via_role_ref)

        token_rows: list[dict[str, Any]] = []
        for token in sorted(tokens_raw, key=lambda item: (item.get("Description") or item.get("AccessorID") or "").lower()):
            token_id = token.get("AccessorID") or token.get("ID") or self._acl_token_name(token)
            accessor_full = token.get("AccessorID") or "-"
            description = token.get("Description") or "-"
            policies = sorted(self._acl_policy_name(policy) for policy in token.get("Policies") or [])
            roles = sorted(self._acl_role_name(role) for role in token.get("Roles") or [])
            token_rows.append(
                {
                    "id": token_id,
                    "name": self._acl_token_name(token),
                    "accessor": self._acl_accessor_tail(accessor_full),
                    "accessor_full": accessor_full,
                    "description": description,
                    "policies": ", ".join(policies) or "-",
                    "roles": ", ".join(roles) or "-",
                    "policies_list": policies,
                    "roles_list": roles,
                    "auth_method": token.get("AuthMethod") or "-",
                    "local": "yes" if token.get("Local") else "no",
                    "expiration": token.get("ExpirationTime") or "-",
                    "kind": "token",
                    "status": "passing",
                    "raw": token,
                }
            )

        policy_rows: list[dict[str, Any]] = []
        for policy in sorted(policies_raw, key=lambda item: (item.get("Name") or item.get("ID") or "").lower()):
            policy_name = self._acl_policy_name(policy)
            tokens = self._acl_resolve_links(token_links_by_policy, policy)
            roles = self._acl_resolve_links(role_links_by_policy, policy)
            token_refs = sorted(
                token_refs_by_policy.get(policy_name, []),
                key=lambda item: (item.get("accessor", ""), item.get("description", "")),
            )
            policy_rows.append(
                {
                    "id": policy.get("ID") or "-",
                    "name": policy_name,
                    "description": policy.get("Description") or "-",
                    "datacenters": ", ".join(policy.get("Datacenters") or []) or "-",
                    "tokens": ", ".join(tokens) or "-",
                    "roles": ", ".join(roles) or "-",
                    "tokens_list": tokens,
                    "roles_list": roles,
                    "token_refs": token_refs,
                    "kind": "policy",
                    "status": "passing",
                    "raw": policy,
                }
            )

        role_rows: list[dict[str, Any]] = []
        for role in sorted(roles_raw, key=lambda item: (item.get("Name") or item.get("ID") or "").lower()):
            role_name = self._acl_role_name(role)
            tokens = self._acl_resolve_links(token_links_by_role, role)
            policies = sorted(self._acl_policy_name(policy) for policy in role.get("Policies") or [])
            token_refs = sorted(
                token_refs_by_role.get(role_name, []),
                key=lambda item: (item.get("accessor", ""), item.get("description", "")),
            )
            role_rows.append(
                {
                    "id": role.get("ID") or "-",
                    "name": role_name,
                    "description": role.get("Description") or "-",
                    "policies": ", ".join(policies) or "-",
                    "tokens": ", ".join(tokens) or "-",
                    "policies_list": policies,
                    "tokens_list": tokens,
                    "token_refs": token_refs,
                    "kind": "role",
                    "status": "passing",
                    "raw": role,
                }
            )

        self.section_meta["tokens"]["list_rows"] = token_rows
        self.section_meta["policies"]["list_rows"] = policy_rows
        self.section_meta["roles"]["list_rows"] = role_rows
        if self._current_mode("tokens") == "list":
            self.section_rows["tokens"] = token_rows
        if self._current_mode("policies") == "list":
            self.section_rows["policies"] = policy_rows
        if self._current_mode("roles") == "list":
            self.section_rows["roles"] = role_rows

    def _member_status(self, status_code: Any) -> str:
        mapping = {1: "passing", 2: "warning", 3: "critical", "alive": "passing", "left": "warning", "failed": "critical"}
        return mapping.get(status_code, "unknown")

    def _cache_key(self, name: str, args: tuple[Any, ...]) -> str:
        encoded_args = "|".join(str(arg) for arg in args)
        return f"{name}|{encoded_args}"

    def _submit_job(self, name: str, args: tuple[Any, ...] = (), ttl: float = CACHE_TTL_SHORT, force: bool = False) -> None:
        key = self._cache_key(name, args)
        if not force and key in self.cache:
            cached_at, payload = self.cache[key]
            if time.time() - cached_at <= ttl:
                self._apply_result(JobResult(key=key, name=name, args=args, ok=True, payload=payload))
                return
        if key in self.in_flight:
            return
        self.in_flight.add(key)
        self.job_queue.put(Job(key=key, name=name, args=args, ttl=ttl, force=force))

    def refresh_current(self, force: bool = False) -> None:
        """Refresh the active section and schedule any required background jobs."""
        section = self.current_section
        self.section_loading[section] = True
        if section == "dashboard":
            self._submit_job("dashboard", ttl=CACHE_TTL_SHORT, force=force)
        elif section == "telemetry":
            self._submit_job("telemetry", ttl=CACHE_TTL_SHORT, force=force)
        elif section == "services":
            if self._current_mode("services") == "list":
                self._submit_job("services_list", ttl=CACHE_TTL_SHORT, force=force)
                self._maybe_load_current_detail(force=force)
            else:
                service_names = self.section_context["services"].get("services") or []
                if service_names:
                    for service_name in service_names:
                        self._submit_job("service_detail", args=(service_name,), ttl=CACHE_TTL_SHORT, force=force)
                else:
                    service_name = self.section_context["services"].get("service")
                    if service_name:
                        self._submit_job("service_detail", args=(service_name,), ttl=CACHE_TTL_SHORT, force=force)
        elif section == "nodes":
            if self._current_mode("nodes") == "list":
                self._submit_job("nodes_list", ttl=CACHE_TTL_SHORT, force=force)
                self._maybe_load_current_detail(force=force)
            else:
                node_names = self.section_context["nodes"].get("nodes") or []
                if node_names:
                    for node_name in node_names:
                        self._submit_job("node_detail", args=(node_name,), ttl=CACHE_TTL_SHORT, force=force)
                else:
                    node_name = self.section_context["nodes"].get("node")
                    if node_name:
                        self._submit_job("node_detail", args=(node_name,), ttl=CACHE_TTL_SHORT, force=force)
        elif section == "kv":
            self._submit_job("kv_list", args=(self.kv_prefix,), ttl=CACHE_TTL_SHORT, force=force)
            self._maybe_load_current_detail(force=force)
        elif section == "sessions":
            self._submit_job("sessions_list", ttl=CACHE_TTL_SHORT, force=force)
        elif section in {"tokens", "policies", "roles", "auth"}:
            if self.acl_capability != "available":
                self.section_loading[section] = False
                self._update_status(self.acl_message)
                self._refresh_screen()
                return
            for acl_section in ("tokens", "policies", "roles", "auth"):
                self.section_loading[acl_section] = True
            self._submit_job("acl_tokens", ttl=CACHE_TTL_MEDIUM, force=force)
            self._submit_job("acl_policies", ttl=CACHE_TTL_MEDIUM, force=force)
            self._submit_job("acl_roles", ttl=CACHE_TTL_MEDIUM, force=force)
            self._submit_job("acl_auth_methods", ttl=CACHE_TTL_MEDIUM, force=force)
        else:
            self.section_loading[section] = False
            self._update_status(f"{section} is not implemented yet")
        self._refresh_screen()

    def _maybe_load_current_detail(self, force: bool = False) -> None:
        section = self.current_section
        selected = self.section_selected.get(section)
        if not selected:
            return
        if section == "services":
            if self._current_mode("services") == "list":
                self._submit_job("service_detail", args=(selected,), ttl=CACHE_TTL_MEDIUM, force=force)
        elif section == "nodes":
            if self._current_mode("nodes") == "list":
                self._submit_job("node_detail", args=(selected,), ttl=CACHE_TTL_MEDIUM, force=force)
        elif section == "kv":
            row = self._find_row_by_id("kv", selected)
            if not row:
                return
            target = row.get("target", "")
            if row.get("kind") == "key":
                self._submit_job("kv_detail", args=(selected, target), ttl=CACHE_TTL_LONG, force=force)
            elif row.get("kind") in {"dir", "parent"}:
                self._submit_job("kv_dir_preview", args=(selected, target), ttl=CACHE_TTL_MEDIUM, force=force)
        elif section == "policies":
            row = self._find_row_by_id("policies", selected)
            if not row:
                return
            policy_id = row.get("id")
            if policy_id and policy_id != "-":
                self._submit_job("acl_policy_detail", args=(policy_id,), ttl=CACHE_TTL_LONG, force=force)
        elif section == "auth":
            row = self._find_row_by_id("auth", selected)
            if not row:
                return
            auth_name = row.get("name")
            if auth_name and auth_name != "-":
                self._submit_job("acl_auth_method_detail", args=(auth_name,), ttl=CACHE_TTL_LONG, force=force)

    def _poll_results(self, loop: urwid.MainLoop, _: Any) -> None:
        changed = False
        while True:
            try:
                result = self.result_queue.get_nowait()
            except queue.Empty:
                break
            self.in_flight.discard(result.key)
            if result.ok:
                self.cache[result.key] = (time.time(), result.payload)
            self._apply_result(result)
            changed = True
        if changed:
            self._refresh_screen()
        loop.set_alarm_in(0.2, self._poll_results)

    def _apply_result(self, result: JobResult) -> None:
        """Merge a completed background job into UI state."""
        if not result.ok:
            self._handle_job_error(result)
            return
        if result.name == "dashboard":
            payload = result.payload
            self.section_rows["dashboard"] = payload["rows"]
            self.section_meta["dashboard"] = payload["raw"]
            self.header_dc = payload["raw"].get("datacenter", "-")
            self.header_leader = payload["raw"].get("leader") or "-"
            self.section_stale["dashboard"] = False
            self.section_loading["dashboard"] = False
            if not self.section_selected["dashboard"] and payload["rows"]:
                self.section_selected["dashboard"] = payload["rows"][0]["id"]
            self._update_status("Dashboard updated")
            return
        if result.name == "telemetry":
            payload = result.payload
            self.section_rows["telemetry"] = payload["rows"]
            self.section_meta["telemetry"] = payload
            self.section_stale["telemetry"] = False
            self.section_loading["telemetry"] = False
            if not self.section_selected["telemetry"] and payload["rows"]:
                self.section_selected["telemetry"] = payload["rows"][0]["id"]
            self._preserve_selection("telemetry")
            self._update_status("Telemetry updated")
            return
        if result.name == "services_list":
            self.section_meta["services"]["list_rows"] = list(result.payload)
            self._sync_bulk_selected("services")
            if self._current_mode("services") == "list":
                self.section_rows["services"] = result.payload
            self.section_stale["services"] = False
            self.section_loading["services"] = False
            self._preserve_selection("services")
            self._prefetch_service_summaries(force=False)
            self._maybe_load_current_detail(force=False)
            self._update_status("Services list updated")
            return
        if result.name == "service_detail":
            service_name = result.args[0]
            self.section_details["services"][service_name] = result.payload
            self.section_meta["services"]["health_cache"][service_name] = result.payload["summary"]
            self._sync_service_row(service_name, result.payload["summary"])
            self.section_stale["services"] = False
            self.section_loading["services"] = False
            if self._current_mode("services") == "instances" and self.section_context["services"].get("service") == service_name:
                self.section_rows["services"] = result.payload.get("instances", [])
                self._preserve_selection("services")
            bulk_services = self.section_context["services"].get("services") or []
            if self._current_mode("services") == "instances" and service_name in bulk_services:
                merged_rows: list[dict[str, Any]] = []
                for name in bulk_services:
                    detail = self.section_details["services"].get(name)
                    if detail:
                        merged_rows.extend(detail.get("instances", []))
                merged_rows.sort(
                    key=lambda row: (
                        str(row.get("service", "")).lower(),
                        str(row.get("node", "")).lower(),
                        str(row.get("name", "")).lower(),
                        str(row.get("address", "")).lower(),
                    )
                )
                self.section_rows["services"] = merged_rows
                self.section_selected["services"] = self.section_selected.get("services") or (merged_rows[0]["id"] if merged_rows else None)
                self._preserve_selection("services")
                pending_many = self.section_meta["services"].get("pending_open_many") or []
                if pending_many and all(name in self.section_details["services"] for name in pending_many):
                    self.section_meta["services"]["pending_open_many"] = None
                    self.section_loading["services"] = False
                elif pending_many:
                    self.section_loading["services"] = True
            if self.section_meta["services"].get("pending_open") == service_name:
                self.section_meta["services"]["pending_open"] = None
                self._open_service_instances(service_name)
                return
            self._update_status(f"Service details updated: {service_name}")
            return
        if result.name == "nodes_list":
            self.section_meta["nodes"]["list_rows"] = list(result.payload)
            self._sync_bulk_selected("nodes")
            if self._current_mode("nodes") == "list":
                self.section_rows["nodes"] = result.payload
            self.section_stale["nodes"] = False
            self.section_loading["nodes"] = False
            self._preserve_selection("nodes")
            self._maybe_load_current_detail(force=False)
            self._update_status("Nodes list updated")
            return
        if result.name == "node_detail":
            node_name = result.args[0]
            self.section_details["nodes"][node_name] = result.payload
            self.section_meta["nodes"]["health_cache"][node_name] = result.payload["summary"]
            self._sync_node_row(node_name, result.payload["summary"])
            self.section_stale["nodes"] = False
            self.section_loading["nodes"] = False
            if self._current_mode("nodes") == "instances" and self.section_context["nodes"].get("node") == node_name:
                self.section_rows["nodes"] = result.payload.get("instances", [])
                self._preserve_selection("nodes")
            bulk_nodes = self.section_context["nodes"].get("nodes") or []
            if self._current_mode("nodes") == "instances" and node_name in bulk_nodes:
                merged_rows: list[dict[str, Any]] = []
                for name in bulk_nodes:
                    detail = self.section_details["nodes"].get(name)
                    if detail:
                        merged_rows.extend(detail.get("instances", []))
                merged_rows.sort(
                    key=lambda row: (
                        str(row.get("node", "")).lower(),
                        str(row.get("service", "")).lower(),
                        str(row.get("name", "")).lower(),
                        str(row.get("address", "")).lower(),
                    )
                )
                self.section_rows["nodes"] = merged_rows
                self.section_selected["nodes"] = self.section_selected.get("nodes") or (merged_rows[0]["id"] if merged_rows else None)
                self._preserve_selection("nodes")
                pending_many = self.section_meta["nodes"].get("pending_open_many") or []
                if pending_many and all(name in self.section_details["nodes"] for name in pending_many):
                    self.section_meta["nodes"]["pending_open_many"] = None
                    self.section_loading["nodes"] = False
                elif pending_many:
                    self.section_loading["nodes"] = True
            if self.section_meta["nodes"].get("pending_open") == node_name:
                self.section_meta["nodes"]["pending_open"] = None
                self._open_node_instances(node_name)
                return
            self._update_status(f"Node details updated: {node_name}")
            return
        if result.name == "kv_list":
            self.section_rows["kv"] = result.payload
            self.section_stale["kv"] = False
            self.section_loading["kv"] = False
            self._preserve_selection("kv")
            self._maybe_load_current_detail(force=False)
            self._update_status(f"KV list updated: /{self.kv_prefix}")
            return
        if result.name == "kv_detail":
            row_id = result.args[0]
            self.section_details["kv"][row_id] = result.payload
            self.section_stale["kv"] = False
            self.section_loading["kv"] = False
            self._update_status(f"KV value updated: {result.payload['key']}")
            return
        if result.name == "kv_dir_preview":
            row_id = result.args[0]
            self.section_details["kv"][row_id] = result.payload
            self.section_stale["kv"] = False
            self.section_loading["kv"] = False
            prefix = result.payload["prefix"]
            self._update_status(f"KV directory preview updated: /{prefix}" if prefix else "KV directory preview updated: /")
            return
        if result.name == "sessions_list":
            self.section_rows["sessions"] = result.payload
            self.section_stale["sessions"] = False
            self.section_loading["sessions"] = False
            self._preserve_selection("sessions")
            self._update_status("Sessions updated")
            return
        if result.name == "acl_probe":
            self.acl_capability = "available"
            self.acl_message = "ACL sections are available"
            self._rebuild_menu()
            self._update_status(self.acl_message)
            return
        if result.name == "acl_policy_detail":
            policy_id = result.args[0]
            self.section_details["policies"][policy_id] = result.payload
            self.section_stale["policies"] = False
            self._update_status(f"Policy details updated: {policy_id}")
            return
        if result.name == "acl_auth_method_detail":
            auth_name = result.args[0]
            self.section_details["auth"][auth_name] = result.payload
            self.section_stale["auth"] = False
            self._update_status(f"Auth method details updated: {auth_name}")
            return
        if result.name == "acl_auth_methods":
            self.section_rows["auth"] = list(result.payload)
            self.section_loading["auth"] = False
            self.section_stale["auth"] = False
            self._preserve_selection("auth")
            self._maybe_load_current_detail(force=False)
            self._update_status("Auth methods updated")
            return
        if result.name in {"acl_tokens", "acl_policies", "acl_roles"}:
            meta_key = {
                "acl_tokens": "tokens",
                "acl_policies": "policies",
                "acl_roles": "roles",
            }[result.name]
            self.section_meta[meta_key]["raw_rows"] = list(result.payload)
            self.section_loading[meta_key] = False
            self.section_stale[meta_key] = False
            self._rebuild_acl_views()
            for acl_section in ("tokens", "policies", "roles", "auth"):
                self._preserve_selection(acl_section)
            self._maybe_load_current_detail(force=False)
            label = self._section_label(meta_key)
            self._update_status(f"{label} updated")
            return

    def _handle_job_error(self, result: JobResult) -> None:
        section_map = {
            "dashboard": "dashboard",
            "telemetry": "telemetry",
            "services_list": "services",
            "service_detail": "services",
            "nodes_list": "nodes",
            "node_detail": "nodes",
            "kv_list": "kv",
            "kv_detail": "kv",
            "kv_dir_preview": "kv",
            "sessions_list": "sessions",
            "acl_probe": "dashboard",
            "acl_policies": "policies",
            "acl_policy_detail": "policies",
            "acl_tokens": "tokens",
            "acl_roles": "roles",
            "acl_auth_methods": "auth",
            "acl_auth_method_detail": "auth",
        }
        section = section_map.get(result.name, self.current_section)
        self.section_loading[section] = False
        self.section_stale[section] = True
        self.last_error = result.error
        self.last_error_at = now_hms()
        if result.name == "acl_probe":
            self.acl_capability = "unavailable"
            self.acl_message = f"ACL sections disabled: {result.error}"
            self._rebuild_menu()
        self._update_status(result.error)
        if not self.popup_open:
            title = "ACL Unavailable" if result.name == "acl_probe" else "Error"
            self._show_error_popup(result.error, title=title)

    def _sync_service_row(self, service_name: str, summary: dict[str, Any]) -> None:
        for row in self.section_rows["services"]:
            if row["id"] == service_name:
                row.update(summary)
                break

    def _sync_node_row(self, node_name: str, summary: dict[str, Any]) -> None:
        for row in self.section_rows["nodes"]:
            if row["id"] == node_name:
                row["status"] = summary.get("node_status", summary.get("status", "unknown"))
                row["status_count"] = summary.get("status_count", "?/?")
                break

    def _prefetch_service_summaries(self, force: bool = False) -> None:
        rows = list(self.section_rows["services"])
        if not rows:
            return
        selected = self.section_selected.get("services")
        rows.sort(key=lambda row: 0 if row["id"] == selected else 1)
        for row in rows:
            self._submit_job("service_detail", args=(row["id"],), ttl=CACHE_TTL_MEDIUM, force=force)

    def _markable_section(self, section: Optional[str] = None) -> bool:
        target = section or self.current_section
        return target in {"services", "nodes"} and self._current_mode(target) == "list"

    def _sync_bulk_selected(self, section: str) -> None:
        if section not in self.bulk_selected:
            return
        list_rows = self.section_meta.get(section, {}).get("list_rows", [])
        valid_ids = {row.get("id") for row in list_rows if row.get("id")}
        self.bulk_selected[section].intersection_update(valid_ids)

    def _toggle_current_bulk_mark(self) -> None:
        section = self.current_section
        if not self._markable_section(section):
            self._update_status("Selection by Space is available only in services/nodes list mode")
            return
        selected = self.section_selected.get(section)
        if not selected:
            self._update_status("No row selected")
            return
        marked = self.bulk_selected[section]
        if selected in marked:
            marked.remove(selected)
        else:
            marked.add(selected)
        self._preserve_selection(section)
        self._update_status(f"Selected {len(marked)} {section}")
        self._refresh_screen()

    def _marked_ids(self, section: str) -> list[str]:
        self._sync_bulk_selected(section)
        return sorted(self.bulk_selected.get(section, set()))

    def _apply_bulk_selection_regex(self, pattern: str) -> None:
        section = self.current_section
        if not self._markable_section(section):
            self._update_status("Regex selection is available only in services/nodes list mode")
            return
        text = pattern.strip()
        if not text:
            self.bulk_selected[section].clear()
            self._close_popup()
            self._update_status(f"Selection cleared for {section}")
            self._refresh_screen()
            return
        try:
            compiled = re.compile(text, re.IGNORECASE)
        except re.error as exc:
            self._update_status(f"Invalid regex: {exc}")
            return
        matched = {
            row["id"]
            for row in self._filtered_rows(section)
            if compiled.search(str(row.get("name", "")))
        }
        self.bulk_selected[section] = matched
        self._close_popup()
        self._preserve_selection(section)
        self._update_status(f"Selected {len(matched)} {section} by regex")
        self._refresh_screen()

    def _current_mode(self, section: str) -> str:
        return self.section_modes.get(section, "list")

    def _acl_root_rows(self, section: str) -> list[dict[str, Any]]:
        return list(self.section_meta.get(section, {}).get("list_rows", []))

    def _find_acl_root_row_by_name(self, section: str, name: str) -> Optional[dict[str, Any]]:
        for row in self._acl_root_rows(section):
            if row.get("name") == name:
                return row
        return None

    def _open_acl_links(self, section: str, row_id: str) -> None:
        if section not in {"tokens", "roles"}:
            return
        row = self._find_row_by_id(section, row_id)
        if not row:
            return
        link_rows: list[dict[str, Any]] = []
        if section == "tokens":
            for role_name in row.get("roles_list", []):
                link_rows.append(
                    {
                        "id": f"acl-link:roles:{role_name}",
                        "name": role_name,
                        "link_type": "role",
                        "target_section": "roles",
                        "target_name": role_name,
                        "kind": "acl_link",
                        "status": "passing",
                    }
                )
            for policy_name in row.get("policies_list", []):
                link_rows.append(
                    {
                        "id": f"acl-link:policies:{policy_name}",
                        "name": policy_name,
                        "link_type": "policy",
                        "target_section": "policies",
                        "target_name": policy_name,
                        "kind": "acl_link",
                        "status": "passing",
                    }
                )
        elif section == "roles":
            for policy_name in row.get("policies_list", []):
                link_rows.append(
                    {
                        "id": f"acl-link:policies:{policy_name}",
                        "name": policy_name,
                        "link_type": "policy",
                        "target_section": "policies",
                        "target_name": policy_name,
                        "kind": "acl_link",
                        "status": "passing",
                    }
                )
        if not link_rows:
            self._update_status(f"No linked items for {row.get('name', row_id)}")
            return
        if section == "tokens":
            source_name = row.get("accessor", row.get("name", row_id))
        else:
            source_name = row.get("name", row_id)
        self.section_modes[section] = "links"
        self.section_context[section] = {"source_id": row_id, "source_name": source_name}
        self.section_rows[section] = link_rows
        self.section_selected[section] = link_rows[0]["id"]
        self._update_status(f"Linked items for {source_name}")
        self._refresh_screen()

    def _close_acl_links(self, section: str) -> None:
        if section not in {"tokens", "roles"}:
            return
        source_id = self.section_context.get(section, {}).get("source_id")
        self.section_modes[section] = "list"
        self.section_context[section] = {}
        self.section_rows[section] = self._acl_root_rows(section)
        self.section_selected[section] = source_id
        self._preserve_selection(section)
        self._update_status(f"Back to {section}")
        self._refresh_screen()

    def _jump_to_acl_item(self, section: str, name: str) -> None:
        current = self.current_section
        if current != section:
            self.history.append(("section", current))
        self.current_section = section
        self.section_modes[section] = "list"
        self.section_context[section] = {}
        self.section_rows[section] = self._acl_root_rows(section)
        target_row = self._find_acl_root_row_by_name(section, name)
        self.section_selected[section] = target_row["id"] if target_row else None
        self._set_focus_area("list")
        self.refresh_current(force=False)
        self._update_status(f"Jumped to {section[:-1] if section.endswith('s') else section}: {name}")

    def _show_token_secret(self) -> None:
        if self.current_section != "tokens" or self._current_mode("tokens") != "list":
            self._update_status("F4 Secret works in token list")
            return
        selected = self.section_selected.get("tokens")
        row = self._find_row_by_id("tokens", selected) if selected else None
        if not row:
            self._update_status("No token selected")
            return
        raw = row.get("raw") or {}
        secret_id = raw.get("SecretID")
        if not secret_id:
            self._update_status("Selected token has no SecretID")
            return
        text = f"AccessorID: {row.get('accessor_full', '-')}\nDescription: {row.get('description', '-')}\n\nSecretID:\n{secret_id}"
        self._show_error_popup(text, title="Token SecretID")

    def _open_service_instances(self, service_name: str) -> None:
        detail = self.section_details["services"].get(service_name)
        if not detail:
            self.section_meta["services"]["pending_open"] = service_name
            self._submit_job("service_detail", args=(service_name,), ttl=CACHE_TTL_MEDIUM, force=True)
            self._update_status(f"Loading instances for service: {service_name}")
            return
        self.section_meta["services"]["pending_open_many"] = None
        self.section_modes["services"] = "instances"
        self.section_context["services"] = {"service": service_name}
        self.section_rows["services"] = detail.get("instances", [])
        selected = self.section_rows["services"][0]["id"] if self.section_rows["services"] else None
        self.section_selected["services"] = selected
        self._update_status(f"Instances for service: {service_name}")
        self._refresh_screen()

    def _open_service_instances_many(self, service_names: list[str]) -> None:
        targets = sorted({name for name in service_names if name})
        if not targets:
            self._update_status("No services selected")
            return
        self.section_meta["services"]["pending_open"] = None
        self.section_modes["services"] = "instances"
        self.section_context["services"] = {"services": targets}
        rows: list[dict[str, Any]] = []
        missing: list[str] = []
        for service_name in targets:
            detail = self.section_details["services"].get(service_name)
            if detail:
                rows.extend(detail.get("instances", []))
            else:
                missing.append(service_name)
                self._submit_job("service_detail", args=(service_name,), ttl=CACHE_TTL_MEDIUM, force=True)
        rows.sort(
            key=lambda row: (
                str(row.get("service", "")).lower(),
                str(row.get("node", "")).lower(),
                str(row.get("name", "")).lower(),
                str(row.get("address", "")).lower(),
            )
        )
        self.section_rows["services"] = rows
        self.section_selected["services"] = rows[0]["id"] if rows else None
        self.section_meta["services"]["pending_open_many"] = list(targets) if missing else None
        self.section_loading["services"] = bool(missing)
        if missing:
            self._update_status(f"Loading instances for selected services: {len(targets)} ({len(missing)} pending)")
        else:
            self._update_status(f"Instances for selected services: {len(targets)}")
        self._refresh_screen()

    def _close_service_instances(self) -> None:
        service_name = self.section_context["services"].get("service")
        service_names = self.section_context["services"].get("services") or []
        self.section_modes["services"] = "list"
        self.section_context["services"] = {}
        self.section_rows["services"] = list(self.section_meta["services"].get("list_rows", []))
        self.section_meta["services"]["pending_open_many"] = None
        self.section_selected["services"] = service_name or (service_names[0] if service_names else None)
        self._preserve_selection("services")
        self._update_status("Back to services")
        self.refresh_current(force=False)

    def _open_node_instances(self, node_name: str) -> None:
        detail = self.section_details["nodes"].get(node_name)
        if not detail:
            self.section_meta["nodes"]["pending_open"] = node_name
            self._submit_job("node_detail", args=(node_name,), ttl=CACHE_TTL_MEDIUM, force=True)
            self._update_status(f"Loading instances for node: {node_name}")
            return
        self.section_meta["nodes"]["pending_open_many"] = None
        self.section_modes["nodes"] = "instances"
        self.section_context["nodes"] = {"node": node_name}
        self.section_rows["nodes"] = detail.get("instances", [])
        selected = self.section_rows["nodes"][0]["id"] if self.section_rows["nodes"] else None
        self.section_selected["nodes"] = selected
        self._update_status(f"Instances on node: {node_name}")
        self._refresh_screen()

    def _open_node_instances_many(self, node_names: list[str]) -> None:
        targets = sorted({name for name in node_names if name})
        if not targets:
            self._update_status("No nodes selected")
            return
        self.section_meta["nodes"]["pending_open"] = None
        self.section_modes["nodes"] = "instances"
        self.section_context["nodes"] = {"nodes": targets}
        rows: list[dict[str, Any]] = []
        missing: list[str] = []
        for node_name in targets:
            detail = self.section_details["nodes"].get(node_name)
            if detail:
                rows.extend(detail.get("instances", []))
            else:
                missing.append(node_name)
                self._submit_job("node_detail", args=(node_name,), ttl=CACHE_TTL_MEDIUM, force=True)
        rows.sort(
            key=lambda row: (
                str(row.get("node", "")).lower(),
                str(row.get("service", "")).lower(),
                str(row.get("name", "")).lower(),
                str(row.get("address", "")).lower(),
            )
        )
        self.section_rows["nodes"] = rows
        self.section_selected["nodes"] = rows[0]["id"] if rows else None
        self.section_meta["nodes"]["pending_open_many"] = list(targets) if missing else None
        self.section_loading["nodes"] = bool(missing)
        if missing:
            self._update_status(f"Loading instances for selected nodes: {len(targets)} ({len(missing)} pending)")
        else:
            self._update_status(f"Instances for selected nodes: {len(targets)}")
        self._refresh_screen()

    def _close_node_instances(self) -> None:
        node_name = self.section_context["nodes"].get("node")
        node_names = self.section_context["nodes"].get("nodes") or []
        self.section_modes["nodes"] = "list"
        self.section_context["nodes"] = {}
        self.section_rows["nodes"] = list(self.section_meta["nodes"].get("list_rows", []))
        self.section_meta["nodes"]["pending_open_many"] = None
        self.section_selected["nodes"] = node_name or (node_names[0] if node_names else None)
        self._preserve_selection("nodes")
        self._update_status("Back to nodes")
        self.refresh_current(force=False)

    def _reset_section_to_root(self, section: str) -> None:
        if section == "services":
            service_name = self.section_context["services"].get("service")
            self.section_modes["services"] = "list"
            self.section_context["services"] = {}
            self.section_rows["services"] = list(self.section_meta["services"].get("list_rows", []))
            self.section_meta["services"]["pending_open_many"] = None
            if service_name:
                self.section_selected["services"] = service_name
            self._preserve_selection("services")
            return
        if section == "nodes":
            node_name = self.section_context["nodes"].get("node")
            self.section_modes["nodes"] = "list"
            self.section_context["nodes"] = {}
            self.section_rows["nodes"] = list(self.section_meta["nodes"].get("list_rows", []))
            self.section_meta["nodes"]["pending_open_many"] = None
            if node_name:
                self.section_selected["nodes"] = node_name
            self._preserve_selection("nodes")
            return
        if section in {"tokens", "policies", "roles"}:
            selected = self.section_selected.get(section)
            self.section_modes[section] = "list"
            self.section_context[section] = {}
            self.section_rows[section] = self._acl_root_rows(section)
            if selected and any(row["id"] == selected for row in self.section_rows[section]):
                self.section_selected[section] = selected
            self._preserve_selection(section)

    def _selected_instance_row(self) -> Optional[dict[str, Any]]:
        section = self.current_section
        if section == "services" and self._current_mode("services") == "instances":
            selected = self.section_selected.get("services")
            return self._find_row_by_id("services", selected) if selected else None
        if section == "nodes" and self._current_mode("nodes") == "instances":
            selected = self.section_selected.get("nodes")
            return self._find_row_by_id("nodes", selected) if selected else None
        return None

    def _jump_to_service(self, service_name: str) -> None:
        current = self.current_section
        if current != "services":
            self.history.append(("section", current))
        self.current_section = "services"
        self.section_modes["services"] = "list"
        self.section_context["services"] = {}
        self.section_rows["services"] = list(self.section_meta["services"].get("list_rows", []))
        self.section_selected["services"] = service_name
        self._set_focus_area("list")
        self.refresh_current(force=False)
        self._update_status(f"Jumped to service: {service_name}")

    def _jump_to_service_filtered(self, service_name: str) -> None:
        current = self.current_section
        if current != "services":
            self.history.append(("section", current))
        self.current_section = "services"
        self.section_modes["services"] = "list"
        self.section_context["services"] = {}
        self.section_rows["services"] = list(self.section_meta["services"].get("list_rows", []))
        self.section_filters["services"] = f"={service_name}"
        self.section_selected["services"] = service_name
        self._set_focus_area("list")
        self.section_loading["services"] = True
        self._submit_job("service_detail", args=(service_name,), ttl=CACHE_TTL_MEDIUM, force=False)
        self._refresh_screen()
        self.refresh_current(force=False)
        self._update_status(f"Filtered services by: {service_name}")

    def _jump_to_node(self, node_name: str) -> None:
        current = self.current_section
        if current != "nodes":
            self.history.append(("section", current))
        self.current_section = "nodes"
        self.section_modes["nodes"] = "list"
        self.section_context["nodes"] = {}
        self.section_rows["nodes"] = list(self.section_meta["nodes"].get("list_rows", []))
        self.section_selected["nodes"] = node_name
        self._set_focus_area("list")
        self.refresh_current(force=False)
        self._update_status(f"Jumped to node: {node_name}")

    def _preserve_selection(self, section: str) -> None:
        rows = self._filtered_rows(section)
        current = self.section_selected.get(section)
        ids = {row["id"] for row in rows}
        if current not in ids:
            self.section_selected[section] = rows[0]["id"] if rows else None

    def _filtered_rows(self, section: str) -> list[dict[str, Any]]:
        """Return rows for a section after applying filters and sort order.

        Args:
            section: Logical section whose current visible rows should be produced.

        Returns:
            Filtered and sorted row list for the active view of that section.

        Raises:
            No explicit exceptions.
        """
        rows = list(self.section_rows.get(section, []))
        filter_text = self.section_filters.get(section, "").strip().lower()
        if self._is_instance_list(section):
            filter_text = ""
        filtered = rows
        if filter_text:
            if section == "services" and filter_text.startswith("="):
                exact_name = filter_text[1:].strip()
                if exact_name:
                    filtered = [row for row in rows if str(row.get("name", "")).lower() == exact_name]
            elif section == "services" and self._current_mode("services") == "list":
                filtered = [row for row in rows if filter_text in str(row.get("name", "")).lower()]
            else:
                matched: list[dict[str, Any]] = []
                for row in rows:
                    blob = " ".join(str(value) for value in row.values()).lower()
                    if filter_text in blob:
                        matched.append(row)
                filtered = matched
        if self._is_instance_list(section) and self._instance_text_filter_active():
            filtered = [row for row in filtered if self._row_matches_instance_text_filter(row)]
        status_scope = self._status_filter_scope(section)
        selected_statuses = self.status_filters.get(status_scope or "", set())
        # Filters are layered: text -> status -> structured instance filter -> sort.
        if status_scope and selected_statuses:
            filtered = [row for row in filtered if self._row_status_bucket(row) in selected_statuses]
        if self._is_instance_list(section) and self._instance_filter_active():
            filtered = [row for row in filtered if self._row_matches_instance_filter(row)]
        return self._sort_rows(section, filtered)

    def _empty_instance_text_filter(self) -> dict[str, str]:
        return {"instance": "", "service": "", "address": "", "mode": "and"}

    def _instance_text_filter_active(self) -> bool:
        spec = self.instance_text_filter
        return bool(
            str(spec.get("instance", "")).strip()
            or str(spec.get("service", "")).strip()
            or str(spec.get("address", "")).strip()
        )

    def _row_matches_instance_text_filter(self, row: dict[str, Any]) -> bool:
        spec = self.instance_text_filter
        instance_pattern = str(spec.get("instance", "")).strip().lower()
        service_pattern = str(spec.get("service", "")).strip().lower()
        address_pattern = str(spec.get("address", "")).strip().lower()
        mode = str(spec.get("mode", "and")).strip().lower()
        checks: list[bool] = []
        if instance_pattern:
            checks.append(instance_pattern in str(row.get("name", "")).lower())
        if service_pattern:
            checks.append(service_pattern in str(row.get("service", "")).lower())
        if address_pattern:
            checks.append(address_pattern in str(row.get("address", "")).lower())
        if not checks:
            return True
        if mode == "or":
            return any(checks)
        return all(checks)

    def _empty_instance_filter(self) -> dict[str, Any]:
        return {
            "has_tags": "",
            "no_tags": "",
            "has_meta_keys": "",
            "no_meta_keys": "",
            "meta_key_pattern": "",
            "meta_value_pattern": "",
            "case_sensitive": False,
            "regex_enabled": True,
        }

    def _is_instance_list(self, section: Optional[str] = None) -> bool:
        target = section or self.current_section
        return target in {"services", "nodes"} and self._current_mode(target) == "instances"

    def _instance_filter_active(self) -> bool:
        spec = self.instance_filter
        keys = (
            "has_tags",
            "no_tags",
            "has_meta_keys",
            "no_meta_keys",
            "meta_key_pattern",
            "meta_value_pattern",
        )
        return any(str(spec.get(key, "")).strip() for key in keys)

    def _parse_filter_list(self, raw: str, case_sensitive: bool) -> list[str]:
        values = [item.strip() for item in str(raw or "").split(",")]
        cleaned = [item for item in values if item]
        if case_sensitive:
            return cleaned
        return [item.lower() for item in cleaned]

    def _normalize_filter_text(self, value: Any, case_sensitive: bool) -> str:
        text = str(value) if value is not None else ""
        return text if case_sensitive else text.lower()

    def _pattern_matches(self, pattern: str, text: str, regex_enabled: bool, case_sensitive: bool) -> bool:
        if not pattern:
            return True
        if regex_enabled:
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                return re.search(pattern, text, flags) is not None
            except re.error:
                pass
        candidate = text if case_sensitive else text.lower()
        needle = pattern if case_sensitive else pattern.lower()
        return needle in candidate

    def _row_matches_instance_filter(self, row: dict[str, Any]) -> bool:
        spec = self.instance_filter
        case_sensitive = bool(spec.get("case_sensitive"))
        regex_enabled = bool(spec.get("regex_enabled"))
        tags = [self._normalize_filter_text(tag, case_sensitive) for tag in row.get("tags", []) or []]
        tag_set = set(tags)
        has_tags = self._parse_filter_list(str(spec.get("has_tags", "")), case_sensitive)
        if has_tags and not all(tag in tag_set for tag in has_tags):
            return False
        no_tags = self._parse_filter_list(str(spec.get("no_tags", "")), case_sensitive)
        if no_tags and any(tag in tag_set for tag in no_tags):
            return False
        meta = row.get("meta") or {}
        normalized_meta = {
            self._normalize_filter_text(key, case_sensitive): self._normalize_filter_text(value, case_sensitive)
            for key, value in meta.items()
        }
        has_meta_keys = self._parse_filter_list(str(spec.get("has_meta_keys", "")), case_sensitive)
        if has_meta_keys and not all(key in normalized_meta for key in has_meta_keys):
            return False
        no_meta_keys = self._parse_filter_list(str(spec.get("no_meta_keys", "")), case_sensitive)
        if no_meta_keys and any(key in normalized_meta for key in no_meta_keys):
            return False
        key_pattern = str(spec.get("meta_key_pattern", "")).strip()
        value_pattern = str(spec.get("meta_value_pattern", "")).strip()
        if key_pattern or value_pattern:
            matched = False
            for key_text, value_text in normalized_meta.items():
                key_ok = self._pattern_matches(key_pattern, key_text, regex_enabled, case_sensitive) if key_pattern else True
                value_ok = (
                    self._pattern_matches(value_pattern, value_text, regex_enabled, case_sensitive) if value_pattern else True
                )
                if key_ok and value_ok:
                    matched = True
                    break
            if not matched:
                return False
        return True

    def _status_filter_scope(self, section: Optional[str] = None) -> Optional[str]:
        target = section or self.current_section
        if target == "services":
            return "instances" if self._current_mode("services") == "instances" else "services"
        if target == "nodes":
            return "instances" if self._current_mode("nodes") == "instances" else "nodes"
        return None

    def _view_sort_key(self, section: Optional[str] = None) -> str:
        target = section or self.current_section
        mode = self._current_mode(target) if target in self.section_modes else "list"
        return f"{target}:{mode}"

    def _sortable_fields(self, section: Optional[str] = None) -> list[tuple[str, str]]:
        target = section or self.current_section
        mode = self._current_mode(target) if target in self.section_modes else "list"
        preferred: dict[str, list[tuple[str, str]]] = {
            "dashboard:list": [("label", "Label"), ("status", "Status"), ("id", "ID")],
            "telemetry:list": [
                ("name", "Metric"),
                ("value", "Value"),
                ("limit", "Limit"),
                ("usage_pct", "Usage %"),
                ("status", "Status"),
            ],
            "services:list": [
                ("name", "Name"),
                ("tags", "Tags"),
                ("instances", "Instances"),
                ("status_count", "Status"),
                ("status", "Health"),
                ("passing", "Passing"),
                ("warning", "Warning"),
                ("critical", "Critical"),
            ],
            "services:instances": [
                ("name", "Instance"),
                ("service", "Service"),
                ("node", "Node"),
                ("address", "Address"),
                ("port", "Port"),
                ("status_count", "Status"),
                ("status", "Health"),
            ],
            "nodes:list": [
                ("name", "Node"),
                ("address", "Address"),
                ("status_count", "Status"),
                ("status", "Health"),
                ("dc", "DC"),
            ],
            "nodes:instances": [
                ("name", "Instance"),
                ("service", "Service"),
                ("node", "Node"),
                ("address", "Address"),
                ("port", "Port"),
                ("status_count", "Status"),
                ("status", "Health"),
            ],
            "kv:list": [("name", "Name"), ("kind", "Kind"), ("target", "Target")],
            "sessions:list": [("name", "Name"), ("node", "Node"), ("ttl", "TTL"), ("behavior", "Behavior"), ("lock_delay", "Lock Delay")],
            "tokens:list": [("accessor", "Accessor"), ("description", "Description"), ("scope", "Scope")],
            "tokens:links": [("link_type", "Type"), ("name", "Name")],
            "policies:list": [("name", "Policy"), ("description", "Description"), ("tokens", "Tokens"), ("roles", "Roles")],
            "roles:list": [("name", "Role"), ("description", "Description"), ("policies", "Policies"), ("tokens", "Tokens")],
            "roles:links": [("link_type", "Type"), ("name", "Name")],
            "auth:list": [("name", "Name"), ("type", "Type"), ("display_name", "Display Name"), ("locality", "Locality")],
        }
        key = f"{target}:{mode}"
        rows = self.section_rows.get(target, [])
        available_keys = {row_key for row in rows for row_key in row.keys()}
        fields = [(field_name, label) for field_name, label in preferred.get(key, []) if field_name in available_keys]
        if fields:
            return fields
        excluded = {"raw", "raw_node", "raw_service", "checks", "node_meta", "meta"}
        discovered: list[tuple[str, str]] = []
        for field_name in sorted(available_keys):
            if field_name in excluded:
                continue
            discovered.append((field_name, field_name.replace("_", " ").title()))
        return discovered

    def _current_sort_option(self, section: Optional[str] = None) -> dict[str, Any]:
        return self.sort_options.get(self._view_sort_key(section), {"field": "", "descending": False})

    def _sort_field_label(self, field_name: str, section: Optional[str] = None) -> str:
        if not field_name:
            return "default"
        for key, label in self._sortable_fields(section):
            if key == field_name:
                return label
        return field_name

    def _sort_value(self, field_name: str, value: Any) -> Any:
        if value is None:
            return (1, "")
        if field_name == "status":
            return (0, status_rank(str(value)))
        if field_name == "status_count":
            text = str(value)
            try:
                left, right = text.split("/", 1)
                return (0, int(left), int(right))
            except Exception:
                return (0, text.lower())
        if isinstance(value, bool):
            return (0, int(value))
        if isinstance(value, (int, float)):
            return (0, value)
        if isinstance(value, list):
            return (0, ",".join(str(item) for item in value).lower())
        if isinstance(value, dict):
            return (0, safe_json(value).lower())
        text = str(value).strip()
        if text:
            if text.isdigit():
                return (0, int(text))
            try:
                return (0, float(text))
            except ValueError:
                pass
        return (0, text.lower())

    def _sort_rows(self, section: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply the user-selected sort option for the current view."""
        option = self._current_sort_option(section)
        field_name = str(option.get("field") or "")
        if not field_name:
            return rows
        if not any(field_name in row for row in rows):
            return rows
        descending = bool(option.get("descending"))
        return sorted(rows, key=lambda row: self._sort_value(field_name, row.get(field_name)), reverse=descending)

    def _status_filter_label(self, scope: str) -> str:
        labels = {
            "services": "Services",
            "nodes": "Nodes",
            "instances": "Instances",
        }
        return labels.get(scope, scope.title())

    def _format_status_filter_values(self, selected: set[str]) -> str:
        ordered = [
            ("passed", "Passed"),
            ("warning", "Warning"),
            ("critical", "Critical"),
            ("no_checks", "No checks"),
        ]
        labels = [label for key, label in ordered if key in selected]
        return ", ".join(labels)

    def _instance_filter_summary(self) -> str:
        parts: list[str] = []
        spec = self.instance_filter
        if spec.get("has_tags"):
            parts.append(f"tag:+{spec['has_tags']}")
        if spec.get("no_tags"):
            parts.append(f"tag:-{spec['no_tags']}")
        if spec.get("has_meta_keys"):
            parts.append(f"meta:+{spec['has_meta_keys']}")
        if spec.get("no_meta_keys"):
            parts.append(f"meta:-{spec['no_meta_keys']}")
        if spec.get("meta_key_pattern"):
            parts.append(f"k={spec['meta_key_pattern']}")
        if spec.get("meta_value_pattern"):
            parts.append(f"v={spec['meta_value_pattern']}")
        if not parts:
            return "-"
        text = " ".join(parts)
        if len(text) <= 48:
            return text
        return text[:45] + "..."

    def _instance_text_filter_summary(self) -> str:
        spec = self.instance_text_filter
        instance = str(spec.get("instance", "")).strip()
        service = str(spec.get("service", "")).strip()
        address = str(spec.get("address", "")).strip()
        mode = str(spec.get("mode", "and")).strip().upper()
        if not instance and not service and not address:
            return "-"
        parts: list[str] = []
        if instance:
            parts.append(f"inst={instance}")
        if service:
            parts.append(f"svc={service}")
        if address:
            parts.append(f"addr={address}")
        if len(parts) > 1:
            parts.append(mode)
        text = " ".join(parts)
        if len(text) <= 48:
            return text
        return text[:45] + "..."

    def _row_status_bucket(self, row: dict[str, Any]) -> str:
        status = str(row.get("status") or "unknown").strip().lower()
        if status == "passing":
            return "passed"
        if status == "warning":
            return "warning"
        if status == "critical":
            return "critical"
        return "no_checks"

    def _find_row_by_id(self, section: str, item_id: str) -> Optional[dict[str, Any]]:
        for row in self.section_rows.get(section, []):
            if row["id"] == item_id:
                return row
        return None

    def _update_header(self) -> None:
        self.header_text.set_text(f"{APP_NAME} | {self.header_dc} | {self.header_leader} | {self.config.addr} | {self.config.auth_mode}")

    def _section_enabled(self, section: str, declared_enabled: bool = True) -> bool:
        if not declared_enabled:
            return False
        if section in {"tokens", "policies", "roles", "auth"}:
            return self.acl_capability == "available"
        return True

    def _enabled_sections(self) -> list[str]:
        sections: list[str] = []
        for key, _, enabled in MENU_ITEMS:
            if self._section_enabled(key, enabled):
                sections.append(key)
        return sections

    def _switch_section_relative(self, offset: int) -> None:
        sections = self._enabled_sections()
        if not sections:
            return
        try:
            index = sections.index(self.current_section)
        except ValueError:
            index = 0
        next_index = (index + offset) % len(sections)
        self._switch_section(sections[next_index], push_history=False)

    def _activate_section_hotkey(self, section: str) -> None:
        declared_enabled = next((enabled for key, _, enabled in MENU_ITEMS if key == section), False)
        if not self._section_enabled(section, declared_enabled):
            if section in {"tokens", "policies", "roles", "auth"}:
                self._update_status(self.acl_message)
            elif section == "mesh":
                self._update_status("Mesh is not implemented yet")
            else:
                self._update_status(f"{self._section_label(section)} is unavailable")
            return
        self._switch_section(section, push_history=False)

    def _update_status(self, message: str) -> None:
        self.status_message = message
        self._refresh_status_line()

    def _refresh_status_line(self) -> None:
        section = self.current_section
        loading = "loading" if self.section_loading.get(section) else "idle"
        stale = "stale" if self.section_stale.get(section) else "fresh"
        filter_text = self.section_filters.get(section, "")
        if self._is_instance_list(section):
            extra = f" filter={self._instance_text_filter_summary()}" if self._instance_text_filter_active() else ""
        else:
            extra = f" filter={filter_text!r}" if filter_text else ""
        status_scope = self._status_filter_scope(section)
        status_values = self.status_filters.get(status_scope or "", set())
        status_extra = f" status={self._format_status_filter_values(status_values)}" if status_values else ""
        instance_extra = f" inst={self._instance_filter_summary()}" if self._is_instance_list(section) and self._instance_filter_active() else ""
        sort_option = self._current_sort_option(section)
        sort_extra = ""
        if sort_option.get("field"):
            direction = "desc" if sort_option.get("descending") else "asc"
            sort_extra = f" sort={self._sort_field_label(str(sort_option['field']), section)}:{direction}"
        path = f" path=/{self.kv_prefix}" if section == "kv" and self.kv_prefix else ""
        error = f" | last error {self.last_error_at}: {self.last_error}" if self.last_error else ""
        self.status_text.set_text(
            f"{section} | {loading}/{stale}{extra}{status_extra}{instance_extra}{sort_extra}{path} | {self.status_message}{error}"
        )

    def _update_footer_keys(self) -> None:
        self.keys_text.set_text(
            "Tab NextSec  Shift+Tab PrevSec  Left/Right Pane  0-9/T Section  Space Mark  F12 MarkRe  F1 Help  F2 Auto  F3 View  F4 Secret  F5 Refresh  F6 Status  F7 Filter  F8 Clear  F9 Inst  F11 Sort  Backspace Back  F10 Exit"
        )

    def _panel_attr_map(self) -> dict[Optional[str], str]:
        return {
            None: "panel_border",
            "line": "panel_border",
            "tlcorner": "panel_border",
            "trcorner": "panel_border",
            "blcorner": "panel_border",
            "brcorner": "panel_border",
            "tline": "panel_border",
            "bline": "panel_border",
            "lline": "panel_border",
            "rline": "panel_border",
            "title": "panel_title",
        }

    def _panel_focus_map(self) -> dict[Optional[str], str]:
        return {
            None: "panel_border_active",
            "line": "panel_border_active",
            "tlcorner": "panel_border_active",
            "trcorner": "panel_border_active",
            "blcorner": "panel_border_active",
            "brcorner": "panel_border_active",
            "tline": "panel_border_active",
            "bline": "panel_border_active",
            "lline": "panel_border_active",
            "rline": "panel_border_active",
            "title": "panel_title_active",
        }

    def _section_label(self, key: str) -> str:
        for item_key, label, _ in MENU_ITEMS:
            if item_key == key:
                return label
        return key.title()

    def _section_tab_label(self, key: str) -> str:
        label = self._section_label(key)
        indicator = self._tab_status_filter_indicator(key)
        if indicator:
            return f"{label}{indicator}"
        return label

    def _status_filter_codes(self, selected: set[str]) -> str:
        ordered = [
            ("passed", "P"),
            ("warning", "W"),
            ("critical", "C"),
            ("no_checks", "0"),
        ]
        return "".join(code for key, code in ordered if key in selected)

    def _tab_status_filter_indicator(self, key: str) -> str:
        if key == "services":
            parts: list[str] = []
            service_codes = self._status_filter_codes(self.status_filters.get("services", set()))
            instance_codes = self._status_filter_codes(self.status_filters.get("instances", set()))
            if service_codes:
                parts.append(f"S:{service_codes}")
            if instance_codes:
                parts.append(f"I:{instance_codes}")
            if self._instance_filter_active():
                parts.append("IF")
            return f"[{' '.join(parts)}]" if parts else ""
        if key == "nodes":
            parts: list[str] = []
            node_codes = self._status_filter_codes(self.status_filters.get("nodes", set()))
            instance_codes = self._status_filter_codes(self.status_filters.get("instances", set()))
            if node_codes:
                parts.append(f"N:{node_codes}")
            if instance_codes:
                parts.append(f"I:{instance_codes}")
            if self._instance_filter_active():
                parts.append("IF")
            return f"[{' '.join(parts)}]" if parts else ""
        return ""

    def _update_panel_styles(self) -> None:
        for widget in (self.content_box, self.details_box):
            widget.set_attr_map(self._panel_attr_map())
            widget.set_focus_map(self._panel_focus_map())

    def _rebuild_menu(self) -> None:
        markup: list[tuple[str, str]] = []
        first = True
        hotkeys = {
            "dashboard": "1",
            "telemetry": "T",
            "services": "2",
            "nodes": "3",
            "kv": "4",
            "sessions": "5",
            "tokens": "6",
            "policies": "7",
            "roles": "8",
            "mesh": "9",
            "auth": "0",
        }
        for key, _, enabled in MENU_ITEMS:
            active = self._section_enabled(key, enabled)
            attr = "menu_current" if key == self.current_section else ("menu_item" if active else "menu_disabled")
            if not first:
                markup.append(("panel_fill", "  "))
            markup.append((attr, f"{hotkeys.get(key, '?')}:{self._section_tab_label(key)}"))
            first = False
        tabs = urwid.Padding(urwid.Text(markup, wrap="clip"), left=1, right=1)
        self.tabs_placeholder.original_widget = urwid.AttrMap(tabs, "panel_fill")
        self._update_header()

    def _rebuild_content(self) -> None:
        """Rebuild the left Items pane from the current section state."""
        section = self.current_section
        rows = self._filtered_rows(section)
        self.content_walker[:] = []
        if section == "dashboard":
            self.list_header.set_text(("list_header", "Item"))
        elif section == "telemetry":
            self.list_header.set_text(("list_header", format_columns(["Metric", "Value", "Limit", "Use%", "State"], [18, 14, 14, 8, 8])))
        elif section == "services":
            if self._current_mode("services") == "list":
                self.list_header.set_text(("list_header", format_columns(["Sel", "Name", "Inst", "Status"], [3, 40, 5, 10])))
            else:
                self.list_header.set_text(("list_header", format_columns(["Instance", "Address", "Port", "Status"], [28, 24, 6, 10])))
        elif section == "nodes":
            if self._current_mode("nodes") == "list":
                self.list_header.set_text(("list_header", format_columns(["Sel", "Node", "Address", "Status", "DC"], [3, 16, 22, 10, 12])))
            else:
                self.list_header.set_text(("list_header", format_columns(["Instance", "Address", "Port", "Status"], [28, 24, 6, 10])))
        elif section == "kv":
            self.list_header.set_text(("list_header", "Name"))
        elif section == "sessions":
            self.list_header.set_text(("list_header", format_columns(["Name", "Node", "TTL", "Behavior"], [22, 20, 10, 10])))
        elif section == "tokens":
            if self._current_mode("tokens") == "links":
                self.list_header.set_text(("list_header", format_columns(["Type", "Name"], [10, 52])))
            else:
                self.list_header.set_text(("list_header", format_columns(["Accessor", "Description"], [14, 48])))
        elif section == "policies":
            self.list_header.set_text(("list_header", format_columns(["Policy", "Description"], [26, 54])))
        elif section == "roles":
            if self._current_mode("roles") == "links":
                self.list_header.set_text(("list_header", format_columns(["Type", "Name"], [10, 52])))
            else:
                self.list_header.set_text(("list_header", format_columns(["Role", "Description", "Policies"], [22, 28, 28])))
        elif section == "auth":
            self.list_header.set_text(("list_header", format_columns(["Name", "Type", "Locality"], [24, 18, 12])))
        else:
            self.list_header.set_text(("list_header", "Not implemented"))
        if not rows:
            self.content_walker.append(urwid.Text(("details_text", "No data")))
            self.content_linebox.set_title(self._section_label(section))
            return
        focus_index = 0
        selected = self.section_selected.get(section)
        for index, row in enumerate(rows):
            line, attr = self._row_to_text(section, row)
            button = PlainButton(line, on_press=self._on_content_activated, user_data=row["id"])
            button.item_id = row["id"]  # type: ignore[attr-defined]
            button.row_payload = row  # type: ignore[attr-defined]
            widget = urwid.AttrMap(button, attr, focus_map="list_item_focus")
            self.content_walker.append(widget)
            if row["id"] == selected:
                focus_index = index
        self.content_walker.set_focus(focus_index)
        self.content_linebox.set_title(self._content_title())

    def _content_title(self) -> str:
        title = self._section_label(self.current_section)
        if self.current_section in {"tokens", "roles"} and self._current_mode(self.current_section) == "links":
            source_name = self.section_context[self.current_section].get("source_name", "")
            return f"{title} links: {source_name}" if source_name else f"{title} links"
        if self.current_section in {"services", "nodes"} and self._current_mode(self.current_section) == "list":
            marked_count = len(self._marked_ids(self.current_section))
            if marked_count:
                title += f" [{marked_count} selected]"
        if self.current_section == "services" and self._current_mode("services") == "instances":
            service_names = self.section_context["services"].get("services") or []
            if service_names:
                title += f" / {len(service_names)} selected / instances"
            else:
                service_name = self.section_context["services"].get("service", "")
                title += f" / {service_name} / instances"
        if self.current_section == "nodes" and self._current_mode("nodes") == "instances":
            node_names = self.section_context["nodes"].get("nodes") or []
            if node_names:
                title += f" / {len(node_names)} selected / instances"
            else:
                node_name = self.section_context["nodes"].get("node", "")
                title += f" / {node_name} / instances"
        if self.current_section == "kv":
            title += f" /{self.kv_prefix}" if self.kv_prefix else " /"
        return title

    def _row_to_text(self, section: str, row: dict[str, Any]) -> tuple[str, str]:
        if section == "dashboard":
            return row["label"], status_attr(row.get("status", "unknown"))
        if section == "telemetry":
            line = format_columns(
                [row["name"], row.get("value_display", "-"), row.get("limit_display", "-"), row.get("usage_display", "-"), row.get("status", "-")],
                [18, 14, 14, 8, 8],
            )
            return line, status_attr(row.get("status", "unknown"))
        if section == "services":
            if self._current_mode("services") == "instances":
                line = format_columns([row["name"], row["address"], row["port"], row.get("status_count", "?/?")], [28, 24, 6, 10])
                return line, status_attr(row.get("status", "unknown"))
            marker = "*" if row.get("id") in self.bulk_selected["services"] else ""
            line = format_columns([marker, row["name"], row["instances"], row.get("status_count", "?/?")], [3, 40, 5, 10])
            return line, status_attr(row.get("status", "unknown"))
        if section == "nodes":
            if self._current_mode("nodes") == "instances":
                line = format_columns([row["name"], row["address"], row["port"], row.get("status_count", "?/?")], [28, 24, 6, 10])
                return line, status_attr(row.get("status", "unknown"))
            marker = "*" if row.get("id") in self.bulk_selected["nodes"] else ""
            line = format_columns([marker, row["name"], row["address"], row.get("status_count", "?/?"), row.get("dc", "-")], [3, 16, 22, 10, 12])
            return line, status_attr(row.get("status", "unknown"))
        if section == "kv":
            kind = row.get("kind", "key")
            if kind in {"dir", "parent"}:
                return row["name"], "kv_dir_item"
            return row["name"], "kv_key_item"
        if section == "sessions":
            line = format_columns([row["name"], row["node"], row["ttl"], row["behavior"]], [22, 20, 10, 10])
            return line, "list_item"
        if section == "tokens":
            if row.get("kind") == "acl_link":
                return format_columns([row["link_type"], row["name"]], [10, 52]), "list_item"
            return format_columns([row["accessor"], row["description"]], [14, 48]), "list_item"
        if section == "policies":
            return format_columns([row["name"], row["description"]], [26, 54]), "list_item"
        if section == "roles":
            if row.get("kind") == "acl_link":
                return format_columns([row["link_type"], row["name"]], [10, 52]), "list_item"
            return format_columns([row["name"], row["description"], row["policies"]], [22, 28, 28]), "list_item"
        if section == "auth":
            return format_columns([row["name"], row["type"], row["locality"]], [24, 18, 12]), "list_item"
        return str(row), "list_item"

    def _rebuild_details(self) -> None:
        """Rebuild the right Details pane while preserving scroll focus when possible."""
        old_focus = 0
        try:
            focus = self.details_list.get_focus()
            if focus and focus[1] is not None:
                old_focus = focus[1]
        except Exception:
            old_focus = 0
        self.details_walker[:] = []
        lines = self._current_detail_lines() or ["No details"]
        for line in lines:
            if isinstance(line, tuple) and len(line) == 2:
                self.details_walker.append(urwid.Text((line[0], normalize_display_text(line[1]))))
            else:
                self.details_walker.append(urwid.Text(("details_text", normalize_display_text(line))))
        if self.details_walker:
            self.details_walker.set_focus(min(old_focus, len(self.details_walker) - 1))
        self.details_linebox.set_title(self._details_title())

    def _details_title(self) -> str:
        item_id = self.section_selected.get(self.current_section)
        if not item_id:
            return "Details"
        if self.current_section in {"services", "nodes"} and self._current_mode(self.current_section) == "instances":
            row = self._find_row_by_id(self.current_section, item_id)
            if row:
                return f"Details: {row.get('service', row.get('name', item_id))} @ {row.get('node', '-')}"
        if self.current_section in {"tokens", "policies", "roles", "auth"}:
            row = self._find_row_by_id(self.current_section, item_id)
            if row:
                if row.get("kind") == "acl_link":
                    return f"Details: {row.get('link_type', 'link')} {row.get('name', item_id)}"
                if self.current_section == "tokens":
                    return f"Details: {row.get('accessor', item_id)}"
                if self.current_section == "auth":
                    return f"Details: {row.get('name', item_id)}"
                return f"Details: {row.get('name', item_id)}"
        if self.current_section == "telemetry":
            row = self._find_row_by_id("telemetry", item_id)
            if row:
                return f"Details: {row.get('name', item_id)}"
        return f"Details: {item_id}"

    def _current_detail_lines(self) -> list[str]:
        section = self.current_section
        selected = self.section_selected.get(section)
        if section == "dashboard":
            raw = self.section_meta.get("dashboard", {})
            return self._dashboard_detail_lines(raw) if raw else ["Loading dashboard summary..."]
        if section == "telemetry":
            row = self._find_row_by_id("telemetry", selected) if selected else None
            return self._telemetry_detail_lines(row) if row else ["Loading telemetry..."]
        if not selected:
            return ["No selection"]
        row = self._find_row_by_id(section, selected)
        if section == "services":
            if self._current_mode("services") == "instances":
                return self._instance_detail_lines(row) if row else ["No instance selected"]
            detail = self.section_details["services"].get(selected)
            return self._service_detail_lines(detail) if detail else ["Loading service details..."]
        if section == "nodes":
            if self._current_mode("nodes") == "instances":
                return self._instance_detail_lines(row) if row else ["No instance selected"]
            detail = self.section_details["nodes"].get(selected)
            return self._node_detail_lines(detail) if detail else ["Loading node details..."]
        if section == "kv":
            return self._kv_detail_lines(selected, row)
        if section == "sessions":
            return self._session_detail_lines(row) if row else ["No session selected"]
        if section in {"tokens", "policies", "roles", "auth"}:
            empty_labels = {"tokens": "token", "policies": "policy", "roles": "role", "auth": "auth method"}
            if row and row.get("kind") == "acl_link":
                return self._acl_link_detail_lines(row)
            if section == "auth":
                return self._auth_detail_lines(row) if row else ["No auth method selected"]
            return self._acl_detail_lines(section, row) if row else [f"No {empty_labels[section]} selected"]
        return ["Section not implemented"]

    def _dashboard_detail_lines(self, raw: dict[str, Any]) -> list[Any]:
        members = raw.get("members", [])
        stats = raw.get("stats", {})
        agent_state = raw.get("agent_state", {})
        lines: list[Any] = [
            f"Datacenter : {raw.get('datacenter', '-')}",
            f"Node       : {raw.get('node_name', '-')}",
            f"Version    : {raw.get('version', '-')}",
            f"Leader     : {raw.get('leader', '-')}",
            f"Peers      : {len(raw.get('peers', []))}",
            f"Members    : {len(members)}",
            "",
            (status_attr(agent_state.get("status", "unknown")), f"Agent state: {agent_state.get('status', '-')}"),
            f"Reason     : {agent_state.get('reason', '-')}",
            f"Raft state : {agent_state.get('raft_state', '-')}",
            f"Known srv  : {agent_state.get('known_servers', '-')}",
            f"Last contact: {agent_state.get('last_contact', '-')}",
            f"Agent svcs : {agent_state.get('services', '-')}",
            f"Agent checks: {agent_state.get('checks', '-')}",
            "",
            "Agent stats:",
        ]
        agent_stats = stats.get("agent", {})
        if agent_stats:
            for key in ("checks", "services", "check_monitors", "check_ttls"):
                if key in agent_stats:
                    lines.append(f"- {key}: {agent_stats[key]}")
        else:
            lines.append("- <no agent stats>")
        raft_stats = stats.get("raft", {})
        if raft_stats:
            lines.extend(["", "Raft stats:"])
            for key in ("state", "last_contact", "num_peers", "num_known_servers", "commit_index", "applied_index"):
                if key in raft_stats:
                    lines.append(f"- {key}: {raft_stats[key]}")
        serf_stats = stats.get("serf_lan", {})
        if serf_stats:
            lines.extend(["", "Serf LAN stats:"])
            for key in ("members", "failed", "left", "health_score"):
                if key in serf_stats:
                    lines.append(f"- {key}: {serf_stats[key]}")
        lines.extend(["", "Members:"])
        for member in members[:12]:
            tags = member.get("Tags", {})
            lines.append(f"- {member.get('Name', '-')}  {member.get('Addr', '-')}:{member.get('Port', '-')}  dc={tags.get('dc', '-')} role={tags.get('role', '-')}")
        if len(members) > 12:
            lines.append(f"... {len(members) - 12} more")
        return lines

    def _telemetry_detail_lines(self, row: Optional[dict[str, Any]]) -> list[Any]:
        if not row:
            return ["No telemetry metric selected"]
        lines = list(row.get("detail_lines", []))
        meta = self.section_meta.get("telemetry", {})
        metrics = meta.get("metrics", {})
        lines.extend(
            [
                "",
                f"Loaded metrics: {sum(len(items) for items in metrics.values())}",
                f"Metric families: {len(metrics)}",
                "F3 shows full Prometheus payload.",
            ]
        )
        return lines

    def _service_detail_lines(self, detail: dict[str, Any]) -> list[str]:
        lines: list[Any] = [
            f"Service: {detail['service']}",
            f"Instances: {detail['summary']['instances']}",
            f"Checks passing/warning/critical: {detail['summary']['passing']}/{detail['summary']['warning']}/{detail['summary']['critical']}",
            (status_attr(detail["summary"]["status"]), f"Status: {detail['summary']['status']}"),
            "",
            "Instances:",
        ]
        for instance in detail["instances"]:
            lines.append(
                (
                    status_attr(instance["status"]),
                    f"- {instance['node']} {instance['address']}:{instance['port']} status={instance['status']} tags={','.join(instance['tags']) or '-'}",
                )
            )
            if instance.get("meta"):
                meta_text = ", ".join(f"{key}={value}" for key, value in sorted(instance["meta"].items()))
                lines.append(f"  meta {meta_text}")
            for check in instance["checks"]:
                check_status = (check.get("Status") or "unknown").lower()
                lines.append(
                    (
                        status_attr(check_status),
                        f"  check {check.get('CheckID', '-')} status={check.get('Status', '-')} output={check.get('Output', '').strip()[:120]}",
                    )
                )
        return lines

    def _instance_detail_lines(self, row: dict[str, Any]) -> list[Any]:
        lines: list[Any] = [
            f"Service : {row.get('service', '-')}",
            f"ServiceID: {row.get('service_id', '-')}",
            f"Node    : {row.get('node', '-')}",
            f"Address : {row.get('address', '-')}:{row.get('port', '-')}",
            (status_attr(row.get("status", "unknown")), f"Status  : {row.get('status', '-')}"),
            f"Tags    : {', '.join(row.get('tags', [])) or '-'}",
            "",
            "Service META:",
        ]
        meta = row.get("meta") or {}
        if meta:
            for key, value in sorted(meta.items()):
                lines.append(f"- {key}={value}")
        else:
            lines.append("- <empty>")
        lines.extend(["", "Node META:"])
        node_meta = row.get("node_meta") or {}
        if node_meta:
            for key, value in sorted(node_meta.items()):
                lines.append(f"- {key}={value}")
        else:
            lines.append("- <empty>")
        lines.extend(["", "Checks:"])
        checks = row.get("checks") or []
        if checks:
            for check in checks:
                check_status = (check.get("Status") or "unknown").lower()
                lines.append(
                    (
                        status_attr(check_status),
                        f"- {check.get('CheckID', '-')} status={check.get('Status', '-')} {check.get('Output', '').strip()[:120]}",
                    )
                )
        else:
            lines.append("- <empty>")
        return lines

    def _node_detail_lines(self, detail: dict[str, Any]) -> list[str]:
        node = detail["node_info"]
        summary = detail["summary"]
        lines = [
            f"Node: {detail['node']}",
            f"Address: {node.get('Address', '-')}",
            f"Datacenter: {node.get('Datacenter', '-')}",
            f"Node status: {summary.get('node_status', '-')}",
            f"Services status: {summary.get('services_status', '-')}",
            "",
            "Meta:",
        ]
        meta = node.get("Meta") or {}
        if meta:
            for key, value in sorted(meta.items()):
                lines.append(f"- {key}={value}")
        else:
            lines.append("- <empty>")
        lines.extend(["", "Instances:"])
        services = detail.get("services") or {}
        if services:
            for service_name, service in sorted(services.items()):
                lines.append(f"- {service_name}: {service.get('Service')} port={service.get('Port')} tags={','.join(service.get('Tags', [])) or '-'}")
        else:
            lines.append("- <empty>")
        lines.extend(["", "Node checks:"])
        node_checks = detail.get("node_checks") or []
        if node_checks:
            for check in node_checks:
                check_status = (check.get("Status") or "unknown").lower()
                lines.append(
                    (
                        status_attr(check_status),
                        f"- {check.get('CheckID', '-')} status={check.get('Status', '-')} {check.get('Output', '').strip()[:120]}",
                    )
                )
        else:
            lines.append("- <empty>")
        lines.extend(["", "Service checks:"])
        service_checks = detail.get("service_checks") or []
        if service_checks:
            for check in service_checks:
                check_status = (check.get("Status") or "unknown").lower()
                lines.append(
                    (
                        status_attr(check_status),
                        f"- {check.get('CheckID', '-')} status={check.get('Status', '-')} {check.get('Output', '').strip()[:120]}",
                    )
                )
        else:
            lines.append("- <empty>")
        return lines

    def _kv_detail_lines(self, selected: str, row: Optional[dict[str, Any]]) -> list[str]:
        if not row:
            return ["No KV selection"]
        kind = row.get("kind")
        detail = self.section_details["kv"].get(selected)
        if kind in {"dir", "parent"}:
            target = row.get("target", "").strip("/")
            if not detail:
                return ["Loading directory preview..."]
            lines = [f"Directory: /{target}/" if target else "Directory: /", ""]
            rows = detail.get("rows", [])
            if not rows:
                lines.append("<empty>")
                return lines
            lines.append("Contents:")
            for child in rows[:40]:
                marker = "[D]" if child.get("kind") == "dir" else "[K]"
                lines.append(f"{marker} {child.get('name', '-')}")
            if len(rows) > 40:
                lines.append(f"... {len(rows) - 40} more")
            return lines
        if not detail:
            return ["Loading KV value..."]
        lines = [f"Key: {detail['key']}", ""]
        for key, value in detail["meta"].items():
            lines.append(f"{key}: {value}")
        lines.extend(["", "Preview:"])
        lines.extend(detail["preview"].splitlines() or ["<empty>"])
        return lines

    def _session_detail_lines(self, row: dict[str, Any]) -> list[str]:
        return safe_json(row["raw"]).splitlines()

    def _acl_token_refs_lines(self, token_refs: list[dict[str, str]]) -> list[str]:
        lines = [
            "Applied to the following tokens:",
            "",
            format_columns(["AccessorID", "Scope", "Source", "Description"], [14, 8, 11, 40]),
        ]
        if not token_refs:
            lines.append("<empty>")
            return lines
        for item in token_refs:
            lines.append(
                format_columns(
                    [
                        item.get("accessor", "-"),
                        item.get("scope", "-"),
                        item.get("source", "-"),
                        item.get("description", "-"),
                    ],
                    [14, 8, 11, 40],
                )
            )
        return lines

    def _acl_detail_lines(self, section: str, row: dict[str, Any]) -> list[str]:
        if section == "tokens":
            return [
                f"AccessorID  : {row.get('accessor_full', '-')}",
                f"Description : {row.get('description', '-')}",
                f"Policies    : {row.get('policies', '-')}",
                f"Roles       : {row.get('roles', '-')}",
                f"Auth Method : {row.get('auth_method', '-')}",
                f"Local       : {row.get('local', '-')}",
                f"Expiration  : {row.get('expiration', '-')}",
                "",
                "Enter opens linked roles and policies.",
                "F3 shows JSON with SecretID masked.",
                "F4 shows SecretID in a popup.",
            ]
        if section == "policies":
            raw = self.section_details["policies"].get(row.get("id", ""), row.get("raw") or {})
            detail_loaded = row.get("id", "") in self.section_details["policies"]
            rules = raw.get("Rules") or ""
            lines = [
                f"Policy      : {row.get('name', '-')}",
                f"PolicyID    : {raw.get('ID', row.get('id', '-'))}",
                f"Description : {row.get('description', '-')}",
                f"Datacenters : {row.get('datacenters', '-')}",
                f"Roles       : {row.get('roles', '-')}",
                "",
            ]
            lines.append("Rules:")
            if rules:
                lines.extend(line.expandtabs(4) for line in rules.splitlines())
            elif not detail_loaded:
                lines.append("Loading policy details...")
            else:
                lines.append("<empty>")
            lines.append("")
            lines.extend(self._acl_token_refs_lines(row.get("token_refs", [])))
            lines.extend(
                [
                    "",
                "F3 shows masked JSON.",
                ]
            )
            return lines
        if section == "roles":
            raw = row.get("raw") or {}
            lines = [
                f"Role        : {row.get('name', '-')}",
                f"RoleID      : {raw.get('ID', row.get('id', '-'))}",
                f"Description : {row.get('description', '-')}",
                f"Policies    : {row.get('policies', '-')}",
                "",
            ]
            lines.extend(self._acl_token_refs_lines(row.get("token_refs", [])))
            lines.extend(
                [
                    "",
                "Enter opens linked policies.",
                "F3 shows masked JSON.",
                ]
            )
            return lines
        return safe_json(row).splitlines()

    def _acl_link_detail_lines(self, row: dict[str, Any]) -> list[str]:
        target_section = row.get("target_section", "")
        target_name = row.get("target_name", "-")
        lines = [
            f"Link type  : {row.get('link_type', '-')}",
            f"Target     : {target_name}",
            f"Section    : {target_section}",
            "",
            "Enter jumps to the target item.",
        ]
        target_row = self._find_acl_root_row_by_name(target_section, target_name) if target_section else None
        if target_row:
            lines.extend(["", *self._acl_detail_lines(target_section, target_row)])
        return lines

    def _auth_detail_lines(self, row: dict[str, Any]) -> list[str]:
        raw = self.section_details["auth"].get(row.get("name", ""), row.get("raw") or {})
        config = raw.get("Config") or {}
        token_locality = raw.get("TokenLocality") or row.get("locality")
        if not token_locality or token_locality == "-":
            token_locality = "local"

        def append_field(lines: list[str], label: str, value: Any) -> None:
            if value is None:
                return
            if isinstance(value, list):
                if not value:
                    return
                rendered = ", ".join(str(item) for item in value)
            else:
                rendered = str(value)
                if not rendered:
                    return
            lines.append(f"{label:<29}: {rendered}")

        lines = [
            f"Name         : {row.get('name', '-')}",
            f"Type         : {row.get('type', '-')}",
            f"Display Name : {raw.get('DisplayName', row.get('display_name', '-'))}",
            f"TokenLocality: {token_locality}",
        ]
        for key in ("MaxTokenTTL", "TokenTTL", "NamespaceRules", "Description"):
            if key in raw:
                lines.append(f"{key:<13}: {raw.get(key)}")

        lines.append("")
        append_field(lines, "Bound audiences", config.get("BoundAudiences"))
        append_field(lines, "JWT validation pub keys", config.get("JWTValidationPubKeys"))
        append_field(lines, "JWKS URL", config.get("JWKSURL"))
        append_field(lines, "JWKS CA Cert", config.get("JWKSCACert"))
        append_field(lines, "CA Cert", config.get("CACert"))
        append_field(lines, "Service account JSON Web Token", config.get("ServiceAccountJWT"))
        append_field(lines, "Host", config.get("Host"))

        if isinstance(config, dict):
            handled_keys = {
                "BoundAudiences",
                "JWTValidationPubKeys",
                "JWKSURL",
                "JWKSCACert",
                "CACert",
                "ServiceAccountJWT",
                "Host",
            }
            extra_items = [(key, value) for key, value in sorted(config.items()) if key not in handled_keys]
            if extra_items:
                lines.extend(["", "Additional Config:"])
                for key, value in extra_items:
                    lines.append(f"- {key}={value}")
        elif config:
            lines.extend(["", "Config:", str(config)])

        lines.extend(["", "F3 shows full JSON."])
        return lines

    def _current_viewer_text(self) -> str:
        section = self.current_section
        selected = self.section_selected.get(section)
        if section == "dashboard":
            return safe_json(self.section_meta.get("dashboard", {}))
        if section == "telemetry":
            meta = self.section_meta.get("telemetry", {})
            return meta.get("raw_text", "Telemetry is still loading.")
        if not selected:
            return "No selection"
        if section == "services":
            if self._current_mode("services") == "instances":
                row = self._find_row_by_id("services", selected)
                return safe_json(row) if row else "No instance"
            detail = self.section_details["services"].get(selected)
            return safe_json(detail["raw"]) if detail else "Service details are still loading."
        if section == "nodes":
            if self._current_mode("nodes") == "instances":
                row = self._find_row_by_id("nodes", selected)
                return safe_json(row) if row else "No instance"
            detail = self.section_details["nodes"].get(selected)
            return safe_json(detail["raw"]) if detail else "Node details are still loading."
        if section == "kv":
            detail = self.section_details["kv"].get(selected)
            if not detail:
                return "KV entry is still loading."
            row = self._find_row_by_id("kv", selected)
            if row and row.get("kind") in {"dir", "parent"}:
                lines = self._kv_detail_lines(selected, row)
                return "\n".join(lines)
            return detail["full_text"] if detail["full_text"] else detail["preview"]
        if section == "sessions":
            row = self._find_row_by_id("sessions", selected)
            return safe_json(row["raw"]) if row else "No session"
        if section in {"tokens", "policies", "roles", "auth"}:
            row = self._find_row_by_id(section, selected)
            if not row:
                return "No ACL selection"
            if row.get("kind") == "acl_link":
                target_section = row.get("target_section", "")
                target_name = row.get("target_name", "")
                target_row = self._find_acl_root_row_by_name(target_section, target_name) if target_section else None
                return safe_json(target_row.get("raw", target_row)) if target_row else safe_json(row)
            if section == "policies":
                return safe_json(self.section_details["policies"].get(row.get("id", ""), row.get("raw", row)))
            if section == "auth":
                return safe_json(self.section_details["auth"].get(row.get("name", ""), row.get("raw", row)))
            return safe_json(row.get("raw", row))
        return f"{section} is not implemented"

    def _refresh_screen(self) -> None:
        self._update_header()
        self._refresh_status_line()
        self._rebuild_menu()
        self._rebuild_content()
        self._rebuild_details()
        self._update_panel_styles()

    def _on_menu_pressed(self, _: PlainButton, section: Optional[str]) -> None:
        if section:
            self._switch_section(section)

    def _on_content_focus_changed(self, position: Optional[int]) -> None:
        if position is None:
            return
        rows = self._filtered_rows(self.current_section)
        if not rows or position < 0 or position >= len(rows):
            return
        selected = rows[position]["id"]
        if self.section_selected.get(self.current_section) == selected:
            return
        self.section_selected[self.current_section] = selected
        self._maybe_load_current_detail(force=False)
        self._rebuild_details()

    def _on_content_activated(self, _: PlainButton, item_id: str) -> None:
        section = self.current_section
        self.section_selected[section] = item_id
        if section == "services":
            if self._current_mode("services") == "list":
                marked = self._marked_ids("services")
                if marked:
                    self._open_service_instances_many(marked)
                else:
                    self._open_service_instances(item_id)
                return
            self._refresh_screen()
            return
        if section == "nodes":
            if self._current_mode("nodes") == "list":
                marked = self._marked_ids("nodes")
                if marked:
                    self._open_node_instances_many(marked)
                else:
                    self._open_node_instances(item_id)
                return
            row = self._find_row_by_id("nodes", item_id)
            if row and row.get("service") and row.get("service") != "-":
                self._jump_to_service_filtered(row.get("service", "-"))
                return
            self._refresh_screen()
            return
        if section == "kv":
            row = self._find_row_by_id("kv", item_id)
            if not row:
                return
            kind = row.get("kind")
            target = row.get("target", "")
            if kind == "parent":
                self.kv_prefix = target
                self.refresh_current(force=True)
                return
            if kind == "dir":
                self.history.append(("kv_prefix", self.kv_prefix))
                self.kv_prefix = target
                self.refresh_current(force=True)
                return
        if section in {"tokens", "roles"}:
            row = self._find_row_by_id(section, item_id)
            if row and row.get("kind") == "acl_link":
                self._jump_to_acl_item(row.get("target_section", ""), row.get("target_name", ""))
                return
            if self._current_mode(section) == "list":
                self._open_acl_links(section, item_id)
                return
        self._maybe_load_current_detail(force=True)
        self._refresh_screen()

    def _switch_section(self, section: str, push_history: bool = True) -> None:
        if section == self.current_section:
            return
        if push_history:
            self.history.append(("section", self.current_section))
        self.current_section = section
        self._reset_section_to_root(section)
        self._set_focus_area("list")
        self.refresh_current(force=False)

    def _set_focus_area(self, area: str) -> None:
        self.current_focus = "details" if area == "details" else "list"
        self.body_pile.focus_position = 1
        self.right_columns.focus_position = 0 if self.current_focus == "list" else 1
        self._update_panel_styles()

    def _on_pane_focus_changed(self, position: int) -> None:
        self.current_focus = "list" if position == 0 else "details"
        self._update_panel_styles()

    def _go_back(self) -> None:
        if self.current_section == "services" and self._current_mode("services") == "instances":
            self._close_service_instances()
            return
        if self.current_section == "nodes" and self._current_mode("nodes") == "instances":
            self._close_node_instances()
            return
        if self.current_section in {"tokens", "roles"} and self._current_mode(self.current_section) == "links":
            self._close_acl_links(self.current_section)
            return
        if self.current_section == "kv" and self.kv_prefix:
            self.kv_prefix = self.kv_prefix.rsplit("/", 1)[0]
            self.refresh_current(force=True)
            return
        while self.history:
            kind, value = self.history.pop()
            if kind == "section":
                self.current_section = value
                self.refresh_current(force=False)
                return
            if kind == "kv_prefix":
                self.kv_prefix = value
                self.current_section = "kv"
                self.refresh_current(force=True)
                return
        self._update_status("History is empty")

    def _toggle_auto_refresh(self) -> None:
        self.auto_refresh = not self.auto_refresh
        self._update_status(f"Auto refresh {'on' if self.auto_refresh else 'off'}")

    def _show_error_popup(self, message: str, title: str = "Error") -> None:
        walker = urwid.SimpleFocusListWalker([urwid.Text(line) for line in message.splitlines() or [""]])
        viewer = urwid.ListBox(walker)
        dialog = PopupDialog(title, viewer, on_close=self._close_popup)
        self._show_popup(dialog, width=90, height=12)

    def _show_popup(self, widget: urwid.Widget, width: int = 80, height: int = 24) -> None:
        self.popup_open = True
        self.current_popup = widget
        overlay = urwid.Overlay(
            widget,
            self.frame,
            align="center",
            width=min(width, 120),
            valign="middle",
            height=min(height, 30),
        )
        self.loop.widget = overlay

    def _close_popup(self) -> None:
        if not self.popup_open:
            return
        self.popup_open = False
        self.current_popup = None
        self.loop.widget = self.frame
        self._refresh_screen()

    def _show_help(self) -> None:
        """Open the in-app help popup with current keyboard shortcuts."""
        help_lines = "\n".join(
            [
                "Tab            next section",
                "Shift+Tab      previous section",
                "Ctrl+Tab       previous section",
                "Left/Right     switch between Items and Details",
                "0..9           jump to numbered section (0=Auth, 1=Dashboard ... 9=Mesh)",
                "T              jump to Telemetry",
                "Enter          open/drill-down current item",
                "               services -> instances, nodes -> node instances",
                "               node instance -> filtered Services list",
                "               tokens/roles -> ACL links, KV dir -> open prefix",
                "Backspace      go back / close instances / parent KV prefix",
                "Ctrl+N         jump from selected instance to node",
                "Alt+S          jump from selected instance to service",
                "Space          toggle selection (services/nodes list mode)",
                "F12            select services/nodes by regex mask",
                "F1             help",
                "F2             toggle auto refresh",
                "F3             open full viewer (JSON/value/details)",
                "F4             show SecretID for selected token",
                "F5             refresh current section",
                "F6             set status filter (services/nodes/instances)",
                "F7 or /        set text filter (services: name, instances: service/address + AND/OR)",
                "F8             choose which filters to clear",
                "F9             set instance tag/meta filter (instance lists only)",
                "F11            set sort field and direction",
                "F10 / Esc      exit confirm on main screen / close popup",
                "Y / N          confirm or cancel exit in exit dialog",
                "Space          toggle checkboxes in filter popups",
            ]
        )
        viewer = urwid.ListBox(urwid.SimpleFocusListWalker([urwid.Text(line) for line in help_lines.splitlines()]))
        dialog = PopupDialog("Help", viewer, on_close=self._close_popup)
        self._show_popup(dialog, width=86, height=24)

    def _show_viewer(self) -> None:
        text = self._current_viewer_text()
        walker = urwid.SimpleFocusListWalker([urwid.Text(line) for line in text.splitlines() or [""]])
        viewer = urwid.ListBox(walker)
        dialog = PopupDialog("Viewer", viewer, on_close=self._close_popup)
        self._show_popup(dialog, width=110, height=28)

    def _show_filter_dialog(self) -> None:
        if self._is_instance_list():
            dialog = InstanceTextFilterDialog(
                initial=dict(self.instance_text_filter),
                on_submit=self._apply_instance_text_filter_from_dialog,
                on_cancel=self._close_popup,
            )
            self._show_popup(dialog, width=82, height=15)
            return
        is_services_list = self.current_section == "services" and self._current_mode("services") == "list"
        dialog = InputDialog(
            title=f"Filter: {self._section_label(self.current_section)}" if not is_services_list else "Filter: Services (name)",
            caption="filter> " if not is_services_list else "service> ",
            initial_text=self.section_filters.get(self.current_section, ""),
            on_submit=self._apply_filter_from_dialog,
            on_cancel=self._close_popup,
        )
        self._show_popup(dialog, width=70, height=8)

    def _show_bulk_selection_regex_dialog(self) -> None:
        if not self._markable_section():
            self._update_status("Regex selection is available only in services/nodes list mode")
            return
        dialog = InputDialog(
            title=f"Select by Regex: {self._section_label(self.current_section)}",
            caption="regex> ",
            initial_text="",
            on_submit=self._apply_bulk_selection_regex,
            on_cancel=self._close_popup,
        )
        self._show_popup(dialog, width=72, height=8)

    def _show_status_filter_dialog(self) -> None:
        scope = self._status_filter_scope()
        if not scope:
            self._update_status("Status filter is available only for nodes, services, and instances")
            return
        dialog = StatusFilterDialog(
            title=f"Status Filter: {self._status_filter_label(scope)}",
            selected=self.status_filters.get(scope, set()),
            on_submit=lambda selected: self._apply_status_filter_from_dialog(scope, selected),
            on_cancel=self._close_popup,
        )
        self._show_popup(dialog, width=40, height=12)

    def _show_instance_filter_dialog(self) -> None:
        if not self._is_instance_list():
            self._update_status("Instance filter is available only in instance lists")
            return
        dialog = InstanceFilterDialog(
            initial=dict(self.instance_filter),
            on_submit=self._apply_instance_filter_from_dialog,
            on_cancel=self._close_popup,
        )
        self._show_popup(dialog, width=100, height=20)

    def _show_clear_filters_dialog(self) -> None:
        dialog = ClearFiltersDialog(
            clear_text_default=True,
            clear_status_default=True,
            clear_instance_default=True,
            on_submit=self._apply_clear_filters_from_dialog,
            on_cancel=self._close_popup,
        )
        self._show_popup(dialog, width=48, height=11)

    def _show_sort_dialog(self) -> None:
        fields = self._sortable_fields()
        if not fields:
            self._update_status("No sortable fields in the current list")
            return
        option = self._current_sort_option()
        dialog = SortDialog(
            title=f"Sort: {self._content_title()}",
            fields=fields,
            current_field=str(option.get("field") or ""),
            descending=bool(option.get("descending")),
            on_submit=self._apply_sort_from_dialog,
            on_cancel=self._close_popup,
        )
        height = min(8 + len(fields), 22)
        self._show_popup(dialog, width=52, height=height)

    def _show_exit_confirm_dialog(self) -> None:
        dialog = ConfirmExitDialog(on_confirm=self._confirm_exit, on_cancel=self._close_popup)
        self._show_popup(dialog, width=36, height=9)

    def _apply_filter_from_dialog(self, value: str) -> None:
        self.section_filters[self.current_section] = value.strip()
        self._close_popup()
        self._preserve_selection(self.current_section)
        self._update_status(f"Filter updated for {self.current_section}")
        self._refresh_screen()

    def _apply_instance_text_filter_from_dialog(self, value: dict[str, Any]) -> None:
        self.instance_text_filter = {
            "instance": str(value.get("instance", "")).strip(),
            "service": str(value.get("service", "")).strip(),
            "address": str(value.get("address", "")).strip(),
            "mode": "or" if str(value.get("mode", "and")).strip().lower() == "or" else "and",
        }
        self._close_popup()
        self._preserve_selection(self.current_section)
        if self._instance_text_filter_active():
            self._update_status(f"Instance text filter updated: {self._instance_text_filter_summary()}")
        else:
            self._update_status("Instance text filter cleared")
        self._refresh_screen()

    def _apply_status_filter_from_dialog(self, scope: str, selected: set[str]) -> None:
        self.status_filters[scope] = set(selected)
        self._close_popup()
        self._preserve_selection(self.current_section)
        if selected:
            labels = self._format_status_filter_values(selected)
            self._update_status(f"Status filter updated for {self._status_filter_label(scope)}: {labels}")
        else:
            self._update_status(f"Status filter cleared for {self._status_filter_label(scope)}")
        self._refresh_screen()

    def _apply_instance_filter_from_dialog(self, value: dict[str, Any]) -> None:
        self.instance_filter = {
            "has_tags": str(value.get("has_tags", "")).strip(),
            "no_tags": str(value.get("no_tags", "")).strip(),
            "has_meta_keys": str(value.get("has_meta_keys", "")).strip(),
            "no_meta_keys": str(value.get("no_meta_keys", "")).strip(),
            "meta_key_pattern": str(value.get("meta_key_pattern", "")).strip(),
            "meta_value_pattern": str(value.get("meta_value_pattern", "")).strip(),
            "case_sensitive": bool(value.get("case_sensitive")),
            "regex_enabled": bool(value.get("regex_enabled")),
        }
        self._close_popup()
        self._preserve_selection(self.current_section)
        if self._instance_filter_active():
            self._update_status(f"Instance filter updated: {self._instance_filter_summary()}")
        else:
            self._update_status("Instance filter cleared")
        self._refresh_screen()

    def _apply_clear_filters_from_dialog(self, selected: set[str]) -> None:
        self._close_popup()
        if not selected:
            self._update_status("No filters selected to clear")
            return
        self._clear_filters(selected)

    def _apply_sort_from_dialog(self, field_name: str, descending: bool) -> None:
        view_key = self._view_sort_key()
        if field_name:
            self.sort_options[view_key] = {"field": field_name, "descending": descending}
            self._close_popup()
            self._preserve_selection(self.current_section)
            direction = "descending" if descending else "ascending"
            self._update_status(f"Sort updated: {self._sort_field_label(field_name)} ({direction})")
        else:
            self.sort_options.pop(view_key, None)
            self._close_popup()
            self._preserve_selection(self.current_section)
            self._update_status("Sort reset to default order")
        self._refresh_screen()

    def _confirm_exit(self) -> None:
        raise urwid.ExitMainLoop()

    def _clear_filters(self, selected: set[str]) -> None:
        status_scope = self._status_filter_scope()
        cleared: list[str] = []
        if "text" in selected:
            if self._is_instance_list():
                self.instance_text_filter = self._empty_instance_text_filter()
            else:
                self.section_filters[self.current_section] = ""
            cleared.append("text")
        if "status" in selected and status_scope:
            self.status_filters[status_scope] = set()
            cleared.append("status")
        if "instance" in selected:
            self.instance_filter = self._empty_instance_filter()
            cleared.append("instance")
        self._preserve_selection(self.current_section)
        if cleared:
            self._update_status(f"Cleared {', '.join(cleared)} filters for {self.current_section}")
        else:
            self._update_status(f"No matching filters to clear for {self.current_section}")
        self._refresh_screen()

    def _unhandled_input(self, key: str) -> None:
        if key == "tab":
            self._switch_section_relative(1)
            return
        if key in {"ctrl tab", "shift tab"}:
            self._switch_section_relative(-1)
            return
        digit_sections = {
            "0": "auth",
            "1": "dashboard",
            "2": "services",
            "3": "nodes",
            "4": "kv",
            "5": "sessions",
            "6": "tokens",
            "7": "policies",
            "8": "roles",
            "9": "mesh",
            "t": "telemetry",
            "T": "telemetry",
        }
        if key in digit_sections:
            self._activate_section_hotkey(digit_sections[key])
            return
        if key == "ctrl n":
            row = self._selected_instance_row()
            if row:
                self._jump_to_node(row.get("node", "-"))
            else:
                self._update_status("Ctrl+N works in instance view")
            return
        if key == "meta s":
            row = self._selected_instance_row()
            if row:
                self._jump_to_service(row.get("service", "-"))
            else:
                self._update_status("Alt+S works in instance view")
            return
        if key == "f1":
            self._show_help()
            return
        if key == "f2":
            self._toggle_auto_refresh()
            return
        if key == "f3":
            self._show_viewer()
            return
        if key == "f4":
            self._show_token_secret()
            return
        if key == "f5":
            self.refresh_current(force=True)
            return
        if key == "f6":
            self._show_status_filter_dialog()
            return
        if key == " ":
            self._toggle_current_bulk_mark()
            return
        if key in {"f12", "meta m"}:
            self._show_bulk_selection_regex_dialog()
            return
        if key in {"f7", "/"}:
            self._show_filter_dialog()
            return
        if key == "f9":
            self._show_instance_filter_dialog()
            return
        if key == "f11":
            self._show_sort_dialog()
            return
        if key == "f8":
            self._show_clear_filters_dialog()
            return
        if key == "backspace":
            self._go_back()
            return
        if key in {"f10", "esc"}:
            self._show_exit_confirm_dialog()
            return

    def _auto_refresh_tick(self, loop: urwid.MainLoop, _: Any) -> None:
        if self.auto_refresh and not self.popup_open:
            self.refresh_current(force=False)
        if self.acl_capability == "probing" and "acl_probe|" not in self.in_flight:
            self._submit_job("acl_probe", ttl=CACHE_TTL_LONG, force=False)
        loop.set_alarm_in(self.config.refresh, self._auto_refresh_tick)


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for the standalone TUI entrypoint."""
    parser = argparse.ArgumentParser(description="Read-only Consul TUI viewer")
    parser.add_argument("--addr", default=os.environ.get("CONSUL_HTTP_ADDR", DEFAULT_ADDR), help="Consul HTTP address")
    parser.add_argument("--token", default=os.environ.get("CONSUL_HTTP_TOKEN", ""), help="Consul ACL token")
    parser.add_argument("--refresh", type=float, default=DEFAULT_REFRESH, help="Auto refresh interval in seconds")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--dc", default="", help="Consul datacenter override")
    parser.add_argument("--ca-file", default="", help="CA bundle file for HTTPS")
    parser.add_argument("--cert-file", default="", help="Client certificate file for HTTPS")
    parser.add_argument("--key-file", default="", help="Client private key file for HTTPS")
    return parser


def parse_args() -> AppConfig:
    """Parse CLI arguments into AppConfig."""
    args = build_parser().parse_args()
    return AppConfig(
        addr=args.addr,
        token=args.token,
        refresh=max(1.0, args.refresh),
        timeout=max(1.0, args.timeout),
        insecure=args.insecure,
        dc=args.dc,
        ca_file=args.ca_file,
        cert_file=args.cert_file,
        key_file=args.key_file,
    )


def main() -> int:
    """Start the TUI application and return a process exit code."""
    config = parse_args()
    app = ConsulTuiApp(config)
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
