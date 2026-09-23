#!/usr/bin/env python3
from __future__ import annotations

import errno
import hashlib
import ipaddress
import lzma
import os
import re
import shutil
import struct
import tempfile
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from urllib import request as urllib_request
from urllib.parse import urlsplit

from common import (
    SESSION_MANIFEST_VERSION,
    TARGET_HOST,
    VERSION,
    encode_worker_message,
    atomic_write_json,
    current_timestamp,
    format_bytes,
    prepare_capture_temp_root,
    read_json_object,
    relative_path_parts,
    sha256_file,
    validate_windows_path_component,
    validate_windows_full_path,
    is_windows_reserved_device_name,
)

DNS_CACHE_MAX_IPS = 4096
DNS_CACHE_MAX_NAMES_PER_IP = 8
DISK_SAFETY_HEADROOM_BYTES = 64 * 1024 * 1024
UNKNOWN_STREAM_RESERVATION_BYTES = 16 * 1024 * 1024
MANIFEST_FLUSH_INTERVAL_SECONDS = 0.75
SAVING_PROGRESS_REPORT_INTERVAL_SECONDS = 0.25
SAVING_PROGRESS_DISPLAY_DELAY_SECONDS = 0.5
SAVING_PROGRESS_SPEED_WINDOW_SECONDS = 1.5
H_CACHE_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MANUAL_H_CACHE_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36"
)

class CaptureDrainRequested(RuntimeError):
    pass

def crc32c(data: bytes) -> int:
    table: list[int] = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
        table.append(crc)

    crc = 0xFFFFFFFF
    for byte in data:
        crc = table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF

def manual_h_cache_url_is_allowed(value: str) -> bool:
    try:
        target = urlsplit(value)
        port = target.port
    except ValueError:
        return False
    return (
        target.scheme.casefold() == "https"
        and (target.hostname or "").casefold() in {"origin.warframe.com", TARGET_HOST}
        and port in {None, 443}
        and target.username is None
        and target.password is None
    )

class ManualFetchRedirectHandler(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not manual_h_cache_url_is_allowed(newurl):
            raise RuntimeError(f"Manual H.Cache.bin fetch refused redirect outside the expected DE HTTPS hosts: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

class DNSHostnameCache:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.entries: dict[str, dict[str, tuple[float, float]]] = {}

    @staticmethod
    def canonical_ip(value: object) -> str | None:
        try:
            text = str(value).strip().split("%", 1)[0]
            address = ipaddress.ip_address(text)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped
            return str(address)
        except ValueError:
            return None

    @staticmethod
    def canonical_hostname(value: object) -> str | None:
        hostname = str(value).strip().rstrip(".").casefold()
        if not hostname or len(hostname) > 253:
            return None
        if DNSHostnameCache.canonical_ip(hostname) is not None:
            return None
        return hostname

    def _valid_bucket(self, ip: str, now: float) -> dict[str, tuple[float, float]]:
        bucket = self.entries.get(ip)
        if not bucket:
            return {}
        expired = [hostname for hostname, (expires, _) in bucket.items() if expires <= now]
        for hostname in expired:
            bucket.pop(hostname, None)
        if not bucket:
            self.entries.pop(ip, None)
            return {}
        return bucket

    def _trim(self, now: float) -> None:
        if len(self.entries) <= DNS_CACHE_MAX_IPS:
            return
        for ip in list(self.entries):
            self._valid_bucket(ip, now)
        if len(self.entries) <= DNS_CACHE_MAX_IPS:
            return
        ordered = sorted(
            self.entries.items(),
            key=lambda item: max((seen for _, seen in item[1].values()), default=0.0),
        )
        for ip, _ in ordered[: len(self.entries) - DNS_CACHE_MAX_IPS]:
            self.entries.pop(ip, None)

    def remember(self, ip: object, hostname: object, ttl: object) -> None:
        address = self.canonical_ip(ip)
        name = self.canonical_hostname(hostname)
        if address is None or name is None:
            return
        try:
            ttl_seconds = int(ttl)
        except (TypeError, ValueError):
            return
        if ttl_seconds <= 0:
            return
        ttl_seconds = min(ttl_seconds, 600)
        now = self.clock()
        bucket = self._valid_bucket(address, now)
        if not bucket:
            bucket = self.entries.setdefault(address, {})
        bucket[name] = (now + ttl_seconds, now)
        if len(bucket) > DNS_CACHE_MAX_NAMES_PER_IP:
            oldest = sorted(bucket, key=lambda item: bucket[item][1])
            for old_name in oldest[: len(bucket) - DNS_CACHE_MAX_NAMES_PER_IP]:
                bucket.pop(old_name, None)
        self._trim(now)

    def lookup(self, ip: object) -> tuple[str, int] | None:
        address = self.canonical_ip(ip)
        if address is None:
            return None
        bucket = self._valid_bucket(address, self.clock())
        if not bucket:
            return None
        names = sorted(bucket, key=lambda item: bucket[item][1], reverse=True)
        return names[0], len(names) - 1

def is_target_request(host: str, url: str) -> bool:
    if host.casefold() != TARGET_HOST:
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return parsed.scheme.casefold() in {"http", "https"} and (parsed.hostname or "").casefold() == TARGET_HOST

def b_cache_manifest_identity(path: str) -> tuple[str, str, str] | None:
    match = re.fullmatch(r"/0/(B\.Cache\.[^/]+\.bin)!([A-Za-z0-9]+)_(.+)", path)
    if match is None:
        return None
    return match.group(1), match.group(2), match.group(3)

def h_cache_manifest_type(path: str) -> str | None:
    match = re.fullmatch(r"/0/H\.Cache\.bin!([A-Za-z0-9]+)_.+", path)
    return match.group(1) if match is not None else None

def is_filtered_root_url(url: str) -> bool:
    try:
        path = urlsplit(url).path
    except ValueError:
        return False
    parts = [part for part in path.split("/") if part]
    return bool(parts) and parts[0].casefold() in {"lotus", "tools"}

def response_content_length(response) -> int | None:
    headers = getattr(response, "headers", {})
    try:
        length = headers.get("content-length") if hasattr(headers, "get") else None
        if length is None:
            return None
        parsed = int(length)
        return parsed if parsed >= 0 else None
    except (TypeError, ValueError):
        return None

def format_response_size(size: int | None) -> str:
    return format_bytes(size) if size is not None else "?"

def passthrough_stream(data: bytes) -> bytes:
    return data

def debug_host(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "<malformed>"
    return (parsed.hostname or "<unknown>").casefold()

def _format_host_for_url(host: str) -> str:
    text = host.strip()
    if ":" in text and not text.startswith("[") and text.count(":") > 1:
        return f"[{text}]"
    return text

def _server_address_parts(context) -> tuple[str, int] | None:
    try:
        address = getattr(context.server, "address", None) or getattr(context.server, "peername", None)
        if not address:
            return None
        return str(address[0]), int(address[1])
    except Exception:
        return None

def _server_address_label(context) -> str:
    address = _server_address_parts(context)
    if address is None:
        return "<unknown>"
    host, port = address
    return f"{_format_host_for_url(host)}:{port}"

def _http_host_from_bytes(data: bytes) -> str | None:
    header_end = data.find(b"\r\n\r\n")
    if header_end < 0:
        return None
    try:
        header_block = data[:header_end].decode("iso-8859-1")
    except UnicodeDecodeError:
        return None
    lines = header_block.split("\r\n")
    if not lines or " HTTP/" not in lines[0].upper():
        return None
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator and name.strip().casefold() == "host":
            host = value.strip()
            return host or None
    return None

def ignored_connection_label(nextlayer) -> str:
    try:
        context = nextlayer.context
        transport = str(getattr(context.client, "transport_protocol", "")).casefold()
        data = bytes(nextlayer.data_client())
    except Exception:
        return "<unknown>"

    if transport == "tcp":
        http_host = _http_host_from_bytes(data)
        if http_host:
            return f"http://{http_host}/"
        try:
            from mitmproxy.proxy.layers.tls import parse_client_hello

            client_hello = parse_client_hello(data)
            sni = getattr(client_hello, "sni", None) if client_hello is not None else None
            if sni:
                return f"https://{_format_host_for_url(str(sni).casefold())}/"
        except (ImportError, ValueError):
            pass
    elif transport == "udp":
        try:
            from mitmproxy.proxy.layers.quic import quic_parse_client_hello_from_datagrams

            client_hello = quic_parse_client_hello_from_datagrams([data])
            sni = getattr(client_hello, "sni", None) if client_hello is not None else None
            if sni:
                return f"https://{_format_host_for_url(str(sni).casefold())}/"
        except (ImportError, ValueError):
            pass
        try:
            from mitmproxy.proxy.layers.tls import dtls_parse_client_hello

            client_hello = dtls_parse_client_hello(data)
            sni = getattr(client_hello, "sni", None) if client_hello is not None else None
            if sni:
                return f"dtls://{_format_host_for_url(str(sni).casefold())}/"
        except (ImportError, ValueError):
            pass

    address = _server_address_label(context)
    if transport == "udp":
        return f"udp://{address}"
    if transport == "tcp":
        return f"tcp://{address}"
    return address

def annotate_dns_hint(label: str, hint: tuple[str, int] | None) -> str:
    if hint is None or not label.startswith(("tcp://", "udp://")):
        return label
    hostname, extra = hint
    if extra == 1:
        suffix = " +1 other"
    elif extra > 1:
        suffix = f" +{extra} others"
    else:
        suffix = ""
    return f"{label} [DNS: {hostname}{suffix}]"

def _is_ignored_passthrough_layer(layer: object) -> bool:
    return (
        layer.__class__.__name__ in {"TCPLayer", "UDPLayer"}
        and hasattr(layer, "flow")
        and getattr(layer, "flow") is None
    )

def safe_path_segment(segment: str) -> str:
    if segment == ".":
        return "%2E"
    if segment == "..":
        return "%2E%2E"
    # '%' introduces our byte escapes and '~' is reserved for synthetic empty/root markers.
    # Escaping both first keeps the mapping injective: a literal "%3A" can never collide with ':'.
    invalid = '<>:"\\|?*'
    result: list[str] = []
    for char in segment:
        if char in {"%", "~"} or char in invalid or ord(char) < 32:
            result.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
        else:
            result.append(char)

    safe = "".join(result)
    while safe.endswith((" ", ".")):
        char = safe[-1]
        safe = safe[:-1] + ("%20" if char == " " else "%2E")

    if is_windows_reserved_device_name(safe):
        safe = "%5F" + safe
    return validate_windows_path_component(safe)

def capture_relative_path(url: str) -> Path:
    try:
        path = urlsplit(url).path
    except ValueError as exc:
        raise ValueError(f"Invalid request URL: {url!r}") from exc

    if path in {"", "/"}:
        return Path("~root")

    # Strip exactly the URL's leading path separator. Additional separators are real empty
    # components and must remain distinguishable from paths where they are absent.
    body = path[1:] if path.startswith("/") else path
    raw_segments = body.split("/")
    trailing_slash = path.endswith("/")
    segments: list[str] = []
    for index, segment in enumerate(raw_segments):
        if segment:
            segments.append(safe_path_segment(segment))
        elif trailing_slash and index == len(raw_segments) - 1:
            segments.append("~index")
        else:
            segments.append("~empty")
    return Path(*segments)

def publish_no_overwrite(temporary: Path, output: Path) -> None:
    temporary.rename(output)

CAPTURE_CONFIG_METADATA_KEYS = (
    "capture_mode",
    "processes",
    "debug",
    "proxy_port",
    "upstream_proxy",
    "stop_on_exit",
    "stop_on_exit_delay",
)

def sanitize_upstream_proxy_metadata(value: object) -> str:
    raw = str(value).strip()
    keyword = raw.casefold()
    if keyword in {"auto", "direct"}:
        return keyword
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return "custom"
    scheme = parsed.scheme.casefold()
    host = parsed.hostname
    if scheme not in {"http", "https"} or not host:
        return "custom"
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return "custom"
    if port is None:
        port = 443 if scheme == "https" else 80
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"

def capture_config_metadata_snapshot(
    options: dict[str, object],
    *,
    changed_at: str | None = None,
) -> dict[str, object]:
    debug_value = options["debug"]
    if debug_value == "global":
        debug = "global"
    elif debug_value is True or debug_value == "on":
        debug = "on"
    else:
        debug = "off"
    return {
        "changed_at": changed_at or current_timestamp(),
        "capture_mode": str(options["capture_mode"]),
        "processes": [str(item) for item in options["processes"]],
        "debug": debug,
        "proxy_port": int(options["proxy_port"]),
        "upstream_proxy": sanitize_upstream_proxy_metadata(options["upstream_proxy"]),
        "stop_on_exit": bool(options["stop_on_exit"]),
        "stop_on_exit_delay": int(options["stop_on_exit_delay"]),
    }

def initial_session_manifest(
    options: dict[str, object],
    capture_directory: str,
    status: str = "starting",
    *,
    session_directory_created_by_tool: bool = True,
    session_id: str | None = None,
    warframe_version_info: dict[str, object] | None = None,
    session_naming: str = "timestamp",
    cleanup_empty_startup: bool = False,
) -> dict[str, object]:
    version_info = warframe_version_info or {}
    started_at = current_timestamp()
    capture_config = capture_config_metadata_snapshot(options, changed_at=started_at)
    return {
        "version": SESSION_MANIFEST_VERSION,
        "session_id": session_id or uuid.uuid4().hex,
        "capture_directory": capture_directory,
        "session_directory_created_by_tool": session_directory_created_by_tool,
        "application_version": VERSION,
        "started_at": started_at,
        "finished_at": None,
        "status": status,
        "cleanup_empty_startup": cleanup_empty_startup,
        "target_host": TARGET_HOST,
        "warframe_version": version_info.get("version"),
        "warframe_version_checked_at": version_info.get("checked_at"),
        "warframe_version_status": version_info.get("status"),
        "warframe_version_previous": version_info.get("previous_version"),
        "session_naming": session_naming,
        "capture_mode": capture_config["capture_mode"],
        "processes": list(capture_config["processes"]),
        "debug": capture_config["debug"],
        "proxy_port": capture_config["proxy_port"],
        "upstream_proxy": capture_config["upstream_proxy"],
        "stop_on_exit": capture_config["stop_on_exit"],
        "stop_on_exit_delay": capture_config["stop_on_exit_delay"],
        "capture_config_history": [capture_config],
        "files": {},
        "conflicts": [],
        "responses_seen": 0,
        "http_statuses": {},
        "captured_files": 0,
        "captured_bytes": 0,
        "duplicates": 0,
        "conflict_count": 0,
        "skipped_partial": 0,
        "skipped_http": 0,
        "filtered_root_paths": 0,
        "extraction_errors": 0,
        "extracted_executable": None,
        "incomplete_responses": 0,
        "capture_errors": 0,
        "disk_full_errors": 0,
        "metadata_write_errors": 0,
        "cleanup_errors": 0,
        "h_cache_validation_errors": 0,
        "recovered_files": 0,
        "update_transition_detected": False,
        "manifest_transitions": [],
        "end_reason": None,
        "failure_reason": None,
    }

def initialize_session_manifest(
    session: Path,
    options: dict[str, object],
    manifest_path: Path,
    status: str = "starting",
    *,
    session_directory_created_by_tool: bool = True,
    session_id: str | None = None,
    warframe_version_info: dict[str, object] | None = None,
    session_naming: str = "timestamp",
    cleanup_empty_startup: bool = False,
) -> Path:
    path = manifest_path.resolve()
    atomic_write_json(
        path,
        initial_session_manifest(
            options,
            session.name,
            status=status,
            session_directory_created_by_tool=session_directory_created_by_tool,
            session_id=session_id,
            warframe_version_info=warframe_version_info,
            session_naming=session_naming,
            cleanup_empty_startup=cleanup_empty_startup,
        ),
    )
    return path

def finalize_session_manifest(
    session: Path,
    status: str,
    manifest_path: Path,
    failure_reason: str | None = None,
    *,
    end_reason: str | None = None,
) -> dict[str, object]:
    path = manifest_path.resolve()
    manifest = read_json_object(path)
    manifest["status"] = status
    manifest["finished_at"] = current_timestamp()
    manifest["end_reason"] = end_reason
    manifest["failure_reason"] = failure_reason if status == "failed" else None
    atomic_write_json(path, manifest)
    return manifest

class CaptureStore:
    def __init__(
        self,
        session_root: Path,
        manifest_path: Path,
        debug: bool = False,
        drain_requested: threading.Event | None = None,
        worker_protocol_enabled: bool = False,
        manual_fetch_upstream: str | None = None,
        manual_fetch_upstream_auth: str | None = None,
    ):
        self.session_root = session_root.resolve()
        self.content_root = (self.session_root / "OpenWF" / "Content").resolve()
        self.temp_root = prepare_capture_temp_root(self.session_root.parent).resolve()
        self.conflict_root = (self.session_root / "Conflicts" / "OpenWF" / "Content").resolve()
        self.manifest_path = manifest_path.resolve()
        self.debug = debug
        self.drain_requested = drain_requested or threading.Event()
        self.worker_protocol_enabled = worker_protocol_enabled
        self.manual_fetch_upstream = manual_fetch_upstream
        self.manual_fetch_upstream_auth = manual_fetch_upstream_auth
        self.lock = threading.RLock()
        self.extraction_lock = threading.Lock()
        self.active_writers: set[CaptureWriter] = set()
        self.capture_disabled = False
        self.reserved_bytes = 0
        self._metadata_error_reported = False
        self._metadata_dirty = False
        self._metadata_changes = 0
        self._metadata_stop = threading.Event()
        self._metadata_thread: threading.Thread | None = None
        self._last_progress_report = 0.0
        self._last_saving_progress_report = 0.0
        self._saving_writer: CaptureWriter | None = None
        self._space_waiters = 0
        self._saving_progress_stop = threading.Event()
        self._saving_progress_thread: threading.Thread | None = None
        self._extracting_progress_active = False
        self._h_cache_fetch_started = False
        self._h_cache_fetch_active = 0
        self._h_cache_fetch_thread: threading.Thread | None = None
        self._h_cache_manifest_type: str | None = None
        self._h_cache_manifest_type_conflict = False
        self._h_cache_manifest_type_conflict_reported = False
        self._h_cache_content_conflict = False
        self._b_cache_manifests: dict[str, tuple[str, str, str]] = {}
        self._update_transition_reported = False

        self.manifest = read_json_object(self.manifest_path)
        if self.manifest.get("version") != SESSION_MANIFEST_VERSION:
            raise RuntimeError(
                f"Unsupported session manifest version: {self.manifest.get('version')!r}. "
                f"Expected {SESSION_MANIFEST_VERSION}."
            )
        files = self.manifest.get("files")
        conflicts = self.manifest.get("conflicts")
        if not isinstance(files, dict) or not isinstance(conflicts, list):
            raise RuntimeError("Session manifest contains invalid capture data.")
        self.files: dict[str, dict] = files
        self.conflicts: list[dict] = conflicts
        self.casefold_paths = {key.casefold(): key for key in self.files}
        self._restore_update_tracking()

    def update_capture_config_metadata(
        self,
        capture_mode: str,
        processes: list[str],
        debug: str,
        proxy_port: int,
        upstream_proxy: str,
        stop_on_exit: bool,
        stop_on_exit_delay: int,
    ) -> None:
        snapshot = capture_config_metadata_snapshot(
            {
                "capture_mode": capture_mode,
                "processes": processes,
                "debug": debug,
                "proxy_port": proxy_port,
                "upstream_proxy": upstream_proxy,
                "stop_on_exit": stop_on_exit,
                "stop_on_exit_delay": stop_on_exit_delay,
            }
        )
        with self.lock:
            history = self.manifest.get("capture_config_history")
            if not isinstance(history, list):
                history = []

            for key in CAPTURE_CONFIG_METADATA_KEYS:
                value = snapshot[key]
                self.manifest[key] = list(value) if key == "processes" else value

            previous = history[-1] if history and isinstance(history[-1], dict) else None
            previous_state = (
                tuple(
                    tuple(previous.get(key, [])) if key == "processes" else previous.get(key)
                    for key in CAPTURE_CONFIG_METADATA_KEYS
                )
                if previous is not None
                else None
            )
            new_state = tuple(
                tuple(snapshot[key]) if key == "processes" else snapshot[key]
                for key in CAPTURE_CONFIG_METADATA_KEYS
            )
            if previous_state != new_state:
                history.append(snapshot)
            self.manifest["capture_config_history"] = history

            if not self._write_manifest_locked():
                raise RuntimeError("Could not persist the updated capture configuration metadata.")

    def _restore_update_tracking(self) -> None:
        # A config reload replaces the worker, not the session. Rebuild the
        # validation baseline from durable records before accepting more traffic.
        for record in list(self.files.values()):
            path = record.get("path")
            if not isinstance(path, str):
                continue
            identity = self._observe_b_cache_manifest(path)
            manifest_type = identity[1] if identity is not None else h_cache_manifest_type(path)
            if manifest_type is not None:
                self._observe_h_cache_manifest_type(manifest_type)

        for record in self.conflicts:
            path = record.get("request_path")
            if isinstance(path, str) and h_cache_manifest_type(path) is not None:
                self._h_cache_content_conflict = True

        if self._h_cache_content_conflict:
            self._remove_generated_unmanaged()
        if self.manifest.get("update_transition_detected"):
            raise RuntimeError(
                "Cannot restart a capture session containing multiple update states; start a new session."
            )

    def log(self, message: str, *, file_suffix: str | None = None) -> None:
        if file_suffix is not None and self.worker_protocol_enabled:
            log_message = f"{message} | {file_suffix}"
            print(
                encode_worker_message(
                    "output",
                    console=log_message if self.debug else message,
                    log=log_message,
                ),
                flush=True,
            )
        else:
            print(message, flush=True)
        payload = self._saving_payload_after_output()
        if payload is not None:
            self._emit_saving_payload(payload)

    def debug_log(self, message: str) -> None:
        if self.debug:
            self.log(f"[Debug] {message}")

    def _stop_for_update_transition(self, transition: dict[str, str], warning: str, reason: str) -> bool:
        with self.lock:
            if self._update_transition_reported:
                return False
            self._update_transition_reported = True
            self.capture_disabled = True
            self.drain_requested.set()
            self.manifest["update_transition_detected"] = True
            transitions = self.manifest.setdefault("manifest_transitions", [])
            if isinstance(transitions, list):
                transitions.append(transition)
            else:
                self.manifest["manifest_transitions"] = [transition]
            self._persist_manifest(force=True)
            self._report_activity_locked()

        self._remove_generated_unmanaged()
        self.log(f"WARNING: {warning}")
        self.log(
            "ERROR: Multiple update states were detected. "
            "Ninja Capture Tool is stopping this session; start a new session for the current update."
        )
        if self.worker_protocol_enabled:
            print(encode_worker_message("fatal", reason=reason), flush=True)
        return True

    def _observe_b_cache_manifest(self, path: str) -> tuple[str, str, str] | None:
        identity = b_cache_manifest_identity(path)
        if identity is None:
            return None
        logical_name, manifest_type, manifest_hash = identity
        previous: tuple[str, str, str] | None
        with self.lock:
            key = logical_name.casefold()
            previous = self._b_cache_manifests.get(key)
            if previous is None:
                self._b_cache_manifests[key] = identity

        if previous is not None and previous[2] != manifest_hash:
            transition = {
                "name": previous[0],
                "previous_type": previous[1],
                "previous_hash": previous[2],
                "new_type": manifest_type,
                "new_hash": manifest_hash,
            }
            self._stop_for_update_transition(
                transition,
                f"{transition['name']} changed during the same capture "
                f"({transition['previous_hash']} -> {transition['new_hash']}).",
                "Multiple update states were detected because "
                f"{transition['name']} changed during the same capture.",
            )
            return None
        return identity

    def _observe_h_cache_manifest_type(self, manifest_type: str) -> None:
        conflict: tuple[str, str] | None = None
        with self.lock:
            if self._h_cache_manifest_type is None:
                self._h_cache_manifest_type = manifest_type
            elif self._h_cache_manifest_type != manifest_type:
                self._h_cache_manifest_type_conflict = True
                if not self._h_cache_manifest_type_conflict_reported:
                    self._h_cache_manifest_type_conflict_reported = True
                    conflict = self._h_cache_manifest_type, manifest_type
        if conflict is not None:
            expected, observed = conflict
            self._stop_for_update_transition(
                {
                    "name": "H.Cache.bin",
                    "previous_type": expected,
                    "new_type": observed,
                },
                f"H.Cache.bin manifest type changed during the same capture ({expected} -> {observed}).",
                "Multiple update states were detected because the H.Cache.bin manifest type "
                f"changed from {expected} to {observed} during the same capture.",
            )

    def maybe_fetch_official_h_cache(self, b_cache_path: str) -> None:
        identity = self._observe_b_cache_manifest(b_cache_path)
        if identity is None:
            return
        logical_name, manifest_type, manifest_hash = identity

        conflict: tuple[str, str] | None = None
        with self.lock:
            if self._h_cache_manifest_type is None:
                self._h_cache_manifest_type = manifest_type
            elif self._h_cache_manifest_type != manifest_type:
                self._h_cache_manifest_type_conflict = True
                if not self._h_cache_manifest_type_conflict_reported:
                    self._h_cache_manifest_type_conflict_reported = True
                    conflict = self._h_cache_manifest_type, manifest_type

            if (
                conflict is not None
                or self.capture_disabled
                or self.drain_requested.is_set()
                or self._h_cache_fetch_started
            ):
                start_fetch = False
            else:
                self._h_cache_fetch_started = True
                self._h_cache_fetch_active = 1
                self._report_activity_locked()
                start_fetch = True

        if conflict is not None:
            expected, observed = conflict
            self._stop_for_update_transition(
                {
                    "name": logical_name,
                    "previous_type": expected,
                    "new_type": observed,
                    "new_hash": manifest_hash,
                },
                f"B.Cache manifest type changed during the same capture ({expected} -> {observed}).",
                "Multiple update states were detected because the B.Cache manifest type "
                f"changed from {expected} to {observed} during the same capture.",
            )
            return
        if not start_fetch:
            return

        self.debug_log(
            "Detected B.Cache.* activity. Acquiring H.Cache.bin for this update..."
        )
        self._h_cache_fetch_thread = threading.Thread(
            target=self._fetch_official_h_cache,
            args=(manifest_type,),
            name="nct-h-cache-fetch",
            daemon=True,
        )
        try:
            self._h_cache_fetch_thread.start()
        except Exception:
            with self.lock:
                self._h_cache_fetch_started = False
                self._h_cache_fetch_active = 0
                self._report_activity_locked()
            raise

    def _remove_generated_unmanaged(self) -> None:
        relative_key = "0/UNMANAGED"
        output = self.content_root / "0" / "UNMANAGED"
        with self.lock:
            existing_key = self.casefold_paths.get(relative_key.casefold())
            record = self.files.get(existing_key) if existing_key is not None else None
            if record is None or record.get("source") != "generated":
                return
            try:
                output.unlink(missing_ok=True)
            except OSError as exc:
                self.record_capture_error("/0/UNMANAGED", exc)
                return
            self.casefold_paths.pop(relative_key.casefold(), None)
            self.files.pop(existing_key, None)
            self.manifest["captured_files"] = len(self.files)
            self.manifest["captured_bytes"] = max(
                0,
                int(self.manifest.get("captured_bytes", 0)) - int(record.get("size", 0)),
            )
            self._persist_manifest(force=True)

    def _record_h_cache_validation_error(self, relative_key: str, message: str) -> None:
        with self.lock:
            key = self.casefold_paths.get(relative_key.casefold())
            record = self.files.get(key) if key is not None else None
            if record is not None:
                previous = record.get("h_cache_validation_error")
                record["h_cache_validated"] = False
                record["h_cache_validation_error"] = message
                if previous != message:
                    self.manifest["h_cache_validation_errors"] = int(
                        self.manifest.get("h_cache_validation_errors", 0)
                    ) + 1
                self._persist_manifest(force=True)
        self._remove_generated_unmanaged()
        self.log(f"WARNING: {message} UNMANAGED was not created.")

    @staticmethod
    def _h_cache_file_has_sane_structure(path: Path) -> bool:
        try:
            raw = path.read_bytes()
        except OSError:
            return False

        # Validate the SHCC container without interpreting or decompressing its
        # payload. The chunk type is intentionally not restricted so a future
        # compression-codec change does not by itself make a valid H.Cache.bin
        # unusable to Ninja Capture Tool.
        if len(raw) < 40 or len(raw) > H_CACHE_MAX_RESPONSE_BYTES:
            return False
        if raw[:8] != b"SHCC\x1f\x00\x00\x00":
            return False

        decompressed_size, compressed_size = struct.unpack_from("<II", raw, 9)
        if decompressed_size == 0 or compressed_size == 0:
            return False
        payload_end = 17 + compressed_size
        if payload_end + 23 != len(raw):
            return False
        if raw[payload_end:-4] != (
            b"\x00\xff\xff\xff\xff"
            b"\x00\x00\x00\x00\x00"
            b"\xff\xff\xff\xff"
            b"\x00\x00\x00\x00\x52"
        ):
            return False
        expected_crc = struct.unpack_from("<I", raw, len(raw) - 4)[0]
        return crc32c(raw[:-4]) == expected_crc

    def _publish_validated_unmanaged(self, manifest_type: str) -> bool:
        with self.lock:
            if (
                self._h_cache_manifest_type_conflict
                or self._h_cache_content_conflict
                or self.capture_disabled
                or self.drain_requested.is_set()
                or bool(self.manifest.get("update_transition_detected"))
                or not self._b_cache_manifests
                or self._h_cache_manifest_type != manifest_type
            ):
                return False
            existing_key = self.casefold_paths.get("0/unmanaged")
            existing_record = self.files.get(existing_key) if existing_key is not None else None
            unmanaged_output = self.content_root / "0" / "UNMANAGED"
            if (
                existing_record is not None
                and existing_record.get("source") == "generated"
                and unmanaged_output.is_file()
                and unmanaged_output.stat().st_size == 0
            ):
                return True
            return self._save_generated_empty_file(
                "0/UNMANAGED",
                {"h_cache_manifest_type": manifest_type},
            )

    def _validate_h_cache_for_unmanaged(self, filename: str) -> bool:
        relative_key = f"0/{filename}"
        manifest_type = h_cache_manifest_type(f"/0/{filename}")
        if manifest_type is None:
            self._record_h_cache_validation_error(
                relative_key,
                "H.Cache.bin has an invalid manifest filename.",
            )
            return False

        with self.lock:
            key = self.casefold_paths.get(relative_key.casefold())
            record = self.files.get(key) if key is not None else None
            path = self.content_root / relative_key
            expected_type = self._h_cache_manifest_type

        if record is None or not path.is_file():
            return False
        if record.get("status") not in {200, "200"}:
            self._record_h_cache_validation_error(
                relative_key,
                "H.Cache.bin did not come from a successful HTTP 200 response.",
            )
            return False
        if expected_type is not None and expected_type != manifest_type:
            self._record_h_cache_validation_error(
                relative_key,
                f"H.Cache.bin manifest type {manifest_type} does not match the captured B.Cache manifest type {expected_type}.",
            )
            return False
        if not self._h_cache_file_has_sane_structure(path):
            self._record_h_cache_validation_error(
                relative_key,
                "H.Cache.bin failed SHCC container validation.",
            )
            return False

        with self.lock:
            key = self.casefold_paths.get(relative_key.casefold())
            record = self.files.get(key) if key is not None else None
            if record is None:
                return False
            record["h_cache_validated"] = True
            record["h_cache_validation_method"] = "shcc_container_crc32c"
            record.pop("h_cache_validation_error", None)
            self._persist_manifest(force=True)

        return self._publish_validated_unmanaged(manifest_type)

    def _manual_fetch_opener(self):
        redirect_handler = ManualFetchRedirectHandler()
        if self.manual_fetch_upstream is None:
            return urllib_request.build_opener(urllib_request.ProxyHandler({}), redirect_handler)

        proxy_handler = urllib_request.ProxyHandler(
            {"http": self.manual_fetch_upstream, "https": self.manual_fetch_upstream}
        )
        if self.manual_fetch_upstream_auth is None:
            return urllib_request.build_opener(proxy_handler, redirect_handler)

        username, separator, password = self.manual_fetch_upstream_auth.partition(":")
        if not separator:
            return urllib_request.build_opener(proxy_handler, redirect_handler)
        password_manager = urllib_request.HTTPPasswordMgrWithDefaultRealm()
        password_manager.add_password(None, self.manual_fetch_upstream, username, password)
        return urllib_request.build_opener(
            proxy_handler,
            urllib_request.ProxyBasicAuthHandler(password_manager),
            redirect_handler,
        )

    def _fetch_official_h_cache_once(self, manifest_type: str) -> None:
        # Prefer an H.Cache.bin already captured in this session. If none was
        # observed, fetch DE's current official response after B.Cache activity
        # establishes that this is an update capture.
        filename = f"H.Cache.bin!{manifest_type}_---------------------w"
        relative_key = f"0/{filename}"
        output = self.content_root / "0" / filename
        with self.lock:
            existing_key = self.casefold_paths.get(relative_key.casefold())
            existing_record = self.files.get(existing_key) if existing_key is not None else None
            direct_exists = (
                existing_record is not None
                and output.is_file()
                and not self._h_cache_content_conflict
            )
        if direct_exists:
            self._validate_h_cache_for_unmanaged(filename)
            return

        source_url = f"https://origin.warframe.com/origin/00000000/0/{filename}"
        capture_url = f"https://{TARGET_HOST}/0/{filename}"
        writer: CaptureWriter | None = None
        try:
            opener = self._manual_fetch_opener()
            request = urllib_request.Request(
                source_url,
                headers={
                    "Accept-Encoding": "identity",
                    "User-Agent": MANUAL_H_CACHE_USER_AGENT,
                },
            )
            with opener.open(request, timeout=10) as response:
                status = int(getattr(response, "status", 0) or response.getcode() or 0)
                if status != 200:
                    raise RuntimeError(f"HTTP {status}")
                final_url = str(getattr(response, "geturl", lambda: source_url)())
                if not manual_h_cache_url_is_allowed(final_url):
                    raise RuntimeError(f"H.Cache.bin response came from an unexpected URL: {final_url}")
                expected_size = response_content_length(response)
                if expected_size is not None and expected_size <= 4:
                    raise RuntimeError("response is not a valid SHCC H.Cache.bin file")
                if expected_size is not None and expected_size > H_CACHE_MAX_RESPONSE_BYTES:
                    raise RuntimeError(
                        f"H.Cache.bin response is unexpectedly large ({format_bytes(expected_size)}; "
                        f"limit {format_bytes(H_CACHE_MAX_RESPONSE_BYTES)})"
                    )
                writer = self.begin(
                    capture_url,
                    status,
                    expected_size,
                    record_metadata={"source": "manual", "source_url": source_url},
                )
                prefix = response.read(5)
                if len(prefix) <= 4 or prefix[:4] != b"SHCC":
                    raise RuntimeError("response is not a valid SHCC H.Cache.bin file")
                received = len(prefix)
                writer.feed(prefix)
                while chunk := response.read(64 * 1024):
                    if self.drain_requested.is_set():
                        raise CaptureDrainRequested("Capture is draining.")
                    received += len(chunk)
                    if received > H_CACHE_MAX_RESPONSE_BYTES:
                        raise RuntimeError(
                            f"H.Cache.bin response exceeded the safe size limit of "
                            f"{format_bytes(H_CACHE_MAX_RESPONSE_BYTES)}"
                        )
                    writer.feed(chunk)
                    if writer.failed:
                        return
                writer.feed(b"")
                if writer.failed:
                    return
                if not writer.output.is_file():
                    raise RuntimeError("H.Cache.bin could not be published to the capture output")

            with self.lock:
                key = self.casefold_paths.get(relative_key.casefold())
                record = self.files.get(key) if key is not None else None
                if writer.publish_result == "conflict":
                    record = None
                if (
                    self._h_cache_manifest_type_conflict
                    or self._h_cache_content_conflict
                    or self.capture_disabled
                    or self.drain_requested.is_set()
                    or bool(self.manifest.get("update_transition_detected"))
                    or record is None
                ):
                    return
        except Exception:
            if writer is not None and not writer.finished and not writer.failed:
                writer.abort()
            raise

    def _fetch_official_h_cache(self, manifest_type: str) -> None:
        filename = f"H.Cache.bin!{manifest_type}_---------------------w"
        last_error: Exception | None = None
        try:
            for attempt in range(2):
                if self.drain_requested.is_set():
                    return
                try:
                    self._fetch_official_h_cache_once(manifest_type)
                    return
                except CaptureDrainRequested:
                    return
                except Exception as exc:
                    last_error = exc
                    if attempt == 0 and not self.drain_requested.wait(1.0):
                        continue
                    break
            if last_error is not None:
                self.record_capture_error(
                    f"/0/{filename}",
                    last_error,
                    file_suffix="Source: Fetched by Ninja Capture Tool",
                )
        finally:
            with self.lock:
                self._h_cache_fetch_active = 0
                self._report_activity_locked()

    def _report_activity_locked(self) -> None:
        if not self.worker_protocol_enabled:
            return
        active = len(self.active_writers) + self._h_cache_fetch_active
        print(encode_worker_message("activity", active=active), flush=True)
        if active == 0 and self.drain_requested.is_set():
            print(encode_worker_message("drained"), flush=True)

    def report_activity(self) -> None:
        with self.lock:
            self._report_activity_locked()

    @staticmethod
    def _record_speed_sample(writer: "CaptureWriter", now: float) -> None:
        samples = writer.progress_speed_samples
        samples.append((now, writer.size))
        cutoff = now - SAVING_PROGRESS_SPEED_WINDOW_SECONDS
        # Keep one sample immediately before the window when possible so the
        # speed covers roughly the whole rolling interval instead of one bursty chunk.
        while len(samples) > 2 and samples[1][0] <= cutoff:
            samples.popleft()

    @staticmethod
    def _saving_payload(writer: "CaptureWriter", now: float) -> dict[str, object]:
        sample_time, sample_size = writer.progress_speed_samples[0]
        elapsed = max(1e-6, now - sample_time)
        return {
            "received": writer.size,
            "expected": writer.expected_size,
            "speed_bps": max(0, int((writer.size - sample_size) / elapsed)),
            "path": writer.url_path,
        }

    def _oldest_displayable_writer_locked(self, now: float) -> "CaptureWriter | None":
        eligible = (
            writer
            for writer in self.active_writers
            if writer.size > 0
            and not writer.finished
            and not writer.failed
            and not writer.waiting_for_space
            and now - writer.started_at >= SAVING_PROGRESS_DISPLAY_DELAY_SECONDS
        )
        return min(eligible, key=lambda writer: writer.started_at, default=None)

    @staticmethod
    def _emit_saving_payload(payload: dict[str, object]) -> None:
        print(encode_worker_message("progress", action="saving", **payload), flush=True)

    @staticmethod
    def _emit_waiting_payload(required: int, available: int, path: str) -> None:
        payload = {
            "required": max(0, required),
            "available": max(0, available),
            "path": path,
        }
        print(encode_worker_message("waiting", **payload), flush=True)

    @staticmethod
    def _clear_transient_progress() -> None:
        print(encode_worker_message("progress_clear"), flush=True)

    def _saving_payload_after_output(self) -> dict[str, object] | None:
        if not self.worker_protocol_enabled:
            return None
        with self.lock:
            if self._extracting_progress_active or self._space_waiters:
                return None
            if not any(
                writer.size > 0 and not writer.finished and not writer.failed
                for writer in self.active_writers
            ):
                return None
            now = time.monotonic()
            if (
                self._saving_writer is None
                or self._saving_writer not in self.active_writers
                or self._saving_writer.finished
                or self._saving_writer.failed
                or self._saving_writer.waiting_for_space
            ):
                self._saving_writer = self._oldest_displayable_writer_locked(now)
            if self._saving_writer is None:
                return None
            self._record_speed_sample(self._saving_writer, now)
            self._last_saving_progress_report = now
            return self._saving_payload(self._saving_writer, now)

    def report_progress(self, writer: "CaptureWriter") -> None:
        if not self.worker_protocol_enabled:
            return
        now = time.monotonic()
        report_activity = False
        saving_payload: dict[str, object] | None = None
        with self.lock:
            self._record_speed_sample(writer, now)
            if now - self._last_progress_report >= 1.0:
                self._last_progress_report = now
                report_activity = True
            if not self._extracting_progress_active and not self._space_waiters and now - writer.started_at >= SAVING_PROGRESS_DISPLAY_DELAY_SECONDS:
                if self._saving_writer is None or self._saving_writer not in self.active_writers:
                    self._saving_writer = self._oldest_displayable_writer_locked(now)
                    self._last_saving_progress_report = 0.0
                    if self._saving_writer is not None:
                        if self._saving_writer is not writer:
                            self._record_speed_sample(self._saving_writer, now)
                        self._last_saving_progress_report = now
                        saving_payload = self._saving_payload(self._saving_writer, now)
                elif (
                    writer is self._saving_writer
                    and now - self._last_saving_progress_report >= SAVING_PROGRESS_REPORT_INTERVAL_SECONDS
                ):
                    self._last_saving_progress_report = now
                    saving_payload = self._saving_payload(writer, now)
        if report_activity:
            print(encode_worker_message("activity"), flush=True)
        if saving_payload is not None:
            self._emit_saving_payload(saving_payload)

    def start_saving_progress_heartbeat(self) -> None:
        if not self.worker_protocol_enabled or self._saving_progress_thread is not None:
            return
        self._saving_progress_stop.clear()
        self._saving_progress_thread = threading.Thread(
            target=self._saving_progress_loop,
            name="nct-saving-progress",
            daemon=True,
        )
        self._saving_progress_thread.start()

    def _saving_progress_loop(self) -> None:
        while not self._saving_progress_stop.wait(SAVING_PROGRESS_REPORT_INTERVAL_SECONDS):
            payload: dict[str, object] | None = None
            now = time.monotonic()
            with self.lock:
                if self._extracting_progress_active or self._space_waiters:
                    continue
                if (
                    self._saving_writer is None
                    or self._saving_writer not in self.active_writers
                    or self._saving_writer.finished
                    or self._saving_writer.failed
                    or self._saving_writer.waiting_for_space
                ):
                    self._saving_writer = self._oldest_displayable_writer_locked(now)
                writer = self._saving_writer
                if writer is None or now - writer.started_at < SAVING_PROGRESS_DISPLAY_DELAY_SECONDS:
                    continue
                if now - self._last_saving_progress_report < SAVING_PROGRESS_REPORT_INTERVAL_SECONDS:
                    continue
                self._record_speed_sample(writer, now)
                self._last_saving_progress_report = now
                payload = self._saving_payload(writer, now)
            if payload is not None:
                self._emit_saving_payload(payload)

    def close_saving_progress_heartbeat(self) -> None:
        self._saving_progress_stop.set()
        thread = self._saving_progress_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        self._saving_progress_thread = None

    def request_drain(self) -> None:
        with self.lock:
            self.drain_requested.set()
            self._report_activity_locked()

    def accepting_captures(self) -> bool:
        return not self.drain_requested.is_set()

    def _write_manifest_locked(self) -> bool:
        try:
            atomic_write_json(self.manifest_path, self.manifest)
        except OSError as exc:
            self._metadata_dirty = True
            self.manifest["metadata_write_errors"] = int(self.manifest.get("metadata_write_errors", 0)) + 1
            if exc.errno == errno.ENOSPC and not self._metadata_error_reported:
                self.manifest["disk_full_errors"] = int(self.manifest.get("disk_full_errors", 0)) + 1
            if not self._metadata_error_reported:
                self._metadata_error_reported = True
                self.log(f"ERROR: Could not update session metadata: {exc}")
                if exc.errno == errno.ENOSPC:
                    self.log("WARNING: The output drive is full; session information will be saved when space is available.")
            return False
        self._metadata_dirty = False
        self._metadata_changes = 0
        if self._metadata_error_reported:
            self._metadata_error_reported = False
            self.log("Session metadata writing recovered.")
        return True

    def _persist_manifest(self, *, force: bool = False) -> bool:
        self._metadata_dirty = True
        self._metadata_changes += 1
        if (
            force
            or self._metadata_thread is None
            or self._metadata_changes >= 32
        ):
            return self._write_manifest_locked()
        return True

    def start_metadata_flusher(self) -> None:
        if self._metadata_thread is not None:
            return
        self._metadata_stop.clear()
        self._metadata_thread = threading.Thread(
            target=self._metadata_flush_loop,
            name="nct-session-metadata",
            daemon=True,
        )
        self._metadata_thread.start()

    def _metadata_flush_loop(self) -> None:
        while not self._metadata_stop.wait(MANIFEST_FLUSH_INTERVAL_SECONDS):
            with self.lock:
                if self._metadata_dirty:
                    self._write_manifest_locked()

    def flush_manifest(self) -> bool:
        with self.lock:
            if not self._metadata_dirty:
                return True
            return self._write_manifest_locked()

    def close_metadata(self) -> bool:
        self._metadata_stop.set()
        thread = self._metadata_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._metadata_thread = None
        return self.flush_manifest()

    def mark_running(self) -> None:
        with self.lock:
            if self.manifest.get("status") == "pending_rotation":
                self.manifest["started_at"] = current_timestamp()
            self.manifest["status"] = "running"
            if not self._persist_manifest(force=True):
                raise RuntimeError("Could not record the running capture state in session metadata.")
            self._report_activity_locked()

    def record_target_response(self, status: int) -> None:
        with self.lock:
            self.manifest["responses_seen"] = int(self.manifest.get("responses_seen", 0)) + 1
            statuses = self.manifest.setdefault("http_statuses", {})
            if not isinstance(statuses, dict):
                statuses = {}
                self.manifest["http_statuses"] = statuses
            key = str(status)
            statuses[key] = int(statuses.get(key, 0)) + 1
            self._persist_manifest()

    def record_skipped_partial(self, path: str, size: int | None) -> None:
        with self.lock:
            self.manifest["skipped_partial"] = int(self.manifest.get("skipped_partial", 0)) + 1
            self._persist_manifest()
        self.log(f"[Skipped] {format_response_size(size)} | 206 | {path} | partial response")

    def record_skipped_http(self) -> None:
        with self.lock:
            self.manifest["skipped_http"] = int(self.manifest.get("skipped_http", 0)) + 1
            self._persist_manifest()

    def record_filtered_root_path(self, path: str) -> None:
        with self.lock:
            self.manifest["filtered_root_paths"] = int(self.manifest.get("filtered_root_paths", 0)) + 1
            self._persist_manifest()
        self.log(f"[Filtered] {path}")

    def record_extraction_error(self, message: str, exc: BaseException | None = None) -> None:
        is_disk_full = isinstance(exc, OSError) and exc.errno == errno.ENOSPC
        with self.lock:
            self.manifest["extraction_errors"] = int(self.manifest.get("extraction_errors", 0)) + 1
            if is_disk_full:
                self.manifest["disk_full_errors"] = int(self.manifest.get("disk_full_errors", 0)) + 1
            self._persist_manifest(force=True)
        self.log(f"ERROR: {message}")
        if is_disk_full:
            self.log("WARNING: Saving failed because the output drive is full; future captures will wait for space and resume automatically.")

    def record_incomplete(
        self,
        path: str,
        expected: int | None,
        received: int,
        reason: str | None = None,
        *,
        file_suffix: str | None = None,
    ) -> None:
        with self.lock:
            self.manifest["incomplete_responses"] = int(self.manifest.get("incomplete_responses", 0)) + 1
            self._persist_manifest(force=True)
        if reason:
            self.log(
                f"ERROR: Incomplete response for {path}: {reason} ({format_bytes(received)} received).",
                file_suffix=file_suffix,
            )
        elif expected is not None:
            self.log(
                f"ERROR: Incomplete response for {path}: expected {expected} bytes, received {received}.",
                file_suffix=file_suffix,
            )
        else:
            self.log(
                f"ERROR: Incomplete response for {path} after {format_bytes(received)}.",
                file_suffix=file_suffix,
            )

    def record_capture_error(
        self,
        path: str,
        exc: BaseException,
        *,
        file_suffix: str | None = None,
    ) -> None:
        is_disk_full = isinstance(exc, OSError) and exc.errno == errno.ENOSPC
        with self.lock:
            self.manifest["capture_errors"] = int(self.manifest.get("capture_errors", 0)) + 1
            if is_disk_full:
                self.manifest["disk_full_errors"] = int(self.manifest.get("disk_full_errors", 0)) + 1
            self._persist_manifest(force=True)
        if is_disk_full:
            self.log(
                f"ERROR: Output drive reported a disk-full error while capturing {path}.",
                file_suffix=file_suffix,
            )
            self.log("WARNING: Later captures remain enabled and will wait for free space instead of switching to passthrough.")
        else:
            self.log(f"ERROR: Capture failed for {path}: {exc}", file_suffix=file_suffix)

    def _begin_writer(
        self,
        relative: Path,
        display_path: str,
        status: int | str | None,
        expected_size: int | None,
        record_metadata: dict[str, object] | None = None,
        *,
        process_name: str | None = None,
        process_pid: int | None = None,
        log_source: str | None = None,
    ) -> "CaptureWriter":
        output_candidate = self.content_root / relative
        temporary_candidate = self.temp_root / relative
        validate_windows_full_path(output_candidate, "Capture output path")
        validate_windows_full_path(temporary_candidate, "Capture temporary path")
        output = output_candidate.resolve()
        temporary_base = temporary_candidate.resolve()
        if not output.is_relative_to(self.content_root) or not temporary_base.is_relative_to(self.temp_root):
            raise RuntimeError(f"Unsafe capture path generated: {display_path}")

        reserved = 0
        if expected_size is not None and expected_size > 0:
            reserved = self.reserve_known_size(expected_size, display_path)
        else:
            with self.lock:
                if self.drain_requested.is_set():
                    raise CaptureDrainRequested
                if self.capture_disabled:
                    raise RuntimeError("Capture is disabled for this session after an earlier output failure.")

        try:
            temporary = temporary_base.parent / f".{uuid.uuid4().hex}.part"
            validate_windows_full_path(temporary, "Capture temporary file path")
            while True:
                try:
                    temporary_base.parent.mkdir(parents=True, exist_ok=True)
                    writer = CaptureWriter(
                        self,
                        relative,
                        output,
                        temporary,
                        display_path,
                        status,
                        expected_size,
                        reserved,
                        record_metadata,
                        process_name=process_name,
                        process_pid=process_pid,
                        log_source=log_source,
                    )
                    break
                except OSError as exc:
                    if exc.errno != errno.ENOSPC:
                        raise
                    self._wait_after_disk_full(1, display_path)
        except BaseException:
            if reserved:
                with self.lock:
                    self.reserved_bytes = max(0, self.reserved_bytes - reserved)
            raise

        with self.lock:
            if self.drain_requested.is_set():
                try:
                    writer.close()
                    writer.temporary.unlink(missing_ok=True)
                finally:
                    if writer.reserved_remaining:
                        self.reserved_bytes = max(0, self.reserved_bytes - writer.reserved_remaining)
                        writer.reserved_remaining = 0
                raise CaptureDrainRequested
            self.active_writers.add(writer)
            self._report_activity_locked()
        return writer

    def begin(
        self,
        url: str,
        status: int | str,
        expected_size: int | None = None,
        *,
        record_metadata: dict[str, object] | None = None,
        process_name: str | None = None,
        process_pid: int | None = None,
    ) -> "CaptureWriter":
        relative = capture_relative_path(url)
        try:
            parsed_url = urlsplit(url)
        except ValueError as exc:
            raise ValueError(f"Invalid request URL: {url!r}") from exc
        return self._begin_writer(
            relative,
            parsed_url.path or "/",
            status,
            expected_size,
            record_metadata,
            process_name=process_name,
            process_pid=process_pid,
        )

    def _save_generated_empty_file(
        self,
        relative_path: str,
        metadata: dict[str, object] | None = None,
    ) -> bool:
        relative = Path(*relative_path_parts(relative_path))
        writer = self._begin_writer(
            relative,
            f"/{relative.as_posix()}",
            None,
            0,
            log_source="Generated by Ninja Capture Tool",
        )
        writer.display_status = "OK"
        writer.feed(b"")
        if writer.publish_result not in {"saved", "duplicate"}:
            return False

        with self.lock:
            key = self.casefold_paths.get(relative.as_posix().casefold())
            record = self.files.get(key) if key is not None else None
            if record is None:
                return False
            if writer.publish_result == "saved" or record.get("source") == "generated":
                record["source"] = "generated"
                if metadata:
                    record.update(metadata)
                self._persist_manifest(force=True)
        return True

    def unregister(self, writer: "CaptureWriter") -> None:
        handoff_payload: dict[str, object] | None = None
        with self.lock:
            if writer in self.active_writers:
                self.active_writers.discard(writer)
                if writer is self._saving_writer:
                    self._saving_writer = None
                    self._last_saving_progress_report = 0.0
                    if self.active_writers and self.worker_protocol_enabled:
                        now = time.monotonic()
                        self._saving_writer = self._oldest_displayable_writer_locked(now)
                        if self._saving_writer is not None:
                            self._record_speed_sample(self._saving_writer, now)
                            self._last_saving_progress_report = now
                            handoff_payload = self._saving_payload(self._saving_writer, now)
                if writer.reserved_remaining:
                    self.reserved_bytes = max(0, self.reserved_bytes - writer.reserved_remaining)
                    writer.reserved_remaining = 0
                self._report_activity_locked()
        if handoff_payload is not None:
            self._emit_saving_payload(handoff_payload)

    def consume_reservation(self, writer: "CaptureWriter", written: int) -> None:
        if written <= 0 or writer.reserved_remaining <= 0:
            return
        with self.lock:
            consumed = min(written, writer.reserved_remaining)
            writer.reserved_remaining -= consumed
            self.reserved_bytes = max(0, self.reserved_bytes - consumed)

    def _wait_for_reservable_space(
        self,
        needed: int,
        path: str,
        reserve,
        *,
        writer: "CaptureWriter | None" = None,
    ) -> int:
        waiting = False
        last_report = 0.0
        try:
            while True:
                with self.lock:
                    if self.drain_requested.is_set():
                        raise CaptureDrainRequested
                    if self.capture_disabled:
                        raise RuntimeError("Capture is disabled for this session after an earlier output failure.")
                    available = max(
                        0,
                        shutil.disk_usage(self.session_root).free
                        - self.reserved_bytes
                        - DISK_SAFETY_HEADROOM_BYTES,
                    )
                    result = reserve(available)
                    if result is not None:
                        return result
                    if not waiting:
                        self._space_waiters += 1
                    if writer is not None:
                        writer.waiting_for_space = True
                if self.worker_protocol_enabled:
                    now = time.monotonic()
                    if not waiting or now - last_report >= 0.25:
                        self._emit_waiting_payload(needed, available, path)
                        last_report = now
                waiting = True
                time.sleep(0.25)
        finally:
            if waiting or writer is not None:
                with self.lock:
                    if waiting:
                        self._space_waiters = max(0, self._space_waiters - 1)
                    if writer is not None:
                        writer.waiting_for_space = False
            if waiting and self.worker_protocol_enabled:
                self._clear_transient_progress()

    def _wait_after_disk_full(
        self,
        needed: int,
        path: str,
        *,
        writer: "CaptureWriter | None" = None,
    ) -> None:
        required = max(1, needed)
        waiting = False
        last_report = 0.0
        with self.lock:
            self.manifest["disk_full_errors"] = int(self.manifest.get("disk_full_errors", 0)) + 1
            self._metadata_dirty = True
            self._metadata_changes += 1
        try:
            while True:
                with self.lock:
                    if self.drain_requested.is_set():
                        raise CaptureDrainRequested
                    free = shutil.disk_usage(self.session_root).free
                    available = max(0, free - DISK_SAFETY_HEADROOM_BYTES)
                    if available >= required:
                        break
                    if not waiting:
                        self._space_waiters += 1
                    if writer is not None:
                        writer.waiting_for_space = True
                if self.worker_protocol_enabled:
                    now = time.monotonic()
                    if not waiting or now - last_report >= 0.25:
                        self._emit_waiting_payload(required, available, path)
                        last_report = now
                waiting = True
                time.sleep(0.25)
        finally:
            if waiting or writer is not None:
                with self.lock:
                    if waiting:
                        self._space_waiters = max(0, self._space_waiters - 1)
                    if writer is not None:
                        writer.waiting_for_space = False
            if waiting and self.worker_protocol_enabled:
                self._clear_transient_progress()

    def write_all_with_disk_wait(
        self,
        file,
        data: bytes,
        path: str,
        *,
        writer: "CaptureWriter | None" = None,
    ) -> None:
        view = memoryview(data)
        written = 0
        while written < len(view):
            try:
                count = file.write(view[written:])
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                self._wait_after_disk_full(len(view) - written, path, writer=writer)
                continue
            if count is None or count <= 0:
                raise OSError("File write returned no progress.")
            written += count

    def publish_with_disk_wait(self, writer: "CaptureWriter") -> str:
        while True:
            try:
                return self.publish(writer)
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                self._wait_after_disk_full(1, writer.url_path, writer=writer)

    def reserve_known_size(self, required: int, path: str) -> int:
        if required <= 0:
            return 0

        def reserve(available: int) -> int | None:
            if self.drain_requested.is_set():
                raise CaptureDrainRequested
            if required > available:
                return None
            self.reserved_bytes += required
            return required

        return self._wait_for_reservable_space(required, path, reserve)

    def reserve_stream_budget(self, writer: "CaptureWriter", minimum_needed: int) -> int:
        if minimum_needed <= writer.reserved_remaining:
            return writer.reserved_remaining

        def reserve(available: int) -> int | None:
            needed = minimum_needed - writer.reserved_remaining
            if needed > available:
                return None
            target = max(UNKNOWN_STREAM_RESERVATION_BYTES, minimum_needed)
            additional = min(available, target - writer.reserved_remaining)
            writer.reserved_remaining += additional
            self.reserved_bytes += additional
            return writer.reserved_remaining

        needed = max(0, minimum_needed - writer.reserved_remaining)
        return self._wait_for_reservable_space(needed, writer.url_path, reserve, writer=writer)

    def reserve_auxiliary_budget(self, reserved_remaining: int, minimum_needed: int, path: str) -> int:
        if minimum_needed <= reserved_remaining:
            return reserved_remaining

        current = reserved_remaining

        def reserve(available: int) -> int | None:
            nonlocal current
            needed = minimum_needed - current
            if needed > available:
                return None
            target = max(UNKNOWN_STREAM_RESERVATION_BYTES, minimum_needed)
            additional = min(available, target - current)
            self.reserved_bytes += additional
            current += additional
            return current

        needed = max(0, minimum_needed - current)
        return self._wait_for_reservable_space(needed, path, reserve)

    def consume_auxiliary_budget(self, reserved_remaining: int, written: int) -> int:
        if written <= 0 or reserved_remaining <= 0:
            return reserved_remaining
        with self.lock:
            consumed = min(written, reserved_remaining)
            self.reserved_bytes = max(0, self.reserved_bytes - consumed)
            return reserved_remaining - consumed

    def release_auxiliary_budget(self, reserved_remaining: int) -> None:
        if reserved_remaining <= 0:
            return
        with self.lock:
            self.reserved_bytes = max(0, self.reserved_bytes - reserved_remaining)

    def _record_file(self, relative_key: str, writer: "CaptureWriter", digest: str) -> None:
        record: dict[str, object] = {
            "size": writer.size,
            "sha256": digest,
            "path": writer.url_path,
        }
        if writer.status is not None:
            record["status"] = writer.status
        if writer.record_metadata:
            record.update(writer.record_metadata)
        self.files[relative_key] = record
        self.casefold_paths[relative_key.casefold()] = relative_key
        self.manifest["captured_files"] = len(self.files)
        self.manifest["captured_bytes"] = int(self.manifest.get("captured_bytes", 0)) + writer.size

    def publish(self, writer: "CaptureWriter") -> str:
        relative_key = writer.relative.as_posix()
        digest = writer.digest.hexdigest()
        size = writer.size
        result: str
        postprocess_path: Path | None = None

        with self.lock:
            existing_key = self.casefold_paths.get(relative_key.casefold())
            existing_record = self.files.get(existing_key) if existing_key is not None else None
            if existing_record is not None:
                if existing_record.get("sha256") == digest and int(existing_record.get("size", -1)) == size:
                    existing_matches = existing_record.get("removed_after_extract") is True
                    if not existing_matches:
                        try:
                            existing_matches = (
                                writer.output.is_file()
                                and writer.output.stat().st_size == size
                                and sha256_file(writer.output) == digest
                            )
                        except OSError:
                            existing_matches = False

                    if existing_matches:
                        writer.temporary.unlink(missing_ok=True)
                        self.manifest["duplicates"] = int(self.manifest.get("duplicates", 0)) + 1
                        self._persist_manifest()
                        result = "duplicate"
                    else:
                        writer.output.parent.mkdir(parents=True, exist_ok=True)
                        writer.temporary.replace(writer.output)
                        result = "saved"
                    postprocess_path = writer.output if writer.output.is_file() else None
                else:
                    result = self._publish_conflict(writer, digest)
                    postprocess_path = None
            else:
                writer.output.parent.mkdir(parents=True, exist_ok=True)
                if writer.output.exists():
                    existing_size = writer.output.stat().st_size
                    existing_hash = sha256_file(writer.output) if existing_size == size else None
                    if existing_hash == digest:
                        writer.temporary.unlink(missing_ok=True)
                        self._record_file(relative_key, writer, digest)
                        self.manifest["duplicates"] = int(self.manifest.get("duplicates", 0)) + 1
                        self._persist_manifest()
                        result = "duplicate"
                        postprocess_path = writer.output
                    else:
                        result = self._publish_conflict(writer, digest)
                        postprocess_path = None
                else:
                    try:
                        publish_no_overwrite(writer.temporary, writer.output)
                    except FileExistsError:
                        existing_size = writer.output.stat().st_size
                        existing_hash = sha256_file(writer.output) if existing_size == size else None
                        if existing_hash == digest:
                            writer.temporary.unlink(missing_ok=True)
                            self._record_file(relative_key, writer, digest)
                            self.manifest["duplicates"] = int(self.manifest.get("duplicates", 0)) + 1
                            self._persist_manifest()
                            result = "duplicate"
                            postprocess_path = writer.output
                        else:
                            result = self._publish_conflict(writer, digest)
                            postprocess_path = None
                    else:
                        self._record_file(relative_key, writer, digest)
                        self._persist_manifest()
                        result = "saved"
                        postprocess_path = writer.output

        log_provenance = self._writer_log_provenance(writer)
        if result == "duplicate":
            self.log(
                f"[Duplicate] {self._writer_log_fields(writer)}",
                file_suffix=log_provenance,
            )
        elif result == "saved":
            self.log(
                f"[Saved] {self._writer_log_fields(writer)}",
                file_suffix=log_provenance,
            )
        elif writer.url_path.startswith("/0/H.Cache.bin!"):
            with self.lock:
                self._h_cache_content_conflict = True
            self._remove_generated_unmanaged()
            self.log("WARNING: Conflicting H.Cache.bin versions were captured; UNMANAGED was not created.")

        if result in {"saved", "duplicate"}:
            h_cache_type = h_cache_manifest_type(writer.url_path)
            if h_cache_type is not None:
                self._observe_h_cache_manifest_type(h_cache_type)
                with self.lock:
                    key = self.casefold_paths.get(relative_key.casefold())
                    record = self.files.get(key) if key is not None else None
                    if record is not None and "source" not in record:
                        record["source"] = "captured"
                        self._persist_manifest(force=True)
                    b_cache_seen = bool(self._b_cache_manifests)
                if b_cache_seen:
                    self._validate_h_cache_for_unmanaged(relative_key.rsplit("/", 1)[-1])

        self.maybe_fetch_official_h_cache(writer.url_path)
        if postprocess_path is not None:
            self._extract_executable_if_needed(writer.relative, postprocess_path)
        return result

    @staticmethod
    def _lzma_alone_uncompressed_size(archive: Path) -> int | None:
        try:
            with archive.open("rb") as source:
                header = source.read(13)
        except OSError:
            return None
        if len(header) != 13:
            return None
        declared = int.from_bytes(header[5:13], "little")
        return None if declared == (1 << 64) - 1 else declared

    @staticmethod
    def _emit_extracting_payload(received: int, expected: int | None, speed_bps: int) -> None:
        payload = {
            "received": received,
            "expected": expected,
            "speed_bps": max(0, speed_bps),
            "path": "Warframe.x64.exe",
        }
        print(encode_worker_message("progress", action="extracting", **payload), flush=True)

    def _extract_executable_if_needed(self, relative: Path, archive: Path) -> None:
        if len(relative.parts) != 1:
            return
        match = re.fullmatch(r"^Warframe\.x64\.exe\.([0-9A-Fa-f]{32})\.lzma$", relative.name)
        if match is None:
            return

        with self.extraction_lock:
            expected_md5 = match.group(1).lower()
            output = self.session_root / "Warframe.x64.exe"
            validate_windows_full_path(output, "Extracted executable path")
            if output.exists():
                try:
                    with output.open("rb") as file:
                        existing_md5 = hashlib.file_digest(
                            file, lambda: hashlib.md5(usedforsecurity=False)
                        ).hexdigest()
                except OSError as exc:
                    self.record_extraction_error(f"Could not verify existing Warframe.x64.exe before extraction: {exc}", exc)
                    return
                if existing_md5 == expected_md5:
                    self.debug_log("Warframe.x64.exe is already extracted and matches the expected MD5.")
                    return
                self.record_extraction_error(
                    "Warframe.x64.exe already exists in the session root with a different MD5; it was not overwritten."
                )
                return

            temporary = self.temp_root / "Warframe.x64.exe.extract.part"
            validate_windows_full_path(temporary, "Executable extraction temporary path")
            temporary.parent.mkdir(parents=True, exist_ok=True)
            md5 = hashlib.md5(usedforsecurity=False)
            size = 0
            reserved_remaining = 0
            expected_size = self._lzma_alone_uncompressed_size(archive)
            extraction_started = time.monotonic()
            speed_samples: deque[tuple[float, int]] = deque([(extraction_started, 0)])
            last_progress_report = 0.0
            with self.lock:
                self._extracting_progress_active = True
            try:
                with lzma.open(archive, "rb") as source, temporary.open("wb", buffering=0) as destination:
                    while chunk := source.read(1024 * 1024):
                        if len(chunk) > reserved_remaining:
                            reserved_remaining = self.reserve_auxiliary_budget(
                                reserved_remaining, len(chunk), "Warframe.x64.exe"
                            )
                        self.write_all_with_disk_wait(destination, chunk, "Warframe.x64.exe")
                        reserved_remaining = self.consume_auxiliary_budget(reserved_remaining, len(chunk))
                        md5.update(chunk)
                        size += len(chunk)
                        if self.worker_protocol_enabled:
                            now = time.monotonic()
                            speed_samples.append((now, size))
                            cutoff = now - SAVING_PROGRESS_SPEED_WINDOW_SECONDS
                            while len(speed_samples) > 2 and speed_samples[1][0] <= cutoff:
                                speed_samples.popleft()
                            if (
                                now - extraction_started >= SAVING_PROGRESS_DISPLAY_DELAY_SECONDS
                                and now - last_progress_report >= SAVING_PROGRESS_REPORT_INTERVAL_SECONDS
                            ):
                                sample_time, sample_size = speed_samples[0]
                                elapsed = max(1e-6, now - sample_time)
                                self._emit_extracting_payload(
                                    size,
                                    expected_size,
                                    int((size - sample_size) / elapsed),
                                )
                                last_progress_report = now
            except CaptureDrainRequested:
                temporary.unlink(missing_ok=True)
                return
            except (OSError, EOFError, lzma.LZMAError) as exc:
                temporary.unlink(missing_ok=True)
                self.record_extraction_error(f"Could not extract {relative.name}: {exc}", exc)
                return
            finally:
                with self.lock:
                    self._extracting_progress_active = False
                self.release_auxiliary_budget(reserved_remaining)

            actual_md5 = md5.hexdigest()
            if actual_md5 != expected_md5:
                temporary.unlink(missing_ok=True)
                self.record_extraction_error(
                    f"Extracted Warframe.x64.exe failed MD5 verification: expected {expected_md5.upper()}, got {actual_md5.upper()}."
                )
                return

            try:
                publish_no_overwrite(temporary, output)
            except FileExistsError:
                temporary.unlink(missing_ok=True)
                self.record_extraction_error("Warframe.x64.exe appeared during extraction and was not overwritten.")
                return
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                self.record_extraction_error(f"Could not publish extracted Warframe.x64.exe: {exc}", exc)
                return

            source_removed = False
            cleanup_error: OSError | None = None
            try:
                archive.unlink()
                source_removed = True
            except OSError as exc:
                cleanup_error = exc

            with self.lock:
                source_record = self.files.get(relative.as_posix())
                if source_removed and source_record is not None:
                    source_record["removed_after_extract"] = True
                self.manifest["extracted_executable"] = {
                    "source": relative.as_posix(),
                    "source_removed": source_removed,
                    "path": "Warframe.x64.exe",
                    "size": size,
                    "md5": actual_md5,
                }
                self._persist_manifest()
            self.log(f"[Extracted] {format_bytes(size)} | MD5 OK | Warframe.x64.exe")
            if cleanup_error is not None:
                self.record_extraction_error(
                    f"Warframe.x64.exe was extracted successfully, but the source archive could not be removed: {cleanup_error}",
                    cleanup_error,
                )

    @staticmethod
    def _writer_log_fields(writer: "CaptureWriter") -> str:
        display_status = writer.status if writer.status is not None else writer.display_status
        status = f" | {display_status}" if display_status is not None else ""
        return f"{format_bytes(writer.size)}{status} | {writer.url_path}"

    @staticmethod
    def _writer_log_provenance(writer: "CaptureWriter") -> str | None:
        if writer.log_source is not None:
            return f"Source: {writer.log_source}"
        if writer.record_metadata.get("source") == "manual":
            return "Source: Fetched by Ninja Capture Tool"
        if writer.process_name is not None and writer.process_pid is not None:
            return f"Process: {writer.process_name} (PID {writer.process_pid})"
        return None

    def _existing_conflict_path(self, writer: "CaptureWriter", digest: str) -> Path | None:
        relative_key = writer.relative.as_posix().casefold()
        for record in self.conflicts:
            if (
                not isinstance(record, dict)
                or str(record.get("path", "")).casefold() != relative_key
                or record.get("sha256") != digest
                or record.get("size") != writer.size
            ):
                continue
            stored_as = record.get("stored_as")
            if not isinstance(stored_as, str):
                continue
            try:
                candidate = self.session_root.joinpath(*relative_path_parts(stored_as)).resolve()
            except (OSError, ValueError):
                continue
            if not candidate.is_relative_to(self.conflict_root) or candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                if candidate.stat().st_size == writer.size and sha256_file(candidate) == digest:
                    return candidate
            except OSError:
                continue
        return None

    def _publish_conflict(self, writer: "CaptureWriter", digest: str) -> str:
        existing = self._existing_conflict_path(writer, digest)
        if existing is not None:
            writer.temporary.unlink(missing_ok=True)
            self.manifest["duplicates"] = int(self.manifest.get("duplicates", 0)) + 1
            self._persist_manifest()
            self.log(
                f"[Duplicate] {self._writer_log_fields(writer)} | conflicting variant already preserved",
                file_suffix=self._writer_log_provenance(writer),
            )
            return "duplicate"

        conflict_candidate = self.conflict_root / writer.relative
        validate_windows_full_path(conflict_candidate, "Capture conflict path")
        conflict = conflict_candidate.resolve()
        if not conflict.is_relative_to(self.conflict_root):
            raise RuntimeError("Unsafe conflict path generated.")
        conflict.parent.mkdir(parents=True, exist_ok=True)
        base = conflict.with_name(f".{digest[:12]}.conflict")
        validate_windows_full_path(base, "Capture conflict file path")
        conflict = base
        counter = 2
        while conflict.exists():
            conflict = base.with_name(f".{digest[:12]}.{counter}.conflict")
            validate_windows_full_path(conflict, "Capture conflict file path")
            counter += 1
        os.replace(writer.temporary, conflict)
        conflict_record: dict[str, object] = {
            "path": writer.relative.as_posix(),
            "stored_as": conflict.relative_to(self.session_root).as_posix(),
            "size": writer.size,
            "sha256": digest,
            "request_path": writer.url_path,
        }
        if writer.status is not None:
            conflict_record["status"] = writer.status
        self.conflicts.append(conflict_record)
        self.manifest["conflict_count"] = len(self.conflicts)
        self._persist_manifest()
        self.log(
            f"[Conflict] {self._writer_log_fields(writer)} | changed during the same capture; preserved separately",
            file_suffix=self._writer_log_provenance(writer),
        )
        return "conflict"

    def abort_all(self) -> None:
        self.close_saving_progress_heartbeat()
        with self.lock:
            writers = list(self.active_writers)
        for writer in writers:
            received = writer.size
            expected = writer.expected_size
            path = writer.url_path
            provenance = self._writer_log_provenance(writer)
            writer.abort()
            self.record_incomplete(
                path,
                expected,
                received,
                "capture session stopped before the response completed",
                file_suffix=provenance,
            )
        self.close_metadata()

class CaptureWriter:
    def __init__(
        self,
        store: CaptureStore,
        relative: Path,
        output: Path,
        temporary: Path,
        url_path: str,
        status: int | str | None,
        expected_size: int | None,
        reserved_remaining: int = 0,
        record_metadata: dict[str, object] | None = None,
        *,
        process_name: str | None = None,
        process_pid: int | None = None,
        log_source: str | None = None,
    ):
        self.store = store
        self.relative = relative
        self.output = output
        self.temporary = temporary
        self.url_path = url_path
        self.status = status
        self.display_status: str | None = None
        self.record_metadata = dict(record_metadata) if record_metadata else {}
        self.process_name = process_name
        self.process_pid = process_pid
        self.log_source = log_source
        self.expected_size = expected_size
        self.reserved_remaining = reserved_remaining
        self.digest = hashlib.sha256()
        self.size = 0
        self.failed = False
        self.finished = False
        self.publish_result: str | None = None
        self.waiting_for_space = False
        self.started_at = time.monotonic()
        self.progress_speed_samples: deque[tuple[float, int]] = deque([(self.started_at, 0)])
        self._file = temporary.open("wb", buffering=0)

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    def abort(self) -> None:
        self.failed = True
        try:
            self.close()
        except OSError as exc:
            self.store.debug_log(f"Could not close incomplete capture {self.url_path}: {exc}")
        try:
            self.temporary.unlink(missing_ok=True)
        except OSError as exc:
            self.store.debug_log(f"Could not remove incomplete capture {self.temporary}: {exc}")
        self.store.unregister(self)

    def feed(self, data: bytes) -> bytes:
        if self.finished or self.failed:
            return data
        if data:
            try:
                if self.expected_size is not None and self.size + len(data) > self.expected_size:
                    received = self.size + len(data)
                    self.abort()
                    self.store.record_incomplete(
                        self.url_path,
                        self.expected_size,
                        received,
                        "response exceeded Content-Length; local capture stopped",
                        file_suffix=self.store._writer_log_provenance(self),
                    )
                    return data
                if self.expected_size is None and len(data) > self.reserved_remaining:
                    self.store.reserve_stream_budget(self, len(data))
                self.store.write_all_with_disk_wait(self._file, data, self.url_path, writer=self)
                self.digest.update(data)
                self.size += len(data)
                self.store.consume_reservation(self, len(data))
                self.store.report_progress(self)
            except CaptureDrainRequested:
                self.abort()
            except Exception as exc:
                provenance = self.store._writer_log_provenance(self)
                self.abort()
                self.store.record_capture_error(self.url_path, exc, file_suffix=provenance)
            return data

        self.finished = True
        try:
            self.close()
            if self.expected_size is not None and self.size != self.expected_size:
                provenance = self.store._writer_log_provenance(self)
                self.abort()
                self.store.record_incomplete(
                    self.url_path,
                    self.expected_size,
                    self.size,
                    file_suffix=provenance,
                )
                return data
            self.publish_result = self.store.publish_with_disk_wait(self)
            self.store.unregister(self)
        except Exception as exc:
            provenance = self.store._writer_log_provenance(self)
            self.abort()
            self.store.record_capture_error(self.url_path, exc, file_suffix=provenance)
        return data

class CaptureAddon:
    def __init__(
        self,
        session_root: Path,
        manifest_path: Path,
        debug: bool | str = False,
        drain_requested: threading.Event | None = None,
        worker_protocol_enabled: bool = False,
        manual_fetch_upstream: str | None = None,
        manual_fetch_upstream_auth: str | None = None,
    ):
        self.store = CaptureStore(
            session_root,
            manifest_path=manifest_path,
            debug=bool(debug),
            drain_requested=drain_requested,
            worker_protocol_enabled=worker_protocol_enabled,
            manual_fetch_upstream=manual_fetch_upstream,
            manual_fetch_upstream_auth=manual_fetch_upstream_auth,
        )
        self._manual_fetch_upstream = manual_fetch_upstream
        self._manual_fetch_upstream_auth = manual_fetch_upstream_auth
        self._session_lock = threading.Lock()
        self._rotation_thread: threading.Thread | None = None
        self._rotation_stop = threading.Event()
        self._debug_value = debug
        self._worker_protocol_enabled = worker_protocol_enabled
        self.global_debug = debug == "global"
        self._ignored_connections_logged: set[str] = set()
        self._ignored_connection_order: deque[str] = deque()
        self.dns_cache = DNSHostnameCache()

    def running(self) -> None:
        self.store.start_metadata_flusher()
        self.store.start_saving_progress_heartbeat()
        self.store.mark_running()
        print(encode_worker_message("ready"), flush=True)

    def request_session_rotation(self, session_root: Path, manifest_path: Path, token: str) -> None:
        thread = self._rotation_thread
        if thread is not None and thread.is_alive():
            print(encode_worker_message("rotation_failed", token=token, error="A session rotation is already pending."), flush=True)
            return
        if self._rotation_stop.is_set():
            print(encode_worker_message("rotation_failed", token=token, error="Capture worker is shutting down."), flush=True)
            return
        self._rotation_thread = threading.Thread(
            target=self._rotate_when_idle,
            args=(session_root, manifest_path, token),
            name="nct-session-rotation",
            daemon=True,
        )
        self._rotation_thread.start()

    def _rotate_when_idle(self, session_root: Path, manifest_path: Path, token: str) -> None:
        new_store: CaptureStore | None = None
        try:
            new_store = CaptureStore(
                session_root,
                manifest_path=manifest_path,
                debug=bool(self._debug_value),
                worker_protocol_enabled=self._worker_protocol_enabled,
                manual_fetch_upstream=self._manual_fetch_upstream,
                manual_fetch_upstream_auth=self._manual_fetch_upstream_auth,
            )
            while True:
                if self._rotation_stop.is_set():
                    new_store.abort_all()
                    return
                old_store_to_close: CaptureStore | None = None
                with self._session_lock:
                    if self._rotation_stop.is_set():
                        new_store.abort_all()
                        return
                    old_store = self.store
                    with old_store.lock:
                        active = len(old_store.active_writers) + old_store._h_cache_fetch_active
                    if active == 0:
                        if self._rotation_stop.is_set():
                            new_store.abort_all()
                            return
                        if not old_store.flush_manifest():
                            raise RuntimeError(
                                "Could not flush the current capture session metadata before starting the new session."
                            )
                        try:
                            new_store.start_metadata_flusher()
                            new_store.start_saving_progress_heartbeat()
                            new_store.mark_running()
                        except Exception:
                            new_store.abort_all()
                            raise

                        # Once the new manifest has been promoted to running, commit
                        # the cutover while still holding the session selector lock.
                        # The rotated control message must enter stdout before any
                        # request can attach to the new store and emit session output;
                        # the parent therefore switches loggers before it can process
                        # a new-session [Saved]/[Filtered]/warning line. Shutdown that
                        # begins during this small commit window waits on this lock.
                        self.store = new_store
                        old_store_to_close = old_store
                        print(encode_worker_message("rotated", token=token), flush=True)

                if old_store_to_close is not None:
                    # No new response can attach to the old store after the pointer
                    # switch. Its background threads can therefore be joined outside
                    # the session selector lock without delaying new response setup.
                    old_store_to_close.close_saving_progress_heartbeat()
                    old_store_to_close.close_metadata()
                    return
                if self._rotation_stop.wait(0.05):
                    return
        except Exception as exc:
            if new_store is not None and self.store is not new_store:
                new_store.abort_all()
            print(encode_worker_message("rotation_failed", token=token, error=str(exc)), flush=True)

    def _promote_dns_passthrough(self, nextlayer) -> bool:
        try:
            context = nextlayer.context
            address = _server_address_parts(context)
            if address is None or address[1] != 53:
                return False
            if str(getattr(context.client, "transport_protocol", "")).casefold() != "udp":
                return False
            data = bytes(nextlayer.data_client())
            if not data:
                return False
            from mitmproxy import dns as mitm_dns
            from mitmproxy.proxy.layers import DNSLayer

            message = mitm_dns.DNSMessage.unpack(data)
            if not message.query:
                return False
            nextlayer.layer = DNSLayer(context)
            return True
        except (ImportError, OSError, TypeError, ValueError):
            return False
        except Exception:
            # A malformed or unsupported packet must remain an untouched raw passthrough.
            return False

    def next_layer(self, nextlayer) -> None:
        if not self.global_debug:
            return
        layer = getattr(nextlayer, "layer", None)
        if layer is None or not _is_ignored_passthrough_layer(layer):
            return
        try:
            address = _server_address_parts(nextlayer.context)
            dns_endpoint = address is not None and address[1] in {53, 5353}
        except Exception:
            dns_endpoint = False
        if dns_endpoint:
            # Only ordinary DNS on UDP/53 is promoted for hostname correlation.
            # mDNS on UDP/5353 remains an untouched, silent raw passthrough.
            if address is not None and address[1] == 53:
                self._promote_dns_passthrough(nextlayer)
            return
        try:
            client = nextlayer.context.client
            client_id = getattr(client, "id", None)
            connection_key = f"id:{client_id}" if client_id is not None else f"object:{id(client)}"
        except Exception:
            connection_key = f"layer:{id(nextlayer)}"
        if connection_key in self._ignored_connections_logged:
            return
        if len(self._ignored_connection_order) >= 8192:
            oldest = self._ignored_connection_order.popleft()
            self._ignored_connections_logged.discard(oldest)
        self._ignored_connections_logged.add(connection_key)
        self._ignored_connection_order.append(connection_key)
        label = ignored_connection_label(nextlayer)
        try:
            address = _server_address_parts(nextlayer.context)
            hint = self.dns_cache.lookup(address[0]) if address is not None else None
        except Exception:
            hint = None
        label = annotate_dns_hint(label, hint)
        with self._session_lock:
            self.store.debug_log(f"{label} (ignored)")

    def dns_response(self, flow) -> None:
        if not self.global_debug:
            return
        response = getattr(flow, "response", None)
        request = getattr(flow, "request", None)
        if response is None or request is None:
            return
        try:
            questions = list(getattr(request, "questions", ()) or ())
            question_name = (
                DNSHostnameCache.canonical_hostname(getattr(questions[0], "name", ""))
                if len(questions) == 1
                else None
            )
            answers = list(getattr(response, "answers", ()) or ())
            additionals = list(getattr(response, "additionals", ()) or ())
        except Exception:
            return

        records = [(item, True) for item in answers] + [(item, False) for item in additionals]
        for record, belongs_to_answer in records:
            record_type = getattr(record, "type", None)
            if record_type not in {1, 28}:
                continue
            try:
                address = str(ipaddress.ip_address(bytes(getattr(record, "data"))))
            except (TypeError, ValueError):
                continue
            ttl = getattr(record, "ttl", 0)
            record_name = getattr(record, "name", "")
            self.dns_cache.remember(address, record_name, ttl)
            if belongs_to_answer and question_name is not None:
                self.dns_cache.remember(address, question_name, ttl)

    def requestheaders(self, flow) -> None:
        if not self.global_debug:
            return
        try:
            host = str(flow.request.pretty_host)
            url = str(flow.request.pretty_url)
            if is_target_request(host, url):
                return
            parsed = urlsplit(url)
            display_host = parsed.hostname or host or "<unknown>"
            port = f":{parsed.port}" if parsed.port is not None else ""
            scheme = parsed.scheme or "http"
            with self._session_lock:
                self.store.debug_log(f"{scheme}://{display_host}{port}/ (ignored)")
        except Exception:
            with self._session_lock:
                self.store.debug_log("<malformed> (ignored)")

    @staticmethod
    def _flow_process_provenance(flow) -> tuple[str | None, int | None]:
        client = getattr(flow, "client_conn", None)
        process_name = getattr(client, "_nct_process_name", None)
        process_pid = getattr(client, "_nct_process_pid", None)
        if not isinstance(process_name, str) or not isinstance(process_pid, int) or isinstance(process_pid, bool):
            return None, None
        process_name = process_name.strip()
        if not process_name or process_pid <= 0 or any(ord(char) < 32 or ord(char) == 127 for char in process_name):
            return None, None
        process_name = process_name.replace("\\", "/").rsplit("/", 1)[-1].strip()
        if not process_name:
            return None, None
        return process_name, process_pid

    def responseheaders(self, flow) -> None:
        # Hold the session selector only through response setup. Once a writer is
        # registered it owns its CaptureStore for the lifetime of that response, so
        # a pending rotation can wait for it without ever splitting one download.
        with self._session_lock:
            store = self.store
            try:
                host = str(flow.request.pretty_host)
                url = str(flow.request.pretty_url)
            except Exception:
                if not self.global_debug:
                    store.debug_log("Filtered malformed request.")
                return

            if not is_target_request(host, url):
                if not self.global_debug:
                    store.debug_log(f"Filtered host: {debug_host(url)}")
                return

            response = getattr(flow, "response", None)
            if response is None:
                store.debug_log(f"No response headers: {urlsplit(url).path or '/'}")
                return

            status = int(getattr(response, "status_code", 0) or 0)
            path = urlsplit(url).path or "/"
            expected_size = response_content_length(response)
            store.record_target_response(status)

            if is_filtered_root_url(url):
                store.record_filtered_root_path(path)
                response.stream = passthrough_stream
                return
            if status == 206:
                store.record_skipped_partial(path, expected_size)
                response.stream = passthrough_stream
                return
            if status != 200:
                store.record_skipped_http()
                store.debug_log(f"Skipped HTTP {status}: {path}")
                response.stream = passthrough_stream
                return
            if not store.accepting_captures():
                store.debug_log(f"Capture restart drain active; forwarding without saving: {path}")
                response.stream = passthrough_stream
                return
            if store.capture_disabled:
                store.debug_log(f"Capture disabled; forwarding without saving: {path}")
                response.stream = passthrough_stream
                return

            process_name, process_pid = self._flow_process_provenance(flow)
            try:
                writer = store.begin(
                    url,
                    status,
                    expected_size,
                    process_name=process_name,
                    process_pid=process_pid,
                )
            except CaptureDrainRequested:
                store.debug_log(f"Capture restart drain active; forwarding without saving: {path}")
                response.stream = passthrough_stream
                return
            except Exception as exc:
                provenance = (
                    f"Process: {process_name} (PID {process_pid})"
                    if process_name is not None and process_pid is not None
                    else None
                )
                store.record_capture_error(path, exc, file_suffix=provenance)
                response.stream = passthrough_stream
                return

            if not hasattr(flow, "metadata") or flow.metadata is None:
                flow.metadata = {}
            flow.metadata["nct_writer"] = writer
            response.stream = writer.feed

    def error(self, flow) -> None:
        metadata = getattr(flow, "metadata", None)
        if not isinstance(metadata, dict):
            return
        writer = metadata.get("nct_writer")
        if isinstance(writer, CaptureWriter) and not writer.finished and not writer.failed:
            received = writer.size
            expected = writer.expected_size
            path = writer.url_path
            provenance = writer.store._writer_log_provenance(writer)
            writer.abort()
            writer.store.record_incomplete(
                path,
                expected,
                received,
                "network flow ended with an error",
                file_suffix=provenance,
            )

    def done(self) -> None:
        self._rotation_stop.set()
        # Synchronize with a rotation that may already be inside the cutover
        # section, then wait for the daemon thread to settle before aborting the
        # active store. This prevents a pending Ctrl+R from starting a new
        # session concurrently with worker shutdown.
        with self._session_lock:
            pass
        thread = self._rotation_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()
        with self._session_lock:
            self.store.abort_all()


def run_frozen_capture_smoke_test() -> int:
    """Exercise the bundled CaptureWriter path inside the frozen executable."""
    with tempfile.TemporaryDirectory(prefix="nct-capture-smoke-") as tmp:
        root = Path(tmp)
        session_root = root / "session"
        (session_root / "OpenWF" / "Content").mkdir(parents=True)
        options = {
            "capture_mode": "system-proxy",
            "processes": ["Launcher.exe", "Warframe.x64.exe"],
            "proxy_port": 0,
            "debug": False,
            "stop_on_exit": False,
            "stop_on_exit_delay": 15,
            "output_root": root,
            "output_path": None,
            "upstream_proxy": "direct",
        }
        manifest_path = root / "smoke_session.json"
        initialize_session_manifest(session_root, options, manifest_path)
        addon = CaptureAddon(session_root, manifest_path=manifest_path, worker_protocol_enabled=False)
        payload = (b"Ninja Capture Tool frozen capture smoke test\n" * 2048) + bytes(range(256))
        writer = addon.store.begin(
            "https://content.warframe.com/0/build/frozen-capture-smoke.bin",
            200,
            expected_size=len(payload),
        )
        midpoint = len(payload) // 2
        writer.feed(payload[:midpoint])
        writer.feed(payload[midpoint:])
        writer.feed(b"")
        saved = session_root / "OpenWF" / "Content" / "0" / "build" / "frozen-capture-smoke.bin"
        if saved.read_bytes() != payload:
            raise RuntimeError("Frozen capture smoke test produced incorrect file contents.")
        manifest = read_json_object(manifest_path)
        record = manifest.get("files", {}).get("0/build/frozen-capture-smoke.bin")
        if not isinstance(record, dict) or record.get("sha256") != hashlib.sha256(payload).hexdigest():
            raise RuntimeError("Frozen capture smoke test did not record the expected SHA-256 metadata.")
    return 0
