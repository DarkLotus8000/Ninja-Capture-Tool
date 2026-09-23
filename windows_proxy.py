#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import fnmatch
import re
import socket
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from common import (
    proxy_recovery_file,
    TARGET_HOST,
    VERSION,
    atomic_write_json,
    current_timestamp,
    parse_json,
)

RECOVERY_VERSION = 1

@dataclass(frozen=True)
class ProxyDeactivationResult:
    restored: bool
    recovery_cleanup_error: str | None = None

    def __bool__(self) -> bool:
        return self.restored

PROXY_SETTING_NAMES = (
    "ProxyEnable",
    "ProxyServer",
    "ProxyOverride",
    "AutoConfigURL",
    "AutoDetect",
)
TARGET_URL = f"https://{TARGET_HOST}/"
_PROXY_VERIFY_ATTEMPTS = 5
_PROXY_VERIFY_RETRY_DELAY_SECONDS = 0.1

def import_winreg():
    if sys.platform != "win32":
        raise RuntimeError("Windows proxy management is only available on Windows.")
    import winreg

    return winreg

def get_proxy_settings() -> dict[str, object]:
    winreg = import_winreg()
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_READ,
    )
    try:
        settings: dict[str, object] = {}
        for name in PROXY_SETTING_NAMES:
            try:
                value, value_type = winreg.QueryValueEx(key, name)
                settings[name] = {"value": value, "type": value_type}
            except FileNotFoundError:
                settings[name] = None
        return settings
    finally:
        winreg.CloseKey(key)

def setting_value(settings: dict[str, object], name: str) -> object | None:
    entry = settings.get(name)
    if isinstance(entry, dict):
        return entry.get("value")
    return None

def normalized_settings(settings: object) -> dict[str, object]:
    if not isinstance(settings, dict) or set(settings) != set(PROXY_SETTING_NAMES):
        raise RuntimeError("Proxy recovery data contains an invalid settings snapshot.")
    normalized: dict[str, object] = {}
    for name in PROXY_SETTING_NAMES:
        entry = settings[name]
        if entry is None:
            normalized[name] = None
            continue
        if not isinstance(entry, dict) or set(entry) != {"value", "type"}:
            raise RuntimeError("Proxy recovery data contains an invalid registry entry.")
        value_type = entry["type"]
        if not isinstance(value_type, int) or isinstance(value_type, bool):
            raise RuntimeError("Proxy recovery data contains an invalid registry type.")
        normalized[name] = {"value": entry["value"], "type": value_type}
    return normalized

def _proxy_setting_equivalent(name: str, left: object, right: object) -> bool:
    if left == right:
        return True

    # Windows may normalize disabled optional proxy values after WinINet is
    # notified. Missing and explicit disabled/empty forms have the same effect.
    if name in {"ProxyEnable", "AutoDetect"}:
        def disabled_dword(entry: object) -> bool:
            return entry is None or (
                isinstance(entry, dict)
                and entry.get("value") == 0
                and isinstance(entry.get("type"), int)
            )
        if disabled_dword(left) and disabled_dword(right):
            return True

    if name == "AutoConfigURL":
        def empty_pac(entry: object) -> bool:
            return entry is None or (isinstance(entry, dict) and entry.get("value") == "")
        if empty_pac(left) and empty_pac(right):
            return True

    if name == "ProxyOverride":
        def override_set(entry: object) -> set[str] | None:
            if not isinstance(entry, dict) or not isinstance(entry.get("value"), str):
                return None
            return {part.strip().casefold() for part in entry["value"].split(";") if part.strip()}
        left_set = override_set(left)
        right_set = override_set(right)
        if left_set is not None and right_set is not None and left_set == right_set:
            return True

    return False

def proxy_settings_equivalent(left: object, right: object) -> bool:
    try:
        left_settings = normalized_settings(left)
        right_settings = normalized_settings(right)
    except RuntimeError:
        return False
    return all(
        _proxy_setting_equivalent(name, left_settings[name], right_settings[name])
        for name in PROXY_SETTING_NAMES
    )

def proxy_settings_mismatches(current: object, expected: object) -> list[str]:
    try:
        current_settings = normalized_settings(current)
        expected_settings = normalized_settings(expected)
    except RuntimeError:
        return list(PROXY_SETTING_NAMES)
    return [
        name
        for name in PROXY_SETTING_NAMES
        if not _proxy_setting_equivalent(name, current_settings[name], expected_settings[name])
    ]

def _verify_proxy_settings(
    expected: dict[str, object],
    failure_message: str,
    *,
    attempts: int = _PROXY_VERIFY_ATTEMPTS,
    retry_delay: float = _PROXY_VERIFY_RETRY_DELAY_SECONDS,
) -> dict[str, object]:
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    current: dict[str, object] | None = None
    mismatches = list(PROXY_SETTING_NAMES)
    for attempt in range(attempts):
        current = get_proxy_settings()
        mismatches = proxy_settings_mismatches(current, expected)
        if not mismatches:
            return current
        if attempt + 1 < attempts and retry_delay > 0:
            time.sleep(retry_delay)
    fields = ", ".join(mismatches)
    raise RuntimeError(f"{failure_message} (mismatch: {fields}).")

def verify_applied_proxy_settings(
    expected: dict[str, object],
    *,
    attempts: int = _PROXY_VERIFY_ATTEMPTS,
    retry_delay: float = _PROXY_VERIFY_RETRY_DELAY_SECONDS,
) -> dict[str, object]:
    return _verify_proxy_settings(
        expected,
        "Windows did not keep the required System Proxy settings",
        attempts=attempts,
        retry_delay=retry_delay,
    )

def restore_proxy_settings(
    settings: dict[str, object],
    *,
    attempts: int = _PROXY_VERIFY_ATTEMPTS,
    retry_delay: float = _PROXY_VERIFY_RETRY_DELAY_SECONDS,
) -> dict[str, object]:
    apply_proxy_settings(settings)
    return _verify_proxy_settings(
        settings,
        "Windows did not retain the restored proxy settings",
        attempts=attempts,
        retry_delay=retry_delay,
    )

def notify_windows_proxy_changed() -> None:
    wininet = ctypes.WinDLL("wininet", use_last_error=True)
    internet_set_option = wininet.InternetSetOptionW
    internet_set_option.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    internet_set_option.restype = wintypes.BOOL
    for option in (39, 37):  # INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH
        ctypes.set_last_error(0)
        if not internet_set_option(None, option, None, 0):
            error = ctypes.get_last_error()
            detail = f"WinError {error}" if error else "unknown Windows error"
            raise RuntimeError(f"Could not notify Windows that proxy settings changed: {detail}.")

def apply_proxy_settings(settings: object) -> None:
    typed = normalized_settings(settings)
    winreg = import_winreg()
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    )
    try:
        for name, entry in typed.items():
            if entry is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, entry["type"], entry["value"])
    finally:
        winreg.CloseKey(key)
    notify_windows_proxy_changed()

def proxy_override_entries(settings: dict[str, object]) -> list[str]:
    value = setting_value(settings, "ProxyOverride")
    if not isinstance(value, str):
        return []
    return [entry.strip() for entry in value.split(";") if entry.strip()]

def override_matches_target(entry: str) -> bool:
    candidate = entry.strip().casefold()
    if not candidate or candidate == "<local>":
        return False
    if "://" in candidate:
        try:
            candidate = (urlsplit(candidate).hostname or candidate).casefold()
        except ValueError:
            pass
    candidate = candidate.split(":", 1)[0]
    return fnmatch.fnmatchcase(TARGET_HOST.casefold(), candidate)

def target_bypasses_existing_proxy(settings: dict[str, object]) -> bool:
    return any(override_matches_target(entry) for entry in proxy_override_entries(settings))

def preserved_proxy_override(settings: dict[str, object]) -> str:
    entries = [entry for entry in proxy_override_entries(settings) if not override_matches_target(entry)]
    if not any(entry.casefold() == "<local>" for entry in entries):
        entries.append("<local>")
    return ";".join(entries)

def build_local_proxy_settings(before: dict[str, object], proxy_port: int) -> dict[str, object]:
    # Registry type values are stable Win32 constants: REG_SZ=1, REG_DWORD=4.
    return {
        "ProxyEnable": {"value": 1, "type": 4},
        "ProxyServer": {"value": f"127.0.0.1:{proxy_port}", "type": 1},
        "ProxyOverride": {"value": preserved_proxy_override(before), "type": 1},
        "AutoConfigURL": None,
        "AutoDetect": {"value": 0, "type": 4},
    }

def parse_upstream_proxy(value: str) -> tuple[str, str | None]:
    candidate = value.strip()
    if not candidate:
        raise RuntimeError("Upstream proxy cannot be empty.")
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("Invalid upstream proxy address.") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("Upstream proxy must use http:// or https:// and include a host.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise RuntimeError("Upstream proxy must not contain a path, query, or fragment.")
    if port is None:
        port = 443 if scheme == "https" else 80
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"

    auth: str | None = None
    if parsed.username is not None or parsed.password is not None:
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        auth = f"{username}:{password}"

    return f"{scheme}://{host}:{port}", auth

def upstream_points_to_local_proxy(upstream: str | None, proxy_port: int) -> bool:
    if upstream is None:
        return False
    parsed = urlsplit(upstream)
    host = (parsed.hostname or "").rstrip(".").casefold()
    return parsed.port == proxy_port and host in {"127.0.0.1", "localhost"}

def proxy_for_scheme(proxy_list: str, scheme: str = "https") -> tuple[str, str | None] | None:
    exact: list[str] = []
    generic: list[str] = []
    unsupported: set[str] = set()
    for entry in re.split(r"[;\s]+", proxy_list.strip()):
        if not entry:
            continue
        if "=" in entry:
            entry_scheme, server = entry.split("=", 1)
            entry_scheme = entry_scheme.strip().casefold()
            if entry_scheme == scheme.casefold() and server.strip():
                exact.append(server.strip())
            elif entry_scheme in {"socks", "socks4", "socks5"}:
                unsupported.add(entry_scheme)
        else:
            generic.append(entry)

    candidate = exact[0] if exact else generic[0] if generic else None
    if candidate is None:
        if unsupported:
            raise RuntimeError("The existing Windows proxy route uses SOCKS, which mitmproxy upstream mode cannot chain automatically.")
        return None
    if candidate.casefold() == "direct":
        return None
    return parse_upstream_proxy(candidate)

def winhttp_auto_proxy_for_url(url: str, *, pac_url: str | None = None, autodetect: bool = False) -> tuple[str, str | None] | None:
    if sys.platform != "win32":
        raise RuntimeError("Windows automatic proxy resolution is only available on Windows.")
    if not pac_url and not autodetect:
        raise ValueError("PAC URL or automatic proxy detection must be enabled.")

    class WinHttpAutoProxyOptions(ctypes.Structure):
        _fields_ = [
            ("dwFlags", wintypes.DWORD),
            ("dwAutoDetectFlags", wintypes.DWORD),
            ("lpszAutoConfigUrl", wintypes.LPCWSTR),
            ("lpvReserved", wintypes.LPVOID),
            ("dwReserved", wintypes.DWORD),
            ("fAutoLogonIfChallenged", wintypes.BOOL),
        ]

    class WinHttpProxyInfo(ctypes.Structure):
        _fields_ = [
            ("dwAccessType", wintypes.DWORD),
            ("lpszProxy", ctypes.c_void_p),
            ("lpszProxyBypass", ctypes.c_void_p),
        ]

    winhttp = ctypes.WinDLL("winhttp", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    winhttp.WinHttpOpen.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    winhttp.WinHttpOpen.restype = ctypes.c_void_p
    winhttp.WinHttpGetProxyForUrl.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(WinHttpAutoProxyOptions), ctypes.POINTER(WinHttpProxyInfo)]
    winhttp.WinHttpGetProxyForUrl.restype = wintypes.BOOL
    winhttp.WinHttpCloseHandle.argtypes = [ctypes.c_void_p]
    winhttp.WinHttpCloseHandle.restype = wintypes.BOOL
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p

    session = winhttp.WinHttpOpen(f"Ninja Capture Tool/{VERSION}", 1, None, None, 0)  # WINHTTP_ACCESS_TYPE_NO_PROXY
    if not session:
        raise ctypes.WinError(ctypes.get_last_error())

    flags = 0
    auto_detect_flags = 0
    if pac_url:
        flags |= 0x2  # WINHTTP_AUTOPROXY_CONFIG_URL
    if autodetect:
        flags |= 0x1  # WINHTTP_AUTOPROXY_AUTO_DETECT
        auto_detect_flags = 0x1 | 0x2  # DHCP, then DNS-A
    options = WinHttpAutoProxyOptions(flags, auto_detect_flags, pac_url, None, 0, True)
    info = WinHttpProxyInfo()

    try:
        if not winhttp.WinHttpGetProxyForUrl(session, url, ctypes.byref(options), ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if info.dwAccessType == 1:  # WINHTTP_ACCESS_TYPE_NO_PROXY
            return None
        if info.dwAccessType != 3 or not info.lpszProxy:  # WINHTTP_ACCESS_TYPE_NAMED_PROXY
            raise RuntimeError("Windows automatic proxy resolution returned an unsupported proxy result.")
        return proxy_for_scheme(ctypes.wstring_at(info.lpszProxy), urlsplit(url).scheme or "https")
    finally:
        if info.lpszProxy:
            kernel32.GlobalFree(info.lpszProxy)
        if info.lpszProxyBypass:
            kernel32.GlobalFree(info.lpszProxyBypass)
        winhttp.WinHttpCloseHandle(session)

def resolve_upstream_proxy(mode: str, settings: dict[str, object]) -> tuple[str | None, str | None]:
    selected = mode.strip()
    if selected.casefold() == "direct":
        return None, None
    if selected.casefold() != "auto":
        return parse_upstream_proxy(selected)

    manual: tuple[str, str | None] | None = None
    enabled = setting_value(settings, "ProxyEnable")
    server = setting_value(settings, "ProxyServer")
    if enabled and isinstance(server, str) and server.strip() and not target_bypasses_existing_proxy(settings):
        manual = proxy_for_scheme(server.strip())

    pac = setting_value(settings, "AutoConfigURL")
    pac_url = pac.strip() if isinstance(pac, str) and pac.strip() else None
    autodetect_value = setting_value(settings, "AutoDetect")
    autodetect = autodetect_value not in {None, 0, False}

    errors: list[str] = []
    if pac_url:
        try:
            resolved = winhttp_auto_proxy_for_url(TARGET_URL, pac_url=pac_url)
            return resolved if resolved is not None else (None, None)
        except (OSError, RuntimeError) as exc:
            errors.append(f"PAC: {exc}")
    if autodetect:
        try:
            resolved = winhttp_auto_proxy_for_url(TARGET_URL, autodetect=True)
            return resolved if resolved is not None else (None, None)
        except (OSError, RuntimeError) as exc:
            errors.append(f"WPAD: {exc}")

    if manual is not None:
        return manual
    if errors:
        raise RuntimeError(
            "Windows automatic proxy resolution failed for content.warframe.com and no manual fallback proxy is configured.\n"
            + "\n".join(errors)
        )
    return None, None

def make_recovery_state(before: dict[str, object], applied: dict[str, object], session: Path, proxy_port: int) -> dict[str, object]:
    return {
        "version": RECOVERY_VERSION,
        "application_version": VERSION,
        "created": current_timestamp(),
        "session": str(session),
        "local_proxy": f"127.0.0.1:{proxy_port}",
        "before": normalized_settings(before),
        "applied": normalized_settings(applied),
    }

def validate_recovery_state(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RuntimeError("Proxy recovery file must contain a JSON object.")
    if value.get("version") != RECOVERY_VERSION:
        raise RuntimeError(
            f"Unsupported proxy recovery format version: {value.get('version')!r}. Expected version {RECOVERY_VERSION}."
        )
    required = {"version", "application_version", "created", "session", "local_proxy", "before", "applied"}
    if set(value) != required:
        raise RuntimeError("Proxy recovery file contains an invalid set of fields.")
    for key in ("application_version", "created", "session", "local_proxy"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise RuntimeError(f"Proxy recovery file contains an invalid {key} value.")
    for key in ("before", "applied"):
        value[key] = normalized_settings(value.get(key))
    return value

def load_recovery_state(path: Path | None = None) -> dict[str, object]:
    path = proxy_recovery_file() if path is None else path
    try:
        value = parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read proxy recovery file {path}: {exc}") from exc
    return validate_recovery_state(value)

def archive_unowned_recovery(path: Path | None = None) -> Path:
    path = proxy_recovery_file() if path is None else path
    suffix = current_timestamp().replace(":", "-").replace("+", "_")
    archived = path.with_name(path.name + f".unowned-{suffix}")
    counter = 2
    while archived.exists():
        archived = path.with_name(path.name + f".unowned-{suffix}-{counter}")
        counter += 1
    path.rename(archived)
    return archived

def proxy_settings_match_recovery_transition(
    current: object, before: object, applied: object
) -> bool:
    try:
        current_settings = normalized_settings(current)
        before_settings = normalized_settings(before)
        applied_settings = normalized_settings(applied)
    except RuntimeError:
        return False
    return all(
        _proxy_setting_equivalent(name, current_settings[name], before_settings[name])
        or _proxy_setting_equivalent(name, current_settings[name], applied_settings[name])
        for name in PROXY_SETTING_NAMES
    )

def _unlink_recovery_file(path: Path) -> str | None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        return str(exc)
    return None

def restore_stale_recovery(path: Path | None = None) -> str | None:
    path = proxy_recovery_file() if path is None else path
    if not path.exists():
        return None
    recovery = load_recovery_state(path)
    current = get_proxy_settings()
    if proxy_settings_equivalent(current, recovery["applied"]):
        restore_proxy_settings(recovery["before"])
        cleanup_error = _unlink_recovery_file(path)
        return "restored-kept" if cleanup_error else "restored"
    if proxy_settings_equivalent(current, recovery["before"]):
        # Re-apply the already-restored registry snapshot so WinINet receives the
        # SETTINGS_CHANGED/REFRESH notifications again. A previous interrupted
        # cleanup may have written the values successfully but failed before the
        # notification reached applications.
        restore_proxy_settings(recovery["before"])
        cleanup_error = _unlink_recovery_file(path)
        return "restored-kept" if cleanup_error else None
    if proxy_settings_match_recovery_transition(current, recovery["before"], recovery["applied"]):
        restore_proxy_settings(recovery["before"])
        cleanup_error = _unlink_recovery_file(path)
        return "restored-kept" if cleanup_error else "restored"
    archived = archive_unowned_recovery(path)
    return f"unowned:{archived}"

def activate_local_proxy(before: dict[str, object], session: Path, proxy_port: int, path: Path | None = None) -> dict[str, object]:
    path = proxy_recovery_file() if path is None else path
    if path.exists():
        raise RuntimeError(
            f"Unresolved System Proxy recovery data already exists at: {path}. "
            "Restart Ninja Capture Tool so the previous proxy state can be recovered before starting another System Proxy session."
        )
    applied = build_local_proxy_settings(before, proxy_port)
    atomic_write_json(path, make_recovery_state(before, applied, session, proxy_port))
    try:
        apply_proxy_settings(applied)
        # WinINet/Windows can normalize disabled optional values after the
        # settings-change notification. Verify the effective state, with a few
        # short read-back retries, instead of requiring byte-for-byte registry
        # identity on the first read.
        current = verify_applied_proxy_settings(applied)
    except Exception as activation_exc:
        try:
            restore_proxy_settings(before)
        except Exception as restore_exc:
            raise RuntimeError(
                f"Could not enable System Proxy ({activation_exc}); restoring the previous Windows proxy settings also failed: "
                f"{restore_exc}. Recovery data was kept at: {path}"
            ) from restore_exc
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    # Keep the exact representation Windows reported for clean shutdown. The
    # recovery file deliberately retains the intended representation written
    # before activation; stale-recovery matching accepts equivalent normalized
    # disabled forms.
    return current

def deactivate_local_proxy(
    before: dict[str, object],
    applied: dict[str, object],
    path: Path | None = None,
) -> ProxyDeactivationResult:
    current = get_proxy_settings()
    if not (
        proxy_settings_equivalent(current, applied)
        or proxy_settings_match_recovery_transition(current, before, applied)
    ):
        return ProxyDeactivationResult(False)
    restore_proxy_settings(before)
    recovery_path = proxy_recovery_file() if path is None else path
    cleanup_error = _unlink_recovery_file(recovery_path)
    return ProxyDeactivationResult(True, cleanup_error)

def ensure_port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            sock.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(f"Local proxy port 127.0.0.1:{port} is already in use.") from exc
