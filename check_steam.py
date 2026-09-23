#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import os
import re
import struct
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import common

WARFRAME_VERSION_URL = "https://conduit.browse.wf/current-version"
WARFRAME_STEAM_APP_ID = 230410
WARFRAME_STEAM_DEPOT_ID = 230411
STEAM_MANIFEST_MIN_VALID_SIZE = 10 * 1024**3
# Accept 2-4 numeric components, e.g. 43.5, 43.5.4, or 43.5.4.1.
_WARFRAME_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,3}$")
_STEAM_APPINFO_CACHE_LOCK = threading.Lock()
_STEAM_APPINFO_CACHE: dict[str, tuple[tuple[int, int], dict[str, object]]] = {}
STEAM_QUERY_WORKER_ARGUMENT = "--internal-steam-query-worker"
STEAM_QUERY_WORKER_SMOKE_ARGUMENT = "--internal-steam-query-worker-smoke"
STEAM_QUERY_RESULT_PREFIX = "__NINJA_STEAM_RESULT__:"
STEAM_QUERY_STAGE_PREFIX = "__NINJA_STEAM_STAGE__:"
WARFRAME_QUERY_WORKER_ARGUMENT = "--internal-warframe-query-worker"
WARFRAME_QUERY_RESULT_PREFIX = "__NINJA_WARFRAME_RESULT__:"

def _read_steam_cstring(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("Unterminated Steam app-info string.")
    try:
        value = data[offset:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Steam app-info contains an invalid UTF-8 string.") from exc
    return value, end + 1

def _parse_steam_string_table(data: bytes, offset: int) -> list[str]:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("Steam app-info string table offset is invalid.")
    count = int.from_bytes(data[offset:offset + 4], "little")
    offset += 4
    if count > 1_000_000:
        raise ValueError("Steam app-info string table is implausibly large.")
    result: list[str] = []
    for _ in range(count):
        value, offset = _read_steam_cstring(data, offset)
        result.append(value)
    return result

def _parse_steam_binary_vdf(data: bytes, *, string_table: list[str] | None = None) -> dict[str, object]:
    offset = 0

    def read(size: int) -> bytes:
        nonlocal offset
        end = offset + size
        if size < 0 or end > len(data):
            raise ValueError("Steam app-info binary VDF is truncated.")
        value = data[offset:end]
        offset = end
        return value

    def read_key() -> str:
        nonlocal offset
        if string_table is None:
            value, offset = _read_steam_cstring(data, offset)
            return value
        index = int.from_bytes(read(4), "little")
        if index >= len(string_table):
            raise ValueError("Steam app-info binary VDF references an invalid string-table key.")
        return string_table[index]

    def read_object() -> dict[str, object]:
        nonlocal offset
        result: dict[str, object] = {}
        while True:
            value_type = read(1)[0]
            if value_type == 0x08:
                return result
            key = read_key()
            if value_type == 0x00:
                value: object = read_object()
            elif value_type == 0x01:
                value, offset = _read_steam_cstring(data, offset)
            elif value_type == 0x02:
                value = int.from_bytes(read(4), "little", signed=True)
            elif value_type == 0x03:
                value = struct.unpack("<f", read(4))[0]
            elif value_type == 0x04:
                value = int.from_bytes(read(4), "little")
            elif value_type == 0x05:
                raw = bytearray()
                while True:
                    unit = read(2)
                    if unit == b"\0\0":
                        break
                    raw.extend(unit)
                try:
                    value = bytes(raw).decode("utf-16-le")
                except UnicodeDecodeError as exc:
                    raise ValueError("Steam app-info contains an invalid UTF-16 string.") from exc
            elif value_type == 0x06:
                value = int.from_bytes(read(4), "little")
            elif value_type == 0x07:
                value = int.from_bytes(read(8), "little")
            elif value_type == 0x0A:
                value = int.from_bytes(read(8), "little", signed=True)
            elif value_type == 0x0B:
                value = read(1)[0]
            elif value_type == 0x0C:
                value = 0
            elif value_type == 0x0D:
                value = 1
            else:
                raise ValueError(f"Unsupported Steam app-info binary VDF type 0x{value_type:02X}.")
            result[key] = value

    parsed = read_object()
    if offset != len(data) and any(byte != 0 for byte in data[offset:]):
        raise ValueError("Steam app-info binary VDF has unexpected trailing data.")
    return parsed

def _find_steam_appinfo_path() -> Path:
    candidates: list[Path] = []
    override = os.environ.get("STEAM_PATH")
    if override:
        candidates.append(Path(override).expanduser())

    if sys.platform == "win32":
        try:
            import winreg
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for key_name in (r"Software\Valve\Steam", r"Software\WOW6432Node\Valve\Steam"):
                    try:
                        with winreg.OpenKey(hive, key_name) as key:
                            for value_name in ("SteamPath", "InstallPath", "SteamExe"):
                                try:
                                    raw, _ = winreg.QueryValueEx(key, value_name)
                                except OSError:
                                    continue
                                if isinstance(raw, str) and raw.strip():
                                    path = Path(raw.strip())
                                    candidates.append(path.parent if path.suffix.casefold() == ".exe" else path)
                    except OSError:
                        continue
        except ImportError:
            pass
        for variable in ("ProgramFiles(x86)", "ProgramFiles"):
            root = os.environ.get(variable)
            if root:
                candidates.append(Path(root) / "Steam")
    else:
        home = Path.home()
        candidates.extend((home / ".steam" / "steam", home / ".local" / "share" / "Steam"))

    seen: set[str] = set()
    for root in candidates:
        key = str(root).casefold()
        if key in seen:
            continue
        seen.add(key)
        path = root / "appcache" / "appinfo.vdf"
        if path.is_file():
            return path
    raise RuntimeError("Steam app-info cache was not found.")

def _optional_nonnegative_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None

def _steam_numeric_field(mapping: dict[str, object], key: str, label: str) -> int | None:
    if key not in mapping or mapping[key] is None:
        return None
    parsed = _optional_nonnegative_int(mapping[key])
    if parsed is None:
        raise RuntimeError(f"Steam app info contains an invalid {label}.")
    return parsed

def normalize_live_query_error(error: object, fallback: str = "unknown error") -> str:
    text = str(error).strip() if error is not None else ""
    return " ".join(text.split()) or fallback

def summarize_steam_live_query_error(error: str | None) -> str:
    text = normalize_live_query_error(error, "")
    lowered = text.casefold()
    if "pysteam-client" in lowered or "no module named 'steam'" in lowered or 'no module named "steam"' in lowered:
        return "Steam client dependency missing"
    if "timed out" in lowered or "timeout" in lowered:
        return "query timed out"
    if "anonymous steam login failed" in lowered:
        return "anonymous Steam login failed"
    if "access token" in lowered:
        return "Steam access token unavailable"
    if "worker" in lowered and ("tagged result" in lowered or "invalid json" in lowered or "invalid result schema" in lowered):
        return "Steam query worker failed"
    return "query failed"

def _steam_manifest_status(size: int | None, download_size: int | None) -> str:
    # Never trust a changed GID by itself. Warframe depot 230411 briefly published
    # the empty manifest 5112463999164762556 on 2026-02-11 before DE replaced it.
    # A plausible Warframe base is far larger than 10 GiB, so anything below that
    # threshold is invalid. An explicit zero download size is also invalid even if the
    # reported installed size looks plausible.
    if download_size == 0:
        return "invalid"
    if size is not None:
        return "valid" if size >= STEAM_MANIFEST_MIN_VALID_SIZE else "invalid"
    return "unvalidated"

def _steam_manifest_from_app_data(
    app_data: dict[str, object],
    *,
    source_kind: str,
) -> dict[str, object]:
    if source_kind not in {"live", "cache"}:
        raise ValueError("Steam manifest source kind must be 'live' or 'cache'.")
    root = app_data.get("appinfo") if isinstance(app_data.get("appinfo"), dict) else app_data
    depots = root.get("depots") if isinstance(root, dict) else None
    depot = depots.get(str(WARFRAME_STEAM_DEPOT_ID)) if isinstance(depots, dict) else None
    manifests = depot.get("manifests") if isinstance(depot, dict) else None
    public = manifests.get("public") if isinstance(manifests, dict) else None
    if isinstance(public, (str, int)):
        public = {"gid": public}
    if not isinstance(public, dict):
        raise RuntimeError(f"Warframe depot {WARFRAME_STEAM_DEPOT_ID} has no public manifest in Steam app info.")

    try:
        manifest_id = int(str(public["gid"]).strip())
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("Steam app info contains an invalid Warframe public manifest ID.") from None
    if manifest_id <= 0 or manifest_id > 0xFFFFFFFFFFFFFFFF:
        raise RuntimeError("Steam app info contains an out-of-range Warframe public manifest ID.")

    size = _steam_numeric_field(public, "size", "Warframe public manifest size")
    download_size = _steam_numeric_field(public, "download", "Warframe public manifest download size")
    return {
        "manifest_id": manifest_id,
        "size": size,
        "status": _steam_manifest_status(size, download_size),
        "source_kind": source_kind,
    }

def read_steam_cached_public_manifest(appinfo_path: Path | None = None) -> dict[str, object]:
    """Read Warframe's public depot manifest from Steam's local app-info cache."""
    path = _find_steam_appinfo_path() if appinfo_path is None else appinfo_path
    try:
        stat_before = path.stat()
    except OSError as exc:
        raise RuntimeError(f"Could not stat Steam app-info cache {path}: {exc}") from exc
    signature = (stat_before.st_size, stat_before.st_mtime_ns)
    cache_key = str(path.resolve(strict=False))
    with _STEAM_APPINFO_CACHE_LOCK:
        cached = _STEAM_APPINFO_CACHE.get(cache_key)
        if cached is not None and cached[0] == signature:
            return dict(cached[1])

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read Steam app-info cache {path}: {exc}") from exc
    if len(data) < 8:
        raise RuntimeError("Steam app-info cache is truncated.")

    magic = int.from_bytes(data[0:4], "little")
    if magic == 0x07564429:
        if len(data) < 16:
            raise RuntimeError("Steam app-info v41 header is truncated.")
        string_table_offset = int.from_bytes(data[8:16], "little")
        string_table = _parse_steam_string_table(data, string_table_offset)
        offset = 16
        entries_end = string_table_offset
    elif magic == 0x07564428:
        string_table = None
        offset = 8
        entries_end = len(data)
    else:
        raise RuntimeError(f"Unsupported Steam app-info format 0x{magic:08X}.")

    while offset + 4 <= entries_end:
        entry_start = offset
        app_id = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        if app_id == 0:
            break
        if offset + 4 > entries_end:
            raise RuntimeError("Steam app-info entry header is truncated.")
        entry_size = int.from_bytes(data[offset:offset + 4], "little")
        entry_end = entry_start + 8 + entry_size
        if entry_size < 60 or entry_end > entries_end:
            raise RuntimeError("Steam app-info entry size is invalid.")
        if app_id != WARFRAME_STEAM_APP_ID:
            offset = entry_end
            continue

        payload = data[entry_start + 68:entry_end]
        try:
            app_data = _parse_steam_binary_vdf(payload, string_table=string_table)
        except ValueError as exc:
            raise RuntimeError(f"Could not parse Warframe Steam app info: {exc}") from exc
        result = _steam_manifest_from_app_data(app_data, source_kind="cache")
        # Cache only a stable snapshot. If Steam rewrote appinfo.vdf while it was
        # being read, return what we parsed but force a fresh read next time.
        try:
            stat_after = path.stat()
        except OSError:
            stat_after = None
        if stat_after is not None and (stat_after.st_size, stat_after.st_mtime_ns) == signature:
            with _STEAM_APPINFO_CACHE_LOCK:
                _STEAM_APPINFO_CACHE[cache_key] = (signature, dict(result))
        return result

    raise RuntimeError(f"Warframe app {WARFRAME_STEAM_APP_ID} was not found in Steam app info.")

def query_steam_public_manifest(
    timeout: float = 30.0,
    *,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    """Query Valve's Steam network directly through anonymous Steam product info (PICS)."""
    try:
        from steam.client import SteamClient
    except ImportError as exc:
        raise RuntimeError(f"pysteam-client[client] {common.STEAM_CLIENT_VERSION} is required for live Steam manifest queries") from exc

    request_timeout = max(1, int(round(timeout)))

    def report(stage: str) -> None:
        if progress is not None:
            progress(stage)

    def app_data_from_product_info(product_info: object) -> dict[str, object]:
        if not isinstance(product_info, dict):
            raise RuntimeError("Steam live query returned no product information")
        apps = product_info.get("apps")
        app_data = apps.get(WARFRAME_STEAM_APP_ID) if isinstance(apps, dict) else None
        if app_data is None and isinstance(apps, dict):
            app_data = apps.get(str(WARFRAME_STEAM_APP_ID))
        if not isinstance(app_data, dict):
            raise RuntimeError(f"Steam live query returned no data for app {WARFRAME_STEAM_APP_ID}")
        return app_data

    client = None
    stage = "client initialization"
    try:
        report(stage)
        client = SteamClient()

        stage = "anonymous login"
        report(stage)
        result = client.anonymous_login()
        try:
            result_code = int(result)
        except (TypeError, ValueError):
            result_code = int(getattr(result, "value", 0))
        if result_code != 1:
            raise RuntimeError(f"anonymous Steam login failed ({result})")

        # Warframe's public app info normally needs no access token. Avoid the
        # extra PICS token request unless Valve explicitly marks the response as
        # missing one; this keeps the common path faster and more predictable.
        stage = "public product info"
        report(stage)
        app_data = app_data_from_product_info(
            client.get_product_info(
                apps=[WARFRAME_STEAM_APP_ID],
                auto_access_tokens=False,
                timeout=request_timeout,
            )
        )
        if app_data.get("_missing_token"):
            stage = "access-token product info"
            report(stage)
            app_data = app_data_from_product_info(
                client.get_product_info(
                    apps=[WARFRAME_STEAM_APP_ID],
                    auto_access_tokens=True,
                    timeout=request_timeout,
                )
            )
            if app_data.get("_missing_token"):
                raise RuntimeError(f"Steam live query requires an access token for app {WARFRAME_STEAM_APP_ID}")

        stage = "manifest parsing"
        report(stage)
        return _steam_manifest_from_app_data(app_data, source_kind="live")
    except RuntimeError as exc:
        raise RuntimeError(f"{stage}: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"{stage}: {str(exc) or exc.__class__.__name__}") from exc
    finally:
        if client is not None:
            stage = "connection cleanup"
            report(stage)
            try:
                if getattr(client, "logged_on", False):
                    client.logout()
            except Exception:
                pass
            try:
                client.disconnect()
            except Exception:
                pass

def _steam_query_worker_timeout(argv: list[str] | None = None) -> float | None:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != STEAM_QUERY_WORKER_ARGUMENT:
        return None
    if len(args) != 2:
        raise ValueError("Steam query worker requires exactly one timeout argument")
    try:
        timeout = float(args[1])
    except ValueError as exc:
        raise ValueError("Steam query worker timeout must be numeric") from exc
    if not math.isfinite(timeout) or not 1.0 <= timeout <= 60.0:
        raise ValueError("Steam query worker timeout must be between 1 and 60 seconds")
    return timeout

def _validate_steam_worker_info(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Steam query worker returned an invalid info object")

    expected_keys = {"manifest_id", "size", "status", "source_kind"}
    if set(value) != expected_keys:
        raise ValueError("Steam query worker returned an invalid info schema")

    manifest_id = value.get("manifest_id")
    if not isinstance(manifest_id, int) or isinstance(manifest_id, bool) or not (0 < manifest_id <= 0xFFFFFFFFFFFFFFFF):
        raise ValueError("Steam query worker returned an invalid manifest ID")

    size = value.get("size")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
        raise ValueError("Steam query worker returned an invalid size")

    status = value.get("status")
    if status not in {"valid", "invalid", "unvalidated"}:
        raise ValueError("Steam query worker returned an invalid manifest status")
    if size is None and status == "valid":
        raise ValueError("Steam query worker returned inconsistent manifest status")
    if isinstance(size, int) and size < STEAM_MANIFEST_MIN_VALID_SIZE and status != "invalid":
        raise ValueError("Steam query worker returned inconsistent manifest status")
    if isinstance(size, int) and size >= STEAM_MANIFEST_MIN_VALID_SIZE and status == "unvalidated":
        raise ValueError("Steam query worker returned inconsistent manifest status")
    if value.get("source_kind") != "live":
        raise ValueError("Steam query worker returned an unexpected source kind")
    return dict(value)

def _emit_steam_query_worker_stage(stage: str) -> None:
    sys.stdout.write(STEAM_QUERY_STAGE_PREFIX + stage + "\n")
    sys.stdout.flush()

def latest_steam_query_worker_stage(output: object) -> str | None:
    if not isinstance(output, str):
        return None
    stages = [
        line[len(STEAM_QUERY_STAGE_PREFIX):].strip()
        for line in output.splitlines()
        if line.startswith(STEAM_QUERY_STAGE_PREFIX)
    ]
    return stages[-1] if stages and stages[-1] else None

def _emit_steam_query_worker_payload(payload: dict[str, object]) -> None:
    sys.stdout.write(STEAM_QUERY_RESULT_PREFIX + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def handle_steam_query_worker_request(argv: list[str] | None = None) -> int | None:
    """Run a hidden Steam worker mode when this process was spawned internally."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in {STEAM_QUERY_WORKER_ARGUMENT, STEAM_QUERY_WORKER_SMOKE_ARGUMENT}:
        return None

    if args[0] == STEAM_QUERY_WORKER_SMOKE_ARGUMENT:
        if len(args) != 1:
            _emit_steam_query_worker_payload({"ok": False, "error": "Steam worker smoke mode accepts no arguments"})
            return 2
        try:
            from steam.client import SteamClient
            if SteamClient is None:
                raise ImportError("steam.client.SteamClient is unavailable")
        except BaseException as exc:
            _emit_steam_query_worker_payload({"ok": False, "error": normalize_live_query_error(exc, exc.__class__.__name__)})
            return 1
        _emit_steam_query_worker_payload({"ok": True, "smoke": "steam-import"})
        return 0

    try:
        timeout = _steam_query_worker_timeout(args)
    except ValueError as exc:
        _emit_steam_query_worker_payload({"ok": False, "error": str(exc)})
        return 2
    assert timeout is not None
    try:
        payload = {"ok": True, "info": query_steam_public_manifest(timeout=timeout, progress=_emit_steam_query_worker_stage)}
    except BaseException as exc:
        payload = {"ok": False, "error": normalize_live_query_error(exc, exc.__class__.__name__)}
    _emit_steam_query_worker_payload(payload)
    return 0

def _attach_steam_worker_kill_job(process: subprocess.Popen) -> None:
    """Tie a Windows Steam worker to this parent with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE."""
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    class JobObjectBasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JobObjectExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JobObjectBasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = JobObjectExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        process_handle = getattr(process, "_handle", None)
        if process_handle is None:
            raise RuntimeError("Steam query worker process handle is unavailable")
        if not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(int(process_handle))):
            raise ctypes.WinError(ctypes.get_last_error())
    except Exception:
        kernel32.CloseHandle(job)
        raise
    setattr(process, "_ninja_steam_job_handle", job)

def _close_steam_worker_kill_job(process: subprocess.Popen) -> None:
    if sys.platform != "win32":
        return
    handle = getattr(process, "_ninja_steam_job_handle", None)
    if not handle:
        return
    setattr(process, "_ninja_steam_job_handle", None)
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(handle)
    except (AttributeError, OSError, TypeError, ValueError):
        pass

def _start_query_subprocess(worker_argument: str, timeout: float, entry_script: Path | None) -> subprocess.Popen:
    worker_timeout = max(1.0, min(float(timeout), 60.0))
    if getattr(sys, "frozen", False):
        command = [sys.executable]
    else:
        script = (entry_script or Path(sys.argv[0])).resolve()
        command = [sys.executable, str(script)]
    command.extend((worker_argument, f"{worker_timeout:g}"))
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
    )
    try:
        _attach_steam_worker_kill_job(process)
    except Exception:
        # Parent-death cleanup is additional hardening, not a requirement for
        # the live query. The normal deadline/termination path still owns the
        # worker if Windows or a host Job Object policy rejects assignment.
        pass
    return process

def start_warframe_query_subprocess(timeout: float = 30.0, *, entry_script: Path | None = None) -> subprocess.Popen:
    """Start a killable child process that performs only the Warframe version query."""
    return _start_query_subprocess(WARFRAME_QUERY_WORKER_ARGUMENT, timeout, entry_script)

def start_steam_query_subprocess(timeout: float = 30.0, *, entry_script: Path | None = None) -> subprocess.Popen:
    """Start a killable child process that performs only the direct Steam live query."""
    return _start_query_subprocess(STEAM_QUERY_WORKER_ARGUMENT, timeout, entry_script)

def collect_warframe_query_subprocess(process: subprocess.Popen) -> tuple[str | None, str | None]:
    """Collect and validate a completed Warframe version worker result."""
    if process.poll() is None:
        raise RuntimeError("Warframe query worker is still running.")
    try:
        stdout, _ = process.communicate(timeout=0.25)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Warframe query worker did not close its output pipe.") from exc
    finally:
        _close_steam_worker_kill_job(process)
    tagged = [
        line[len(WARFRAME_QUERY_RESULT_PREFIX):].strip()
        for line in (stdout or "").splitlines()
        if line.startswith(WARFRAME_QUERY_RESULT_PREFIX)
    ]
    if not tagged:
        return None, f"Warframe query worker exited with code {process.returncode} without returning a tagged result"
    try:
        payload = json.loads(tagged[-1])
    except json.JSONDecodeError:
        return None, "Warframe query worker returned invalid JSON"
    if not isinstance(payload, dict):
        return None, "Warframe query worker returned an invalid result schema"
    if payload.get("ok") is True:
        if set(payload) != {"ok", "version"}:
            return None, "Warframe query worker returned an invalid result schema"
        version = payload.get("version")
        if not isinstance(version, str) or not _WARFRAME_VERSION_RE.fullmatch(version):
            return None, "Warframe query worker returned an invalid version"
        return version, None
    if payload.get("ok") is not False or set(payload) != {"ok", "error"}:
        return None, "Warframe query worker returned an invalid result schema"
    error = payload.get("error")
    if not isinstance(error, str) or not error.strip():
        return None, "Warframe query worker failed without a valid error message"
    return None, normalize_live_query_error(error)

def collect_steam_query_subprocess(process: subprocess.Popen) -> tuple[dict[str, object] | None, str | None]:
    """Collect and validate a completed Steam worker result."""
    if process.poll() is None:
        raise RuntimeError("Steam query worker is still running.")
    try:
        stdout, _ = process.communicate(timeout=0.25)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Steam query worker did not close its output pipe.") from exc
    finally:
        _close_steam_worker_kill_job(process)
    tagged = [
        line[len(STEAM_QUERY_RESULT_PREFIX):].strip()
        for line in (stdout or "").splitlines()
        if line.startswith(STEAM_QUERY_RESULT_PREFIX)
    ]
    if not tagged:
        return None, f"Steam query worker exited with code {process.returncode} without returning a tagged result"
    try:
        payload = json.loads(tagged[-1])
    except json.JSONDecodeError:
        return None, "Steam query worker returned invalid JSON"
    if not isinstance(payload, dict):
        return None, "Steam query worker returned an invalid result schema"
    if payload.get("ok") is True:
        if set(payload) != {"ok", "info"}:
            return None, "Steam query worker returned an invalid result schema"
        try:
            return _validate_steam_worker_info(payload.get("info")), None
        except ValueError as exc:
            return None, str(exc)
    if payload.get("ok") is not False or set(payload) != {"ok", "error"}:
        return None, "Steam query worker returned an invalid result schema"
    error = payload.get("error")
    if not isinstance(error, str) or not error.strip():
        return None, "Steam query worker failed without a valid error message"
    return None, normalize_live_query_error(error)

def terminate_steam_query_subprocess(process: subprocess.Popen, *, timeout: float = 1.0) -> str:
    """Hard-stop an internal Steam worker, reap it, and return any captured worker output."""
    if process.poll() is not None:
        try:
            stdout, _ = process.communicate(timeout=0.1)
        except (OSError, subprocess.TimeoutExpired):
            stdout = ""
        finally:
            _close_steam_worker_kill_job(process)
        return stdout or ""
    try:
        process.terminate()
    except OSError:
        pass
    wait_timeout = max(0.0, timeout)
    kill_timeout = min(0.5, max(0.1, wait_timeout))
    try:
        process.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=kill_timeout)
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        stdout, _ = process.communicate(timeout=min(0.1, kill_timeout))
    except (OSError, subprocess.TimeoutExpired):
        stdout = ""
    finally:
        _close_steam_worker_kill_job(process)
    return stdout or ""

def terminate_warframe_query_subprocess(process: subprocess.Popen, *, timeout: float = 1.0) -> str:
    return terminate_steam_query_subprocess(process, timeout=timeout)

def steam_manifest_with_cache_fallback(
    live_info: dict[str, object] | None,
    live_error: str | None,
) -> tuple[dict[str, object] | None, str | None]:
    """Use the local Steam cache only when the direct Steam worker failed."""
    if live_info is not None:
        return live_info, None
    error = live_error or "unknown Steam query failure"
    try:
        cached = read_steam_cached_public_manifest()
    except Exception as cache_exc:
        return None, f"direct Steam live query failed: {error}; local Steam cache fallback failed: {cache_exc}"
    cached = dict(cached)
    cached["live_error"] = error
    return cached, None

def fetch_current_warframe_version(timeout: float = 30.0) -> str:
    from common import VERSION
    request = urllib.request.Request(
        WARFRAME_VERSION_URL,
        headers={
            "User-Agent": f"NinjaCaptureTool/{VERSION}",
            "Accept": "text/plain",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            final = urlsplit(response.geturl())
            if final.scheme.casefold() != "https" or (final.hostname or "").casefold() != "conduit.browse.wf":
                raise RuntimeError("version endpoint redirected to an unexpected host")
            payload = response.read(65)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(str(reason)) from exc
    except TimeoutError as exc:
        raise RuntimeError("request timed out") from exc
    if len(payload) > 64:
        raise RuntimeError("response was unexpectedly large")
    try:
        version = payload.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("response was not ASCII text") from exc
    if not _WARFRAME_VERSION_RE.fullmatch(version):
        raise RuntimeError(f"invalid version string: {version!r}")
    return version

def summarize_warframe_live_query_error(error: str | None) -> str:
    text = normalize_live_query_error(error)
    lowered = text.casefold()
    if "handshake operation timed out" in lowered:
        return "TLS handshake timed out"
    if "getaddrinfo failed" in lowered or "11001" in lowered:
        return "DNS lookup failed"
    if "10053" in lowered:
        return "connection aborted locally"
    if "10054" in lowered:
        return "connection reset by peer"
    if "timed out" in lowered or "timeout" in lowered:
        return "query timed out"
    return text

def _warframe_query_worker_timeout(argv: list[str] | None = None) -> float | None:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != WARFRAME_QUERY_WORKER_ARGUMENT:
        return None
    if len(args) != 2:
        raise ValueError("Warframe query worker requires exactly one timeout argument")
    try:
        timeout = float(args[1])
    except ValueError as exc:
        raise ValueError("Warframe query worker timeout must be numeric") from exc
    if not math.isfinite(timeout) or not 1.0 <= timeout <= 60.0:
        raise ValueError("Warframe query worker timeout must be between 1 and 60 seconds")
    return timeout

def _emit_warframe_query_worker_payload(payload: dict[str, object]) -> None:
    sys.stdout.write(WARFRAME_QUERY_RESULT_PREFIX + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()

def handle_warframe_query_worker_request(argv: list[str] | None = None) -> int | None:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] != WARFRAME_QUERY_WORKER_ARGUMENT:
        return None
    try:
        timeout = _warframe_query_worker_timeout(args)
    except ValueError as exc:
        _emit_warframe_query_worker_payload({"ok": False, "error": str(exc)})
        return 2
    assert timeout is not None
    try:
        payload = {"ok": True, "version": fetch_current_warframe_version(timeout=timeout)}
    except BaseException as exc:
        payload = {"ok": False, "error": normalize_live_query_error(exc, exc.__class__.__name__)}
    _emit_warframe_query_worker_payload(payload)
    return 0

def _optional_state_manifest_id(value: object, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Invalid {label} in Warframe live state.")
    return value

def _optional_state_nonnegative_int(value: object, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"Invalid {label} in Warframe live state.")
    return value

def _optional_state_timestamp(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("Invalid high-water observation timestamp in Warframe live state.")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("Invalid high-water observation timestamp in Warframe live state.") from exc
    return value

def _version_content_branch(version: str) -> str:
    parts = version.split(".")
    return f"{int(parts[0])}.{int(parts[1])}"

def _content_branch_key(branch: str) -> tuple[int, int]:
    major, minor = branch.split(".", 1)
    return int(major), int(minor)

def _validate_steam_tracking_state(
    *,
    high_water_version: str,
    last_valid_steam_manifest_id: object,
    last_valid_steam_manifest_size: object,
    awaiting_content_branch: object,
    awaiting_from_manifest_id: object,
    pre_transition_manifest_id: object = None,
    pre_transition_manifest_size: object = None,
    pre_transition_content_branch: object = None,
) -> dict[str, object]:
    last_manifest_id = _optional_state_manifest_id(last_valid_steam_manifest_id, "Steam manifest ID")
    last_manifest_size = _optional_state_nonnegative_int(last_valid_steam_manifest_size, "Steam manifest size")
    awaiting_manifest_id = _optional_state_manifest_id(awaiting_from_manifest_id, "awaiting Steam manifest ID")
    branch = awaiting_content_branch
    if branch is not None and (not isinstance(branch, str) or not re.fullmatch(r"\d+\.\d+", branch)):
        raise ValueError("Invalid awaiting content branch in Warframe live state.")
    if last_manifest_id is None and last_manifest_size is not None:
        raise ValueError("Incomplete saved Steam manifest state.")
    if last_manifest_id is not None:
        if last_manifest_size is None:
            raise ValueError("Saved valid Steam manifest is missing its installed size.")
        if last_manifest_size < STEAM_MANIFEST_MIN_VALID_SIZE:
            raise ValueError("Saved valid Steam manifest is below the minimum valid installed size.")
    if branch is None and awaiting_manifest_id is not None:
        raise ValueError("Incomplete awaiting Steam manifest state.")
    if branch is not None and branch != _version_content_branch(high_water_version):
        raise ValueError("Awaiting Steam content branch does not match the Warframe high-water version.")

    result: dict[str, object] = {
        "last_valid_steam_manifest_id": last_manifest_id,
        "last_valid_steam_manifest_size": last_manifest_size,
        "awaiting_content_branch": branch,
        "awaiting_from_manifest_id": awaiting_manifest_id,
    }
    candidate_id = _optional_state_manifest_id(pre_transition_manifest_id, "pre-transition Steam manifest ID")
    candidate_size = _optional_state_nonnegative_int(pre_transition_manifest_size, "pre-transition Steam manifest size")
    candidate_branch = pre_transition_content_branch
    if candidate_branch is not None and (
        not isinstance(candidate_branch, str) or not re.fullmatch(r"\d+\.\d+", candidate_branch)
    ):
        raise ValueError("Invalid pre-transition content branch in Warframe live state.")
    if candidate_id is None:
        if any(item is not None for item in (candidate_size, candidate_branch)):
            raise ValueError("Incomplete pre-transition Steam manifest state.")
    elif candidate_branch is None:
        raise ValueError("Incomplete pre-transition Steam manifest state.")
    else:
        if candidate_size is None:
            raise ValueError("Saved pre-transition Steam candidate is missing its installed size.")
        if candidate_size < STEAM_MANIFEST_MIN_VALID_SIZE:
            raise ValueError("Saved pre-transition Steam candidate is below the minimum valid installed size.")
        if candidate_id != last_manifest_id or candidate_size != last_manifest_size:
            raise ValueError("Pre-transition Steam candidate does not match the last valid Steam manifest.")
        high_water_branch = _version_content_branch(high_water_version)
        if branch is None:
            if candidate_branch != high_water_branch:
                raise ValueError("Idle pre-transition Steam candidate does not match the Warframe high-water branch.")
        else:
            if _content_branch_key(candidate_branch) >= _content_branch_key(high_water_branch):
                raise ValueError("Pending pre-transition Steam candidate must belong to an older content branch.")
            if awaiting_manifest_id != candidate_id:
                raise ValueError("Pending pre-transition Steam candidate does not match the awaiting manifest baseline.")
    result.update(
        {
            "pre_transition_manifest_id": candidate_id,
            "pre_transition_manifest_size": candidate_size,
            "pre_transition_content_branch": candidate_branch,
        }
    )
    return result

def load_live_tracking_state(path: Path | None = None) -> dict[str, object]:
    path = common.warframe_version_state_file() if path is None else path
    from common import read_json_object
    if not path.exists():
        return {}
    value = read_json_object(path)
    version = value.get("high_water_version")
    if not isinstance(version, str) or not _WARFRAME_VERSION_RE.fullmatch(version):
        raise RuntimeError(f"Invalid Warframe version state: {path}")
    observed_at = _optional_state_timestamp(value.get("high_water_observed_at"))
    result: dict[str, object] = {"high_water_version": version}
    if observed_at is not None:
        result["high_water_observed_at"] = observed_at
    try:
        steam_state = _validate_steam_tracking_state(
            high_water_version=version,
            last_valid_steam_manifest_id=value.get("last_valid_steam_manifest_id"),
            last_valid_steam_manifest_size=value.get("last_valid_steam_manifest_size"),
            awaiting_content_branch=value.get("awaiting_content_branch"),
            awaiting_from_manifest_id=value.get("awaiting_from_manifest_id"),
            pre_transition_manifest_id=value.get("pre_transition_manifest_id"),
            pre_transition_manifest_size=value.get("pre_transition_manifest_size"),
            pre_transition_content_branch=value.get("pre_transition_content_branch"),
        )
    except ValueError as exc:
        raise RuntimeError(str(exc)) from exc
    result.update(steam_state)
    return result

def _write_live_tracking_state(
    *,
    high_water_version: str,
    high_water_observed_at: str | None = None,
    last_valid_steam_manifest_id: int | None = None,
    last_valid_steam_manifest_size: int | None = None,
    awaiting_content_branch: str | None = None,
    awaiting_from_manifest_id: int | None = None,
    pre_transition_manifest_id: int | None = None,
    pre_transition_manifest_size: int | None = None,
    pre_transition_content_branch: str | None = None,
    path: Path | None = None,
) -> None:
    path = common.warframe_version_state_file() if path is None else path
    from common import atomic_write_json, current_timestamp
    if not _WARFRAME_VERSION_RE.fullmatch(high_water_version):
        raise ValueError(f"Invalid Warframe version string: {high_water_version!r}")
    if high_water_observed_at is not None:
        try:
            datetime.fromisoformat(high_water_observed_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as exc:
            raise ValueError("Invalid high-water observation timestamp.") from exc
    _validate_steam_tracking_state(
        high_water_version=high_water_version,
        last_valid_steam_manifest_id=last_valid_steam_manifest_id,
        last_valid_steam_manifest_size=last_valid_steam_manifest_size,
        awaiting_content_branch=awaiting_content_branch,
        awaiting_from_manifest_id=awaiting_from_manifest_id,
        pre_transition_manifest_id=pre_transition_manifest_id,
        pre_transition_manifest_size=pre_transition_manifest_size,
        pre_transition_content_branch=pre_transition_content_branch,
    )
    state = {
        "high_water_version": high_water_version,
        "high_water_observed_at": high_water_observed_at or current_timestamp(),
        "last_valid_steam_manifest_id": last_valid_steam_manifest_id,
        "last_valid_steam_manifest_size": last_valid_steam_manifest_size,
        "awaiting_content_branch": awaiting_content_branch,
        "awaiting_from_manifest_id": awaiting_from_manifest_id,
        "pre_transition_manifest_id": pre_transition_manifest_id,
        "pre_transition_manifest_size": pre_transition_manifest_size,
        "pre_transition_content_branch": pre_transition_content_branch,
    }
    atomic_write_json(path, {key: value for key, value in state.items() if value is not None})

def load_warframe_version_high_water(path: Path | None = None) -> str | None:
    state = load_live_tracking_state(path)
    version = state.get("high_water_version")
    return version if isinstance(version, str) else None

def save_warframe_version_high_water(
    version: str,
    *,
    checked_at: str | None = None,
    path: Path | None = None,
) -> None:
    path = common.warframe_version_state_file() if path is None else path
    try:
        existing = load_live_tracking_state(path)
    except Exception:
        existing = {}
    _write_live_tracking_state(
        high_water_version=version,
        high_water_observed_at=checked_at,
        last_valid_steam_manifest_id=existing.get("last_valid_steam_manifest_id") if isinstance(existing.get("last_valid_steam_manifest_id"), int) else None,
        last_valid_steam_manifest_size=existing.get("last_valid_steam_manifest_size") if isinstance(existing.get("last_valid_steam_manifest_size"), int) else None,
        awaiting_content_branch=existing.get("awaiting_content_branch") if isinstance(existing.get("awaiting_content_branch"), str) else None,
        awaiting_from_manifest_id=existing.get("awaiting_from_manifest_id") if isinstance(existing.get("awaiting_from_manifest_id"), int) else None,
        pre_transition_manifest_id=existing.get("pre_transition_manifest_id") if isinstance(existing.get("pre_transition_manifest_id"), int) else None,
        pre_transition_manifest_size=existing.get("pre_transition_manifest_size") if isinstance(existing.get("pre_transition_manifest_size"), int) else None,
        pre_transition_content_branch=existing.get("pre_transition_content_branch") if isinstance(existing.get("pre_transition_content_branch"), str) else None,
        path=path,
    )

def save_steam_tracking_state(
    *,
    last_valid_steam_manifest_id: int | None,
    last_valid_steam_manifest_size: int | None,
    awaiting_content_branch: str | None,
    awaiting_from_manifest_id: int | None,
    pre_transition_manifest_id: int | None = None,
    pre_transition_manifest_size: int | None = None,
    pre_transition_content_branch: str | None = None,
    high_water_version: str | None = None,
    high_water_observed_at: str | None = None,
    path: Path | None = None,
) -> None:
    path = common.warframe_version_state_file() if path is None else path
    try:
        existing = load_live_tracking_state(path)
    except Exception:
        existing = {}
    existing_high_water = existing.get("high_water_version") if isinstance(existing.get("high_water_version"), str) else None
    high_water = high_water_version or existing_high_water
    if not isinstance(high_water, str):
        raise RuntimeError("Cannot save Steam tracking state before a Warframe version is known.")
    observed_at = high_water_observed_at
    if observed_at is None and existing_high_water == high_water:
        existing_observed_at = existing.get("high_water_observed_at")
        if isinstance(existing_observed_at, str):
            observed_at = existing_observed_at
    _write_live_tracking_state(
        high_water_version=high_water,
        high_water_observed_at=observed_at,
        last_valid_steam_manifest_id=last_valid_steam_manifest_id,
        last_valid_steam_manifest_size=last_valid_steam_manifest_size,
        awaiting_content_branch=awaiting_content_branch,
        awaiting_from_manifest_id=awaiting_from_manifest_id,
        pre_transition_manifest_id=pre_transition_manifest_id,
        pre_transition_manifest_size=pre_transition_manifest_size,
        pre_transition_content_branch=pre_transition_content_branch,
        path=path,
    )
