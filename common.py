#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import shutil
import stat
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from ctypes import wintypes
from datetime import datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

VERSION = "1.0.0"

def display_version(version: str = VERSION) -> str:
    parts = version.split(".")
    while len(parts) > 2 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)

def format_duration(seconds: float) -> str:
    total_seconds = max(0, round(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"

def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON key "{key}".')
        result[key] = value
    return result

def _reject_nonfinite_json(value: str):
    raise ValueError(f"Non-standard JSON constant is not allowed: {value}")

def parse_json(data: str | bytes):
    return json.loads(data, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_nonfinite_json)

MITMPROXY_VERSION = "12.2.3"
STEAM_CLIENT_VERSION = "1.8.2"
TARGET_HOST = "content.warframe.com"
ALLOW_HOSTS_REGEX = r"^content\.warframe\.com(?::\d+)?$"
_WORKER_MESSAGE_PREFIX = "__NCT_WORKER__:"
SESSION_MANIFEST_VERSION = 1
RELEASE_MANIFEST_FILE = "data/release_manifest.json"
RELEASE_MANIFEST_VERSION = 1
NCT_LICENSE_RELEASE_FILE = "data/licenses/Ninja-Capture-Tool-LICENSE.txt"
RELEASE_BUILD_ENV = "NCT_RELEASE_BUILD"
PRESERVED_RELEASE_FILES = frozenset({"config.json"})
_SESSION_VERSION_NAME_RE = re.compile(r"^\d+(?:\.\d+){1,3}$")
_ATOMIC_JSON_WRITE_LOCK = threading.Lock()

ANSI_RED = "\x1b[31m"
ANSI_YELLOW = "\x1b[33m"
ANSI_GREEN = "\x1b[32m"
ANSI_CYAN = "\x1b[36m"
_COLOR_SUPPORT_LOCK = threading.Lock()
_COLOR_SUPPORT_CACHE: dict[int, bool] = {}
_SEVERITY_TOKEN_RE = re.compile(r"(?m)^(\[Proxy\] )?(ERROR:|WARNING:)")
_HTTP_STATUS_TOKEN_RE = re.compile(r"(?<=\| )(\d{3})(?= \|)")
_HTTP_DEBUG_STATUS_TOKEN_RE = re.compile(r"(?<=HTTP )(\d{3})(?=[:\s])")
_TRANSIENT_PROGRESS_RE = re.compile(r"(?m)^(\[(?:Saving|Extracting|Waiting|Update)\] )(.+?)( \| )")

def encode_worker_message(message_type: str, **payload: object) -> str:
    return _WORKER_MESSAGE_PREFIX + json.dumps(
        {"type": message_type, **payload},
        ensure_ascii=False,
        separators=(",", ":"),
    )

def parse_worker_message(line: str) -> dict[str, Any] | None:
    if not line.startswith(_WORKER_MESSAGE_PREFIX):
        return None
    try:
        message = json.loads(line[len(_WORKER_MESSAGE_PREFIX):])
    except json.JSONDecodeError as exc:
        raise ValueError("Malformed worker message.") from exc
    if not isinstance(message, dict) or not isinstance(message.get("type"), str):
        raise ValueError("Malformed worker message.")
    return message

def _enable_windows_virtual_terminal(stream) -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(ctypes.c_void_p(handle), ctypes.byref(mode)):
            return False
        enable_virtual_terminal_processing = 0x0004
        if mode.value & enable_virtual_terminal_processing:
            return True
        return bool(
            kernel32.SetConsoleMode(
                ctypes.c_void_p(handle),
                mode.value | enable_virtual_terminal_processing,
            )
        )
    except (AttributeError, OSError, ValueError):
        return False

def console_supports_color(stream) -> bool:
    """Return whether ANSI color is safe for this interactive stream."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        if not stream.isatty():
            return False
        key = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return False
    with _COLOR_SUPPORT_LOCK:
        cached = _COLOR_SUPPORT_CACHE.get(key)
        if cached is not None:
            return cached
        supported = _enable_windows_virtual_terminal(stream)
        _COLOR_SUPPORT_CACHE[key] = supported
        return supported

def _colored(token: str, color: str) -> str:
    return f"{color}{token}\x1b[0m"

def style_console_text(message: str, stream, *, status_tokens: bool = False) -> str:
    """Color only semantic status tokens; redirected output remains plain text."""
    if not console_supports_color(stream):
        return message

    def severity_replacement(match: re.Match[str]) -> str:
        prefix = match.group(1) or ""
        token = match.group(2)
        return prefix + _colored(token, ANSI_RED if token == "ERROR:" else ANSI_YELLOW)

    styled = _SEVERITY_TOKEN_RE.sub(severity_replacement, message)
    if not status_tokens:
        return styled

    def http_replacement(match: re.Match[str]) -> str:
        token = match.group(1)
        code = int(token)
        if 200 <= code < 300 and code != 206:
            color = ANSI_GREEN
        elif code == 206 or 300 <= code < 400:
            color = ANSI_YELLOW
        elif 400 <= code < 600:
            color = ANSI_RED
        else:
            return token
        return _colored(token, color)

    styled = _TRANSIENT_PROGRESS_RE.sub(
        lambda match: match.group(1) + _colored(match.group(2), ANSI_CYAN) + match.group(3),
        styled,
    )
    styled = _HTTP_STATUS_TOKEN_RE.sub(http_replacement, styled)
    styled = _HTTP_DEBUG_STATUS_TOKEN_RE.sub(http_replacement, styled)
    styled = re.sub(r"(?<=\| )OK(?= \|)", lambda match: _colored(match.group(0), ANSI_GREEN), styled)
    styled = styled.replace("MD5 OK", _colored("MD5 OK", ANSI_GREEN))
    return styled

def print_console(message: object = "", *, file=None, flush: bool = False, status_tokens: bool = False) -> None:
    stream = sys.stdout if file is None else file
    print(style_console_text(str(message), stream, status_tokens=status_tokens), file=stream, flush=flush)

def print_error(message: object, *, flush: bool = False) -> None:
    print_console(f"ERROR: {message}", file=sys.stderr, flush=flush)

def print_warning(message: object, *, flush: bool = False) -> None:
    print_console(f"WARNING: {message}", file=sys.stderr, flush=flush)

def get_tool_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

TOOL_DIR = get_tool_dir()
FROZEN_RUNTIME_DIR_NAME = "runtime"
DATA_DIR = TOOL_DIR / "data"
_LOCAL_APP_DATA_FOLDER_ID = "f1b32785-6fba-4fcf-9d55-7b8e7f157091"

class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

def _guid(value: str) -> _GUID:
    return _GUID.from_buffer_copy(uuid.UUID(value).bytes_le)

def windows_local_app_data_directory() -> Path:
    if sys.platform != "win32":
        raise RuntimeError("Windows LocalAppData lookup is only supported on Windows.")
    try:
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)
        shell32.SHGetKnownFolderPath.argtypes = [
            ctypes.POINTER(_GUID),
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        shell32.SHGetKnownFolderPath.restype = ctypes.c_int32
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ole32.CoTaskMemFree.restype = None

        folder_id = _guid(_LOCAL_APP_DATA_FOLDER_ID)
        result_path = ctypes.c_void_p()
        result = shell32.SHGetKnownFolderPath(ctypes.byref(folder_id), 0, None, ctypes.byref(result_path))
    except (AttributeError, OSError) as exc:
        raise RuntimeError("Could not resolve Windows LocalAppData through the Known Folder API.") from exc
    if result != 0 or not result_path.value:
        raise RuntimeError(f"Could not resolve Windows LocalAppData (HRESULT 0x{result & 0xFFFFFFFF:08X}).")
    try:
        value = ctypes.wstring_at(result_path.value)
    finally:
        ole32.CoTaskMemFree(result_path)
    if not value:
        raise RuntimeError("Windows returned an empty LocalAppData path.")
    return Path(value)

def nct_local_app_data_root() -> Path:
    return windows_local_app_data_directory() / "DarkLotus" / "Ninja Capture Tool"

def installation_state_id(install_dir: Path) -> str:
    installation = str(install_dir.resolve()).replace("/", "\\").casefold()
    return hashlib.sha256(installation.encode("utf-8")).hexdigest()[:16]

def runtime_state_directory(install_dir: Path = TOOL_DIR) -> Path:
    return nct_local_app_data_root() / "state" / installation_state_id(install_dir)

def mitmproxy_conf_directory() -> Path:
    # The HTTPS CA belongs to the Windows user, not to one portable Ninja Capture Tool path.
    # Keeping a single confdir means rebuilding, moving, or renaming Ninja Capture Tool keeps
    # using the same already-trusted CA instead of generating another root.
    return nct_local_app_data_root() / "mitmproxy"

def proxy_recovery_file() -> Path:
    # Windows proxy settings belong to the current Windows user rather than to
    # one portable Ninja Capture Tool installation. A shared recovery record lets a moved or
    # renamed Ninja Capture Tool copy recover an interrupted System Proxy transition.
    return nct_local_app_data_root() / "state" / "proxy_recovery.json"

def session_recovery_file(install_dir: Path = TOOL_DIR) -> Path:
    return runtime_state_directory(install_dir) / "session_recovery.json"

def warframe_version_state_file(install_dir: Path = TOOL_DIR) -> Path:
    return install_dir.resolve() / "data" / "warframe_version.json"

def update_state_file(install_dir: Path = TOOL_DIR) -> Path:
    return install_dir.resolve() / "data" / "update_state.json"

def update_temp_root(install_dir: Path = TOOL_DIR) -> Path:
    return install_dir.resolve() / "temp"

def user_capture_activity_lock_path() -> Path:
    return nct_local_app_data_root() / "locks" / ".capture.lock"

def capture_activity_lock_path(install_dir: Path) -> Path:
    return nct_local_app_data_root() / "locks" / f"{installation_state_id(install_dir)}.capture.lock"

class FileLockBusyError(RuntimeError):
    pass

@contextmanager
def windows_file_lock(path: Path, timeout_seconds: int, timeout_message: str):
    import msvcrt

    path.parent.mkdir(parents=True, exist_ok=True)
    file = path.open("a+b")
    locked = False
    deadline = time.monotonic() + max(0, timeout_seconds)
    try:
        file.seek(0, 2)
        if file.tell() < 1:
            file.write(b"\0")
            file.flush()
        while True:
            file.seek(0)
            try:
                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
                locked = True
                break
            except OSError as exc:
                if exc.errno not in {errno.EACCES, errno.EDEADLK}:
                    raise
                if time.monotonic() >= deadline:
                    raise FileLockBusyError(timeout_message) from exc
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        yield
    finally:
        if locked:
            try:
                file.seek(0)
                msvcrt.locking(file.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        file.close()

def cleanup_temp_root_if_empty(temp_root: Path) -> None:
    try:
        temp_root.rmdir()
    except OSError:
        # Leave it alone if another operation is still using it, cleanup failed, or anything else remains inside it.
        pass

def validate_mitmproxy_installation() -> str:
    try:
        version = importlib.metadata.version("mitmproxy")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError(
            f"mitmproxy {MITMPROXY_VERSION} is required. Install it with: "
            f"py -3.14 -m pip install mitmproxy=={MITMPROXY_VERSION}"
        ) from None
    if version != MITMPROXY_VERSION:
        raise RuntimeError(
            f"mitmproxy {MITMPROXY_VERSION} is required for this Ninja Capture Tool build; found {version}. "
            f"Install the expected version with: py -3.14 -m pip install mitmproxy=={MITMPROXY_VERSION}"
        )
    return version

def validate_windows_capture_package() -> str:
    if sys.platform != "win32":
        return "not-applicable"

    try:
        module = importlib.import_module("mitmproxy_windows")
    except ImportError as exc:
        raise RuntimeError(
            "mitmproxy-windows is required for process-local capture on Windows. "
            f"Reinstall mitmproxy {MITMPROXY_VERSION}."
        ) from exc

    package_file = getattr(module, "__file__", None)
    if not package_file:
        raise RuntimeError("Could not locate the installed mitmproxy-windows package.")
    package_root = Path(package_file).resolve().parent

    if not any(path.is_file() for path in package_root.rglob("windows-redirector.exe")):
        raise RuntimeError("mitmproxy-windows is missing windows-redirector.exe.")
    if not any(path.is_file() and "windivert" in path.name.casefold() for path in package_root.rglob("*")):
        raise RuntimeError("mitmproxy-windows is missing its WinDivert runtime files.")

    try:
        return importlib.metadata.version("mitmproxy-windows")
    except importlib.metadata.PackageNotFoundError:
        return "installed"

def sha256_file(path: Path) -> str:
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()

def parse_version(value: str) -> tuple[int, ...]:
    text = value.strip()
    if text[:1].lower() == "v":
        text = text[1:]
    parts = text.split(".")
    if len(parts) < 2 or any(not part.isdigit() for part in parts):
        raise ValueError(f"Invalid version: {value!r}")
    return tuple(int(part) for part in parts)

def compare_versions(left: str, right: str) -> int:
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    width = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (width - len(left_parts))
    padded_right = right_parts + (0,) * (width - len(right_parts))
    return (padded_left > padded_right) - (padded_left < padded_right)

def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False

    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return ctypes.get_last_error() == 5  # ERROR_ACCESS_DENIED still means a process exists.

def process_identity(pid: int) -> str | None:
    # A PID can eventually be reused. Pair it with the Windows process creation time so stale update work is not
    # mistaken for a live Ninja Capture Tool updater merely because an unrelated process later received the same PID.
    if pid <= 0:
        return None

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        created = wintypes.FILETIME()
        exited = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not kernel32.GetProcessTimes(
            handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)
        ):
            return None
        creation = (created.dwHighDateTime << 32) | created.dwLowDateTime
        return f"{pid}:{creation}"
    finally:
        kernel32.CloseHandle(handle)

def process_matches_identity(pid: int, identity: object) -> bool:
    if not process_is_running(pid):
        return False
    if not isinstance(identity, str) or not identity:
        return True
    current = process_identity(pid)
    return current is None or current == identity

def is_windows_reserved_device_name(segment: str) -> bool:
    stem = segment.split(".", 1)[0].rstrip(" ").casefold()
    return (
        stem in {"con", "prn", "aux", "nul", "conin$", "conout$"}
        or re.fullmatch(r"(?:com|lpt)(?:[1-9]|[¹²³])", stem) is not None
    )

_INVALID_SESSION_PATH_CHARS = frozenset('<>:"|?*')

def validate_session_path_syntax(
    path: Path | str,
    label: str = "Capture session path",
    *,
    require_child: bool = True,
    reserve_temp_name: bool = True,
) -> Path:
    """Reject Windows-invalid or ambiguous user-selected directory paths without sanitizing them."""
    candidate = Path(path)
    text = str(path)
    if not text or "\0" in text:
        raise ValueError(f"{label} is empty or contains an invalid NUL character.")

    # Inspect the exact user spelling before PureWindowsPath normalizes explicit
    # dot components away. User-selected capture paths are rejected rather than
    # silently reinterpreted.
    namespace_text = text.replace("/", "\\")
    if namespace_text.startswith(("\\\\?\\", "\\\\.\\", "\\??\\", "\\\\??\\")):
        raise ValueError(f"{label} uses a Windows device or extended path namespace, which is not supported: {text}")
    if any(segment in {".", ".."} for segment in re.split(r"[\\/]", text)):
        raise ValueError(f"{label} cannot contain '.' or '..' path components: {text}")

    windows = PureWindowsPath(text)
    if windows.drive and not windows.root:
        raise ValueError(f"{label} uses a drive-relative path, which is not supported: {text}")
    if windows.root and not windows.drive and (isinstance(path, str) or sys.platform == "win32"):
        raise ValueError(f"{label} uses a rooted path without an explicit drive or network share: {text}")

    parts = list(windows.parts)
    if windows.anchor and parts and parts[0] == windows.anchor:
        parts = parts[1:]
    if require_child and not parts and windows.anchor:
        raise ValueError(f"{label} must name a directory below the filesystem root: {text}")

    for segment in parts:
        if segment in {".", ".."}:
            raise ValueError(f"{label} cannot contain '.' or '..' path components: {text}")
        if not segment:
            continue
        if segment.endswith((" ", ".")):
            raise ValueError(f"{label} contains a component ending in a space or period: {segment!r}")
        if any(ord(character) < 32 for character in segment):
            raise ValueError(f"{label} contains a control character: {segment!r}")
        if any(character in _INVALID_SESSION_PATH_CHARS for character in segment):
            raise ValueError(f"{label} contains a Windows-invalid character: {segment!r}")
        if is_windows_reserved_device_name(segment):
            raise ValueError(f"{label} contains a reserved Windows device name: {segment!r}")
        validate_windows_path_component(segment)
    if reserve_temp_name and windows.name.casefold() == ".temp":
        raise ValueError(f"{label} cannot use the reserved Ninja Capture Tool session directory name '.temp'.")
    return candidate

def validate_existing_session_root(path: Path, label: str = "Capture session path") -> None:
    """Do not let recursive mkdir turn a typo such as a nonexistent drive letter into opaque errors."""
    if sys.platform != "win32":
        return
    anchor = path.anchor
    if not anchor:
        return
    root = Path(anchor)
    if not root.exists():
        raise RuntimeError(f"{label} uses a drive or network root that does not exist or is unavailable: {anchor}")

def path_is_reparse_point(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return path.is_symlink()
    attributes = int(getattr(info, "st_file_attributes", 0) or 0)
    return path.is_symlink() or bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))

def resolve_session_output_path(
    path: Path | str,
    base: Path,
    label: str = "Capture session path",
    *,
    require_child: bool = True,
    reserve_temp_name: bool = True,
    reject_existing_reparse: bool = False,
) -> Path:
    raw = validate_session_path_syntax(
        path,
        label,
        require_child=require_child,
        reserve_temp_name=reserve_temp_name,
    )
    if not raw.is_absolute():
        raw = base / raw
    validate_existing_session_root(raw, label)
    if reject_existing_reparse and path_is_reparse_point(raw):
        raise RuntimeError(f"{label} cannot be a symbolic link, junction, or reparse point: {raw}")
    resolved = raw.resolve()
    validate_windows_full_path(resolved, label)
    validate_existing_session_root(resolved, label)
    return resolved

def relative_path_parts(relative: str) -> tuple[str, ...]:
    if not isinstance(relative, str) or not relative or "\0" in relative:
        raise ValueError(f"Unsafe relative path: {relative!r}")

    posix = PurePosixPath(relative.replace("\\", "/"))
    windows = PureWindowsPath(relative)
    if not posix.parts or posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts:
        raise ValueError(f"Unsafe relative path: {relative!r}")

    for part in posix.parts:
        if (
            ":" in part
            or any(character in part for character in '<>"|?*')
            or any(ord(character) < 32 for character in part)
            or part.endswith((" ", "."))
            or is_windows_reserved_device_name(part)
        ):
            raise ValueError(f"Unsafe relative path: {relative!r}")
    return posix.parts

def cleanup_temporary_file(path: Path) -> None:
    primary_error_active = sys.exception() is not None
    try:
        path.unlink(missing_ok=True)
    except OSError:
        if not primary_error_active:
            raise

def format_bytes(size: int) -> str:
    value = float(max(0, size))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")

def atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _ATOMIC_JSON_WRITE_LOCK:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        try:
            temporary.write_text(json.dumps(value, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")
            os.replace(temporary, path)
        finally:
            cleanup_temporary_file(temporary)

def ensure_directory_writable(path: Path, label: str) -> None:
    validate_windows_full_path(path, f"{label} path")
    if path.exists() and not path.is_dir():
        raise RuntimeError(f"{label} path is not a directory: {path}")
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f".nct-write-test-{uuid.uuid4().hex}.tmp"
        try:
            with probe.open("xb", buffering=0) as file:
                file.write(b"Ninja Capture Tool")
        finally:
            cleanup_temporary_file(probe)
    except OSError as exc:
        raise RuntimeError(f"{label} is not writable: {path}\n{exc}") from exc

def prepare_runtime_state_directory() -> None:
    ensure_directory_writable(runtime_state_directory(), "Runtime state directory")

def prepare_output_directory(output_root: Path) -> int:
    ensure_directory_writable(output_root, "Output directory")
    return shutil.disk_usage(output_root).free

def _capture_temp_marker(temp_root: Path) -> Path:
    return temp_root / ".nct-owned"

def _capture_temp_is_owned(temp_root: Path) -> bool:
    marker = _capture_temp_marker(temp_root)
    if temp_root.is_symlink() or not temp_root.is_dir() or marker.is_symlink() or not marker.is_file():
        return False
    try:
        return marker.read_text(encoding="ascii") == "Ninja Capture Tool temporary workspace\n"
    except OSError:
        return False

def clear_stale_capture_temp(output_root: Path) -> bool:
    temp_root = output_root / ".temp"
    if not temp_root.exists() and not temp_root.is_symlink():
        return False
    if not _capture_temp_is_owned(temp_root):
        raise RuntimeError(
            f"Output temporary path already exists and is not a Ninja Capture Tool workspace: {temp_root}"
        )

    # An interrupted or forcibly terminated capture can leave the owned workspace
    # for the next launch to remove. Do not report that recovery unless actual
    # capture data (for example a .part file) survived; the marker and empty
    # directories are routine bookkeeping, not stale payload.
    marker = _capture_temp_marker(temp_root)
    had_stale_payload = False
    try:
        for path in temp_root.rglob("*"):
            if path == marker:
                continue
            if path.is_symlink() or path.is_file():
                had_stale_payload = True
                break
    except OSError:
        # Be conservative if the workspace cannot be enumerated completely.
        had_stale_payload = True

    try:
        shutil.rmtree(temp_root)
    except OSError as exc:
        raise RuntimeError(f"Could not remove stale temporary capture data from {temp_root}: {exc}") from exc
    return had_stale_payload

def prepare_capture_temp_root(output_root: Path) -> Path:
    temp_root = output_root / ".temp"
    if temp_root.exists() or temp_root.is_symlink():
        if _capture_temp_is_owned(temp_root):
            return temp_root
        raise RuntimeError(
            f"Output temporary path already exists and is not a Ninja Capture Tool workspace: {temp_root}"
        )
    created = False
    try:
        temp_root.mkdir()
        created = True
        _capture_temp_marker(temp_root).write_text("Ninja Capture Tool temporary workspace\n", encoding="ascii")
    except OSError as exc:
        if created:
            shutil.rmtree(temp_root, ignore_errors=True)
        raise RuntimeError(f"Could not create temporary capture workspace {temp_root}: {exc}") from exc
    return temp_root

def remove_capture_temp_root(temp_root: Path) -> None:
    if not temp_root.exists() and not temp_root.is_symlink():
        return
    if not _capture_temp_is_owned(temp_root):
        raise RuntimeError(f"Refusing to remove unowned temporary capture path: {temp_root}")
    shutil.rmtree(temp_root)

def session_artifact_paths(metadata_root: Path, session_id: str) -> tuple[Path, Path]:
    return (
        metadata_root / f"{session_id}_capture.log",
        metadata_root / f"{session_id}_session.json",
    )

def _session_identifier_is_available(output_root: Path, session_id: str) -> bool:
    log_path, manifest_path = session_artifact_paths(output_root, session_id)
    session = output_root / session_id
    return (
        not session.exists()
        and not log_path.exists()
        and not manifest_path.exists()
        and not session_manifest_paths_for_capture_directory(session)
    )

def allocate_session_identifier(output_root: Path, now: datetime | None = None) -> str:
    output_root.mkdir(parents=True, exist_ok=True)
    moment = now or datetime.now().astimezone()
    base_name = moment.strftime("%Y-%m-%d_%H-%M-%S")
    for index in range(1, 10000):
        name = base_name if index == 1 else f"{base_name}_{index}"
        if _session_identifier_is_available(output_root, name):
            return name
    raise RuntimeError("Could not allocate a unique capture session identifier.")

def create_session_directory(output_root: Path, now: datetime | None = None) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    # The directory name is also the metadata prefix for automatic sessions, so
    # avoid collisions with both existing capture directories and sidecar files.
    moment = now or datetime.now().astimezone()
    base_name = moment.strftime("%Y-%m-%d_%H-%M-%S")
    for index in range(1, 10000):
        name = base_name if index == 1 else f"{base_name}_{index}"
        if not _session_identifier_is_available(output_root, name):
            continue
        session = output_root / name
        try:
            session.mkdir()
        except FileExistsError:
            continue
        return session
    raise RuntimeError("Could not allocate a unique capture session directory.")

def create_named_session_directory(output_root: Path, base_name: str) -> Path:
    if not _SESSION_VERSION_NAME_RE.fullmatch(base_name):
        raise RuntimeError(f"Invalid automatic session name: {base_name!r}")
    output_root.mkdir(parents=True, exist_ok=True)
    for index in range(1, 10000):
        name = base_name if index == 1 else f"{base_name}_{index}"
        if not _session_identifier_is_available(output_root, name):
            continue
        session = output_root / name
        try:
            session.mkdir()
        except FileExistsError:
            continue
        return session
    raise RuntimeError("Could not allocate a unique version-named capture session directory.")

def session_manifest_paths_for_capture_directory(session: Path) -> list[Path]:
    if not session.parent.is_dir():
        return []
    target = session.name.casefold()
    matches: list[Path] = []
    for manifest_path in session.parent.glob("*_session.json"):
        manifest = load_capture_session_manifest(manifest_path)
        if manifest is not None and str(manifest.get("capture_directory", "")).casefold() == target:
            matches.append(manifest_path)
    return matches

def create_exact_session_directory(path: Path) -> Path:
    validate_session_path_syntax(path)
    validate_existing_session_root(path)
    if path_is_reparse_point(path):
        raise RuntimeError(f"Capture session path cannot be a symbolic link, junction, or reparse point: {path}")
    existing_manifests = session_manifest_paths_for_capture_directory(path)
    if existing_manifests:
        raise RuntimeError(
            f"Capture session path already exists and session metadata already refers to this directory name: {path}. "
            "Move or remove the old session metadata before reusing the name."
        )
    if path.exists():
        if not path.is_dir():
            raise RuntimeError(f"Capture session path is not a directory: {path}")
        try:
            if next(path.iterdir(), None) is not None:
                raise RuntimeError(f"Capture session path already exists and is not empty: {path}")
        except OSError as exc:
            raise RuntimeError(f"Could not inspect capture session directory {path}: {exc}") from exc
        return path
    try:
        path.mkdir(parents=True)
    except FileExistsError:
        raise RuntimeError(f"Capture session path already exists and could not be claimed safely: {path}") from None
    except OSError as exc:
        raise RuntimeError(f"Could not create capture session directory {path}: {exc}") from exc
    return path

def current_timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")

def read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON file must contain an object: {path}")
    return value

def session_warning_count(manifest: dict[str, object]) -> int:
    return sum(
        int(manifest.get(key, 0) or 0)
        for key in (
            "conflict_count",
            "skipped_partial",
            "incomplete_responses",
            "capture_errors",
            "extraction_errors",
            "metadata_write_errors",
            "cleanup_errors",
            "h_cache_validation_errors",
        )
    )

def is_session_id(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None

def reconcile_interrupted_session_manifest(
    session: Path,
    manifest: dict[str, Any],
) -> tuple[int, list[str]]:
    """Add files that reached OpenWF/Content before an interrupted metadata flush."""
    content_root = session / "OpenWF" / "Content"
    if content_root.is_symlink() or not content_root.is_dir():
        return 0, []
    files = manifest.get("files")
    if not isinstance(files, dict):
        return 0, [f"Could not reconcile interrupted capture metadata because its file table is invalid: {session}"]

    known = {str(relative).casefold() for relative in files}
    recovered = 0
    warnings: list[str] = []
    try:
        for directory, directory_names, file_names in os.walk(content_root, followlinks=False):
            current = Path(directory)
            # Ninja Capture Tool never intentionally creates symlinked capture directories. Never
            # descend into one during recovery.
            safe_directories: list[str] = []
            for name in directory_names:
                candidate = current / name
                if candidate.is_symlink():
                    warnings.append(f"Skipped symbolic link while reconciling interrupted capture metadata: {candidate}")
                else:
                    safe_directories.append(name)
            directory_names[:] = safe_directories

            for name in file_names:
                path = current / name
                if path.is_symlink():
                    warnings.append(f"Skipped symbolic link while reconciling interrupted capture metadata: {path}")
                    continue
                relative = path.relative_to(content_root).as_posix()
                key = relative.casefold()
                if key in known:
                    continue
                try:
                    size = path.stat().st_size
                    digest = sha256_file(path)
                except OSError as exc:
                    warnings.append(f"Could not reconcile captured file {path}: {exc}")
                    continue
                files[relative] = {
                    "size": size,
                    "sha256": digest,
                    "path": "/" + relative,
                    "source": "recovered",
                }
                known.add(key)
                recovered += 1
    except OSError as exc:
        warnings.append(f"Could not fully scan interrupted capture output {content_root}: {exc}")

    if recovered:
        manifest["recovered_files"] = int(manifest.get("recovered_files", 0) or 0) + recovered
        manifest["captured_files"] = len(files)
        total = 0
        for record in files.values():
            if not isinstance(record, dict):
                continue
            size = record.get("size")
            if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
                total += size
        manifest["captured_bytes"] = total
    return recovered, warnings

def load_capture_session_manifest(manifest_path: Path) -> dict[str, Any] | None:
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return None
    try:
        manifest = read_json_object(manifest_path)
    except RuntimeError:
        return None
    captured_files = manifest.get("captured_files")
    capture_directory = manifest.get("capture_directory")
    manifest_session_id = manifest.get("session_id")
    started_at = manifest.get("started_at")
    finished_at = manifest.get("finished_at")
    processes = manifest.get("processes")
    if (
        manifest.get("version") != SESSION_MANIFEST_VERSION
        or manifest.get("target_host") != TARGET_HOST
        or manifest.get("status") not in {"pending_rotation", "starting", "running", "interrupted", "completed", "completed_with_warnings", "failed", "aborted"}
        or not is_session_id(manifest_session_id)
        or not isinstance(started_at, str)
        or not started_at
        or (finished_at is not None and not isinstance(finished_at, str))
        or manifest.get("capture_mode") not in {"local", "system-proxy"}
        or manifest.get("debug") not in {"off", "on", "global"}
        or not isinstance(processes, list)
        or any(not isinstance(process, str) or not process for process in processes)
        or not isinstance(capture_directory, str)
        or not capture_directory
        or PurePosixPath(capture_directory).name != capture_directory
        or PureWindowsPath(capture_directory).name != capture_directory
        or capture_directory in {".", ".."}
        or not isinstance(manifest.get("files"), dict)
        or not isinstance(manifest.get("conflicts"), list)
        or isinstance(captured_files, bool)
        or not isinstance(captured_files, int)
        or captured_files < 0
    ):
        return None
    return manifest

def remove_empty_capture_session_directory(session: Path, *, remove_root: bool) -> None:
    if remove_root:
        shutil.rmtree(session)
        return
    if session.is_symlink() or not session.is_dir():
        return
    for directory, _, _ in os.walk(session, topdown=False):
        current = Path(directory)
        if current == session:
            continue
        try:
            current.rmdir()
        except OSError:
            pass

def session_has_payload(session: Path) -> bool:
    try:
        return any(path.is_symlink() or path.is_file() for path in session.rglob("*"))
    except OSError:
        # Recovery must be conservative. An unreadable session is never considered
        # empty and therefore is never deleted automatically.
        return True

def _manifest_log_path(manifest_path: Path) -> Path:
    suffix = "_session.json"
    if not manifest_path.name.endswith(suffix):
        raise ValueError(f"Not a capture session manifest path: {manifest_path}")
    return manifest_path.with_name(manifest_path.name[:-len(suffix)] + "_capture.log")

def _manifest_for_capture_directory(session: Path) -> Path | None:
    matches = session_manifest_paths_for_capture_directory(session)
    return matches[0] if len(matches) == 1 else None

def _recover_stale_session(
    session: Path,
    manifest_path: Path,
    *,
    expected_session_id: str | None = None,
    allow_empty_starting_cleanup: bool = False,
    allow_empty_running_cleanup: bool = False,
) -> tuple[int, list[str], bool]:
    if session.is_symlink() or not session.is_dir():
        return 0, [], False
    manifest = load_capture_session_manifest(manifest_path)
    if manifest is None or manifest.get("capture_directory") != session.name:
        return 0, [], False
    if expected_session_id is not None and manifest.get("session_id") != expected_session_id:
        return 0, [f"Recorded session identity no longer matches its capture metadata: {manifest_path}"], False

    interrupted = 0
    warnings: list[str] = []
    status = manifest.get("status")
    has_payload = session_has_payload(session)
    if (
        (
            status in {"pending_rotation", "completed", "aborted"}
            or (status == "starting" and (allow_empty_starting_cleanup or manifest.get("cleanup_empty_startup") is True))
            or (status == "running" and allow_empty_running_cleanup)
        )
        and session_warning_count(manifest) == 0
        and manifest["captured_files"] == 0
        and not manifest["files"]
        and not manifest["conflicts"]
        and not manifest.get("failure_reason")
        and not manifest.get("update_transition_detected")
        and not has_payload
    ):
        try:
            remove_empty_capture_session_directory(
                session,
                remove_root=bool(manifest.get("session_directory_created_by_tool", True)),
            )
        except OSError as exc:
            warnings.append(f"Could not clean up empty previous capture session {session}: {exc}")
        else:
            for artifact in (_manifest_log_path(manifest_path), manifest_path):
                try:
                    artifact.unlink(missing_ok=True)
                except OSError as exc:
                    warnings.append(f"Could not remove stale session metadata file {artifact}: {exc}")
            return 0, warnings, True
    if status in {"starting", "running"} or (status == "pending_rotation" and has_payload):
        _, reconciliation_warnings = reconcile_interrupted_session_manifest(session, manifest)
        warnings.extend(reconciliation_warnings)
        manifest["status"] = "interrupted"
        manifest["finished_at"] = current_timestamp()
        manifest["end_reason"] = "interrupted"
        try:
            atomic_write_json(manifest_path, manifest)
            interrupted = 1
        except Exception as exc:
            warnings.append(f"Could not recover previous session metadata at {manifest_path}: {exc}")
    return interrupted, warnings, False

def recover_stale_session(session: Path) -> tuple[int, list[str], bool]:
    manifest_path = _manifest_for_capture_directory(session)
    if manifest_path is None:
        return 0, [], False
    return _recover_stale_session(session, manifest_path)

def recover_stale_session_exact(
    session: Path,
    manifest_path: Path,
    expected_session_id: str | None = None,
    *,
    allow_empty_starting_cleanup: bool = False,
    allow_empty_running_cleanup: bool = False,
) -> tuple[int, list[str], bool]:
    """Recover one recorded session without scanning or choosing among sidecars."""
    try:
        if session.parent.resolve() != manifest_path.parent.resolve():
            return 0, [f"Recorded session metadata is not beside its capture directory: {manifest_path}"], False
    except OSError as exc:
        return 0, [f"Could not resolve recorded session recovery paths: {exc}"], False
    return _recover_stale_session(
        session,
        manifest_path,
        expected_session_id=expected_session_id,
        allow_empty_starting_cleanup=allow_empty_starting_cleanup,
        allow_empty_running_cleanup=allow_empty_running_cleanup,
    )

def recover_stale_sessions(output_root: Path) -> tuple[int, list[str]]:
    if not output_root.is_dir():
        return 0, []

    interrupted = 0
    warnings: list[str] = []
    manifests_by_directory: dict[str, list[Path]] = {}
    directory_names: dict[str, str] = {}
    for manifest_path in output_root.glob("*_session.json"):
        manifest = load_capture_session_manifest(manifest_path)
        if manifest is None:
            continue
        capture_directory = str(manifest["capture_directory"])
        key = capture_directory.casefold()
        manifests_by_directory.setdefault(key, []).append(manifest_path)
        directory_names[key] = capture_directory

    for key, manifest_paths in manifests_by_directory.items():
        capture_directory = directory_names[key]
        session = output_root / capture_directory
        if len(manifest_paths) != 1:
            warnings.append(
                f"Multiple session manifests refer to the same capture directory {session}; recovery was skipped to avoid choosing the wrong metadata."
            )
            continue
        marked, child_warnings, _ = _recover_stale_session(session, manifest_paths[0])
        interrupted += marked
        warnings.extend(child_warnings)
    return interrupted, warnings

def utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2

def validate_windows_path_component(segment: str) -> str:
    # Windows filesystem path components are limited to 255 UTF-16 code units.
    if utf16_units(segment) > 255:
        raise ValueError(f"Path component exceeds the Windows filesystem limit and cannot be preserved exactly: {segment!r}")
    return segment

def validate_windows_full_path(path: Path, label: str = "Path") -> Path:
    # Win32 Unicode paths have an absolute upper bound of 32,767 UTF-16 code units. Keep a small margin for
    # internal prefixes/terminators and fail with a useful message before an opaque filesystem error occurs.
    if sys.platform == "win32" and utf16_units(str(path)) > 32760:
        raise ValueError(f"{label} exceeds the Windows path-length limit and cannot be used: {path}")
    return path
