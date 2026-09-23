#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import hashlib
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from ctypes import wintypes
from pathlib import Path

import instance_lock
from common import (
    RELEASE_BUILD_ENV,
    TOOL_DIR,
    atomic_write_json,
    installation_state_id,
    nct_local_app_data_root,
    read_json_object,
    windows_file_lock,
)
from update import UPDATE_INSTALLER_ARGUMENT

ELEVATION_TASK_RUN_ARGUMENT = "--elevation-task-run"
INSTALL_ELEVATION_TASK_ARGUMENT = "--install-elevation-task"
ELEVATION_HANDOFF_SCHEMA_VERSION = 1
ELEVATION_HANDOFF_TIMEOUT_SECONDS = 12.0
ELEVATION_REQUEST_MAX_AGE_SECONDS = ELEVATION_HANDOFF_TIMEOUT_SECONDS + 5.0
ELEVATION_REQUEST_FUTURE_TOLERANCE_SECONDS = 5.0
_ELEVATION_TASK_NAME_RE = re.compile(r"^Ninja Capture Tool [0-9a-f]{16}$", re.IGNORECASE)

def is_elevated() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False

def _launch_target() -> tuple[str, list[str]]:
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve()), []
    return str(Path(sys.executable).resolve()), [str((TOOL_DIR / "ninja_capture_tool.py").resolve())]

def _task_action() -> tuple[str, str]:
    command, prefix = _launch_target()
    return command, subprocess.list2cmdline([*prefix, ELEVATION_TASK_RUN_ARGUMENT])

def _elevation_state_directory() -> Path:
    return nct_local_app_data_root() / "elevation" / installation_state_id(TOOL_DIR)

def _elevation_request_file() -> Path:
    return _elevation_state_directory() / ".elevation-request.json"

def _elevation_ack_file(request_id: str) -> Path:
    return _elevation_state_directory() / f".elevation-ack-{_validate_request_id(request_id)}.json"

def _elevation_request_lock_file() -> Path:
    return _elevation_state_directory() / ".elevation-request.lock"

def _prepare_elevation_state_directory() -> None:
    try:
        _elevation_state_directory().mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError("Could not prepare Ninja Capture Tool's elevation handoff directory.") from exc

def _elevation_task_path(user_id: str | None = None) -> str:
    if user_id is None:
        user_id = _current_windows_user_id()
    installation = str(TOOL_DIR.resolve()).replace("/", "\\").casefold()
    identity = hashlib.sha256(f"{user_id.casefold()}\0{installation}".encode("utf-8")).hexdigest()[:16]
    return rf"\Ninja Capture Tool {identity}"

def _decode_schtasks_output(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data[:64]:
        try:
            return data.decode("utf-16")
        except UnicodeError:
            pass
    for encoding in ("utf-8", "mbcs" if sys.platform == "win32" else "utf-8"):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeError):
            continue
    return data.decode("utf-8", errors="replace")

def _task_xml_value(root: ET.Element, local_name: str) -> str | None:
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == local_name:
            return element.text
    return None

def _task_xml_bool(root: ET.Element, local_name: str) -> bool | None:
    value = _task_xml_value(root, local_name)
    if value is None:
        return None
    normalized = value.strip().casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None

def _current_windows_user_id() -> str:
    if sys.platform != "win32":
        raise RuntimeError("Windows user lookup is only supported on Windows.")
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not determine the current Windows user for the elevation task.") from exc
    match = re.search(rb"\bS-\d+(?:-\d+)+\b", result.stdout)
    if result.returncode != 0 or match is None:
        raise RuntimeError("Could not determine the current Windows user for the elevation task.")
    return match.group(0).decode("ascii")

def _build_elevation_task_xml(user_id: str) -> bytes:
    namespace = "http://schemas.microsoft.com/windows/2004/02/mit/task"
    ET.register_namespace("", namespace)

    def q(name: str) -> str:
        return f"{{{namespace}}}{name}"

    command, arguments = _task_action()
    root = ET.Element(q("Task"), {"version": "1.4"})
    registration = ET.SubElement(root, q("RegistrationInfo"))
    ET.SubElement(registration, q("Description")).text = "Ninja Capture Tool administrator elevation"
    ET.SubElement(root, q("Triggers"))

    principals = ET.SubElement(root, q("Principals"))
    principal = ET.SubElement(principals, q("Principal"), {"id": "Author"})
    ET.SubElement(principal, q("UserId")).text = user_id
    ET.SubElement(principal, q("LogonType")).text = "InteractiveToken"
    ET.SubElement(principal, q("RunLevel")).text = "HighestAvailable"

    settings = ET.SubElement(root, q("Settings"))
    ET.SubElement(settings, q("MultipleInstancesPolicy")).text = "IgnoreNew"
    ET.SubElement(settings, q("DisallowStartIfOnBatteries")).text = "false"
    ET.SubElement(settings, q("StopIfGoingOnBatteries")).text = "false"
    ET.SubElement(settings, q("AllowHardTerminate")).text = "true"
    ET.SubElement(settings, q("StartWhenAvailable")).text = "false"
    ET.SubElement(settings, q("RunOnlyIfNetworkAvailable")).text = "false"
    ET.SubElement(settings, q("AllowStartOnDemand")).text = "true"
    ET.SubElement(settings, q("Enabled")).text = "true"
    ET.SubElement(settings, q("Hidden")).text = "false"
    ET.SubElement(settings, q("RunOnlyIfIdle")).text = "false"
    ET.SubElement(settings, q("WakeToRun")).text = "false"
    ET.SubElement(settings, q("ExecutionTimeLimit")).text = "PT0S"
    ET.SubElement(settings, q("Priority")).text = "7"

    actions = ET.SubElement(root, q("Actions"), {"Context": "Author"})
    execute = ET.SubElement(actions, q("Exec"))
    ET.SubElement(execute, q("Command")).text = command
    if arguments:
        ET.SubElement(execute, q("Arguments")).text = arguments
    ET.SubElement(execute, q("WorkingDirectory")).text = str(TOOL_DIR.resolve())

    return ET.tostring(root, encoding="utf-16", xml_declaration=True)

def _query_elevation_task(task_path: str) -> ET.Element | None:
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", task_path, "/XML"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        return ET.fromstring(_decode_schtasks_output(result.stdout))
    except ET.ParseError:
        return None

def _task_owned_by_user(root: ET.Element, user_id: str) -> bool:
    return (_task_xml_value(root, "UserId") or "").strip().casefold() == user_id.casefold()

def _task_matches_current_installation(root: ET.Element, user_id: str) -> bool:
    expected_command, expected_arguments = _task_action()
    command = _task_xml_value(root, "Command")
    arguments = _task_xml_value(root, "Arguments") or ""
    working_directory = _task_xml_value(root, "WorkingDirectory")
    if command is None or working_directory is None or not _task_owned_by_user(root, user_id):
        return False
    try:
        command_matches = os.path.normcase(os.path.abspath(command)) == os.path.normcase(os.path.abspath(expected_command))
        working_directory_matches = os.path.normcase(os.path.abspath(working_directory)) == os.path.normcase(
            os.path.abspath(str(TOOL_DIR.resolve()))
        )
    except (OSError, ValueError):
        return False
    return command_matches and working_directory_matches and arguments == expected_arguments

def elevation_task_exists() -> bool:
    if sys.platform != "win32":
        return False
    try:
        user_id = _current_windows_user_id()
    except RuntimeError:
        return False
    current = _query_elevation_task(_elevation_task_path(user_id))
    return current is not None and _task_owned_by_user(current, user_id)

def _task_has_no_triggers(root: ET.Element) -> bool:
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Triggers":
            return len(element) == 0
    return False

def _task_runtime_requirements_are_current(root: ET.Element) -> bool:
    # Task Scheduler may normalize nonessential XML settings when a task is
    # stored and exported again. Only reject settings that would prevent the
    # on-demand elevation task from working as intended.
    if not _task_has_no_triggers(root):
        return False
    enabled = _task_xml_bool(root, "Enabled")
    allow_start_on_demand = _task_xml_bool(root, "AllowStartOnDemand")
    return enabled is not False and allow_start_on_demand is not False

def elevation_task_is_current() -> bool:
    if sys.platform != "win32":
        return False
    try:
        current_user_id = _current_windows_user_id()
    except RuntimeError:
        return False
    root = _query_elevation_task(_elevation_task_path(current_user_id))
    if root is None:
        return False

    command = _task_xml_value(root, "Command")
    task_user_id = (_task_xml_value(root, "UserId") or "").strip()
    run_level = _task_xml_value(root, "RunLevel")
    logon_type = _task_xml_value(root, "LogonType")
    if (
        command is None
        or task_user_id.casefold() != current_user_id.casefold()
        or run_level != "HighestAvailable"
        or logon_type != "InteractiveToken"
        or not _task_runtime_requirements_are_current(root)
    ):
        return False
    return _task_matches_current_installation(root, current_user_id)

def _list_nct_elevation_tasks() -> list[str]:
    script = (
        "$service = New-Object -ComObject 'Schedule.Service'; "
        "$service.Connect(); "
        "$root = $service.GetFolder('\\'); "
        "$root.GetTasks(0) | ForEach-Object { "
        "if ($_.Name -match '^Ninja Capture Tool [0-9A-Fa-f]{16}$') { "
        "[Console]::Out.WriteLine($_.Name) } }"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    tasks: list[str] = []
    for line in _decode_schtasks_output(result.stdout).splitlines():
        name = line.strip()
        if _ELEVATION_TASK_NAME_RE.fullmatch(name):
            tasks.append(rf"\{name}")
    return tasks

def _stale_compiled_elevation_task_installation(root: ET.Element, user_id: str) -> Path | None:
    if (
        not _task_owned_by_user(root, user_id)
        or (_task_xml_value(root, "Description") or "").strip() != "Ninja Capture Tool administrator elevation"
        or (_task_xml_value(root, "RunLevel") or "").strip() != "HighestAvailable"
        or (_task_xml_value(root, "LogonType") or "").strip() != "InteractiveToken"
        or not _task_runtime_requirements_are_current(root)
    ):
        return None

    command = (_task_xml_value(root, "Command") or "").strip()
    arguments = (_task_xml_value(root, "Arguments") or "").strip()
    working_directory = (_task_xml_value(root, "WorkingDirectory") or "").strip()
    if not command or arguments != ELEVATION_TASK_RUN_ARGUMENT or not working_directory:
        return None

    try:
        command_path = Path(command)
        installation = Path(working_directory)
        if command_path.name.casefold() != "ninjacapturetool.exe":
            return None
        if os.path.normcase(os.path.abspath(str(command_path.parent))) != os.path.normcase(
            os.path.abspath(str(installation))
        ):
            return None
    except (OSError, ValueError):
        return None
    return installation

def _installation_path_is_clearly_gone(path: Path) -> bool:
    try:
        if path.exists():
            return False
        anchor = path.anchor
        if not anchor:
            return False
        return Path(anchor).exists()
    except OSError:
        return False

def _cleanup_stale_elevation_tasks(user_id: str) -> int:
    current_task = _elevation_task_path(user_id).casefold()
    removed = 0
    for task_path in _list_nct_elevation_tasks():
        if task_path.casefold() == current_task:
            continue
        root = _query_elevation_task(task_path)
        if root is None:
            continue
        installation = _stale_compiled_elevation_task_installation(root, user_id)
        if installation is None or not _installation_path_is_clearly_gone(installation):
            continue
        try:
            _delete_elevation_task(task_path)
        except RuntimeError:
            print(
                f"WARNING: Obsolete elevation task for missing Ninja Capture Tool installation could not be removed: {installation}",
                file=sys.stderr,
            )
            continue
        removed += 1
    return removed

def _delete_elevation_task(task_path: str) -> bool:
    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", task_path, "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Could not remove the Ninja Capture Tool elevation task.")
    if result.returncode != 0:
        raise RuntimeError("Could not remove the Ninja Capture Tool elevation task.")
    return True

def install_elevation_task() -> None:
    if sys.platform != "win32" or not is_elevated():
        raise RuntimeError("Administrator privileges are required to install the elevation task.")
    user_id = _current_windows_user_id()
    task_path = _elevation_task_path(user_id)
    xml_data = _build_elevation_task_xml(user_id)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="nct-elevation-task-", suffix=".xml", delete=False) as handle:
            handle.write(xml_data)
            temporary_path = Path(handle.name)
        result = subprocess.run(
            ["schtasks", "/Create", "/TN", task_path, "/XML", str(temporary_path), "/F"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Could not install the Ninja Capture Tool elevation task.") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
    if result.returncode != 0:
        detail = _decode_schtasks_output(result.stderr).strip() or _decode_schtasks_output(result.stdout).strip()
        if not detail:
            detail = f"schtasks exited with code {result.returncode}"
        raise RuntimeError(f"Could not install the Ninja Capture Tool elevation task: {detail}")
    if not elevation_task_is_current():
        raise RuntimeError("The Ninja Capture Tool elevation task was created but did not match the expected configuration.")
    _cleanup_stale_elevation_tasks(user_id)

def _cleanup_elevation_state_directory() -> bool:
    try:
        state_directory = _elevation_state_directory()
    except RuntimeError:
        return False
    if not state_directory.exists():
        return True
    paths = [
        state_directory / ".elevation-request.json",
        state_directory / ".elevation-request.lock",
        *state_directory.glob(".elevation-ack-*.json"),
        *state_directory.glob(".*.tmp"),
    ]
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            return False
    try:
        state_directory.rmdir()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True

def remove_elevation_task() -> bool:
    if sys.platform != "win32":
        return False
    try:
        user_id = _current_windows_user_id()
    except RuntimeError:
        _cleanup_elevation_state_directory()
        return False

    removed = False
    task_path = _elevation_task_path(user_id)
    current = _query_elevation_task(task_path)
    if current is not None and _task_owned_by_user(current, user_id):
        _delete_elevation_task(task_path)
        removed = True
    if not _cleanup_elevation_state_directory():
        print(
            "WARNING: Ninja Capture Tool's per-installation elevation handoff state could not be fully removed.",
            file=sys.stderr,
        )
    return removed

def _validate_request_id(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise RuntimeError("Invalid elevation request identifier.")
    return value

def _validate_elevation_request(value: object, *, now: float | None = None) -> tuple[list[str], bool, str]:
    if not isinstance(value, dict):
        raise RuntimeError("Invalid elevation request.")
    if value.get("schema_version") != ELEVATION_HANDOFF_SCHEMA_VERSION:
        raise RuntimeError("Unsupported elevation handoff schema version.")
    request_id = _validate_request_id(value.get("request_id"))
    created_at = value.get("created_at_unix")
    if isinstance(created_at, bool) or not isinstance(created_at, (int, float)) or not math.isfinite(float(created_at)):
        raise RuntimeError("Invalid elevation request timestamp.")
    current_time = time.time() if now is None else now
    age = current_time - float(created_at)
    if age > ELEVATION_REQUEST_MAX_AGE_SECONDS:
        raise RuntimeError("The Ninja Capture Tool elevation request has expired.")
    if age < -ELEVATION_REQUEST_FUTURE_TOLERANCE_SECONDS:
        raise RuntimeError("The Ninja Capture Tool elevation request timestamp is in the future.")
    argv = value.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise RuntimeError("Invalid elevation request arguments.")
    task_installed = value.get("task_installed", False)
    if not isinstance(task_installed, bool):
        raise RuntimeError("Invalid elevation request state.")
    forbidden = {
        ELEVATION_TASK_RUN_ARGUMENT,
        INSTALL_ELEVATION_TASK_ARGUMENT,
        UPDATE_INSTALLER_ARGUMENT,
        "--proxy-worker",
    }
    if any(item in forbidden for item in argv):
        raise RuntimeError("Invalid internal argument in elevation request.")
    return list(argv), task_installed, request_id

def current_elevation_request_id() -> str | None:
    try:
        request = read_json_object(_elevation_request_file())
        if request.get("schema_version") != ELEVATION_HANDOFF_SCHEMA_VERSION:
            return None
        return _validate_request_id(request.get("request_id"))
    except RuntimeError:
        return None

def consume_elevation_request() -> tuple[list[str], bool, str]:
    try:
        request = read_json_object(_elevation_request_file())
    except RuntimeError as exc:
        raise RuntimeError("Could not read the Ninja Capture Tool elevation request.") from exc
    return _validate_elevation_request(request)

def _matching_elevation_ack(expected_request_id: str) -> tuple[str, str | None] | None:
    ack_file = _elevation_ack_file(expected_request_id)
    if not ack_file.exists():
        return None
    try:
        value = read_json_object(ack_file)
    except RuntimeError:
        return None
    if value.get("schema_version") != ELEVATION_HANDOFF_SCHEMA_VERSION:
        return None
    if value.get("request_id") != expected_request_id:
        return None
    status = value.get("status")
    if status not in {"started", "busy", "failed"}:
        return None
    message = value.get("message")
    if message is not None and not isinstance(message, str):
        return None
    return status, message

def acknowledge_elevation_request(
    request_id: str,
    *,
    status: str = "started",
    message: str | None = None,
) -> None:
    request_id = _validate_request_id(request_id)
    if status not in {"started", "busy", "failed"}:
        raise RuntimeError("Invalid elevation acknowledgement status.")
    if message is not None and not isinstance(message, str):
        raise RuntimeError("Invalid elevation acknowledgement message.")
    payload: dict[str, object] = {
        "schema_version": ELEVATION_HANDOFF_SCHEMA_VERSION,
        "request_id": request_id,
        "status": status,
    }
    if message:
        payload["message"] = message[:1000]
    try:
        atomic_write_json(_elevation_ack_file(request_id), payload)
    except OSError as exc:
        raise RuntimeError("Could not acknowledge the Ninja Capture Tool elevation request.") from exc

def clear_elevation_request(request_id: str) -> bool:
    request_id = _validate_request_id(request_id)
    request_file = _elevation_request_file()
    try:
        value = read_json_object(request_file)
    except RuntimeError:
        return False
    if value.get("request_id") != request_id:
        return False
    try:
        request_file.unlink(missing_ok=True)
    except OSError:
        return False
    return True

def clear_elevation_ack(request_id: str) -> None:
    try:
        _elevation_ack_file(request_id).unlink(missing_ok=True)
    except OSError:
        pass

def _cleanup_orphaned_elevation_handoff_artifacts() -> None:
    try:
        state_directory = _elevation_state_directory()
    except RuntimeError:
        return
    if not state_directory.exists():
        return
    for path in (*state_directory.glob(".elevation-ack-*.json"), *state_directory.glob(".*.tmp")):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

def _raise_for_elevation_ack(ack: tuple[str, str | None] | None) -> bool:
    if ack is None:
        return False
    status, message = ack
    if status in {"started", "busy"}:
        return True
    detail = (message or "the elevated process reported an unspecified startup failure").strip()
    raise RuntimeError(f"Ninja Capture Tool could not start elevated: {detail}")

def launch_via_elevation_task(argv: list[str], *, task_installed: bool = False) -> None:
    if sys.platform != "win32":
        raise RuntimeError("Scheduled-task elevation is only supported on Windows.")
    _prepare_elevation_state_directory()
    request_file = _elevation_request_file()
    with windows_file_lock(
        _elevation_request_lock_file(),
        10,
        "Another Ninja Capture Tool elevation request is already starting.",
    ):
        if instance_lock.another_capture_is_active():
            raise RuntimeError("Another Ninja Capture Tool capture is already running.")

        _cleanup_orphaned_elevation_handoff_artifacts()
        request_id = uuid.uuid4().hex
        request_file.unlink(missing_ok=True)
        atomic_write_json(
            request_file,
            {
                "schema_version": ELEVATION_HANDOFF_SCHEMA_VERSION,
                "request_id": request_id,
                "created_at_unix": time.time(),
                "argv": list(argv),
                "task_installed": task_installed,
            },
        )

        # Task Scheduler's IgnoreNew policy can report /Run success while the
        # previous elevated task instance is still finishing shutdown. Retry the
        # task briefly, but trust only a matching acknowledgement from
        # the elevated instance. Each request has its own acknowledgement file so
        # a delayed older task cannot overwrite a newer request's acknowledgement.
        deadline = time.monotonic() + ELEVATION_HANDOFF_TIMEOUT_SECONDS
        last_error: BaseException | None = None
        try:
            while time.monotonic() < deadline:
                if _raise_for_elevation_ack(_matching_elevation_ack(request_id)):
                    return
                if not request_file.exists():
                    raise RuntimeError(
                        "The Ninja Capture Tool elevation request disappeared without a matching acknowledgement."
                    )
                try:
                    result = subprocess.run(
                        ["schtasks", "/Run", "/TN", _elevation_task_path()],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
                    last_error = exc
                else:
                    if result.returncode == 0:
                        wait_until = min(deadline, time.monotonic() + 1.0)
                        while time.monotonic() < wait_until:
                            if _raise_for_elevation_ack(_matching_elevation_ack(request_id)):
                                return
                            if not request_file.exists():
                                raise RuntimeError(
                                    "The Ninja Capture Tool elevation request disappeared without a matching acknowledgement."
                                )
                            time.sleep(0.05)
                    else:
                        last_error = RuntimeError(f"schtasks exited with code {result.returncode}")
                if time.monotonic() < deadline:
                    time.sleep(0.1)
        finally:
            clear_elevation_request(request_id)
            clear_elevation_ack(request_id)

        if last_error is not None:
            raise RuntimeError(
                "Could not start Ninja Capture Tool through its elevation task; "
                "the previous task instance may still be shutting down."
            ) from last_error
        raise RuntimeError(
            "Timed out waiting for the Ninja Capture Tool elevation task to acknowledge startup; "
            "the previous task instance may still be shutting down."
        )

class _ShellExecuteInfoW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
    ]

def run_elevated_and_wait(argv: list[str], *, show_window: bool = False) -> int:
    if os.environ.get(RELEASE_BUILD_ENV) == "1":
        raise RuntimeError("Elevation is disabled during a Ninja Capture Tool release build.")
    if sys.platform != "win32":
        raise RuntimeError("Elevation is only supported on Windows.")

    command, prefix = _launch_target()
    parameters = subprocess.list2cmdline([*prefix, *argv])
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfoW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    info = _ShellExecuteInfoW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = command
    info.lpParameters = parameters
    info.lpDirectory = str(TOOL_DIR)
    info.nShow = 1 if show_window else 0  # SW_SHOWNORMAL / SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.get_last_error()
        if error == 1223:  # ERROR_CANCELLED
            raise RuntimeError("Administrator elevation was cancelled or denied.")
        raise ctypes.WinError(error)
    if not info.hProcess:
        raise RuntimeError("Could not obtain the elevated Ninja Capture Tool process handle.")

    try:
        wait_result = kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)  # INFINITE
        if wait_result not in {0, 0x80}:  # WAIT_OBJECT_0 / WAIT_ABANDONED
            raise ctypes.WinError(ctypes.get_last_error())
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(exit_code.value)
    finally:
        kernel32.CloseHandle(info.hProcess)

