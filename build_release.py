#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import zipfile
from pathlib import Path

# Keep the release builder itself from creating __pycache__ in the source tree.
sys.dont_write_bytecode = True

from packaging.requirements import Requirement
from packaging.version import InvalidVersion, Version

from common import (
    FileLockBusyError,
    FROZEN_RUNTIME_DIR_NAME,
    NCT_LICENSE_RELEASE_FILE,
    PRESERVED_RELEASE_FILES,
    RELEASE_BUILD_ENV,
    RELEASE_MANIFEST_FILE,
    RELEASE_MANIFEST_VERSION,
    STEAM_CLIENT_VERSION,
    VERSION,
    capture_activity_lock_path,
    display_version,
    format_bytes,
    format_duration,
    parse_json,
    print_error,
    validate_mitmproxy_installation,
    validate_windows_capture_package,
    windows_file_lock,
)
from config import load_config
from check_steam import STEAM_QUERY_RESULT_PREFIX, STEAM_QUERY_WORKER_SMOKE_ARGUMENT
ROOT = Path(__file__).resolve().parent
DISPLAY_VERSION = display_version()
RELEASE_DIR = ROOT / "release"
RELEASE_TEMP_DIR = ROOT / "release_temp"
DATA_DIR = ROOT / "data"
LICENSES_DIR = DATA_DIR / "licenses"
FAVICON = DATA_DIR / "favicon.ico"
FALLBACK_LICENSE_FILES = {
    "python": LICENSES_DIR / "Python_LICENSE.txt",
}
VERSIONED_FALLBACK_LICENSE_FILES = {
    ("gevent-eventemitter", "2.1"): LICENSES_DIR / "gevent_eventemitter_LICENSE.txt",
    ("mitmproxy-rs", "0.12.11"): LICENSES_DIR / "mitmproxy_rs_LICENSE.txt",
    ("publicsuffix2", "2.20191221"): LICENSES_DIR / "publicsuffix2_LICENSE.txt",
}
NCT_LICENSE_RELEASE_NAME = Path(NCT_LICENSE_RELEASE_FILE).name
MIN_PYINSTALLER_VERSION = Version("6.22.1")
_ACTIVE_BUILD_PROCESS: subprocess.Popen | None = None
KNOWN_RUNTIME_LOCK_FILES = {
    "data/.update.lock",
}
RELEASE_SOURCE_FILES = (
    ".gitattributes",
    ".gitignore",
    "README.md",
    "LICENSE",
    "build_release.py",
    "capture.py",
    "common.py",
    "config.py",
    "config.json",
    "elevation.py",
    "instance_lock.py",
    "check_live.py",
    "ninja_capture_tool.py",
    "runtime.py",
    "session.py",
    "check_steam.py",
    "update.py",
    "windows_proxy.py",
    "data/favicon.ico",
    "data/licenses/Python_LICENSE.txt",
    "data/licenses/gevent_eventemitter_LICENSE.txt",
    "data/licenses/mitmproxy_rs_LICENSE.txt",
    "data/licenses/publicsuffix2_LICENSE.txt",
    "requirements.txt",
    "tests/support.py",
    "tests/test_build_release.py",
    "tests/test_capture.py",
    "tests/test_config.py",
    "tests/test_elevation.py",
    "tests/test_entrypoint.py",
    "tests/test_session.py",
    "tests/test_steam_tracking.py",
    "tests/test_update.py",
    "tests/test_windows_proxy.py",
)

def source_tree_artifacts(root: Path = ROOT) -> list[str]:
    artifacts: list[str] = []
    for current_root, directories, filenames in os.walk(root):
        current = Path(current_root)
        for directory in list(directories):
            if directory == ".git":
                directories.remove(directory)
                continue
            if directory in {".pytest_cache", ".mypy_cache", ".ruff_cache", "htmlcov", "__pycache__"}:
                path = current / directory
                artifacts.append(path.relative_to(root).as_posix() + "/")
                directories.remove(directory)
        for filename in filenames:
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if filename.endswith(".lock") and relative in KNOWN_RUNTIME_LOCK_FILES:
                continue
            if filename in {".coverage", "coverage.xml"} or filename.endswith((".part", ".pyc", ".pyo", ".lock")):
                artifacts.append(relative)
    return sorted(artifacts, key=str.casefold)

def validate_source_tree_cleanliness(root: Path = ROOT) -> None:
    artifacts = source_tree_artifacts(root)
    if not artifacts:
        return
    details = "\n".join(f"- {path}" for path in artifacts)
    raise RuntimeError(f"Generated/cache artifacts must be removed before building a release:\n{details}")

def release_source_fingerprint(root: Path = ROOT) -> str:
    digest = hashlib.sha256()
    for relative in RELEASE_SOURCE_FILES:
        path = root / relative
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"Could not read release source file while checking build consistency: {path}") from exc
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
    return digest.hexdigest()

def _runtime_build_lock_specs(root: Path) -> list[tuple[Path, str]]:
    return [
        *(
            (root / relative, f"Active runtime lock: {relative}")
            for relative in sorted(KNOWN_RUNTIME_LOCK_FILES)
        ),
        (capture_activity_lock_path(root), "Active runtime lock: LocalAppData capture lock"),
    ]

@contextlib.contextmanager
def runtime_build_barrier(root: Path = ROOT):
    if sys.platform != "win32":
        yield
        return

    with contextlib.ExitStack() as locks:
        try:
            for path, message in _runtime_build_lock_specs(root):
                locks.enter_context(windows_file_lock(path, 0, message))
        except FileLockBusyError as exc:
            raise RuntimeError(
                "Ninja Capture Tool is currently running or updating. Close it before building a release.\n"
                f"{exc}"
            ) from exc
        except PermissionError as exc:
            raise RuntimeError(
                "Ninja Capture Tool runtime locks could not be acquired. Close Ninja Capture Tool before building a release."
            ) from exc
        yield

def sanitize_staged_runtime_locks(stage: Path) -> None:
    for relative in KNOWN_RUNTIME_LOCK_FILES:
        path = stage / relative
        if path.is_dir():
            raise RuntimeError(f"Expected a runtime lock file but found a directory in release staging: {relative}")
        path.unlink(missing_ok=True)

    leftovers = sorted(
        path.relative_to(stage).as_posix()
        for path in stage.rglob("*.lock")
        if path.is_file()
    )
    if leftovers:
        details = "\n".join(f"- {path}" for path in leftovers)
        raise RuntimeError(f"Release staging contains unexpected runtime lock files:\n{details}")

def clean_markdown_inline(text: str) -> str:
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", text)
    return text.replace("***", "").replace("**", "").replace("`", "")

def create_release_readme(markdown: str) -> str:
    lines: list[str] = []
    in_code = False
    skip_section = False
    skipped_sections = {"Running from source", "Standalone Windows build", "Tests", "Planned later work"}

    for line in markdown.splitlines():
        if line.startswith("## "):
            heading = clean_markdown_inline(line[3:])
            skip_section = heading in skipped_sections
            if skip_section:
                continue
            lines.extend([heading, "-" * len(heading)])
            continue
        if skip_section:
            continue
        if line.startswith("### "):
            heading = clean_markdown_inline(line[4:])
            lines.extend([heading, "~" * len(heading)])
            continue
        if line.startswith("```"):
            in_code = not in_code
            continue
        if line == "When running from source, use `py -3.14 ninja_capture_tool.py` instead.":
            continue
        if line.startswith("# "):
            heading = clean_markdown_inline(line[2:])
            lines.extend([heading, "=" * len(heading), f"Version {DISPLAY_VERSION}"])
            continue

        line = clean_markdown_inline(line)
        if in_code and line:
            line = "    " + line
        lines.append(line)

    return "\n".join(lines).rstrip()

ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)

def validate_ico(path: Path) -> None:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read icon file: {path}") from exc
    if len(data) < 6:
        raise RuntimeError(f"Invalid ICO file: {path}")
    reserved, icon_type, count = struct.unpack_from("<HHH", data, 0)
    directory_end = 6 + count * 16
    if reserved != 0 or icon_type != 1 or count == 0 or len(data) < directory_end:
        raise RuntimeError(f"Invalid ICO file: {path}")
    if count != len(ICO_SIZES):
        raise RuntimeError(
            f"ICO must contain exactly these resolutions: {', '.join(f'{size}x{size}' for size in ICO_SIZES)}: {path}"
        )

    found_sizes: set[int] = set()
    for index in range(count):
        entry_offset = 6 + index * 16
        width = data[entry_offset] or 256
        height = data[entry_offset + 1] or 256
        planes, bit_count = struct.unpack_from("<HH", data, entry_offset + 4)
        size, offset = struct.unpack_from("<II", data, entry_offset + 8)
        if (
            width != height
            or width not in ICO_SIZES
            or width in found_sizes
            or planes not in {0, 1}
            or bit_count != 32
            or size == 0
            or offset < directory_end
            or offset + size > len(data)
        ):
            raise RuntimeError(f"Invalid ICO entry in {path}")

        payload = data[offset:offset + size]
        if (
            len(payload) < 26
            or not payload.startswith(b"\x89PNG\r\n\x1a\n")
            or payload[12:16] != b"IHDR"
        ):
            raise RuntimeError(f"ICO entry {width}x{height} must be PNG-compressed: {path}")
        png_width, png_height = struct.unpack_from(">II", payload, 16)
        if png_width != width or png_height != height:
            raise RuntimeError(f"ICO entry dimensions do not match its PNG payload: {path}")
        # PNG color types 4 and 6 contain an alpha channel.
        if payload[25] not in {4, 6}:
            raise RuntimeError(f"ICO entry {width}x{height} must contain transparency: {path}")
        found_sizes.add(width)

    if found_sizes != set(ICO_SIZES):
        raise RuntimeError(
            f"ICO must contain exactly these resolutions: {', '.join(f'{size}x{size}' for size in ICO_SIZES)}: {path}"
        )

def validate_environment() -> None:
    if sys.platform != "win32":
        raise RuntimeError("Releases must be built on Windows.")
    if struct.calcsize("P") != 8:
        raise RuntimeError("A 64-bit Python installation is required to build the Windows x64 release.")
    if sys.version_info[:2] != (3, 14):
        raise RuntimeError("Python 3.14 is required to build releases. Run: py -3.14 build_release.py")
    validate_source_tree_cleanliness()

    missing = [ROOT / name for name in RELEASE_SOURCE_FILES if not (ROOT / name).is_file()]
    if missing:
        raise RuntimeError("Required source files are missing:\n" + "\n".join(f"- {path}" for path in missing))
    load_config(ROOT / "config.json")
    validate_ico(FAVICON)
    validate_mitmproxy_installation()
    validate_windows_capture_package()
    try:
        steam_client_version = importlib.metadata.version("pysteam-client")
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError(f"pysteam-client[client] {STEAM_CLIENT_VERSION} is required. Run: py -3.14 -m pip install -r requirements.txt") from None
    if steam_client_version != STEAM_CLIENT_VERSION:
        raise RuntimeError(f"pysteam-client {STEAM_CLIENT_VERSION} is required. Installed version: {steam_client_version}")

    try:
        pyinstaller_version = Version(importlib.metadata.version("pyinstaller"))
    except importlib.metadata.PackageNotFoundError:
        raise RuntimeError("PyInstaller is not installed for Python 3.14. Run: py -3.14 -m pip install pyinstaller") from None
    except InvalidVersion as exc:
        raise RuntimeError(f"Could not parse the installed PyInstaller version: {exc}") from exc
    if pyinstaller_version < MIN_PYINSTALLER_VERSION:
        raise RuntimeError(f"PyInstaller {MIN_PYINSTALLER_VERSION} or newer is required for Python 3.14. Installed version: {pyinstaller_version}")

def remove_release_temp() -> None:
    for attempt in range(20):
        try:
            shutil.rmtree(RELEASE_TEMP_DIR)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == 19:
                raise
            time.sleep(0.1)

def release_publication_path() -> Path:
    return RELEASE_TEMP_DIR / "publication"

def previous_release_path() -> Path:
    return RELEASE_TEMP_DIR / "previous_release"

def _restore_stashed_release_if_needed() -> None:
    previous = previous_release_path()
    if not (previous.exists() or previous.is_symlink()):
        return
    if RELEASE_DIR.exists() or RELEASE_DIR.is_symlink():
        return
    _replace_path_with_retry(previous, RELEASE_DIR)

def clean_stale_release_temp() -> None:
    if not RELEASE_TEMP_DIR.exists():
        return
    print("[Cleaning] Previous temporary build files")
    try:
        _restore_stashed_release_if_needed()
        remove_release_temp()
    except OSError as exc:
        raise RuntimeError(f"Could not recover/remove previous temporary build files: {RELEASE_TEMP_DIR}") from exc

def _terminate_active_build_process() -> None:
    process = _ACTIVE_BUILD_PROCESS
    if process is None or process.poll() is not None:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=0.5)
    except (OSError, subprocess.TimeoutExpired):
        pass

def _release_console_control_handler(control_type: int) -> bool:
    # Ctrl+C follows Python's normal KeyboardInterrupt path. Window close, logoff,
    # and shutdown events may terminate the process without unwinding finally blocks.
    if control_type not in {2, 5, 6}:
        return False
    _terminate_active_build_process()
    try:
        _restore_stashed_release_if_needed()
    except OSError:
        return False
    try:
        remove_release_temp()
    except OSError:
        pass
    return False

@contextlib.contextmanager
def release_console_cleanup():
    if sys.platform != "win32":
        yield
        return

    handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
    handler = handler_type(_release_console_control_handler)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetConsoleCtrlHandler.argtypes = [handler_type, ctypes.c_bool]
    kernel32.SetConsoleCtrlHandler.restype = ctypes.c_bool
    if not kernel32.SetConsoleCtrlHandler(handler, True):
        raise OSError(ctypes.get_last_error(), "Could not install release build console cleanup handler.")
    try:
        yield
    finally:
        kernel32.SetConsoleCtrlHandler(handler, False)

@contextlib.contextmanager
def release_lock():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32
    kernel32.ReleaseMutex.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel32.CreateMutexW(None, False, "Local\\DarkLotus.NinjaCaptureTool.Release")
    if not handle:
        raise OSError(ctypes.get_last_error(), "Could not create release mutex.")
    result = kernel32.WaitForSingleObject(handle, 0)
    if result == 0x102:
        kernel32.CloseHandle(handle)
        raise RuntimeError("Another Ninja Capture Tool release build is already running.")
    if result not in {0, 0x80}:
        error = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise OSError(error, "Could not acquire release mutex.")
    try:
        yield
    finally:
        kernel32.ReleaseMutex(handle)
        kernel32.CloseHandle(handle)

def run_tests() -> None:
    print("[Testing] Source test suite")
    try:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [
                sys.executable,
                "-W", "error::DeprecationWarning",
                "-W", "error::RuntimeWarning",
                "-W", "error::ResourceWarning",
                "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py",
            ],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=300,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Source test suite timed out.") from exc
    if result.returncode != 0:
        details = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip()) or "No output was produced."
        raise RuntimeError(f"Source test suite failed:\n{details}")

def create_version_file(destination: Path) -> Path:
    parts = VERSION.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise RuntimeError("VERSION must contain three numeric components.")
    numbers = [int(part) for part in parts]
    if any(number > 65535 for number in numbers):
        raise RuntimeError("Every VERSION component must be between 0 and 65535 for Windows version resources.")
    version = (*numbers, 0)
    file = destination / "version.txt"
    file.write_text(
        f'''VSVersionInfo(\n  ffi=FixedFileInfo(filevers={version!r}, prodvers={version!r}, mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),\n  kids=[\n    StringFileInfo([StringTable('040904B0', [\n      StringStruct('CompanyName', 'DarkLotus'),\n      StringStruct('FileDescription', 'Ninja Capture Tool'),\n      StringStruct('FileVersion', '{DISPLAY_VERSION}'),\n      StringStruct('InternalName', 'NinjaCaptureTool'),\n      StringStruct('LegalCopyright', 'DarkLotus'),\n      StringStruct('ProductName', 'Ninja Capture Tool'),\n      StringStruct('ProductVersion', '{DISPLAY_VERSION}')\n    ])]),\n    VarFileInfo([VarStruct('Translation', [1033, 1200])])\n  ]\n)\n''',
        encoding="utf-8",
    )
    return file

def create_application_manifest(destination: Path) -> Path:
    path = destination / "NinjaCaptureTool.manifest"
    path.write_text("""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
""", encoding="utf-8", newline="\n")
    return path

def pyinstaller_command(
    dist: Path, work: Path, specs: Path, version_file: Path, manifest_file: Path
) -> list[str]:
    return [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--log-level",
        "WARN",
        "--onedir",
        "--contents-directory",
        FROZEN_RUNTIME_DIR_NAME,
        "--windowed",
        "--noupx",
        "--name",
        "NinjaCaptureTool",
        "--distpath",
        str(dist),
        "--workpath",
        str(work),
        "--specpath",
        str(specs),
        "--version-file",
        str(version_file),
        "--manifest",
        str(manifest_file),
        "--icon",
        str(FAVICON),
        "--exclude-module",
        "pycparser.lextab",
        "--exclude-module",
        "pycparser.yacctab",
        "--collect-all",
        "mitmproxy",
        "--collect-all",
        "mitmproxy_rs",
        "--collect-all",
        "mitmproxy_windows",
        "--recursive-copy-metadata",
        "mitmproxy",
        "--collect-all",
        "steam",
        "--recursive-copy-metadata",
        "pysteam-client",
        str(ROOT / "ninja_capture_tool.py"),
    ]

def release_build_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment[RELEASE_BUILD_ENV] = "1"
    return environment

def _run_tracked_build_process(
    command: list[str],
    *,
    timeout: float | None = None,
    capture_output: bool = False,
    **kwargs,
) -> subprocess.CompletedProcess:
    global _ACTIVE_BUILD_PROCESS
    if capture_output:
        if "stdout" in kwargs or "stderr" in kwargs:
            raise ValueError("capture_output cannot be combined with stdout or stderr")
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    process = subprocess.Popen(command, **kwargs)
    _ACTIVE_BUILD_PROCESS = process
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        _terminate_active_build_process()
        raise
    finally:
        if _ACTIVE_BUILD_PROCESS is process:
            _ACTIVE_BUILD_PROCESS = None
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

def build_executable(dist: Path, work: Path, specs: Path, version_file: Path, manifest_file: Path) -> Path:
    global _ACTIVE_BUILD_PROCESS
    print("[Compiling] NinjaCaptureTool.exe")
    process = subprocess.Popen(
        pyinstaller_command(dist, work, specs, version_file, manifest_file),
        cwd=ROOT,
        env=release_build_environment(),
    )
    _ACTIVE_BUILD_PROCESS = process
    try:
        returncode = process.wait()
    except BaseException:
        _terminate_active_build_process()
        raise
    finally:
        if _ACTIVE_BUILD_PROCESS is process:
            _ACTIVE_BUILD_PROCESS = None
    if returncode != 0:
        raise RuntimeError(f"PyInstaller failed for NinjaCaptureTool.exe with exit code {returncode}.")
    distribution = dist / "NinjaCaptureTool"
    executable = distribution / "NinjaCaptureTool.exe"
    runtime = distribution / FROZEN_RUNTIME_DIR_NAME
    if not executable.is_file():
        raise RuntimeError(f"PyInstaller did not create the expected executable: {executable}")
    if not runtime.is_dir() or runtime.is_symlink() or next(runtime.iterdir(), None) is None:
        raise RuntimeError(f"PyInstaller did not create the expected runtime directory: {runtime}")
    validate_pe_x64(executable)
    return executable

def validate_pe_x64(executable: Path) -> None:
    with executable.open("rb") as file:
        if file.read(2) != b"MZ":
            raise RuntimeError(f"Built executable is not a valid PE file: {executable}")
        file.seek(0x3C)
        pe_offset_bytes = file.read(4)
        if len(pe_offset_bytes) != 4:
            raise RuntimeError(f"Built executable has an invalid PE header: {executable}")
        pe_offset = struct.unpack("<I", pe_offset_bytes)[0]
        file.seek(pe_offset)
        if file.read(4) != b"PE\0\0":
            raise RuntimeError(f"Built executable has an invalid PE signature: {executable}")
        machine_bytes = file.read(2)
        if len(machine_bytes) != 2 or struct.unpack("<H", machine_bytes)[0] != 0x8664:
            raise RuntimeError("Built executable is not Windows x64.")

def smoke_test_steam_worker_import(executable: Path, environment: dict[str, str]) -> None:
    result = _run_tracked_build_process(
        [str(executable), STEAM_QUERY_WORKER_SMOKE_ARGUMENT],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        timeout=30,
    )
    tagged = [
        line[len(STEAM_QUERY_RESULT_PREFIX):].strip()
        for line in result.stdout.splitlines()
        if line.startswith(STEAM_QUERY_RESULT_PREFIX)
    ]
    try:
        payload = json.loads(tagged[-1]) if tagged else None
    except json.JSONDecodeError:
        payload = None
    if result.returncode != 0 or payload != {"ok": True, "smoke": "steam-import"}:
        details = result.stderr.strip() or result.stdout.strip() or "No tagged Steam worker result was produced."
        raise RuntimeError(f"Standalone Steam worker smoke test failed:\n{details}")

def smoke_test(executable: Path) -> None:
    checks = (
        (["--version"], f"Ninja Capture Tool v{DISPLAY_VERSION}"),
        (["--help"], "Capture Warframe CDN responses"),
        (["--update-installer", "--version"], f"Ninja Capture Tool v{DISPLAY_VERSION}"),
    )
    environment = release_build_environment()
    environment["NCT_HEADLESS"] = "1"
    for arguments, expected in checks:
        result = _run_tracked_build_process(
            [str(executable), *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            timeout=120,
        )
        if result.returncode != 0 or expected not in result.stdout:
            details = result.stderr.strip() or result.stdout.strip() or "No output was produced."
            raise RuntimeError(f"Standalone executable smoke test failed for {' '.join(arguments)}:\n{details}")
    smoke_test_steam_worker_import(executable, environment)

def smoke_test_frozen_capture(executable: Path) -> None:
    environment = release_build_environment()
    environment["NCT_HEADLESS"] = "1"
    environment["NCT_SMOKE_TEST"] = "frozen-capture"
    result = _run_tracked_build_process(
        [str(executable)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        timeout=120,
    )
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "No output was produced."
        raise RuntimeError(f"Frozen CaptureWriter smoke test failed:\n{details}")

def normalized_distribution_name(name: str) -> str:
    return name.casefold().replace("_", "-").replace(".", "-")

def dependency_closure(root_name: str, *, extras: frozenset[str] = frozenset()) -> list[importlib.metadata.Distribution]:
    pending: list[tuple[str, frozenset[str]]] = [(root_name, extras)]
    processed_extras: dict[str, set[str]] = {}
    result: dict[str, importlib.metadata.Distribution] = {}
    while pending:
        name, active_extras = pending.pop()
        key = normalized_distribution_name(name)
        seen = processed_extras.setdefault(key, set())
        marker_extras = set(active_extras) or {""}
        if marker_extras.issubset(seen):
            continue
        seen.update(marker_extras)
        try:
            distribution = importlib.metadata.distribution(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(f"Could not inspect bundled dependency metadata: {name}") from exc
        result.setdefault(key, distribution)
        for raw_requirement in distribution.requires or []:
            requirement = Requirement(raw_requirement)
            if requirement.marker is not None:
                applies_without_extra = requirement.marker.evaluate({"extra": ""})
                applies_with_extra = any(requirement.marker.evaluate({"extra": extra}) for extra in active_extras)
                if not applies_without_extra and not applies_with_extra:
                    continue
            pending.append((requirement.name, frozenset(requirement.extras)))
    return sorted(result.values(), key=lambda item: normalized_distribution_name(item.metadata["Name"] or ""))

def is_license_or_notice_name(name: str) -> bool:
    lowered = name.casefold()
    return lowered.startswith(("license", "copying", "notice")) or lowered.endswith(
        (".license", ".copying", ".notice")
    )

def distribution_license_files(distribution: importlib.metadata.Distribution) -> list[Path]:
    result: list[Path] = []
    for item in distribution.files or []:
        if is_license_or_notice_name(Path(str(item)).name):
            path = Path(distribution.locate_file(item))
            if path.is_file():
                result.append(path)
    return result

def fallback_license_files(distribution: importlib.metadata.Distribution) -> list[Path]:
    name = normalized_distribution_name(distribution.metadata["Name"] or "")
    version = distribution.version
    fallback = VERSIONED_FALLBACK_LICENSE_FILES.get((name, version))
    if fallback is None:
        fallback = FALLBACK_LICENSE_FILES.get(name)
    if fallback is None:
        return []
    if not fallback.is_file():
        raise RuntimeError(f"Bundled fallback license file is missing: {fallback}")
    return [fallback]

def find_python_license() -> Path:
    for name in ("LICENSE.txt", "LICENSE"):
        candidate = Path(sys.base_prefix) / name
        if candidate.is_file():
            return candidate
    fallback = FALLBACK_LICENSE_FILES["python"]
    if fallback.is_file():
        return fallback
    raise RuntimeError(
        f"Could not locate the Python license under {sys.base_prefix} or at {fallback}."
    )

def normalized_license_output_name(prefix: str, source: Path, index: int, total: int) -> str:
    name = source.name
    lowered = name.casefold()
    for suffix in (".txt", ".rst", ".md"):
        if lowered.endswith(suffix):
            name = name[: -len(suffix)]
            break
    ordinal = f"{index}-" if total > 1 else ""
    return f"{prefix}-{ordinal}{name}.txt"

def collect_third_party_licenses(stage: Path) -> None:
    destination = stage / "data" / "licenses"
    destination.mkdir(parents=True, exist_ok=True)
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    shutil.copy2(find_python_license(), destination / f"Python-{python_version}-LICENSE.txt")

    missing: list[str] = []
    distributions: dict[str, importlib.metadata.Distribution] = {}
    for root_name in ("mitmproxy", "pysteam-client"):
        extras = frozenset({"client"}) if root_name == "pysteam-client" else frozenset()
        for distribution in dependency_closure(root_name, extras=extras):
            key = normalized_distribution_name(distribution.metadata["Name"] or "")
            distributions.setdefault(key, distribution)
    for distribution in sorted(distributions.values(), key=lambda item: normalized_distribution_name(item.metadata["Name"] or "")):
        name = distribution.metadata["Name"] or "unknown"
        version = distribution.version
        licenses = distribution_license_files(distribution) or fallback_license_files(distribution)
        if not licenses:
            missing.append(f"{name} {version}")
            continue
        prefix = f"{normalized_distribution_name(name)}-{version}"
        for index, path in enumerate(licenses, 1):
            target = destination / normalized_license_output_name(prefix, path, index, len(licenses))
            if target.exists():
                raise RuntimeError(f"Duplicate flattened license filename: {target.name}")
            shutil.copy2(path, target)
    if missing:
        raise RuntimeError(
            "Could not locate license/notice files for bundled dependencies:\n"
            + "\n".join(f"- {item}" for item in missing)
        )

def remove_duplicate_runtime_license_files(stage: Path) -> list[str]:
    runtime = stage / FROZEN_RUNTIME_DIR_NAME
    licenses = stage / "data" / "licenses"
    if not runtime.is_dir() or not licenses.is_dir():
        return []

    preserved_digests: set[str] = set()
    for path in licenses.iterdir():
        if path.is_file():
            with path.open("rb") as file:
                preserved_digests.add(hashlib.file_digest(file, "sha256").hexdigest())

    removed: list[str] = []
    for path in sorted(runtime.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not path.is_file() or path.is_symlink() or not is_license_or_notice_name(path.name):
            continue
        with path.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
        if digest not in preserved_digests:
            continue
        relative = path.relative_to(stage).as_posix()
        path.unlink()
        removed.append(relative)
    return removed

def release_managed_file_hashes(stage: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for path in sorted(stage.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        if relative == RELEASE_MANIFEST_FILE or relative in PRESERVED_RELEASE_FILES:
            continue
        with path.open("rb") as file:
            files[relative] = hashlib.file_digest(file, "sha256").hexdigest()
    return files

def write_release_manifest(stage: Path) -> None:
    manifest = {
        "format_version": RELEASE_MANIFEST_VERSION,
        "application_version": VERSION,
        "files": release_managed_file_hashes(stage),
    }
    path = stage / RELEASE_MANIFEST_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

def validate_release_manifest(stage: Path) -> None:
    path = stage / RELEASE_MANIFEST_FILE
    try:
        value = parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Release manifest is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Release manifest must contain a JSON object.")
    if value.get("format_version") != RELEASE_MANIFEST_VERSION:
        raise RuntimeError("Release manifest has an unsupported format version.")
    if value.get("application_version") != VERSION:
        raise RuntimeError("Release manifest application version does not match the build version.")
    files = value.get("files")
    if not isinstance(files, dict) or any(
        not isinstance(name, str)
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for name, digest in files.items()
    ):
        raise RuntimeError("Release manifest contains invalid file hashes.")
    if files != release_managed_file_hashes(stage):
        raise RuntimeError("Release manifest does not match the staged release files.")

def validate_stage(stage: Path) -> None:
    required = {"NinjaCaptureTool.exe", FROZEN_RUNTIME_DIR_NAME, "config.json", "README.txt", "data"}
    actual = {path.name for path in stage.iterdir()}
    if actual != required:
        raise RuntimeError(f"Unexpected release staging contents: {sorted(actual)}")
    runtime = stage / FROZEN_RUNTIME_DIR_NAME
    if not runtime.is_dir() or runtime.is_symlink() or next(runtime.iterdir(), None) is None:
        raise RuntimeError("Release runtime directory is missing or empty.")
    data_dir = stage / "data"
    expected_data = {"licenses", Path(RELEASE_MANIFEST_FILE).name}
    if {path.name for path in data_dir.iterdir()} != expected_data:
        raise RuntimeError("Release data directory contains unexpected runtime files before first run.")
    licenses = data_dir / "licenses"
    license_files = [path for path in licenses.iterdir() if path.is_file()]
    if not license_files or any(path.is_dir() for path in licenses.iterdir()):
        raise RuntimeError("Release licenses directory must contain a flat set of license files.")
    if not (licenses / NCT_LICENSE_RELEASE_NAME).is_file():
        raise RuntimeError("Release licenses directory is missing Ninja Capture Tool's license.")
    if any(path.suffix.casefold() != ".txt" for path in license_files):
        raise RuntimeError("Release license files must use the .txt extension.")
    validate_release_manifest(stage)

def release_archive_path(directory: Path | None = None) -> Path:
    root = RELEASE_DIR if directory is None else directory
    return root / f"NinjaCaptureTool-v{VERSION}-Windows-x64.zip"

def release_checksum_path(directory: Path | None = None) -> Path:
    archive = release_archive_path(directory)
    return archive.with_name(archive.name + ".sha256")

def release_extract_path(directory: Path | None = None) -> Path:
    root = RELEASE_DIR if directory is None else directory
    return root / f"NinjaCaptureTool-v{VERSION}"

def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)

def _remove_path_with_retry(path: Path, attempts: int = 20, delay_seconds: float = 0.1) -> None:
    for attempt in range(attempts):
        try:
            _remove_path(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)

def _replace_path_with_retry(source: Path, destination: Path, attempts: int = 20, delay_seconds: float = 0.1) -> None:
    for attempt in range(attempts):
        try:
            source.replace(destination)
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay_seconds)

def stash_existing_release() -> bool:
    previous = previous_release_path()
    if previous.exists() or previous.is_symlink():
        raise RuntimeError(f"Temporary previous-release path already exists: {previous}")
    if not (RELEASE_DIR.exists() or RELEASE_DIR.is_symlink()):
        return False
    if RELEASE_DIR.is_symlink() or not RELEASE_DIR.is_dir():
        raise RuntimeError(f"Release output path is not a real directory: {RELEASE_DIR}")
    _replace_path_with_retry(RELEASE_DIR, previous)
    return True

def extract_release_archive(archive: Path, publication: Path) -> Path:
    destination = release_extract_path(publication)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError(f"Release extraction destination already exists: {destination}")
    with zipfile.ZipFile(archive, "r") as zip_file:
        zip_file.extractall(publication)
    if not destination.is_dir() or destination.is_symlink():
        raise RuntimeError("Release archive did not extract to the expected top-level directory.")
    validate_stage(destination)
    return destination

def smoke_test_release_archive(archive: Path) -> None:
    temporary_root = RELEASE_TEMP_DIR / "archive_smoke"
    _remove_path(temporary_root)
    temporary_root.mkdir(parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(archive, "r") as zip_file:
            zip_file.extractall(temporary_root)
        release_root = temporary_root / f"NinjaCaptureTool-v{VERSION}"
        children = list(temporary_root.iterdir())
        if children != [release_root] or not release_root.is_dir() or release_root.is_symlink():
            raise RuntimeError("Packaged release did not extract to the expected top-level directory.")
        executable = release_root / "NinjaCaptureTool.exe"
        runtime = release_root / FROZEN_RUNTIME_DIR_NAME
        if not executable.is_file():
            raise RuntimeError("Packaged release is missing NinjaCaptureTool.exe.")
        if not runtime.is_dir() or runtime.is_symlink() or next(runtime.iterdir(), None) is None:
            raise RuntimeError("Packaged release runtime directory is missing or empty.")
        smoke_test(executable)
        smoke_test_frozen_capture(executable)
    finally:
        _remove_path_with_retry(temporary_root)

class ReleaseArgumentParser(argparse.ArgumentParser):
    """Keep release-builder argument errors consistent with the tool's severity format."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        if message[:1].islower():
            message = message[0].upper() + message[1:]
        print_error(message)
        self.exit(2)

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = ReleaseArgumentParser(description="Build the Ninja Capture Tool Windows release.")
    parser.add_argument(
        "-e",
        "--extract",
        action="store_true",
        help="Also extract the completed release ZIP beside the archive.",
    )
    return parser.parse_args(argv)

def create_release_outputs(stage: Path, publication: Path, previous_release: Path | None = None) -> tuple[Path, Path, str, str]:
    validate_stage(stage)
    publication.mkdir(parents=True, exist_ok=False)
    archive = release_archive_path(publication)
    checksum = release_checksum_path(publication)
    prefix = Path(f"NinjaCaptureTool-v{VERSION}")
    try:
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zip_file:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    zip_file.write(path, (prefix / path.relative_to(stage)).as_posix())
        validate_release_archive(archive, stage)
        print("[Testing] Packaged release")
        smoke_test_release_archive(archive)
        with archive.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
        checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")

        result = "created"
        if previous_release is not None:
            previous_archive = release_archive_path(previous_release)
            if previous_archive.is_file():
                with previous_archive.open("rb") as file:
                    previous_digest = hashlib.file_digest(file, "sha256").hexdigest()
                result = "unchanged" if previous_digest == digest else "replaced"
        return archive, checksum, digest, result
    except BaseException:
        _remove_path_with_retry(publication)
        raise

def validate_release_publication(publication: Path, *, include_extracted: bool) -> None:
    archive = release_archive_path(publication)
    checksum = release_checksum_path(publication)
    expected = {archive.name, checksum.name}
    if include_extracted:
        expected.add(release_extract_path(publication).name)
    actual = {path.name for path in publication.iterdir()}
    if actual != expected:
        raise RuntimeError(f"Unexpected final release publication contents: {sorted(actual)}")
    if not archive.is_file() or not checksum.is_file():
        raise RuntimeError("Final release publication is missing its archive or checksum.")
    if include_extracted:
        extracted = release_extract_path(publication)
        if not extracted.is_dir() or extracted.is_symlink():
            raise RuntimeError("Final release publication is missing its extracted release directory.")

def publish_release_directory(publication: Path) -> None:
    if RELEASE_DIR.exists() or RELEASE_DIR.is_symlink():
        raise RuntimeError(f"Release directory unexpectedly exists before final publication: {RELEASE_DIR}")
    _replace_path_with_retry(publication, RELEASE_DIR)

def validate_release_archive(archive: Path, stage: Path) -> None:
    prefix = f"NinjaCaptureTool-v{VERSION}/"
    expected_names = {
        prefix + path.relative_to(stage).as_posix()
        for path in stage.rglob("*")
        if path.is_file()
    }
    with zipfile.ZipFile(archive, "r") as zip_file:
        bad_member = zip_file.testzip()
        if bad_member is not None:
            raise RuntimeError(f"Release archive CRC validation failed: {bad_member}")
        names = zip_file.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("Release archive contains duplicate members.")
        actual_names = set(names)
        if actual_names != expected_names:
            missing = sorted(expected_names - actual_names, key=str.casefold)
            extra = sorted(actual_names - expected_names, key=str.casefold)
            details = []
            if missing:
                details.append("Missing: " + ", ".join(missing))
            if extra:
                details.append("Unexpected: " + ", ".join(extra))
            raise RuntimeError("Release archive member set does not match the staged release. " + " ".join(details))

        manifest_name = prefix + RELEASE_MANIFEST_FILE
        try:
            archived_manifest = parse_json(zip_file.read(manifest_name).decode("utf-8"))
            staged_manifest = parse_json((stage / RELEASE_MANIFEST_FILE).read_text(encoding="utf-8"))
        except (KeyError, UnicodeDecodeError, OSError, ValueError) as exc:
            raise RuntimeError(f"Release archive manifest is invalid: {exc}") from exc
        if archived_manifest != staged_manifest:
            raise RuntimeError("Release archive manifest does not match the staged release manifest.")
        files = archived_manifest.get("files") if isinstance(archived_manifest, dict) else None
        if not isinstance(files, dict):
            raise RuntimeError("Release archive manifest contains invalid file metadata.")
        for relative, expected_digest in files.items():
            try:
                with zip_file.open(prefix + relative, "r") as member:
                    actual_digest = hashlib.file_digest(member, "sha256").hexdigest()
            except KeyError as exc:
                raise RuntimeError(f"Release archive is missing managed file: {relative}") from exc
            if actual_digest != expected_digest:
                raise RuntimeError(f"Release archive hash mismatch: {relative}")

def main(argv: list[str] | None = None) -> int:
    started = time.perf_counter()
    args = parse_args([] if argv is None else argv)
    extracted: Path | None = None
    try:
        validate_environment()
        with release_lock():
            with release_console_cleanup():
                clean_stale_release_temp()
                RELEASE_TEMP_DIR.mkdir(parents=True, exist_ok=False)
                stashed_release = False
                publication = release_publication_path()
                try:
                    stashed_release = stash_existing_release()
                    # Take a stable snapshot while runtime activity is excluded, then let the source tests run
                    # without holding Ninja Capture Tool's installation locks. Some Windows tests intentionally exercise those
                    # same locks. Reacquiring the barrier and comparing the snapshot closes the TOCTOU window:
                    # the exact source that passed tests must be the source that is built.
                    with runtime_build_barrier():
                        tested_source_fingerprint = release_source_fingerprint()
                    run_tests()
                    with runtime_build_barrier():
                        validate_source_tree_cleanliness()
                        if release_source_fingerprint() != tested_source_fingerprint:
                            raise RuntimeError(
                                "Release source changed while the source test suite was running. "
                                "Retry the build after all Ninja Capture Tool/update activity has stopped."
                            )
                        dist = RELEASE_TEMP_DIR / "dist"
                        work = RELEASE_TEMP_DIR / "work"
                        specs = RELEASE_TEMP_DIR / "specs"
                        stage = RELEASE_TEMP_DIR / "stage"
                        for directory in (dist, work, specs, stage):
                            directory.mkdir()
                        version_file = create_version_file(RELEASE_TEMP_DIR)
                        manifest_file = create_application_manifest(RELEASE_TEMP_DIR)
                        executable = build_executable(dist, work / "main", specs, version_file, manifest_file)
                        # Smoke-test a disposable copy so first-run configuration or future runtime side effects
                        # can never contaminate the pristine PyInstaller distribution that is staged for release.
                        smoke_distribution = RELEASE_TEMP_DIR / "smoke" / executable.parent.name
                        smoke_distribution.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copytree(executable.parent, smoke_distribution)
                        smoke_executable = smoke_distribution / executable.name
                        print("[Testing] Standalone executable")
                        smoke_test(smoke_executable)
                        smoke_test_frozen_capture(smoke_executable)
                        for source in sorted(executable.parent.iterdir(), key=lambda path: path.name.casefold()):
                            destination = stage / source.name
                            if source.is_dir():
                                shutil.copytree(source, destination)
                            else:
                                shutil.copy2(source, destination)
                        shutil.copy2(ROOT / "config.json", stage / "config.json")
                        release_licenses = stage / "data" / "licenses"
                        release_licenses.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(ROOT / "LICENSE", release_licenses / NCT_LICENSE_RELEASE_NAME)
                        readme = create_release_readme((ROOT / "README.md").read_text(encoding="utf-8"))
                        (stage / "README.txt").write_text(readme, encoding="utf-8", newline="\r\n")
                        collect_third_party_licenses(stage)
                        remove_duplicate_runtime_license_files(stage)
                        sanitize_staged_runtime_locks(stage)
                        write_release_manifest(stage)
                        previous = previous_release_path() if stashed_release else None
                        temporary_archive, temporary_checksum, digest, result = create_release_outputs(
                            stage, publication, previous
                        )
                        if args.extract:
                            extract_release_archive(temporary_archive, publication)
                        validate_release_publication(publication, include_extracted=args.extract)
                        publish_release_directory(publication)
                        archive = release_archive_path()
                        checksum = release_checksum_path()
                        extracted = release_extract_path() if args.extract else None
                except BaseException:
                    restore_error: OSError | None = None
                    try:
                        _restore_stashed_release_if_needed()
                    except OSError as exc:
                        restore_error = exc
                    if restore_error is None:
                        try:
                            remove_release_temp()
                        except OSError as cleanup_exc:
                            print(
                                f"WARNING: Could not remove temporary build files after the build failed: {RELEASE_TEMP_DIR}: {cleanup_exc}",
                                file=sys.stderr,
                            )
                    else:
                        print(
                            f"WARNING: Could not restore the previous release after the build failed. "
                            f"Recovery data was kept at {previous_release_path()}: {restore_error}",
                            file=sys.stderr,
                        )
                    raise
                else:
                    try:
                        remove_release_temp()
                    except OSError as exc:
                        print(
                            f"WARNING: Release completed, but temporary build files could not be removed: {RELEASE_TEMP_DIR}: {exc}",
                            file=sys.stderr,
                        )

        duration = format_duration(time.perf_counter() - started)
        summary = (
            f'\n[{result.capitalize()}] Release completed successfully.\n'
            f'Version: {DISPLAY_VERSION}\n'
            f'Duration: {duration}\n'
            f'Size: {format_bytes(archive.stat().st_size)}\n'
            f'Archive: {archive}\n'
            f'SHA-256: {digest}\n'
            f'Checksum: {checksum}'
        )
        if extracted is not None:
            summary += f'\nExtracted: {extracted}'
        print(summary)
        return 0
    except KeyboardInterrupt:
        print("\nRelease creation interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print_error(exc)
        return 1

def run_main_with_console_title(argv: list[str]) -> int:
    if sys.platform != "win32":
        return main(argv)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetConsoleTitleW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    kernel32.GetConsoleTitleW.restype = ctypes.c_uint
    kernel32.SetConsoleTitleW.argtypes = [ctypes.c_wchar_p]
    kernel32.SetConsoleTitleW.restype = ctypes.c_bool
    previous_title = ctypes.create_unicode_buffer(32768)
    kernel32.GetConsoleTitleW(previous_title, len(previous_title))
    changed = kernel32.SetConsoleTitleW(f"Building latest release... - Ninja Capture Tool (v{DISPLAY_VERSION})")
    try:
        return main(argv)
    finally:
        if changed:
            kernel32.SetConsoleTitleW(previous_title.value)

if __name__ == "__main__":
    raise SystemExit(run_main_with_console_title(sys.argv[1:]))
