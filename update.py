#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import deque
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from common import (
    atomic_write_json,
    FROZEN_RUNTIME_DIR_NAME,
    FileLockBusyError,
    NCT_LICENSE_RELEASE_FILE,
    PRESERVED_RELEASE_FILES,
    RELEASE_MANIFEST_FILE,
    RELEASE_MANIFEST_VERSION,
    update_state_file,
    update_temp_root,
    TOOL_DIR,
    VERSION,
    display_version,
    capture_activity_lock_path,
    cleanup_temp_root_if_empty,
    cleanup_temporary_file,
    compare_versions,
    format_bytes,
    parse_json,
    parse_version,
    process_identity,
    process_matches_identity,
    print_error,
    print_warning,
    relative_path_parts,
    sha256_file,
    style_console_text,
    windows_file_lock,
)
from config import DEFAULT_CONFIG, ErrorArgumentParser, SingleUseStoreTrueAction, validate_config

UPDATE_STATE_FILE: Path | None = None
UPDATE_ATTEMPTS = 3
UPDATE_INSTALLER_ARGUMENT = "--update-installer"
UPDATE_SESSION_FILE = "update_session.json"
MAX_GITHUB_JSON_BYTES = 4 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
LOCAL_DISPLAY_VERSION = display_version()
TEMP_ROOT: Path | None = None
_UPDATE_WORK_NAME_RE = re.compile(r"^update_[0-9a-f]{32}$", re.IGNORECASE)
_UPDATE_BACKUP_NAME_RE = re.compile(r"^backup_[0-9a-f]{32}$", re.IGNORECASE)
_PRESERVED_RELEASE_FILE_KEYS = frozenset(name.casefold() for name in PRESERVED_RELEASE_FILES)
_RELEASE_MANIFEST_KEY = RELEASE_MANIFEST_FILE.casefold()

def _update_temp_root() -> Path:
    return update_temp_root() if TEMP_ROOT is None else TEMP_ROOT

class CaptureActiveError(RuntimeError):
    pass

class UpdaterBusyError(RuntimeError):
    pass

def _update_state_path() -> Path:
    return update_state_file() if UPDATE_STATE_FILE is None else UPDATE_STATE_FILE

def _read_update_state() -> dict[str, Any]:
    path = _update_state_path()
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        raise
    try:
        value = parse_json(text)
    except ValueError as exc:
        raise ValueError(f"Invalid update state: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("Update state must be a JSON object.")
    for key in ("last_successful_check", "last_failed_check"):
        stored = value.get(key)
        if stored is not None and (not isinstance(stored, int) or isinstance(stored, bool) or stored < 0):
            raise ValueError(f"Update state contains invalid {key}.")
    return value

def _stored_check_time(config: dict[str, Any], key: str) -> int | None:
    value = config.get(key)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None

def automatic_update_check_due(now: float | None = None) -> bool:
    try:
        state = _read_update_state()
    except (OSError, ValueError):
        return True

    current = time.time() if now is None else now
    successful = _stored_check_time(state, "last_successful_check")
    failed = _stored_check_time(state, "last_failed_check")

    if failed is not None and (successful is None or failed >= successful):
        age = current - failed
        return age < 0 or age >= 15 * 60
    if successful is not None:
        age = current - successful
        return age < 0 or age >= 24 * 60 * 60
    return True

def _record_update_check_result(result: str, now: float | None = None) -> None:
    if not getattr(sys, "frozen", False):
        return

    try:
        try:
            state = _read_update_state()
        except ValueError:
            # update_state.json is disposable cooldown cache. If it is corrupted,
            # replace it with fresh state instead of retrying GitHub on every launch
            # until the user manually deletes the file.
            state = {}
        timestamp = int(time.time() if now is None else now)
        if result == "success":
            state["last_successful_check"] = timestamp
            state.pop("last_failed_check", None)
        elif result == "failure":
            state["last_failed_check"] = timestamp
            state.pop("last_successful_check", None)
        elif result == "update_available":
            state.pop("last_successful_check", None)
            state.pop("last_failed_check", None)
        else:
            raise ValueError(f"Unknown update check result: {result}")
        atomic_write_json(_update_state_path(), state)
    except OSError:
        pass

def _request(url: str, timeout: float):
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"NinjaCaptureTool/{VERSION}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    return urllib.request.urlopen(request, timeout=timeout)

def _request_json(url: str) -> dict[str, Any]:
    with _request(url, 5) as response:
        payload = response.read(MAX_GITHUB_JSON_BYTES + 1)
    if len(payload) > MAX_GITHUB_JSON_BYTES:
        raise RuntimeError("GitHub update metadata response is unexpectedly large.")
    try:
        result = parse_json(payload)
    except ValueError as exc:
        raise RuntimeError(f"GitHub returned invalid JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise RuntimeError("GitHub returned an unexpected response.")
    return result

def latest_release() -> dict[str, Any]:
    release = _request_json("https://api.github.com/repos/DarkLotus8000/Ninja-Capture-Tool/releases/latest")
    tag = release.get("tag_name")
    assets = release.get("assets")
    html_url = release.get("html_url")
    if not isinstance(tag, str) or not tag.strip():
        raise RuntimeError("Latest GitHub Release does not contain a valid tag name.")
    parse_version(tag)
    if not isinstance(assets, list):
        raise RuntimeError("Latest GitHub Release does not contain an asset list.")
    if not isinstance(html_url, str) or not html_url.lower().startswith("https://github.com/"):
        html_url = "https://github.com/DarkLotus8000/Ninja-Capture-Tool/releases"
    version = tag[1:] if tag[:1].lower() == "v" else tag
    return {"version": version, "assets": assets, "url": html_url}

def find_release_asset(release: dict[str, Any], name: str) -> tuple[str, int]:
    for asset in release["assets"]:
        if not isinstance(asset, dict) or asset.get("name") != name:
            continue
        url = asset.get("browser_download_url")
        size = asset.get("size")
        if not isinstance(url, str) or not url.lower().startswith("https://"):
            raise RuntimeError(f"GitHub Release asset has an invalid download URL: {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise RuntimeError(f"GitHub Release asset has an invalid or missing size: {name}")
        return url, size
    raise RuntimeError(f"Required GitHub Release asset is missing: {name}")

def check_for_update() -> dict[str, Any] | None:
    release = latest_release()
    if compare_versions(release["version"], VERSION) <= 0:
        return None
    return release

def check_update_only() -> int:
    try:
        release = latest_release()
        comparison = compare_versions(release["version"], VERSION)
        if comparison < 0:
            _record_update_check_result("success")
            print(f"[Update] Local Ninja Capture Tool v{LOCAL_DISPLAY_VERSION} is newer than the latest release v{display_version(str(release['version']))}.")
        elif comparison == 0:
            _record_update_check_result("success")
            print(f"[Update] Ninja Capture Tool v{LOCAL_DISPLAY_VERSION} is up to date.")
        else:
            _record_update_check_result("update_available")
            print(f"[Update] Ninja Capture Tool v{display_version(str(release['version']))} is available.\nCurrent version: v{LOCAL_DISPLAY_VERSION}\nRelease: {release['url']}")
        return 0
    except KeyboardInterrupt:
        print("\nUpdate check cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        _record_update_check_result("failure")
        print_error(f"Update check failed: {exc}")
        return 1

def handle_early_update_request(argv: list[str]) -> int | None:
    cleanup_relaunched_update_work()
    cleanup_stale_update_work()

    parser = ErrorArgumentParser(add_help=False, allow_abbrev=False)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", "--auto-update", action=SingleUseStoreTrueAction)
    group.add_argument("-n", "--no-auto-update", action=SingleUseStoreTrueAction)
    group.add_argument("-U", "--check-update", action=SingleUseStoreTrueAction)
    args, remaining = parser.parse_known_args(argv)
    if not args.check_update:
        return None
    if remaining:
        parser.error("--check-update must be used without capture arguments")
    return check_update_only()

def _ensure_free_space(path: Path, required: int, purpose: str) -> None:
    if required <= 0:
        return
    free = shutil.disk_usage(path).free
    if free < required:
        raise RuntimeError(
            f"Not enough free disk space to {purpose}: {format_bytes(required)} required, {format_bytes(free)} available."
        )

class _UpdateProgress:
    DISPLAY_DELAY_SECONDS = 0.5
    REPORT_INTERVAL_SECONDS = 0.25
    SPEED_WINDOW_SECONDS = 1.5

    def __init__(self, label: str, total: int, path: str) -> None:
        self.label = label
        self.total = max(0, total)
        self.path = path
        self.completed = 0
        self.started_at = time.monotonic()
        self.last_report = 0.0
        self.speed_samples: deque[tuple[float, int]] = deque([(self.started_at, 0)])
        self.progress_width = 0
        self.finished = False
        self.last_plain_percent = -10
        self.last_plain_time = self.started_at

    @staticmethod
    def _interactive_console() -> bool:
        try:
            return sys.stdout.isatty()
        except (AttributeError, OSError, ValueError):
            return False

    def _record_speed_sample(self, now: float) -> None:
        self.speed_samples.append((now, self.completed))
        cutoff = now - self.SPEED_WINDOW_SECONDS
        while len(self.speed_samples) > 2 and self.speed_samples[1][0] <= cutoff:
            self.speed_samples.popleft()

    def _message(self, now: float) -> str:
        sample_time, sample_size = self.speed_samples[0]
        elapsed = max(1e-6, now - sample_time)
        speed_bps = max(0, int((self.completed - sample_size) / elapsed))
        if self.total > 0:
            percent = min(100.0, self.completed * 100.0 / self.total)
            return (
                f"{self.label} {format_bytes(self.completed)} / {format_bytes(self.total)} ({percent:.1f}%)"
                f" | {format_bytes(speed_bps)}/s | {self.path}"
            )
        return f"{self.label} {format_bytes(self.completed)} | {format_bytes(speed_bps)}/s | {self.path}"

    @staticmethod
    def _truncate(message: str, width: int) -> str:
        if len(message) <= width:
            return message
        separator = " | "
        if separator in message:
            prefix, path = message.rsplit(separator, 1)
            available = width - len(prefix) - len(separator)
            if available >= 4:
                message = prefix + separator + "..." + path[-(available - 3):]
        if len(message) > width:
            message = message[:width] if width <= 3 else message[: width - 3] + "..."
        return message

    def _render_interactive(self, now: float) -> None:
        try:
            width = max(1, shutil.get_terminal_size(fallback=(120, 24)).columns - 1)
        except OSError:
            width = 119
        message = self._truncate(self._message(now), width)
        styled = style_console_text(message, sys.stdout, status_tokens=True)
        padding = max(0, self.progress_width - len(message))
        try:
            sys.stdout.write("\r" + styled + (" " * padding))
            sys.stdout.flush()
        except (OSError, ValueError):
            self.progress_width = 0
            return
        self.progress_width = len(message)

    def update(self, amount: int) -> None:
        self.completed += max(0, amount)
        now = time.monotonic()
        self._record_speed_sample(now)
        if self._interactive_console():
            if now - self.started_at < self.DISPLAY_DELAY_SECONDS and self.completed < self.total:
                return
            if now - self.last_report < self.REPORT_INTERVAL_SECONDS and self.completed < self.total:
                return
            self.last_report = now
            self._render_interactive(now)
            return

        if self.total <= 0:
            return
        percent = min(100, self.completed * 100 // self.total)
        if percent >= self.last_plain_percent + 10 or now - self.last_plain_time >= 5 or self.completed >= self.total:
            print(self._message(now))
            self.last_plain_percent = percent
            self.last_plain_time = now

    def finish(self) -> None:
        if self.finished:
            return
        self.completed = self.total if self.total > 0 else self.completed
        now = time.monotonic()
        self._record_speed_sample(now)
        if self._interactive_console():
            self._render_interactive(now)
            try:
                sys.stdout.write("\n")
                sys.stdout.flush()
            except (OSError, ValueError):
                pass
            self.progress_width = 0
        elif self.total > 0 and self.last_plain_percent < 100:
            print(self._message(now))
        self.finished = True

    def abort(self) -> None:
        if self.progress_width <= 0:
            return
        try:
            sys.stdout.write("\r" + (" " * self.progress_width) + "\r")
            sys.stdout.flush()
        except (OSError, ValueError):
            pass
        self.progress_width = 0

def _download_file(
    url: str,
    destination: Path,
    expected_size: int | None = None,
    progress_label: str | None = None,
    max_size: int | None = None,
) -> None:
    temporary = destination.with_name(destination.name + ".part")
    temporary.unlink(missing_ok=True)
    written = 0
    progress = (
        _UpdateProgress(progress_label, expected_size, destination.name)
        if progress_label is not None and expected_size is not None
        else None
    )
    try:
        with _request(url, 30) as response, temporary.open("xb") as output:
            while chunk := response.read(256 * 1024):
                limits = [value for value in (expected_size, max_size) if value is not None]
                limit = min(limits) if limits else None
                if limit is not None and written + len(chunk) > limit:
                    raise RuntimeError(
                        f"Downloaded update file exceeds the expected size limit: {destination.name}"
                    )
                if output.write(chunk) != len(chunk):
                    raise RuntimeError(f"Could not completely write downloaded update file: {destination.name}")
                written += len(chunk)
                if progress is not None:
                    progress.update(len(chunk))
        if expected_size is not None and written != expected_size:
            raise RuntimeError(
                f"Downloaded size does not match GitHub metadata for {destination.name}: "
                f"{format_bytes(written)} instead of {format_bytes(expected_size)}"
            )
        if progress is not None:
            progress.finish()
        temporary.replace(destination)
    except BaseException:
        if progress is not None:
            progress.abort()
        cleanup_temporary_file(temporary)
        raise

def _read_expected_checksum(path: Path, archive_name: str) -> str:
    lines = [line.strip() for line in path.read_text(encoding="ascii").splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError("Release checksum file must contain exactly one non-empty line.")
    parts = lines[0].split()
    if len(parts) != 2 or len(parts[0]) != 64 or any(char not in "0123456789abcdefABCDEF" for char in parts[0]):
        raise RuntimeError("Release checksum file has an unexpected format.")
    if parts[1].lstrip("*") != archive_name:
        raise RuntimeError("Release checksum file has an unexpected filename.")
    return parts[0].lower()

def _safe_archive_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\0" in name:
        raise RuntimeError(f"Unsafe update archive path: {name!r}")
    try:
        return relative_path_parts(name)
    except ValueError as exc:
        raise RuntimeError(f"Unsafe update archive path: {name!r}") from exc

def _validate_release_config(path: Path) -> None:
    try:
        value = parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Downloaded release contains invalid config.json: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Downloaded release config.json must contain a JSON object.")
    unknown = sorted(set(value) - set(DEFAULT_CONFIG))
    if unknown:
        raise RuntimeError(f"Downloaded release config.json contains unknown option(s): {', '.join(unknown)}")
    config = dict(DEFAULT_CONFIG)
    config.update(value)
    validate_config(config)

def _parse_release_manifest(path: Path) -> tuple[str, dict[str, str]]:
    try:
        value = parse_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Release manifest is invalid: {exc}") from exc
    if not isinstance(value, dict) or value.get("format_version") != RELEASE_MANIFEST_VERSION:
        raise RuntimeError("Release manifest has an unsupported format version.")
    application_version = value.get("application_version")
    files = value.get("files")
    if not isinstance(application_version, str) or not application_version:
        raise RuntimeError("Release manifest has an invalid application version.")
    if not isinstance(files, dict):
        raise RuntimeError("Release manifest files must be a JSON object.")

    normalized: dict[str, str] = {}
    for name, digest in files.items():
        if not isinstance(name, str) or not isinstance(digest, str):
            raise RuntimeError("Release manifest contains invalid file metadata.")
        try:
            parts = relative_path_parts(name)
        except ValueError as exc:
            raise RuntimeError(f"Release manifest contains an unsafe path: {name!r}") from exc
        canonical = "/".join(parts)
        folded = name.casefold()
        if canonical != name or folded in _PRESERVED_RELEASE_FILE_KEYS or folded == _RELEASE_MANIFEST_KEY:
            raise RuntimeError(f"Release manifest contains an invalid managed path: {name!r}")
        if folded in normalized:
            raise RuntimeError(f"Release manifest contains a duplicate managed path: {name!r}")
        if len(digest) != 64 or any(character not in "0123456789abcdefABCDEF" for character in digest):
            raise RuntimeError(f"Release manifest contains an invalid SHA-256 for {name!r}.")
        normalized[folded] = digest.lower()
    return application_version, {name: files[name].lower() for name in files}

def _validate_staged_release_manifest(stage: Path, expected_version: str) -> dict[str, str]:
    _validate_staged_release_tree(stage)
    application_version, files = _parse_release_manifest(stage / RELEASE_MANIFEST_FILE)
    if application_version != expected_version:
        raise RuntimeError("Release manifest application version does not match the expected target version.")

    actual: set[str] = set()
    for path in stage.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(stage).as_posix()
        folded = relative.casefold()
        if folded == _RELEASE_MANIFEST_KEY or folded in _PRESERVED_RELEASE_FILE_KEYS:
            continue
        actual.add(relative)
    if actual != set(files):
        raise RuntimeError("Release manifest does not match the downloaded release files.")

    for name, expected in files.items():
        target = stage.joinpath(*name.split("/"))
        if sha256_file(target).lower() != expected:
            raise RuntimeError(f"Release manifest SHA-256 does not match {name!r}.")
    return files

def _validate_staged_release_tree(stage: Path) -> None:
    """Reject links, junctions, reparse points, and special files anywhere in stage."""
    try:
        root_stat = stage.lstat()
    except OSError as exc:
        raise RuntimeError(f"Could not inspect staged update directory:\n{stage}") from exc
    if stat.S_ISLNK(root_stat.st_mode) or _is_reparse_stat(root_stat) or not stat.S_ISDIR(root_stat.st_mode):
        raise RuntimeError(
            f"Staged update directory must be a real directory, not a symlink, junction, or reparse point:\n{stage}"
        )

    pending = [stage]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = list(entries)
        except OSError as exc:
            raise RuntimeError(f"Could not inspect staged update contents:\n{directory}") from exc
        for entry in children:
            path = Path(entry.path)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeError(f"Could not inspect staged update entry:\n{path}") from exc
            if stat.S_ISLNK(entry_stat.st_mode) or _is_reparse_stat(entry_stat):
                raise RuntimeError(
                    f"Staged update contains a symlink, junction, or reparse point:\n{path}"
                )
            if stat.S_ISDIR(entry_stat.st_mode):
                pending.append(path)
            elif not stat.S_ISREG(entry_stat.st_mode):
                raise RuntimeError(f"Staged update contains an unsupported filesystem entry:\n{path}")

def _load_installed_release_manifest(install_dir: Path) -> dict[str, str] | None:
    try:
        _, files = _parse_release_manifest(install_dir / RELEASE_MANIFEST_FILE)
        return files
    except (OSError, RuntimeError):
        # Older releases have no manifest, and a locally damaged/edited manifest must never make the updater delete
        # files speculatively. In either case, simply skip obsolete-file cleanup for this update.
        return None

def extract_release_archive(archive_path: Path, destination: Path, release_version: str) -> Path:
    expected_root = f"NinjaCaptureTool-v{release_version}"
    seen: set[str] = set()
    destination.mkdir(parents=True, exist_ok=False)

    with zipfile.ZipFile(archive_path, "r") as archive:
        members = archive.infolist()
        if not members:
            raise RuntimeError("Downloaded release archive is empty.")

        extracted_size = 0
        for member in members:
            clean_name = member.filename.rstrip("/")
            if not clean_name:
                continue
            parts = _safe_archive_parts(clean_name)
            if not parts or parts[0] != expected_root:
                raise RuntimeError(f"Unexpected release archive root: {member.filename}")
            folded = clean_name.casefold()
            if folded in seen:
                raise RuntimeError(f"Release archive contains a duplicate path: {member.filename}")
            seen.add(folded)
            mode = (member.external_attr >> 16) & 0xFFFF
            if mode & 0o170000 == 0o120000:
                raise RuntimeError(f"Release archive contains a symbolic link: {member.filename}")
            if not member.is_dir():
                extracted_size += member.file_size

        _ensure_free_space(destination.parent, extracted_size, "extract the update")

        for member in members:
            clean_name = member.filename.rstrip("/")
            if not clean_name:
                continue
            parts = _safe_archive_parts(clean_name)
            relative = parts[1:]
            if not relative:
                continue
            target = destination.joinpath(*relative)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=8 * 1024 * 1024)

    required = (
        "NinjaCaptureTool.exe",
        "config.json",
        "README.txt",
        NCT_LICENSE_RELEASE_FILE,
        RELEASE_MANIFEST_FILE,
    )
    missing = [name for name in required if not (destination / Path(name)).is_file()]
    if missing:
        raise RuntimeError("Downloaded release is incomplete; missing: " + ", ".join(missing))
    runtime = destination / FROZEN_RUNTIME_DIR_NAME
    if not runtime.is_dir() or runtime.is_symlink() or next(runtime.iterdir(), None) is None:
        raise RuntimeError("Downloaded release is incomplete; runtime directory is missing or empty.")
    _validate_release_config(destination / "config.json")
    _validate_staged_release_manifest(destination, release_version)
    licenses = destination / "data" / "licenses"
    if not licenses.is_dir() or not any(path.is_file() for path in licenses.iterdir()):
        raise RuntimeError("Downloaded release does not contain its license files.")
    return destination

def download_release(release: dict[str, Any], work: Path) -> Path:
    version = release["version"]
    archive_name = f"NinjaCaptureTool-v{version}-Windows-x64.zip"
    checksum_name = archive_name + ".sha256"
    archive_url, archive_size = find_release_asset(release, archive_name)
    checksum_url, checksum_size = find_release_asset(release, checksum_name)
    if checksum_size > MAX_CHECKSUM_BYTES:
        raise RuntimeError("Release checksum asset is unexpectedly large.")
    archive_path = work / archive_name
    checksum_path = work / checksum_name

    _ensure_free_space(work, archive_size + checksum_size, "download the update")

    last_error: Exception | None = None
    for attempt in range(1, UPDATE_ATTEMPTS + 1):
        archive_path.unlink(missing_ok=True)
        checksum_path.unlink(missing_ok=True)
        try:
            print(f"[Update] Downloading Ninja Capture Tool v{display_version(str(version))} (attempt {attempt}/{UPDATE_ATTEMPTS})...")
            _download_file(checksum_url, checksum_path, checksum_size, max_size=MAX_CHECKSUM_BYTES)
            _download_file(archive_url, archive_path, archive_size, "[Update]")
            expected = _read_expected_checksum(checksum_path, archive_name)
            actual = sha256_file(archive_path)
            if actual.lower() != expected:
                raise RuntimeError("Downloaded release SHA-256 does not match its checksum file.")
            return archive_path
        except Exception as exc:
            last_error = exc
            if attempt < UPDATE_ATTEMPTS:
                print(f"[Update] Download failed (attempt {attempt}/{UPDATE_ATTEMPTS}): {exc}", file=sys.stderr)
                time.sleep(attempt)
    raise RuntimeError(f"Update download failed after {UPDATE_ATTEMPTS} attempts: {last_error}")

def _validate_temporary_updater(executable: Path) -> None:
    expected = f"Ninja Capture Tool v{LOCAL_DISPLAY_VERSION}"
    environment = os.environ.copy()
    try:
        result = subprocess.run(
            [str(executable), UPDATE_INSTALLER_ARGUMENT, "--version"],
            cwd=TOOL_DIR,
            capture_output=True,
            text=True,
            timeout=150,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Temporary Ninja Capture Tool updater did not respond to --version within 150 seconds: {executable}"
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Temporary Ninja Capture Tool updater could not be started: {executable}: {exc}") from exc

    actual = result.stdout.strip()
    if result.returncode != 0:
        detail = result.stderr.strip() or actual or f"exit code {result.returncode}"
        raise RuntimeError(f"Temporary Ninja Capture Tool updater failed its version check: {executable}\n{detail}")
    if actual != expected:
        raise RuntimeError(
            "Temporary Ninja Capture Tool updater version does not match this release.\n"
            f"Expected: {expected}\n"
            f"Actual: {actual or '(no version output)'}"
        )

def _copy_application_for_update(work: Path) -> Path:
    source = Path(sys.executable).resolve()
    if not source.is_file():
        raise RuntimeError(f"Ninja Capture Tool executable is missing: {source}")
    temporary = work / "NinjaCaptureToolUpdater.exe"
    shutil.copy2(source, temporary)

    runtime = source.parent / FROZEN_RUNTIME_DIR_NAME
    if runtime.exists() or runtime.is_symlink():
        if runtime.is_symlink() or not runtime.is_dir():
            raise RuntimeError(f"Ninja Capture Tool runtime directory is invalid: {runtime}")
        shutil.copytree(runtime, work / FROZEN_RUNTIME_DIR_NAME)

    _validate_temporary_updater(temporary)
    return temporary

def launch_updater(temporary_updater: Path, stage: Path, argv: list[str], target_version: str) -> None:
    # Revalidate the self-copy immediately before handoff. It lives inside this update workspace, so Ninja Capture Tool never needs
    # a second shipped executable or the system temporary directory.
    _validate_temporary_updater(temporary_updater)
    command = [
        str(temporary_updater),
        UPDATE_INSTALLER_ARGUMENT,
        "--install-dir",
        str(TOOL_DIR),
        "--stage-dir",
        str(stage),
        "--parent-pid",
        str(os.getpid()),
        "--target-version",
        target_version,
        "--relaunch-executable",
        str(Path(sys.executable).resolve()),
        "--relaunch-cwd",
        str(Path.cwd().resolve()),
        "--",
        *argv,
    ]
    environment = os.environ.copy()
    subprocess.Popen(command, cwd=TOOL_DIR, env=environment)

def _update_session_is_active(work: Path) -> bool:
    if sys.platform != "win32":
        return False
    session = work / UPDATE_SESSION_FILE
    try:
        session_stat = session.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        # Metadata that cannot be inspected at all is ambiguous. Leave the
        # workspace alone rather than risk deleting a live updater.
        return True
    if (
        stat.S_ISLNK(session_stat.st_mode)
        or _is_reparse_stat(session_stat)
        or not stat.S_ISREG(session_stat.st_mode)
    ):
        return False
    try:
        raw_state = session.read_text(encoding="utf-8")
    except OSError:
        return True
    try:
        state = parse_json(raw_state)
    except ValueError:
        # Corrupt metadata is not a valid live-process identity. Recovery backup
        # protection is handled separately by _update_work_backup_state().
        return False
    if not isinstance(state, dict):
        return False
    pid = state.get("pid")
    identity = state.get("process_identity")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or not isinstance(identity, str)
        or not identity
    ):
        return False
    try:
        return process_matches_identity(pid, identity)
    except Exception:
        # Only uncertainty while inspecting an otherwise valid process identity
        # is treated as possibly active.
        return True

def _update_session_transaction_state(work: Path) -> str | None:
    session = work / UPDATE_SESSION_FILE
    try:
        session_stat = session.lstat()
    except OSError:
        return None
    if (
        stat.S_ISLNK(session_stat.st_mode)
        or _is_reparse_stat(session_stat)
        or not stat.S_ISREG(session_stat.st_mode)
    ):
        return None
    try:
        state = parse_json(session.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(state, dict):
        return None
    transaction_state = state.get("transaction_state")
    return transaction_state if isinstance(transaction_state, str) else None

def _update_session_backup_is_disposable(work: Path) -> bool:
    return _update_session_transaction_state(work) in {"committed", "rolled_back"}

def _update_work_backup_state(work: Path) -> bool | None:
    """Return True for a real Ninja Capture Tool backup, False for none, None when inspection is unsafe."""
    try:
        work_stat = work.lstat()
        if stat.S_ISLNK(work_stat.st_mode) or _is_reparse_stat(work_stat) or not stat.S_ISDIR(work_stat.st_mode):
            return None
        for path in work.iterdir():
            if not _UPDATE_BACKUP_NAME_RE.fullmatch(path.name):
                continue
            path_stat = path.lstat()
            if stat.S_ISLNK(path_stat.st_mode) or _is_reparse_stat(path_stat) or not stat.S_ISDIR(path_stat.st_mode):
                return None
            return True
        return False
    except OSError:
        return None

def _update_work_has_backup(work: Path) -> bool:
    # Unknown/unsafe state is treated conservatively as recovery data so callers
    # never delete an updater workspace they could not inspect safely.
    return _update_work_backup_state(work) is not False

def _validated_cleanup_temp_root() -> Path | None:
    temp_root = _update_temp_root()
    try:
        temp_root.lstat()
    except (FileNotFoundError, OSError):
        return None
    try:
        _, validated = _validate_update_temp_root(temp_root, TOOL_DIR)
    except RuntimeError:
        # Cleanup is optional. If Ninja Capture Tool's temp directory is redirected, on another volume,
        # or otherwise unsafe, leave it completely untouched.
        return None
    return validated

def _validated_cleanup_work(work: Path, temp_root: Path) -> Path | None:
    if not _UPDATE_WORK_NAME_RE.fullmatch(work.name) or not _paths_equal(work.parent, temp_root):
        return None
    try:
        work_stat = work.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(work_stat.st_mode) or _is_reparse_stat(work_stat) or not stat.S_ISDIR(work_stat.st_mode):
        return None
    return Path(os.path.abspath(str(work)))

def cleanup_deferred_update_payload(work: Path, install_dir: Path) -> None:
    try:
        _, stage = _validate_update_workspace(work / "stage", install_dir)
    except RuntimeError:
        # The updater is deferring rather than installing. Never perform
        # destructive cleanup if the workspace no longer has the exact safe
        # shape that was validated for installation.
        return
    work = stage.parent
    if _update_work_backup_state(work) is not False:
        return
    try:
        current_executable = Path(sys.executable).resolve()
        children = list(work.iterdir())
    except OSError:
        return
    for child in children:
        try:
            child_stat = child.lstat()
            if stat.S_ISLNK(child_stat.st_mode) or _is_reparse_stat(child_stat):
                continue
            if (
                child.resolve() == current_executable
                or child.name == UPDATE_SESSION_FILE
                or (current_executable.parent == work and child.name == FROZEN_RUNTIME_DIR_NAME)
            ):
                continue
            _remove_path(child)
        except OSError:
            # The updater is already deferring safely. Cleanup is best-effort and stale-work cleanup can retry later.
            continue

def cleanup_stale_update_work(max_age_seconds: int = 7 * 24 * 60 * 60) -> None:
    if max_age_seconds < 0:
        return
    temp_root = _validated_cleanup_temp_root()
    if temp_root is None:
        return
    cutoff = time.time() - max_age_seconds
    try:
        candidates = list(temp_root.iterdir())
    except OSError:
        return

    for work in candidates:
        work = _validated_cleanup_work(work, temp_root)
        if work is None:
            continue
        try:
            if work.lstat().st_mtime > cutoff:
                continue
            # An unterminated backup means an interrupted/incomplete transaction may need manual recovery.
            # Backups from committed installs or fully restored rollbacks are only cleanup debris.
            backup_state = _update_work_backup_state(work)
            if backup_state is None or (backup_state is True and not _update_session_backup_is_disposable(work)):
                continue
            # The temporary self-updater runs from inside update_<id>; never remove its directory while it is alive.
            if _update_session_is_active(work):
                continue
            shutil.rmtree(work)
        except OSError:
            # Startup cleanup is best-effort and must never block normal Ninja Capture Tool use.
            continue
    cleanup_temp_root_if_empty(temp_root)

def stale_update_recovery_backups(max_age_seconds: int = 7 * 24 * 60 * 60) -> list[Path]:
    if max_age_seconds < 0:
        return []
    temp_root = _validated_cleanup_temp_root()
    if temp_root is None:
        return []
    cutoff = time.time() - max_age_seconds
    try:
        candidates = list(temp_root.iterdir())
    except OSError:
        return []

    preserved: list[Path] = []
    for work in candidates:
        work = _validated_cleanup_work(work, temp_root)
        if work is None:
            continue
        try:
            if work.lstat().st_mtime > cutoff:
                continue
            if (
                _update_work_backup_state(work) is not True
                or _update_session_backup_is_disposable(work)
                or _update_session_is_active(work)
            ):
                continue
            preserved.append(work)
        except OSError:
            continue
    return sorted(preserved, key=lambda path: path.name.casefold())

def cleanup_relaunched_update_work() -> None:
    value = os.environ.pop("NCT_UPDATE_WORK_CLEANUP", None)
    if not value:
        return

    temp_root = _validated_cleanup_temp_root()
    if temp_root is None:
        return
    work = _validated_cleanup_work(Path(value), temp_root)
    if work is None:
        return
    backup_state = _update_work_backup_state(work)
    if backup_state is None or (backup_state is True and not _update_session_backup_is_disposable(work)):
        return

    # This flag is set only after a successful handoff or successful rollback. Terminal transaction backups are safe cleanup debris,
    # while an unterminated backup remains protected above. The relaunched Ninja Capture Tool can race the final moments of the temporary
    # updater exiting, so retry briefly until the updater exits and Windows releases the mapped executable.
    for _ in range(50):
        if _update_session_is_active(work):
            time.sleep(0.1)
            continue
        try:
            shutil.rmtree(work)
            break
        except FileNotFoundError:
            break
        except OSError:
            time.sleep(0.1)
    cleanup_temp_root_if_empty(temp_root)

def handle_automatic_update(
    args: argparse.Namespace,
    argv: list[str],
    configured_auto_update: bool,
) -> int | None:
    if os.environ.pop("NCT_SKIP_UPDATE_CHECK_ONCE", None) == "1":
        return None
    if args.no_auto_update:
        return None

    enabled = True if args.auto_update else configured_auto_update
    if not enabled:
        return None

    if not getattr(sys, "frozen", False):
        if args.auto_update:
            print("[Update] Automatic installation is only available in the Windows release executable.", file=sys.stderr)
        return None

    if not args.auto_update and not automatic_update_check_due():
        return None

    try:
        release = check_for_update()
    except KeyboardInterrupt:
        print("\nUpdate cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        _record_update_check_result("failure")
        print_warning(f"Automatic update failed; continuing with v{LOCAL_DISPLAY_VERSION}: {exc}")
        return None

    if release is None:
        _record_update_check_result("success")
        return None

    # The GitHub check itself succeeded and found an update. From this point onward, failures are installation failures,
    # not update-check failures, so they must not start the short check cooldown. A later launch should retry the update.
    _record_update_check_result("update_available")

    work: Path | None = None
    temp_root = _update_temp_root()
    try:
        temp_root.mkdir(parents=True, exist_ok=True)
        _, temp_root = _validate_update_temp_root(temp_root, TOOL_DIR)
        work = temp_root / f"update_{uuid.uuid4().hex}"
        work.mkdir()
        temporary_updater = _copy_application_for_update(work)
        print(f"[Update] Ninja Capture Tool v{display_version(str(release['version']))} is available (current: v{LOCAL_DISPLAY_VERSION}).")
        archive = download_release(release, work)
        stage = extract_release_archive(archive, work / "stage", release["version"])
        launch_updater(temporary_updater, stage, argv, release["version"])
        print("[Update] Update verified. Restarting to install...")
        return 0
    except KeyboardInterrupt:
        print("\nUpdate cancelled.", file=sys.stderr)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        cleanup_temp_root_if_empty(temp_root)
        return 130
    except Exception as exc:
        print_warning(f"Automatic update failed; continuing with v{LOCAL_DISPLAY_VERSION}: {exc}")
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        cleanup_temp_root_if_empty(temp_root)
        return None

def ignore_interrupts() -> None:
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, signal.SIG_IGN)

def updater_install_lock_path(install_dir: Path) -> Path:
    return install_dir.resolve() / "data" / ".update.lock"

@contextmanager
def updater_install_lock(install_dir: Path, timeout_seconds: int = 0):
    # Serialize updates through the installation rather than a user-scoped named mutex. Windows byte-range locks are
    # system-wide for the file, survive UAC token differences, and are released automatically on process exit.
    try:
        with windows_file_lock(
            updater_install_lock_path(install_dir),
            timeout_seconds,
            "Another Ninja Capture Tool update is already in progress.",
        ):
            yield
    except FileLockBusyError as exc:
        raise UpdaterBusyError(str(exc)) from exc

@contextmanager
def capture_install_lock(install_dir: Path, timeout_seconds: int = 0):
    try:
        with windows_file_lock(
            capture_activity_lock_path(install_dir),
            timeout_seconds,
            "Another Ninja Capture Tool capture is active.",
        ):
            yield
    except FileLockBusyError as exc:
        raise CaptureActiveError(str(exc)) from exc

def wait_for_process_exit(pid: int, timeout_seconds: int = 30) -> None:
    if pid <= 0:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
    if not handle:
        error = ctypes.get_last_error()
        if error == 87:  # ERROR_INVALID_PARAMETER: process no longer exists.
            return
        raise OSError(error, f"Could not open Ninja Capture Tool process {pid}.")
    try:
        result = kernel32.WaitForSingleObject(handle, timeout_seconds * 1000)
        if result == 0x102:
            raise RuntimeError("Timed out waiting for Ninja Capture Tool to exit.")
        if result not in {0, 0x80}:
            raise OSError(ctypes.get_last_error(), "Could not wait for Ninja Capture Tool to exit.")
    finally:
        kernel32.CloseHandle(handle)

def _write_update_session_state(work: Path, state: dict[str, Any]) -> None:
    session = work / UPDATE_SESSION_FILE
    temporary = session.with_name(f"{session.name}.tmp")
    try:
        temporary.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8", newline="\n")
        temporary.replace(session)
    finally:
        cleanup_temporary_file(temporary)

def write_update_session(work: Path) -> None:
    pid = os.getpid()
    _write_update_session_state(
        work,
        {
            "pid": pid,
            "process_identity": process_identity(pid),
            "transaction_state": "active",
        },
    )

def _mark_update_session_transaction_state(work: Path, transaction_state: str) -> None:
    if transaction_state not in {"committed", "rolled_back"}:
        raise ValueError(f"Invalid updater terminal transaction state: {transaction_state!r}")
    session = work / UPDATE_SESSION_FILE
    try:
        session_stat = session.lstat()
        if (
            stat.S_ISLNK(session_stat.st_mode)
            or _is_reparse_stat(session_stat)
            or not stat.S_ISREG(session_stat.st_mode)
        ):
            raise RuntimeError("Updater session state is not a real regular file.")
        state = parse_json(session.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not mark the updater transaction as {transaction_state}.") from exc
    if not isinstance(state, dict):
        raise RuntimeError(
            f"Could not mark the updater transaction as {transaction_state}: invalid updater session state."
        )
    pid = state.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or not state.get("process_identity"):
        raise RuntimeError(
            f"Could not mark the updater transaction as {transaction_state}: invalid updater session identity."
        )
    state["transaction_state"] = transaction_state
    _write_update_session_state(work, state)

def mark_update_session_committed(work: Path) -> None:
    _mark_update_session_transaction_state(work, "committed")

def mark_update_session_rolled_back(work: Path) -> None:
    _mark_update_session_transaction_state(work, "rolled_back")

def _is_reparse_stat(stat_result) -> bool:
    attributes = int(getattr(stat_result, "st_file_attributes", 0))
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))

def _validate_update_destination_path(install_dir: Path, relative: Path = Path()) -> None:
    # Never traverse an existing symlink/junction/reparse point while replacing installation files. In particular,
    # an existing directory junction such as data/licenses must not redirect updater writes outside the tool folder.
    current = install_dir
    parts = [part for part in relative.parts if part not in {"", "."}]
    for index in range(len(parts) + 1):
        try:
            current_stat = current.lstat()
        except FileNotFoundError:
            # Once an ancestor is absent, deeper children cannot already redirect traversal.
            break
        except OSError as exc:
            raise RuntimeError(f"Could not inspect Ninja Capture Tool update destination:\n{current}") from exc
        if stat.S_ISLNK(current_stat.st_mode) or _is_reparse_stat(current_stat):
            raise RuntimeError(
                f"Ninja Capture Tool update destination contains a symlink, junction, or reparse point:\n{current}"
            )
        if index == len(parts):
            break
        current = current / parts[index]

def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)

def _paths_equal(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(str(left))) == os.path.normcase(os.path.abspath(str(right)))

def _validate_update_temp_root(temp_root: Path, install_dir: Path) -> tuple[Path, Path]:
    # Automatic-update work must stay in the real <install>\temp directory on
    # the same physical volume as the installation. Validate this before copying
    # the self-updater, downloading, or extracting any release payload.
    install = Path(os.path.abspath(str(install_dir)))
    temporary = Path(os.path.abspath(str(temp_root)))
    expected = install / "temp"

    if not _paths_equal(temporary, expected):
        raise RuntimeError("Ninja Capture Tool update temp directory is outside the installation directory.")

    _validate_update_destination_path(install)
    try:
        temp_stat = temporary.lstat()
    except OSError as exc:
        raise RuntimeError(f"Could not inspect Ninja Capture Tool temp directory:\n{temporary}") from exc
    if stat.S_ISLNK(temp_stat.st_mode) or _is_reparse_stat(temp_stat):
        raise RuntimeError(
            f"Ninja Capture Tool temp directory must not be a symlink, junction, or reparse point:\n{temporary}"
        )
    if not stat.S_ISDIR(temp_stat.st_mode):
        raise RuntimeError(f"Ninja Capture Tool temp path is not a directory:\n{temporary}")

    try:
        install_device = install.stat().st_dev
        temp_device = temporary.stat().st_dev
    except OSError as exc:
        raise RuntimeError("Could not determine Ninja Capture Tool temp-directory volume.") from exc
    if install_device != temp_device:
        raise RuntimeError("Ninja Capture Tool temp directory must be on the same drive as the installation.")

    return install.resolve(), temporary.resolve()

def _validate_update_workspace(stage: Path, install_dir: Path) -> tuple[Path, Path]:
    # The updater publishes staged release entries with rename(), so the workspace
    # must be the exact Ninja Capture Tool-owned <install>\temp\update_<uuid>\stage tree on the
    # same physical volume. Reject any unexpected or redirected workspace before
    # backup creation or mutation of the installed release.
    install = Path(os.path.abspath(str(install_dir)))
    staged = Path(os.path.abspath(str(stage)))
    temp_root = install / "temp"
    work = staged.parent

    if staged.name.casefold() != "stage" or not _UPDATE_WORK_NAME_RE.fullmatch(work.name):
        raise RuntimeError("Invalid Ninja Capture Tool update workspace layout.")
    if not _paths_equal(work.parent, temp_root):
        raise RuntimeError("Update staging directory is outside Ninja Capture Tool's temp directory.")

    _validate_update_destination_path(install)
    for path, label in ((temp_root, "temp directory"), (work, "update workspace"), (staged, "staged update directory")):
        try:
            path_stat = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"Could not inspect Ninja Capture Tool {label}:\n{path}") from exc
        if stat.S_ISLNK(path_stat.st_mode) or _is_reparse_stat(path_stat):
            raise RuntimeError(f"Ninja Capture Tool {label} must not be a symlink, junction, or reparse point:\n{path}")
        if not stat.S_ISDIR(path_stat.st_mode):
            raise RuntimeError(f"Ninja Capture Tool {label} is not a directory:\n{path}")

    try:
        install_device = install.stat().st_dev
        stage_device = staged.stat().st_dev
    except OSError as exc:
        raise RuntimeError("Could not determine Ninja Capture Tool update workspace volume.") from exc
    if install_device != stage_device:
        raise RuntimeError("Update staging directory must be on the same drive as Ninja Capture Tool.")

    return install.resolve(), staged.resolve()

def _publish_staged_item(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError(f"Update destination still exists before staged publish: {destination}")
    try:
        source.rename(destination)
    except OSError as exc:
        raise RuntimeError(
            "Could not publish the staged update with a same-volume rename. "
            "The update staging directory must remain on the same drive as Ninja Capture Tool."
        ) from exc

def rollback_staged_release(
    changes: list[tuple[Path, Path | None]],
    backup: Path,
    work: Path | None = None,
) -> None:
    rollback_errors: list[str] = []
    for destination, saved in reversed(changes):
        try:
            if destination.exists() or destination.is_symlink():
                _remove_path(destination)
            if saved is not None and saved.exists():
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(saved), str(destination))
        except Exception as exc:
            rollback_errors.append(f"{destination}: {exc}")

    if rollback_errors:
        raise RuntimeError(
            f"Rollback was incomplete. Backup retained at {backup}. Rollback errors: {'; '.join(rollback_errors)}"
        )
    if work is not None:
        try:
            mark_update_session_rolled_back(work)
        except Exception as exc:
            raise RuntimeError(
                f"Rollback restored the previous installation but could not record its terminal state. "
                f"Backup retained at {backup}: {exc}"
            ) from exc
    # Once the terminal state is durable, backup deletion is only cleanup. If
    # Windows/antivirus still holds a file, the relaunched process or stale-work
    # cleanup may safely retry later.
    shutil.rmtree(backup, ignore_errors=True)

def _validate_installed_release_manifest(
    install_dir: Path,
    expected_version: str,
    expected_files: dict[str, str],
) -> None:
    manifest_relative = Path(*RELEASE_MANIFEST_FILE.split("/"))
    _validate_update_destination_path(install_dir, manifest_relative)
    manifest = install_dir / manifest_relative
    try:
        manifest_stat = manifest.lstat()
    except OSError as exc:
        raise RuntimeError(f"Installed release manifest could not be inspected:\n{manifest}") from exc
    if (
        stat.S_ISLNK(manifest_stat.st_mode)
        or _is_reparse_stat(manifest_stat)
        or not stat.S_ISREG(manifest_stat.st_mode)
    ):
        raise RuntimeError(f"Installed release manifest is not a real regular file:\n{manifest}")

    application_version, installed_files = _parse_release_manifest(manifest)
    if application_version != expected_version:
        raise RuntimeError("Installed release manifest application version does not match the expected target version.")
    if installed_files != expected_files:
        raise RuntimeError("Installed release manifest does not match the prevalidated staged release manifest.")

    for name, expected_digest in expected_files.items():
        relative = Path(*name.split("/"))
        _validate_update_destination_path(install_dir, relative)
        target = install_dir / relative
        try:
            target_stat = target.lstat()
        except OSError as exc:
            raise RuntimeError(f"Installed release file could not be inspected: {name!r}.") from exc
        if (
            stat.S_ISLNK(target_stat.st_mode)
            or _is_reparse_stat(target_stat)
            or not stat.S_ISREG(target_stat.st_mode)
        ):
            raise RuntimeError(f"Installed release file is not a real regular file: {name!r}.")
        try:
            actual_digest = sha256_file(target).lower()
        except OSError as exc:
            raise RuntimeError(f"Installed release file could not be hashed: {name!r}.") from exc
        if actual_digest != expected_digest:
            raise RuntimeError(f"Installed release SHA-256 does not match {name!r}.")

def install_staged_release(
    stage: Path,
    install_dir: Path,
    target_version: str,
    transaction_work: Path | None = None,
) -> tuple[Path, list[tuple[Path, Path | None]]]:
    if not stage.is_dir():
        raise RuntimeError(f"Staged update directory does not exist: {stage}")
    if not install_dir.is_dir():
        raise RuntimeError(f"Ninja Capture Tool directory does not exist: {install_dir}")

    _validate_update_destination_path(install_dir)
    _validate_update_destination_path(install_dir, Path("data"))
    new_managed_files = _validate_staged_release_manifest(stage, target_version)
    old_managed_files = _load_installed_release_manifest(install_dir)

    backup = stage.parent / f"backup_{uuid.uuid4().hex}"
    backup.mkdir()
    changes: list[tuple[Path, Path | None]] = []

    def replace(source: Path, destination: Path, relative: Path) -> None:
        _validate_update_destination_path(install_dir, relative)
        saved: Path | None = None
        if destination.exists() or destination.is_symlink():
            saved = backup / relative
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(destination), str(saved))
        changes.append((destination, saved))
        _publish_staged_item(source, destination)

    try:
        whole_directory_replacements = {
            source.name.casefold()
            for source in stage.iterdir()
            if source.is_dir() and source.name.casefold() != "data"
        }
        if old_managed_files is not None:
            new_folded = {name.casefold() for name in new_managed_files}
            obsolete = sorted(
                (name for name in old_managed_files if name.casefold() not in new_folded),
                key=str.casefold,
            )
            for relative_name in obsolete:
                if relative_name.split("/", 1)[0].casefold() in whole_directory_replacements:
                    continue
                relative = Path(*relative_name.split("/"))
                _validate_update_destination_path(install_dir, relative)
                destination = install_dir / relative
                if destination.is_symlink() or not destination.is_file():
                    continue
                try:
                    current_digest = sha256_file(destination).lower()
                except OSError:
                    continue
                if current_digest != old_managed_files[relative_name]:
                    # A user or another program changed the old release file. Preserve it rather than deleting data
                    # based solely on updater metadata.
                    continue
                saved = backup.joinpath(*relative_name.split("/"))
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(destination), str(saved))
                changes.append((destination, saved))

        staged_sources = sorted(stage.iterdir(), key=lambda path: path.name.casefold())
        runtime_name = FROZEN_RUNTIME_DIR_NAME.casefold()
        executable_name = "ninjacapturetool.exe"
        deferred_names = {runtime_name, executable_name}
        ordinary_sources = [source for source in staged_sources if source.name.casefold() not in deferred_names]
        release_manifest_relative = Path(*RELEASE_MANIFEST_FILE.split("/"))
        release_manifest_source = stage / release_manifest_relative

        for source in ordinary_sources:
            name = source.name.casefold()
            top_relative = Path(source.name)
            _validate_update_destination_path(install_dir, top_relative)
            if name == "config.json" and (install_dir / source.name).exists():
                # config.json is user configuration. A release supplies defaults only for fresh installations.
                continue
            if name != "data":
                replace(source, install_dir / source.name, top_relative)
                continue

            destination_data = install_dir / "data"
            destination_data.mkdir(parents=True, exist_ok=True)
            for data_source in sorted(source.rglob("*"), key=lambda path: path.as_posix().casefold()):
                if not data_source.is_file():
                    continue
                relative_in_data = data_source.relative_to(source)
                relative = Path("data") / relative_in_data
                _validate_update_destination_path(install_dir, relative)
                data_destination = install_dir / relative
                normalized_relative = relative.as_posix().casefold()
                if normalized_relative == RELEASE_MANIFEST_FILE.casefold():
                    # The manifest is updater commit metadata. Publish it only
                    # after the new runtime and immediately before the executable.
                    continue
                replace(data_source, data_destination, relative)

        for source in staged_sources:
            if source.name.casefold() == runtime_name:
                replace(source, install_dir / source.name, Path(source.name))

        replace(
            release_manifest_source,
            install_dir / release_manifest_relative,
            release_manifest_relative,
        )

        for source in staged_sources:
            if source.name.casefold() == executable_name:
                replace(source, install_dir / source.name, Path(source.name))

        # Revalidate the published installation against the exact file map that
        # was authenticated before any mutation. Do not trust a newly installed
        # manifest alone: it could have changed after the staged preflight.
        _validate_installed_release_manifest(install_dir, target_version, new_managed_files)
    except BaseException as install_error:
        try:
            rollback_staged_release(changes, backup, transaction_work)
        except Exception as rollback_error:
            raise RuntimeError(f"Update installation failed and {rollback_error}") from install_error
        raise

    return backup, changes

def _read_installed_version(executable: Path, cwd: Path) -> str:
    environment = os.environ.copy()
    environment["NCT_HEADLESS"] = "1"
    try:
        result = subprocess.run(
            [str(executable), "--version"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=150,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Updated executable did not respond to --version: {executable.name}") from exc
    except OSError as exc:
        raise RuntimeError(f"Updated executable could not be started: {executable.name}: {exc}") from exc

    output = result.stdout.strip()
    prefix = "Ninja Capture Tool v"
    if result.returncode != 0 or not output.startswith(prefix) or "\n" in output or "\r" in output:
        details = result.stderr.strip() or output or f"exit code {result.returncode}"
        raise RuntimeError(f"Updated executable failed validation: {executable.name}: {details}")
    version = output[len(prefix):]
    try:
        parse_version(version)
    except ValueError as exc:
        raise RuntimeError(f"Updated executable returned an invalid version: {executable.name}: {version!r}") from exc
    return version

def validate_installed_executable(executable: Path, target_version: str, cwd: Path) -> None:
    installed_version = _read_installed_version(executable, cwd)
    if compare_versions(installed_version, target_version) != 0:
        raise RuntimeError(
            f"Updated executable failed validation: {executable.name}: "
            f"expected v{display_version(target_version)}, got v{display_version(installed_version)}"
        )

def installed_executable_satisfies_target(executable: Path, target_version: str, cwd: Path) -> str | None:
    try:
        installed_version = _read_installed_version(executable, cwd)
        if compare_versions(installed_version, target_version) >= 0:
            return installed_version
    except Exception:
        pass
    return None

def relaunch(executable: Path, argv: list[str], cwd: Path, cleanup_work: Path | None = None) -> subprocess.Popen:
    environment = os.environ.copy()
    # Skip exactly one automatic update check after a handoff without modifying the user's original arguments.
    environment["NCT_SKIP_UPDATE_CHECK_ONCE"] = "1"
    if cleanup_work is not None:
        environment["NCT_UPDATE_WORK_CLEANUP"] = str(cleanup_work)
    return subprocess.Popen([str(executable), *argv], cwd=cwd, env=environment)

def run_update_installer(argv: list[str] | None = None) -> int:
    if sys.platform != "win32":
        print_error("Ninja Capture Tool updater is Windows-only.")
        return 1

    ignore_interrupts()
    parser = ErrorArgumentParser(description="Internal Ninja Capture Tool update installer.")
    parser.add_argument("--install-dir", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--stage-dir", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--parent-pid", type=int, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--target-version", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--relaunch-executable", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("--relaunch-cwd", type=Path, required=True, help=argparse.SUPPRESS)
    parser.add_argument("relaunch_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    parser.add_argument("-v", "--version", action="version", version=f"Ninja Capture Tool v{LOCAL_DISPLAY_VERSION}")
    args = parser.parse_args(argv)

    target_version = args.target_version.strip()
    if target_version[:1].lower() == "v":
        target_version = target_version[1:]
    try:
        parse_version(target_version)
    except ValueError as exc:
        print_error(f"Invalid Ninja Capture Tool update target version: {args.target_version!r}: {exc}")
        return 1

    try:
        install_dir, stage = _validate_update_workspace(args.stage_dir, args.install_dir)
    except Exception as exc:
        print_error(f"Invalid Ninja Capture Tool update workspace: {exc}")
        return 1
    work = stage.parent
    executable = args.relaunch_executable.resolve()
    relaunch_cwd = args.relaunch_cwd.resolve()
    relaunch_args = args.relaunch_args
    if relaunch_args[:1] == ["--"]:
        relaunch_args = relaunch_args[1:]

    transaction: tuple[Path, list[tuple[Path, Path | None]]] | None = None
    installed_version: str | None = None
    update_installed = False
    install_failed = False

    try:
        write_update_session(work)
        wait_for_process_exit(args.parent_pid)
        try:
            with updater_install_lock(install_dir):
                try:
                    with capture_install_lock(install_dir):
                        # Revalidate at the actual mutation boundary. The updater
                        # may have waited for the parent and for both locks after
                        # the early validation, so do not trust the workspace to
                        # have remained unchanged during that gap.
                        install_dir, stage = _validate_update_workspace(stage, install_dir)
                        installed_version = installed_executable_satisfies_target(
                            executable, target_version, install_dir
                        )
                        if installed_version is None:
                            try:
                                transaction = install_staged_release(
                                    stage, install_dir, target_version, transaction_work=work
                                )
                                validate_installed_executable(executable, target_version, install_dir)
                                mark_update_session_committed(work)
                            except Exception as exc:
                                if transaction is not None:
                                    backup, changes = transaction
                                    try:
                                        rollback_staged_release(changes, backup, work)
                                    except Exception as rollback_error:
                                        print_error(
                                            f"Ninja Capture Tool update failed and rollback was incomplete: {rollback_error}"
                                        )
                                        return 1
                                elif (
                                    _update_work_has_backup(work)
                                    and not _update_session_backup_is_disposable(work)
                                ):
                                    print_error(
                                        f"Ninja Capture Tool update failed and rollback was incomplete; "
                                        f"recovery data was retained: {exc}"
                                    )
                                    return 1
                                print_error(
                                    f"Ninja Capture Tool update failed; the previous installation was restored when possible: {exc}"
                                )
                                install_failed = True
                            else:
                                backup, _ = transaction
                                shutil.rmtree(backup, ignore_errors=True)
                                update_installed = True
                except CaptureActiveError:
                    print(
                        "[Update] Installation deferred because another Ninja Capture Tool capture is active. "
                        "The update will be checked again on the next run."
                    )
                    cleanup_deferred_update_payload(work, install_dir)
                    return 0
        except UpdaterBusyError:
            print(
                "[Update] Installation deferred because another Ninja Capture Tool update is already in progress. "
                "Ninja Capture Tool was not restarted while installation files may be changing; start it again after the update finishes."
            )
            cleanup_deferred_update_payload(work, install_dir)
            return 0

        # Release update coordination before starting a new Ninja Capture Tool process; it may need the same locks.
        try:
            relaunch(executable, relaunch_args, relaunch_cwd, work)
        except Exception as relaunch_error:
            if install_failed:
                prefix = "after the failed update"
            else:
                prefix = "after the update"
            print_error(f"Could not restart Ninja Capture Tool {prefix}: {relaunch_error}")
            return 1

        if install_failed:
            return 1
        if installed_version is not None:
            if compare_versions(installed_version, target_version) > 0:
                print(
                    f"[Update] Ninja Capture Tool v{display_version(installed_version)} is already installed; "
                    f"skipping queued update to v{display_version(target_version)}."
                )
            else:
                print(f"[Update] Ninja Capture Tool v{display_version(target_version)} was already installed by another updater.")
            return 0
        if update_installed:
            print(f"[Update] Ninja Capture Tool updated successfully to v{display_version(target_version)}.")
            return 0
        raise RuntimeError("Updater reached an unexpected state.")
    except Exception as exc:
        print_error(f"Ninja Capture Tool updater could not start the installation: {exc}")
        if not _update_work_has_backup(work):
            try:
                relaunch(executable, relaunch_args, relaunch_cwd, work)
            except Exception as relaunch_error:
                print_error(f"Could not restart Ninja Capture Tool after the failed update: {relaunch_error}")
        return 1
