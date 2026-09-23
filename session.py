#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path

import capture
import common
import config as nct_config
import elevation
import runtime
import windows_proxy

from check_live import LiveTrackingMixin, SteamManifestObservation

UPSTREAM_AUTH_ENV = "NCT_UPSTREAM_AUTH"
_SESSION_RECOVERY_FILE: Path | None = None

def _session_recovery_path() -> Path:
    return common.session_recovery_file() if _SESSION_RECOVERY_FILE is None else _SESSION_RECOVERY_FILE

class SessionLogger:
    def __init__(self, path: Path):
        self.path = path
        # Console output can block while classic Windows QuickEdit selection is
        # active. Keep file logging independent so a blocked console never holds
        # the worker-output reader or capture-log writer behind the same lock.
        self.console_lock = threading.Lock()
        self.file_lock = threading.Lock()
        self.file_error_reported = False
        self._file = None
        self._closed = False
        self._progress_width = 0
        path.parent.mkdir(parents=True, exist_ok=True)
        self._file = path.open("a", encoding="utf-8", buffering=1)

    @staticmethod
    def _interactive_console() -> bool:
        try:
            return sys.stdout.isatty()
        except (AttributeError, OSError, ValueError):
            return False

    def _clear_progress_locked(self) -> None:
        if self._progress_width <= 0:
            return
        try:
            sys.stdout.write("\r" + (" " * self._progress_width) + "\r")
            sys.stdout.flush()
        except (OSError, ValueError):
            pass
        self._progress_width = 0

    def show_progress(self, message: str) -> None:
        if not self._interactive_console():
            return
        with self.console_lock:
            if self._closed:
                return
            try:
                width = max(1, shutil.get_terminal_size(fallback=(120, 24)).columns - 1)
            except OSError:
                width = 119
            display_message = message
            if len(display_message) > width:
                separator = " | "
                if separator in display_message:
                    prefix, path = display_message.rsplit(separator, 1)
                    available = width - len(prefix) - len(separator)
                    if available >= 4:
                        display_message = prefix + separator + "..." + path[-(available - 3):]
                if len(display_message) > width:
                    display_message = (
                        display_message[:width]
                        if width <= 3
                        else display_message[: width - 3] + "..."
                    )
            styled = common.style_console_text(display_message, sys.stdout, status_tokens=True)
            padding = max(0, self._progress_width - len(display_message))
            try:
                sys.stdout.write("\r" + styled + (" " * padding))
                sys.stdout.flush()
            except (OSError, ValueError):
                self._progress_width = 0
                return
            self._progress_width = len(display_message)

    def clear_progress(self) -> None:
        with self.console_lock:
            self._clear_progress_locked()

    def _close_file(self) -> OSError | None:
        if self._file is None:
            return None
        try:
            self._file.close()
        except OSError as exc:
            return exc
        finally:
            self._file = None
        return None

    def close(self) -> None:
        self._closed = True
        # Do not let a QuickEdit-blocked console prevent shutdown/file cleanup.
        if self.console_lock.acquire(timeout=0.1):
            try:
                self._clear_progress_locked()
            finally:
                self.console_lock.release()
        with self.file_lock:
            close_error = self._close_file()
        if close_error is not None and not self.file_error_reported:
            self.file_error_reported = True
            common.print_warning(f"Could not close capture log cleanly: {close_error}", flush=True)

    def _write_to_file(self, message: str) -> None:
        if self._closed:
            return
        if self._file is None:
            self._file = self.path.open("a", encoding="utf-8", buffering=1)
        timestamp = common.current_timestamp()
        lines = message.split("\n")
        self._file.write("".join(f"{timestamp} {line}\n" for line in lines))
        self._file.flush()

    def write(self, message: str, console: bool = True, file: bool = True) -> None:
        if file:
            warning: str | None = None
            recovered = False
            with self.file_lock:
                if not self._closed:
                    try:
                        self._write_to_file(message)
                    except OSError as exc:
                        self._close_file()
                        if not self.file_error_reported:
                            self.file_error_reported = True
                            warning = f"Could not write capture log: {exc}"
                    else:
                        if self.file_error_reported:
                            self.file_error_reported = False
                            recovered = True
            # Reporting a logging problem is best-effort and deliberately outside
            # file_lock; console selection must not hold up later file writes.
            if console and warning is not None:
                common.print_warning(warning, flush=True)
            elif console and recovered:
                print("Capture log writing recovered.", flush=True)

        if console:
            with self.console_lock:
                if self._closed:
                    return
                self._clear_progress_locked()
                common.print_console(message, flush=True, status_tokens=True)

def _debug_mode_label(value: object) -> str:
    if value == "global":
        return "Global"
    return "On" if bool(value) else "Off"

def _capture_mode_label(value: object) -> str:
    return "Local" if str(value) == "local" else "System Proxy"

def _progress_message(
    action: str, received: int, expected: int | None, path: str, speed_bps: int | None = None
) -> str:
    received = max(0, int(received))
    speed = f" | {common.format_bytes(speed_bps)}/s" if speed_bps is not None and speed_bps >= 0 else ""
    if expected is not None and expected > 0:
        percent = min(100.0, received * 100.0 / expected)
        return (
            f"[{action}] {common.format_bytes(received)} / {common.format_bytes(expected)} ({percent:.1f}%)"
            f"{speed} | {path}"
        )
    return f"[{action}] {common.format_bytes(received)}{speed} | {path}"

def _waiting_message(required: int, available: int, path: str) -> str:
    return (
        f"[Waiting] {common.format_bytes(max(0, required))} needed / {common.format_bytes(max(0, available))} available"
        f" | Free disk space to continue | {path}"
    )

def _rollback_session_creation(
    session_root: Path | None,
    manifest_path: Path | None,
    log_path: Path | None,
    *,
    session_directory_created_by_tool: bool = True,
) -> list[str]:
    errors: list[str] = []
    if session_root is not None:
        try:
            common.remove_empty_capture_session_directory(
                session_root,
                remove_root=session_directory_created_by_tool,
            )
        except FileNotFoundError:
            pass
        except OSError as exc:
            errors.append(f"session directory: {exc}")
    for artifact, label in ((manifest_path, "session metadata"), (log_path, "capture log")):
        if artifact is None:
            continue
        try:
            artifact.unlink(missing_ok=True)
        except OSError as exc:
            errors.append(f"{label}: {exc}")
    return errors

def _next_session_recovery_archive_path(path: Path, label: str) -> Path:
    suffix = common.current_timestamp().replace(":", "-").replace("+", "_")
    archived = path.with_name(path.name + f".{label}-{suffix}")
    counter = 2
    while archived.exists():
        archived = path.with_name(path.name + f".{label}-{suffix}-{counter}")
        counter += 1
    return archived

def _archive_session_recovery_file(path: Path, label: str) -> Path:
    archived = _next_session_recovery_archive_path(path, label)
    path.rename(archived)
    return archived

def recover_recorded_capture_sessions(path: Path | None = None) -> tuple[int, int, list[str]]:
    """Recover every exact session path recorded by a previous interrupted Ninja Capture Tool run."""
    path = _session_recovery_path() if path is None else path
    if not path.exists():
        return 0, 0, []

    interrupted = 0
    removed = 0
    warnings: list[str] = []
    try:
        record = common.read_json_object(path)
    except RuntimeError as exc:
        try:
            archived = _archive_session_recovery_file(path, "invalid")
            warnings.append(f"Could not read previous session recovery data: {exc}. The record was preserved at: {archived}")
        except OSError as archive_exc:
            warnings.append(
                f"Previous session recovery data could not be read: {exc}. "
                f"It was left at {path} because it could not be preserved separately: {archive_exc}"
            )
        return interrupted, removed, warnings

    entries = record.get("sessions")
    if record.get("version") != 1 or not isinstance(entries, list):
        try:
            archived = _archive_session_recovery_file(path, "unsupported")
            warnings.append(f"Previous session recovery data is unsupported or malformed and was preserved at: {archived}")
        except OSError as exc:
            warnings.append(
                f"Unsupported or malformed previous session recovery data was left at {path} "
                f"because it could not be preserved separately: {exc}"
            )
        return interrupted, removed, warnings

    remaining: list[dict[str, object]] = []
    malformed_entries: list[object] = []
    settled_temp_parents: set[Path] = set()
    unresolved_temp_parents: set[Path] = set()
    settled_entries: list[tuple[dict[str, object], Path]] = []

    def keep(entry: dict[str, object]) -> None:
        if entry not in remaining:
            remaining.append(entry)

    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            malformed_entries.append(raw_entry)
            continue
        entry = raw_entry
        session_value = entry.get("session")
        manifest_value = entry.get("manifest")
        recorded_session_id = entry.get("session_id")
        startup_pending = entry.get("startup_pending", False)
        if (
            not isinstance(session_value, str)
            or not session_value
            or not isinstance(manifest_value, str)
            or not manifest_value
            or not common.is_session_id(recorded_session_id)
            or not isinstance(startup_pending, bool)
        ):
            malformed_entries.append(entry)
            continue

        session_root = Path(session_value)
        manifest_path = Path(manifest_value)
        if not session_root.is_absolute() or not manifest_path.is_absolute():
            malformed_entries.append(entry)
            continue

        try:
            common.validate_existing_session_root(session_root, "Recorded capture session")
            common.validate_existing_session_root(manifest_path, "Recorded session metadata")
            session_root = session_root.resolve()
            manifest_path = manifest_path.resolve()
        except (OSError, RuntimeError) as exc:
            keep(entry)
            warnings.append(
                f"Could not access a recorded capture session; recovery will be retried on the next launch: "
                f"{session_root} ({exc})"
            )
            try:
                unresolved_temp_parents.add(session_root.parent.resolve())
            except OSError:
                pass
            continue

        if manifest_path.parent != session_root.parent:
            keep(entry)
            unresolved_temp_parents.add(session_root.parent)
            warnings.append(
                f"Recorded session metadata is not beside its capture directory; recovery will be retried on the next launch: "
                f"{manifest_path}"
            )
            continue

        if not session_root.exists() and not manifest_path.exists():
            settled_temp_parents.add(session_root.parent)
            settled_entries.append((entry, session_root.parent))
            continue

        manifest = common.load_capture_session_manifest(manifest_path)
        if manifest is None or str(manifest.get("capture_directory", "")).casefold() != session_root.name.casefold():
            keep(entry)
            unresolved_temp_parents.add(session_root.parent)
            warnings.append(
                f"Recorded session metadata no longer matches its capture directory; recovery will be retried on the next launch: "
                f"{session_root}"
            )
            continue
        if manifest.get("session_id") != recorded_session_id:
            keep(entry)
            unresolved_temp_parents.add(session_root.parent)
            warnings.append(
                f"Recorded session identity no longer matches its capture metadata; recovery was skipped to avoid touching a reused path: "
                f"{session_root}"
            )
            continue

        if not session_root.exists() and (
            manifest.get("status") in {"pending_rotation", "completed", "aborted"}
            and common.session_warning_count(manifest) == 0
            and int(manifest.get("captured_files", 0)) == 0
        ):
            suffix = "_session.json"
            session_id = manifest_path.name[:-len(suffix)] if manifest_path.name.endswith(suffix) else ""
            log_path = common.session_artifact_paths(manifest_path.parent, session_id)[0] if session_id else None
            try:
                if log_path is not None:
                    log_path.unlink(missing_ok=True)
                manifest_path.unlink(missing_ok=True)
            except OSError as exc:
                keep(entry)
                unresolved_temp_parents.add(session_root.parent)
                warnings.append(
                    f"Could not remove stale metadata for a missing capture session; recovery will be retried on the next launch: {exc}"
                )
            else:
                settled_temp_parents.add(session_root.parent)
                settled_entries.append((entry, session_root.parent))
            continue

        status_before_recovery = str(manifest.get("status", ""))
        marked, child_warnings, recovered = common.recover_stale_session_exact(
            session_root,
            manifest_path,
            recorded_session_id,
            allow_empty_starting_cleanup=startup_pending,
            allow_empty_running_cleanup=startup_pending,
        )
        interrupted += marked
        # An empty aborted session, including one whose final metadata write could
        # not finish before Windows ended an intentional pre-start window close, is
        # routine housekeeping rather than user-visible recovery work.
        silent_startup_abort = (
            (startup_pending or manifest.get("cleanup_empty_startup") is True)
            and status_before_recovery in {"starting", "running"}
        )
        if recovered and status_before_recovery != "aborted" and not silent_startup_abort:
            removed += 1
        warnings.extend(child_warnings)

        post_manifest = common.load_capture_session_manifest(manifest_path)
        settled = recovered or marked > 0 or (
            post_manifest is not None
            and post_manifest.get("status") not in {"pending_rotation", "starting", "running"}
        ) or (not session_root.exists() and not manifest_path.exists())
        if settled:
            settled_temp_parents.add(session_root.parent)
            settled_entries.append((entry, session_root.parent))
        else:
            keep(entry)
            unresolved_temp_parents.add(session_root.parent)
            warnings.append(
                f"Could not fully recover a recorded capture session; recovery will be retried on the next launch: {session_root}"
            )

    for metadata_root in settled_temp_parents - unresolved_temp_parents:
        try:
            common.clear_stale_capture_temp(metadata_root)
        except RuntimeError as exc:
            warnings.append(str(exc))
            for entry, parent in settled_entries:
                if parent == metadata_root:
                    keep(entry)

    malformed_unarchived: list[object] = []
    if malformed_entries:
        archived = _next_session_recovery_archive_path(path, "invalid")
        try:
            common.atomic_write_json(archived, {"version": 1, "sessions": malformed_entries})
        except OSError as exc:
            malformed_unarchived = malformed_entries
            warnings.append(
                f"Could not preserve {len(malformed_entries)} malformed session recovery "
                f"entr{'y' if len(malformed_entries) == 1 else 'ies'} separately; "
                f"the entr{'y was' if len(malformed_entries) == 1 else 'ies were'} left in {path}: {exc}"
            )
        else:
            warnings.append(
                f"Preserved {len(malformed_entries)} malformed session recovery "
                f"entr{'y' if len(malformed_entries) == 1 else 'ies'} at: {archived}"
            )

    entries_for_next_launch: list[object] = [*remaining, *malformed_unarchived]
    if entries_for_next_launch:
        try:
            common.atomic_write_json(path, {"version": 1, "sessions": entries_for_next_launch})
        except OSError as exc:
            warnings.append(f"Could not update session recovery data for the next launch: {exc}")
    else:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            warnings.append(f"Could not remove resolved session recovery data at {path}: {exc}")
    return interrupted, removed, warnings

class CaptureSession(LiveTrackingMixin):
    def __init__(
        self,
        options: dict[str, object],
        setup_messages: list[str] | None = None,
        cli_args: argparse.Namespace | None = None,
        config_path: Path = nct_config.CONFIG_FILE,
    ):
        self.options = dict(options)
        self.setup_messages = list(setup_messages or [])
        self.proxy_port = int(options["proxy_port"])
        self.output_root = Path(options["output_root"])
        explicit_output = options.get("output_path")
        self.output_path = Path(explicit_output) if explicit_output is not None else None
        self.session_root: Path | None = None
        self.session_directory_created_by_tool = True
        self.manifest_path: Path | None = None
        self.log_path: Path | None = None
        self.temp_root: Path | None = None
        self.logger: SessionLogger | None = None
        self.process: subprocess.Popen | None = None
        self.worker_job = None
        self.reader_thread: threading.Thread | None = None
        self.reader_failure: Exception | None = None
        self.reader_failed = threading.Event()
        self.worker_startup_error: str | None = None
        self.ready = threading.Event()
        self.worker_drained = threading.Event()
        self.config_metadata_updated = threading.Event()
        self.config_metadata_update_token: str | None = None
        self.config_metadata_update_error: str | None = None
        self.worker_activity_lock = threading.Lock()
        self.worker_activity_seen = False
        self.worker_active_captures = 0
        self.worker_last_progress = time.monotonic()
        self.worker_output_lock = threading.Lock()
        self.worker_retirement_lock = threading.Lock()
        self.retiring_worker_ids: set[int] = set()
        self.worker_output_held = False
        self.worker_output_buffer: list[tuple[str, str]] = []
        self.worker_console_condition = threading.Condition()
        self.worker_console_urgent_queue: deque[str] = deque()
        self.worker_console_queue: deque[str] = deque()
        self.worker_console_dropped = 0
        self.worker_console_stop = False
        self.worker_console_thread: threading.Thread | None = None
        self.worker_console_rendering = False
        self.pending_live_status_updates: dict[str, str] = {}
        self.worker_progress_message: str | None = None
        self.worker_progress_generation = 0
        self.previous_proxy: dict[str, object] | None = None
        self.applied_proxy: dict[str, object] | None = None
        self.cleaned_up = False
        self.started = False
        self.capture_active_announced = False
        self.failed = False
        self.failure_reason: str | None = None
        self.end_reason: str | None = None
        self.console_closing = False
        self.suppress_console_output = False
        self.shutdown_requested = threading.Event()
        self.shutdown_complete = threading.Event()
        self.cli_args = cli_args
        self.config_path = config_path
        self.config_locked_keys = nct_config.runtime_locked_config_keys(cli_args) if cli_args is not None else set()
        self.config_reload_enabled = cli_args is not None
        self.config_signature = nct_config.config_file_signature(config_path) if self.config_reload_enabled else None
        self.config_pending_signature: str | None = self.config_signature
        self.config_pending_since: float | None = None
        self.config_rejected_signature: str | None = None
        self.config_rejected_signature_set = False
        self.rotation_lock = threading.Lock()
        self.pending_rotation: dict[str, object] | None = None
        self.deferred_rotation_cleanup: list[dict[str, object]] = []
        self.unresolved_session_recovery: list[dict[str, object]] = []
        self.restart_prompt_state: str | None = None
        self.restart_prompt_text = ""
        self.restart_prompt_previous_suppression = False
        self.restart_prompt_deferred = False
        self.warframe_version_high_water: str | None = None
        self.live_warframe_version: str | None = None
        self.live_warframe_error: str | None = None
        self.live_steam_manifest: SteamManifestObservation | None = None
        self.live_steam_error: str | None = None
        self.live_status_header_initialized = False
        self.live_status_rows: dict[str, int | None] = {}
        self.live_status_texts: dict[str, str] = {}
        self.live_status_console_lock = threading.Lock()
        self.pending_live_status_log_messages: list[str] = []
        self.next_live_check_at: float | None = None
        self.awaiting_content_branch: str | None = None
        self.awaiting_from_manifest_id: int | None = None
        self.last_valid_steam_manifest_id: int | None = None
        self.last_valid_steam_manifest_size: int | None = None
        self.pre_transition_manifest_id: int | None = None
        self.pre_transition_manifest_size: int | None = None
        self.pre_transition_content_branch: str | None = None
        self.steam_tracking_state_loaded = False
        self.warframe_status_lock = threading.Lock()
        self.warframe_status_process: subprocess.Popen | None = None
        self.warframe_status_started_at: float | None = None
        self.warframe_status_checked_at: str | None = None
        self.warframe_status_pending_announce = False
        self.steam_status_lock = threading.Lock()
        self.steam_status_process: subprocess.Popen | None = None
        self.steam_status_started_at: float | None = None
        self.steam_status_pending_announce = False
        self.steam_status_pending_content_update = False

    def enable_config_reload(
        self,
        cli_args: argparse.Namespace,
        config_path: Path = nct_config.CONFIG_FILE,
        *,
        initial_signature: str | None = None,
    ) -> None:
        self.cli_args = cli_args
        self.config_path = config_path
        self.config_locked_keys = nct_config.runtime_locked_config_keys(cli_args)
        self.config_reload_enabled = True
        # When startup supplies a signature, it is the exact snapshot that produced
        # the active runtime options. Do not replace it with a newer on-disk hash or
        # that newer save could be mistaken for configuration already in effect.
        self.config_signature = initial_signature or nct_config.config_file_signature(config_path)
        self.config_pending_signature = self.config_signature
        self.config_pending_since = None
        self.config_rejected_signature = None
        self.config_rejected_signature_set = False

    def _automatic_session_naming_mode(self, version_info: dict[str, object]) -> str:
        if bool(self.options["name_session_after_warframe_version"]):
            version = version_info.get("version")
            status = version_info.get("status")
            if isinstance(version, str) and status not in {"backwards", "unavailable"}:
                return "warframe_version"
        return "timestamp"

    def _create_automatic_session_directory(
        self,
        metadata_root: Path,
        version_info: dict[str, object],
        messages: list[tuple[str, str]],
    ) -> tuple[Path, str, str]:
        session_naming = self._automatic_session_naming_mode(version_info)
        if session_naming == "warframe_version":
            version = version_info["version"]
            assert isinstance(version, str)
            session = common.create_named_session_directory(metadata_root, version)
            # For automatic version naming, keep the human-facing diagnostic
            # sidecars aligned with the capture-directory name. The manifest's
            # internal session_id remains an independent UUID.
            return session, session.name, session_naming
        if bool(self.options["name_session_after_warframe_version"]):
            messages.append(("info", "[Session] Automatic version naming unavailable; using timestamp session name instead."))
        session = common.create_session_directory(metadata_root)
        return session, session.name, session_naming

    @staticmethod
    def _session_recovery_entry(
        session_root: Path,
        manifest_path: Path,
        *,
        startup_pending: bool | None = None,
    ) -> dict[str, object]:
        manifest = common.load_capture_session_manifest(manifest_path)
        if manifest is None:
            raise RuntimeError(f"Capture session metadata is missing or invalid: {manifest_path}")
        entry: dict[str, object] = {
            "session": str(session_root.resolve()),
            "manifest": str(manifest_path.resolve()),
            "session_id": str(manifest["session_id"]),
        }
        if startup_pending is not None:
            entry["startup_pending"] = startup_pending
        return entry

    @staticmethod
    def _append_unique_recovery_entry(entries: list[dict[str, object]], entry: dict[str, object]) -> None:
        if entry not in entries:
            entries.append(entry)

    def _remember_unresolved_session(self, session_root: Path, manifest_path: Path) -> None:
        entry = self._session_recovery_entry(session_root, manifest_path)
        with self.rotation_lock:
            self._append_unique_recovery_entry(self.unresolved_session_recovery, entry)

    def _write_session_recovery_record(self, *, include_current: bool = True) -> None:
        entries: list[dict[str, object]] = []
        with self.rotation_lock:
            for entry in self.unresolved_session_recovery:
                self._append_unique_recovery_entry(entries, entry)
            pending = self.pending_rotation
            deferred = list(self.deferred_rotation_cleanup)
            current_root = self.session_root
            current_manifest = self.manifest_path

        if include_current and current_root is not None and current_manifest is not None:
            self._append_unique_recovery_entry(
                entries,
                self._session_recovery_entry(
                    current_root,
                    current_manifest,
                    startup_pending=not self.capture_active_announced,
                ),
            )
        if pending is not None:
            self._append_unique_recovery_entry(
                entries,
                self._session_recovery_entry(
                    Path(pending["session_root"]),
                    Path(pending["manifest_path"]),
                ),
            )
        for target in deferred:
            self._append_unique_recovery_entry(
                entries,
                self._session_recovery_entry(
                    Path(target["session_root"]),
                    Path(target["manifest_path"]),
                ),
            )

        if entries:
            common.atomic_write_json(_session_recovery_path(), {"version": 1, "sessions": entries})
        else:
            _session_recovery_path().unlink(missing_ok=True)

    def _close_restart_prompt(self) -> None:
        with self.worker_console_condition:
            self.restart_prompt_state = None
            self.restart_prompt_text = ""
            self.suppress_console_output = self.restart_prompt_previous_suppression
            self.worker_console_condition.notify_all()

    def log(self, message: str, *, console: bool = True) -> None:
        show_console = console and not self.suppress_console_output
        if self.logger is None:
            if show_console:
                print(message, flush=True)
        else:
            self.logger.write(message, console=show_console)

    def console(self, message: str) -> None:
        if self.logger is None:
            if not self.suppress_console_output:
                print(message, flush=True)
        else:
            self.logger.write(message, console=not self.suppress_console_output, file=False)

    @staticmethod
    def _worker_output_is_urgent(line: str) -> bool:
        return bool(re.match(r"^(?:\[Proxy\] )?(?:ERROR:|WARNING:)", line))

    def _start_worker_console_dispatcher(self) -> None:
        thread = self.worker_console_thread
        if thread is not None and thread.is_alive():
            return
        with self.worker_console_condition:
            self.worker_console_stop = False
        self.worker_console_thread = threading.Thread(
            target=self._worker_console_loop,
            name="nct-worker-console",
            daemon=True,
        )
        self.worker_console_thread.start()

    def _stop_worker_console_dispatcher(self, timeout: float = 0.25) -> None:
        with self.worker_console_condition:
            self.worker_console_stop = True
            self.pending_live_status_updates.clear()
            self.worker_progress_message = None
            self.worker_progress_generation += 1
            self.worker_console_condition.notify_all()
        thread = self.worker_console_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=timeout)
        self.worker_console_thread = None

    def _worker_console_loop(self) -> None:
        seen_progress_generation = -1
        while True:
            with self.worker_console_condition:
                self.worker_console_condition.wait_for(
                    lambda: self.worker_console_stop
                    or (
                        self.restart_prompt_state is None
                        and (
                            bool(self.worker_console_urgent_queue)
                            or bool(self.pending_live_status_updates)
                            or bool(self.worker_console_queue)
                            or self.worker_console_dropped > 0
                            or self.worker_progress_generation != seen_progress_generation
                        )
                    )
                )
                if self.worker_console_stop and self.restart_prompt_state is not None:
                    return
                if (
                    self.worker_console_stop
                    and not self.worker_console_urgent_queue
                    and not self.worker_console_queue
                    and not self.pending_live_status_updates
                ):
                    return
                if self.restart_prompt_state is not None:
                    continue
                dropped = self.worker_console_dropped
                self.worker_console_dropped = 0
                status_update: tuple[str, str] | None = None
                if self.worker_console_urgent_queue:
                    line = self.worker_console_urgent_queue.popleft()
                elif self.pending_live_status_updates:
                    key = next(iter(self.pending_live_status_updates))
                    status_update = (key, self.pending_live_status_updates.pop(key))
                    line = None
                else:
                    line = self.worker_console_queue.popleft() if self.worker_console_queue else None
                progress = self.worker_progress_message
                progress_generation = self.worker_progress_generation
                rendering_permanent = bool(dropped) or line is not None or status_update is not None
                if rendering_permanent:
                    self.worker_console_rendering = True

            try:
                if dropped:
                    self.console(
                        f"WARNING: {dropped:,} worker console line{'s' if dropped != 1 else ''} "
                        "were omitted while the console was busy; the capture log contains the complete output."
                    )
                if status_update is not None:
                    self._render_live_status_line(*status_update)
                if line is not None:
                    self.console(line)
            finally:
                if rendering_permanent:
                    with self.worker_console_condition:
                        self.worker_console_rendering = False
                        self.worker_console_condition.notify_all()
            if progress_generation != seen_progress_generation:
                seen_progress_generation = progress_generation
                if self.logger is not None and not self.suppress_console_output:
                    if progress is None:
                        self.logger.clear_progress()
                    else:
                        self.logger.show_progress(progress)

    def _persist_and_queue_worker_output(
        self,
        line: str,
        *,
        urgent: bool = False,
        log_line: str | None = None,
    ) -> None:
        if self.logger is not None:
            self.logger.write(log_line if log_line is not None else line, console=False)
        self._start_worker_console_dispatcher()
        with self.worker_console_condition:
            # A blocked classic Windows QuickEdit console must never back-pressure
            # the worker pipe. The capture log above keeps the complete stream. Keep the
            # newest ordinary console lines when the display falls far behind, while
            # errors/warnings use a separate FIFO so their arrival order is preserved.
            if urgent:
                if len(self.worker_console_urgent_queue) >= 256:
                    self.worker_console_urgent_queue.popleft()
                    self.worker_console_dropped += 1
                self.worker_console_urgent_queue.append(line)
            else:
                if len(self.worker_console_queue) >= 2048:
                    self.worker_console_queue.popleft()
                    self.worker_console_dropped += 1
                self.worker_console_queue.append(line)
            self.worker_console_condition.notify()

    def _set_worker_progress(self, message: str | None) -> None:
        self._start_worker_console_dispatcher()
        with self.worker_console_condition:
            self.worker_progress_message = message
            self.worker_progress_generation += 1
            self.worker_console_condition.notify()

    def _hold_worker_output(self) -> None:
        with self.worker_output_lock:
            self.worker_output_held = True

    def _release_worker_output(self) -> None:
        # Flush queued lines while holding the ordering lock so newly arriving
        # worker output cannot jump ahead of lines buffered during the restart.
        with self.worker_output_lock:
            self.worker_output_held = False
            buffered = self.worker_output_buffer
            self.worker_output_buffer = []
            if self.worker_console_thread is None:
                # Preserve synchronous behavior for sessions that never started a
                # worker (notably configuration/unit-test paths).
                for line, log_line in buffered:
                    if line == log_line:
                        self.log(line)
                    elif self.logger is None:
                        if not self.suppress_console_output:
                            print(line, flush=True)
                    else:
                        self.logger.write(log_line, console=False)
                        self.logger.write(line, console=not self.suppress_console_output, file=False)
                return
            for line, log_line in buffered:
                self._persist_and_queue_worker_output(
                    line,
                    urgent=self._worker_output_is_urgent(line),
                    log_line=log_line,
                )

    def _queue_worker_output(self, line: str, *, log_line: str | None = None) -> None:
        resolved_log_line = log_line if log_line is not None else line
        if self._worker_output_is_urgent(line):
            self._persist_and_queue_worker_output(line, urgent=True, log_line=resolved_log_line)
            return
        with self.worker_output_lock:
            if self.worker_output_held:
                self.worker_output_buffer.append((line, resolved_log_line))
                return
            self._persist_and_queue_worker_output(line, log_line=resolved_log_line)

    def _emit_saving_progress(self, message: str) -> None:
        with self.worker_output_lock:
            if self.worker_output_held:
                return
        self._set_worker_progress(message)

    def _handle_worker_output_message(self, message: dict[str, object]) -> None:
        console_line = message.get("console")
        log_line = message.get("log")
        if (
            not isinstance(console_line, str)
            or not isinstance(log_line, str)
            or not console_line
            or not log_line
            or "\n" in console_line
            or "\r" in console_line
            or "\n" in log_line
            or "\r" in log_line
        ):
            return
        self._set_worker_progress(None)
        self._queue_worker_output(console_line, log_line=log_line)

    def _handle_worker_progress_message(self, message: dict[str, object], message_type: str) -> None:
        try:
            path = str(message["path"])
            if message_type == "waiting":
                required = int(message["required"])
                available = int(message["available"])
            else:
                action = str(message["action"])
                if action not in {"saving", "extracting"}:
                    return
                received = int(message["received"])
                expected_value = message.get("expected")
                expected = int(expected_value) if expected_value is not None else None
                speed_value = message.get("speed_bps")
                speed_bps = int(speed_value) if speed_value is not None else None
        except (KeyError, TypeError, ValueError):
            return
        with self.worker_activity_lock:
            self.worker_activity_seen = True
            self.worker_last_progress = time.monotonic()
        if message_type == "waiting":
            self._emit_saving_progress(_waiting_message(required, available, path))
        else:
            self._emit_saving_progress(_progress_message(action.capitalize(), received, expected, path, speed_bps))

    def _handle_worker_message(self, message: dict[str, object]) -> None:
        message_type = message["type"]
        if message_type == "output":
            self._handle_worker_output_message(message)
        elif message_type == "ready":
            self.ready.set()
        elif message_type == "startup_error":
            reason = message.get("reason")
            detail = message.get("detail")
            trace = message.get("traceback")
            if not isinstance(reason, str) or not reason.strip() or "\n" in reason or "\r" in reason:
                return
            self.worker_startup_error = reason.strip()
            logger = self.logger
            if logger is not None:
                logger.write(f"ERROR: {self.worker_startup_error}", console=False)
                if isinstance(detail, str) and detail.strip():
                    logger.write(f"[Worker exception] {detail.strip()}", console=False)
                if isinstance(trace, str) and trace.strip():
                    for trace_line in trace.rstrip().splitlines():
                        logger.write(f"[Traceback] {trace_line}", console=False)
        elif message_type == "rotated":
            self._complete_session_rotation(str(message.get("token", "")))
        elif message_type == "rotation_failed":
            self._fail_session_rotation(
                str(message.get("token", "")),
                str(message.get("error", "Session rotation failed.")),
            )
        elif message_type == "config_metadata_updated":
            token = str(message.get("token", ""))
            if token and token == self.config_metadata_update_token:
                error = message.get("error")
                self.config_metadata_update_error = str(error).strip() if isinstance(error, str) and error.strip() else None
                self.config_metadata_updated.set()
        elif message_type == "fatal":
            self.failed = True
            self.failure_reason = str(message.get("reason", "Capture worker reported a fatal session error."))
            self.shutdown_requested.set()
        elif message_type == "drained":
            with self.worker_activity_lock:
                self.worker_activity_seen = True
                self.worker_active_captures = 0
                self.worker_last_progress = time.monotonic()
            self._set_worker_progress(None)
            self.worker_drained.set()
        elif message_type == "progress_clear":
            with self.worker_activity_lock:
                self.worker_activity_seen = True
                self.worker_last_progress = time.monotonic()
            self._set_worker_progress(None)
        elif message_type == "activity":
            with self.worker_activity_lock:
                self.worker_activity_seen = True
                self.worker_last_progress = time.monotonic()
                active = message.get("active")
                if active is not None:
                    try:
                        self.worker_active_captures = max(0, int(active))
                    except (TypeError, ValueError):
                        pass
                    if self.worker_active_captures == 0:
                        self._set_worker_progress(None)
        elif message_type in {"progress", "waiting"}:
            self._handle_worker_progress_message(message, message_type)

    def _read_worker_output(self, process: subprocess.Popen) -> None:
        assert process.stdout is not None
        pending_retiring_spawn_failure: str | None = None

        def worker_is_retiring() -> bool:
            with self.worker_retirement_lock:
                return id(process) in self.retiring_worker_ids

        def queue_plain_worker_line(line: str) -> None:
            nonlocal pending_retiring_spawn_failure
            retiring = worker_is_retiring()
            normalized = line.removeprefix("[Proxy] ").strip()
            if retiring and normalized == "Failed to spawn connection handler:":
                if pending_retiring_spawn_failure is not None:
                    self._set_worker_progress(None)
                    self._queue_worker_output(pending_retiring_spawn_failure)
                pending_retiring_spawn_failure = line if line.startswith("[") else "[Proxy] " + line
                return
            if pending_retiring_spawn_failure is not None:
                pending = pending_retiring_spawn_failure
                pending_retiring_spawn_failure = None
                if not (retiring and normalized == "RuntimeError: Event loop is closed"):
                    self._set_worker_progress(None)
                    self._queue_worker_output(pending)
                elif retiring:
                    return
            if not line.startswith("["):
                line = "[Proxy] " + line
            self._set_worker_progress(None)
            self._queue_worker_output(line)

        try:
            for raw_line in process.stdout:
                line = raw_line.rstrip("\r\n")
                if not line:
                    continue
                try:
                    message = common.parse_worker_message(line)
                except ValueError:
                    continue
                if message is not None:
                    if pending_retiring_spawn_failure is not None:
                        self._set_worker_progress(None)
                        self._queue_worker_output(pending_retiring_spawn_failure)
                        pending_retiring_spawn_failure = None
                    self._handle_worker_message(message)
                    continue
                queue_plain_worker_line(line)
        except (OSError, ValueError) as exc:
            # A pipe close is expected after shutdown or worker exit. The same
            # exception raised while the worker is still alive means parent-side
            # output handling failed and must not be silently mistaken for EOF.
            poll = getattr(process, "poll", None)
            return_code = poll() if callable(poll) else None
            if self.shutdown_requested.is_set() or return_code is not None:
                return
            self.reader_failure = exc
            self.reader_failed.set()
        except Exception as exc:
            self.reader_failure = exc
            self.reader_failed.set()
        finally:
            if pending_retiring_spawn_failure is not None:
                self._set_worker_progress(None)
                self._queue_worker_output(pending_retiring_spawn_failure)
            with self.worker_retirement_lock:
                self.retiring_worker_ids.discard(id(process))

    def _raise_reader_failure(self) -> None:
        if not self.reader_failed.is_set():
            return
        failure = self.reader_failure
        detail = str(failure).strip() if failure is not None else "unknown error"
        self.failed = True
        raise RuntimeError(f"Capture worker communication failed: {detail}") from failure

    def _finalize_worker_state(self, timeout: float = 1.0) -> bool:
        process = self.process
        reader = self.reader_thread

        # Never detach the process object while the proxy worker is still alive.
        # Shutdown and fallback termination still need the real process handle until
        # the worker has actually exited.
        if process is not None and process.poll() is None:
            return False

        if reader is not None:
            reader.join(timeout=timeout)
        if process is not None and process.stdin is not None:
            try:
                process.stdin.close()
            except (OSError, ValueError):
                pass
        if process is not None and process.stdout is not None:
            try:
                process.stdout.close()
            except (OSError, ValueError):
                pass
        if reader is not None and reader.is_alive():
            reader.join(timeout=0.25)
        if reader is None or not reader.is_alive():
            with self.worker_retirement_lock:
                self.retiring_worker_ids.discard(id(process))

        self.process = None
        self.reader_thread = None
        self.ready = threading.Event()
        self.worker_drained = threading.Event()
        with self.worker_activity_lock:
            self.worker_activity_seen = False
            self.worker_active_captures = 0
            self.worker_last_progress = time.monotonic()
        return True

    def _drain_worker_before_restart(self) -> None:
        process = self.process
        if process is None or process.poll() is not None:
            return
        stdin = process.stdin
        if stdin is None:
            return

        self.worker_drained.clear()
        with self.worker_activity_lock:
            active = self.worker_active_captures
            activity_seen = self.worker_activity_seen
            self.worker_last_progress = time.monotonic()
        try:
            stdin.write(common.encode_worker_message("drain") + "\n")
            stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            return

        if active > 0:
            self.log("Waiting for active capture to finish before restarting...")
        elif not activity_seen:
            # The ready/activity messages normally arrive before this point. Give a
            # slow pipe a short chance to catch up before deciding there is no active work.
            for _ in range(2):
                if self.worker_drained.wait(0.25):
                    return
                self._poll_restart_hotkey(defer_restart=True)

        while not self.worker_drained.wait(0.25):
            self._poll_restart_hotkey(defer_restart=True)
            if process.poll() is not None:
                return
            with self.worker_activity_lock:
                active = self.worker_active_captures
                last_progress = self.worker_last_progress
            if active <= 0:
                for _ in range(20):
                    if self.worker_drained.wait(0.25):
                        return
                    self._poll_restart_hotkey(defer_restart=True)
                    if process.poll() is not None:
                        return
                self.log("WARNING: Capture worker did not acknowledge drain completion; restarting it anyway.")
                return
            if time.monotonic() - last_progress >= 3 * 60 * 60:
                self.log("WARNING: Active capture made no progress for 3 hours; restarting the capture worker anyway.")
                return

    def _worker_upstream_for_options(self, options: dict[str, object]) -> tuple[str | None, str | None]:
        if str(options["capture_mode"]) != "system-proxy":
            return None, None
        if self.previous_proxy is None:
            raise RuntimeError("Previous Windows proxy settings are unavailable.")
        upstream, upstream_auth = windows_proxy.resolve_upstream_proxy(str(options["upstream_proxy"]), self.previous_proxy)
        if windows_proxy.upstream_points_to_local_proxy(upstream, int(options["proxy_port"])):
            raise RuntimeError("The selected upstream proxy points back to Ninja Capture Tool and would create a proxy loop.")
        return upstream, upstream_auth

    def _restart_worker_for_options(self, new_options: dict[str, object]) -> None:
        old_options = dict(self.options)
        try:
            self._stop_worker()
            self._finalize_worker_state(timeout=1.5)
            self.options = dict(new_options)
            self.proxy_port = int(new_options["proxy_port"])
            upstream, upstream_auth = self._worker_upstream_for_options(new_options)
            self._start_worker(upstream, upstream_auth)
            self._wait_for_worker_ready()
        except Exception as exc:
            try:
                self._stop_worker()
                self._finalize_worker_state(timeout=1.0)
                self.options = old_options
                self.proxy_port = int(old_options["proxy_port"])
                upstream, upstream_auth = self._worker_upstream_for_options(old_options)
                self._start_worker(upstream, upstream_auth)
                self._wait_for_worker_ready()
            except Exception as rollback_exc:
                raise nct_config.ConfigApplyError(
                    f"{exc}; restoring the previous capture worker also failed: {rollback_exc}",
                    rollback_restored=False,
                ) from rollback_exc
            raise nct_config.ConfigApplyError(str(exc), rollback_restored=True) from exc

    def _deactivate_system_proxy_for_restart(self) -> None:
        if self.applied_proxy is None or self.previous_proxy is None:
            return
        result = windows_proxy.deactivate_local_proxy(self.previous_proxy, self.applied_proxy)
        if not result:
            raise RuntimeError(
                "Windows proxy settings changed after Ninja Capture Tool started, so the capture subsystem cannot be restarted safely."
            )
        if result.recovery_cleanup_error is not None:
            raise RuntimeError(
                "Previous Windows proxy settings were restored, but the recovery record could not be removed; "
                f"the capture subsystem cannot be restarted safely until it can be cleaned up: {result.recovery_cleanup_error}"
            )
        self.applied_proxy = None
        self.previous_proxy = None

    def _stop_capture_subsystem_for_restart(self) -> None:
        self._deactivate_system_proxy_for_restart()
        self._stop_worker()
        self._finalize_worker_state(timeout=1.5)

    def _start_capture_subsystem_for_options(self, options: dict[str, object]) -> None:
        mode = str(options["capture_mode"])
        if sys.platform == "win32" and not elevation.is_elevated():
            raise RuntimeError("Ninja Capture Tool's capture runtime requires administrator privileges.")

        self.options = dict(options)
        self.proxy_port = int(options["proxy_port"])
        self.previous_proxy = None
        self.applied_proxy = None
        upstream: str | None = None
        upstream_auth: str | None = None
        if mode == "system-proxy":
            windows_proxy.ensure_port_available(self.proxy_port)
            self.previous_proxy = windows_proxy.get_proxy_settings()
            upstream, upstream_auth = windows_proxy.resolve_upstream_proxy(str(options["upstream_proxy"]), self.previous_proxy)
            if windows_proxy.upstream_points_to_local_proxy(upstream, self.proxy_port):
                self.previous_proxy = None
                raise RuntimeError("The selected upstream proxy points back to Ninja Capture Tool and would create a proxy loop.")

        try:
            self._start_worker(upstream, upstream_auth)
            self._wait_for_worker_ready()
            if mode == "system-proxy":
                assert self.previous_proxy is not None and self.session_root is not None
                self.applied_proxy = windows_proxy.activate_local_proxy(self.previous_proxy, self.session_root, self.proxy_port)
        except Exception:
            self._stop_worker()
            self._finalize_worker_state(timeout=1.0)
            self.applied_proxy = None
            self.previous_proxy = None
            raise

    def _restart_capture_subsystem(self, new_options: dict[str, object]) -> None:
        old_options = dict(self.options)
        # If we no longer own the active System Proxy settings, abort before
        # stopping the old worker. That preserves the last known-good subsystem.
        try:
            self._stop_capture_subsystem_for_restart()
        except Exception as exc:
            if common.proxy_recovery_file().exists():
                raise nct_config.ConfigApplyError(
                    f"{exc}; unresolved System Proxy recovery data remains and must be recovered before capture can continue",
                    rollback_restored=False,
                ) from exc
            raise
        try:
            self._start_capture_subsystem_for_options(new_options)
        except Exception as exc:
            # A failed System Proxy activation keeps its recovery record when the
            # previous Windows settings could not be verified after restoration.
            # Never start another subsystem on top of that unresolved state: doing
            # so could overwrite the only snapshot capable of repairing Windows.
            if common.proxy_recovery_file().exists():
                raise nct_config.ConfigApplyError(
                    f"{exc}; unresolved System Proxy recovery data remains and must be recovered before capture can continue",
                    rollback_restored=False,
                ) from exc
            try:
                self._stop_worker()
                self._finalize_worker_state(timeout=1.0)
                self._start_capture_subsystem_for_options(old_options)
            except Exception as rollback_exc:
                raise nct_config.ConfigApplyError(
                    f"{exc}; restoring the previous capture subsystem also failed: {rollback_exc}",
                    rollback_restored=False,
                ) from rollback_exc
            raise nct_config.ConfigApplyError(str(exc), rollback_restored=True) from exc

    def _sync_session_capture_config_metadata(self, options: dict[str, object]) -> None:
        if self.manifest_path is None:
            return
        process = self.process
        if process is None or process.poll() is not None or process.stdin is None:
            self.log("WARNING: Could not update current session capture configuration metadata because the capture worker is unavailable.")
            return

        token = hashlib.sha256(f"config:{time.time_ns()}:{self.manifest_path}".encode("utf-8")).hexdigest()[:24]
        self.config_metadata_update_token = token
        self.config_metadata_update_error = None
        self.config_metadata_updated.clear()
        snapshot = capture.capture_config_metadata_snapshot(options)
        try:
            process.stdin.write(
                common.encode_worker_message(
                    "config_metadata",
                    token=token,
                    capture_mode=str(snapshot["capture_mode"]),
                    processes=[str(item) for item in snapshot["processes"]],
                    debug=str(snapshot["debug"]),
                    proxy_port=int(snapshot["proxy_port"]),
                    upstream_proxy=str(snapshot["upstream_proxy"]),
                    stop_on_exit=bool(snapshot["stop_on_exit"]),
                    stop_on_exit_delay=int(snapshot["stop_on_exit_delay"]),
                )
                + "\n"
            )
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            self.log(f"WARNING: Could not update current session capture configuration metadata: {exc}")
            return

        if not self.config_metadata_updated.wait(5.0):
            self.log("WARNING: Capture worker did not confirm the current session capture configuration metadata update.")
            return
        if self.config_metadata_update_error is not None:
            self.log(
                "WARNING: Could not update current session capture configuration metadata: "
                f"{self.config_metadata_update_error}"
            )

    def _config_change_lines(self, old: dict[str, object], new: dict[str, object]) -> list[str]:
        lines: list[str] = []
        if old["capture_mode"] != new["capture_mode"]:
            lines.append(
                f"[Config] Capture mode: {_capture_mode_label(old['capture_mode'])} -> {_capture_mode_label(new['capture_mode'])}"
            )
        if old["debug"] != new["debug"]:
            lines.append(f"[Config] Debug: {_debug_mode_label(old['debug'])} -> {_debug_mode_label(new['debug'])}")
        if old["processes"] != new["processes"]:
            lines.append(f"[Config] Processes: {', '.join(str(item) for item in new['processes'])}")
        if old["stop_on_exit"] != new["stop_on_exit"]:
            lines.append(f"[Config] Stop on exit: {'On' if bool(new['stop_on_exit']) else 'Off'}")
        if old["stop_on_exit_delay"] != new["stop_on_exit_delay"]:
            lines.append(f"[Config] Stop-on-exit delay: {int(new['stop_on_exit_delay'])}s")
        if old["proxy_port"] != new["proxy_port"]:
            lines.append(f"[Config] Proxy port: {int(new['proxy_port'])}")
        if old["upstream_proxy"] != new["upstream_proxy"]:
            raw_upstream = str(new["upstream_proxy"]).strip()
            keyword = raw_upstream.casefold()
            if keyword == "auto":
                display = "Auto"
            elif keyword == "direct":
                display = "Direct"
            else:
                try:
                    endpoint, _ = windows_proxy.parse_upstream_proxy(raw_upstream)
                except RuntimeError:
                    display = "Custom"
                else:
                    display = f"Custom ({endpoint})"
            lines.append(f"[Config] Upstream proxy: {display}")
        if old["output_root"] != new["output_root"]:
            lines.append(f"[Config] Output root: {new['output_root']} (next launch)")
        if old["name_session_after_warframe_version"] != new["name_session_after_warframe_version"]:
            lines.append(
                f"[Config] Version-based session naming: "
                f"{'On' if bool(new['name_session_after_warframe_version']) else 'Off'} (next session)"
            )
        if old["live_check_interval_seconds"] != new["live_check_interval_seconds"]:
            interval = int(new["live_check_interval_seconds"])
            lines.append(f"[Config] Live check interval: {interval}s")
        if old["auto_update"] != new["auto_update"]:
            lines.append(f"[Config] Automatic updates: {'On' if bool(new['auto_update']) else 'Off'} (next launch)")
        return lines

    def _effective_reloaded_config(self, config: dict[str, object]) -> dict[str, object]:
        effective = dict(config)
        for key in self.config_locked_keys:
            if key not in effective or key not in self.options:
                continue
            value = self.options[key]
            effective[key] = str(value) if isinstance(value, Path) else value
        return effective

    def _apply_reloaded_config(
        self,
        config: dict[str, object],
        *,
        recovering_from_rejection: bool = False,
    ) -> bool | None:
        if self.cli_args is None:
            return False
        effective_config = self._effective_reloaded_config(config)
        new_options = nct_config.resolve_runtime_options(self.cli_args, effective_config)
        old_options = dict(self.options)
        changed = {
            key
            for key in (
                "capture_mode",
                "processes",
                "stop_on_exit",
                "stop_on_exit_delay",
                "proxy_port",
                "debug",
                "output_root",
                "name_session_after_warframe_version",
                "live_check_interval_seconds",
                "upstream_proxy",
                "auto_update",
            )
            if old_options[key] != new_options[key]
        }
        if not changed:
            if recovering_from_rejection:
                self.log("[Config] Configuration is valid again. Current runtime configuration unchanged.")
                self.console("")
            return False

        subsystem_restart = "capture_mode" in changed or (
            str(new_options["capture_mode"]) == "system-proxy"
            and bool({"proxy_port", "upstream_proxy"}.intersection(changed))
        )
        worker_restart = "debug" in changed or (
            str(new_options["capture_mode"]) == "local"
            and new_options["debug"] != "global"
            and "processes" in changed
        )
        if str(new_options["capture_mode"]) == "local" and (subsystem_restart or worker_restart):
            try:
                runtime.ensure_local_capture_compatible(new_options)
            except RuntimeError as exc:
                detail = str(exc).strip().rstrip(".")
                self.log(f"[Config] Reload rejected: {detail}. Current runtime configuration unchanged.")
                self.console("")
                # None distinguishes a semantically rejected config from a
                # successful/no-op reload. The watcher keeps the last applied
                # signature active and remembers this exact rejected file state
                # separately so it is reported only once.
                return None

        self.log("[Config] Change detected.")
        for line in self._config_change_lines(old_options, new_options):
            self.log(line)

        if subsystem_restart:
            self._drain_worker_before_restart()
            self.console("")
            self._hold_worker_output()
            try:
                self.log("Restarting capture subsystem to apply changes...")
                self._restart_capture_subsystem(new_options)
                self.log("Capture subsystem restarted successfully.")
            finally:
                self._release_worker_output()
        elif worker_restart:
            self._drain_worker_before_restart()
            self.console("")
            self._hold_worker_output()
            try:
                self.log("Restarting capture worker to apply changes...")
                self._restart_worker_for_options(new_options)
                self.log("Capture worker restarted successfully.")
            finally:
                self._release_worker_output()
        else:
            self.options = dict(new_options)
            self.proxy_port = int(new_options["proxy_port"])
        if "live_check_interval_seconds" in changed:
            self._schedule_next_live_check()
        if {
            "capture_mode",
            "processes",
            "debug",
            "proxy_port",
            "upstream_proxy",
            "stop_on_exit",
            "stop_on_exit_delay",
        }.intersection(changed):
            self._sync_session_capture_config_metadata(new_options)
        if old_options["capture_mode"] != new_options["capture_mode"]:
            runtime.set_console_title(str(new_options["capture_mode"]))
        if old_options["debug"] != "global" and new_options["debug"] == "global":
            self.console(
                "Global debug can log hostnames and IP addresses from unrelated local applications; "
                "review the session capture log before sharing it."
            )
        self.console("")
        return False

    def _poll_config_reload(self, now: float | None = None) -> bool:
        if not self.config_reload_enabled or self.cli_args is None:
            return False
        moment = time.monotonic() if now is None else now
        signature = nct_config.config_file_signature(self.config_path)
        if signature == self.config_signature:
            self.config_pending_signature = signature
            self.config_pending_since = None
            if self.config_rejected_signature_set:
                self.log("[Config] Configuration is valid again. Current runtime configuration unchanged.")
                self.console("")
            self.config_rejected_signature = None
            self.config_rejected_signature_set = False
            return False
        if self.config_rejected_signature_set:
            if signature == self.config_rejected_signature:
                self.config_pending_signature = signature
                self.config_pending_since = None
                return False
            # Keep the rejection marker while a different file state is debounced
            # and validated. That lets a successfully repaired no-op snapshot
            # report that configuration is valid again instead of silently clearing
            # the last visible "Reload rejected" status.
        if signature != self.config_pending_signature:
            self.config_pending_signature = signature
            self.config_pending_since = moment
            return False
        if self.config_pending_since is None:
            self.config_pending_since = moment
            return False
        if moment - self.config_pending_since < 0.5:
            return False

        self.config_pending_since = None
        attempted_signature = signature

        def remember_rejected_state(candidate: str | None) -> None:
            # Keep config_signature tied to the last successfully accepted/applied
            # config. A rejected or rolled-back file state is tracked separately
            # so it is reported once without being mistaken for the active runtime
            # configuration. If the editor saved again meanwhile, leave the newer
            # state untouched so it receives its own debounce/retry cycle.
            if nct_config.config_file_signature(self.config_path) == candidate:
                self.config_rejected_signature = candidate
                self.config_rejected_signature_set = True
                self.config_pending_signature = candidate
                self.config_pending_since = None

        try:
            try:
                config, snapshot_signature = nct_config.load_exact_config_snapshot(
                    self.config_path,
                    allow_empty_processes="processes" in self.config_locked_keys,
                    create_if_missing=False,
                )
            except nct_config.ConfigSnapshotChanged:
                # The debounced state changed while it was being read or validated.
                # Leave it unprocessed and let the next poll debounce the new bytes.
                return False
            if snapshot_signature != signature:
                # A newer save landed between the debounce hash and the exact-byte
                # snapshot. Never apply it without giving that state its own debounce.
                return False

            duplicate_count, cleaned_signature = nct_config.clean_duplicate_config_processes(
                self.config_path,
                expected_signature=snapshot_signature,
                emit=self.log,
            )
            if cleaned_signature is not None:
                # The cleaned file is the exact state being considered for this
                # reload. Do not mark it active until semantic application succeeds.
                attempted_signature = cleaned_signature
                self.config_pending_signature = cleaned_signature
            else:
                attempted_signature = snapshot_signature
            if duplicate_count:
                self.console("")

            # The file may have been saved again after the debounced snapshot was
            # loaded/validated (or after our duplicate cleanup completed). Never
            # apply an obsolete snapshot and unnecessarily restart capture. Leave
            # the newer signature unprocessed so the normal debounce path can pick
            # it up on a later poll once that save has settled.
            if nct_config.config_file_signature(self.config_path) != attempted_signature:
                return False

            apply_result = self._apply_reloaded_config(
                config,
                recovering_from_rejection=self.config_rejected_signature_set,
            )
            if apply_result is None:
                remember_rejected_state(attempted_signature)
                return False

            # Only a successfully accepted/no-op config becomes the watcher's active
            # signature. This preserves the meaning of config_signature as the file
            # state that produced the current runtime configuration.
            self.config_signature = attempted_signature
            self.config_pending_signature = attempted_signature
            self.config_rejected_signature = None
            self.config_rejected_signature_set = False
            return bool(apply_result)
        except nct_config.ConfigApplyError as exc:
            remember_rejected_state(attempted_signature)
            detail = str(exc).strip().rstrip(".")
            self.log(f"[Config] Apply failed: {detail}.")
            if exc.rollback_restored:
                self.log("[Config] Previous runtime configuration restored.")
                self.console("")
                return False

            self.log("ERROR: Previous runtime configuration could not be restored; stopping Ninja Capture Tool.")
            self.failed = True
            self.failure_reason = f"Live configuration change failed and rollback could not be restored: {detail}."
            if self.end_reason is None:
                self.end_reason = "config_reload_failure"
            self.shutdown_requested.set()
            self.console("")
            return True
        except Exception as exc:
            remember_rejected_state(attempted_signature)
            details = nct_config.describe_config_errors(exc)
            if "config.json auto_update must be true or false" in details:
                for detail in details:
                    self.log(f"ERROR: {detail}.")
                self.log("[Config] Reload rejected. Current runtime configuration unchanged.")
            else:
                detail = "; ".join(details)
                self.log(f"[Config] Reload rejected: {detail}. Current runtime configuration unchanged.")
            self.console("")
            return False

    def _start_worker(self, upstream: str | None, upstream_auth: str | None = None) -> None:
        assert self.session_root is not None
        assert self.manifest_path is not None
        runtime.ensure_local_capture_compatible(self.options)
        command = runtime.worker_command(self.session_root, self.options, upstream, manifest_path=self.manifest_path)
        environment = os.environ.copy()
        environment.pop(UPSTREAM_AUTH_ENV, None)
        if upstream_auth is not None:
            environment[UPSTREAM_AUTH_ENV] = upstream_auth
        with self.worker_activity_lock:
            self.worker_activity_seen = False
            self.worker_active_captures = 0
            self.worker_last_progress = time.monotonic()
        self.worker_drained.clear()
        self.reader_failure = None
        self.reader_failed.clear()
        self.worker_startup_error = None
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.worker_job, worker_job_name = runtime.create_worker_job()
        environment.pop(runtime.WORKER_JOB_ENV, None)
        if worker_job_name is not None:
            environment[runtime.WORKER_JOB_ENV] = worker_job_name
        try:
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
                env=environment,
            )
        except BaseException:
            runtime.close_worker_job(self.worker_job)
            self.worker_job = None
            raise
        if sys.platform == "win32" and self.worker_job is None:
            self.log(
                "WARNING: Could not create a Windows Job Object for the capture worker; "
                "process-tree fallback will be used during shutdown."
            )
        self.reader_thread = threading.Thread(
            target=self._read_worker_output,
            args=(self.process,),
            name="nct-proxy-output",
            daemon=True,
        )
        self.reader_thread.start()

    def _wait_for_worker_ready(self) -> None:
        while True:
            self._raise_reader_failure()
            if self.worker_startup_error is not None:
                raise RuntimeError(self.worker_startup_error)
            if self.shutdown_requested.is_set():
                raise KeyboardInterrupt
            if self.ready.wait(0.1):
                return
            assert self.process is not None
            if self.process.poll() is not None:
                reader = self.reader_thread
                if reader is not None and reader is not threading.current_thread():
                    reader.join(timeout=0.5)
                self._raise_reader_failure()
                if self.worker_startup_error is not None:
                    raise RuntimeError(self.worker_startup_error)
                raise RuntimeError(f"Capture worker exited during startup with code {self.process.returncode}.")

    def start(self) -> None:
        common.prepare_runtime_state_directory()
        version_info, live_messages = self._current_warframe_version_snapshot()
        common.print_console(
            "[Notice] Update Patch creation supports Warframe Hotfixes only; use the original, unupdated Steam manifest base for that content update "
            "(for example, ~U43.5.1 / 4895911296145320793 -> U43.5.4, while U43.6 or U44 requires a newer base).",
            flush=True,
        )
        self._initialize_live_status_header(version_info)
        self._emit_live_status_messages(live_messages)
        self._start_warframe_status_query(announce_current=True)
        self._start_steam_status_query(announce_current=True, content_update=False)
        self._schedule_next_live_check()

        recorded_interrupted, recorded_removed, recorded_warnings = recover_recorded_capture_sessions()
        if recorded_removed:
            print(f"[Recovery] Removed {recorded_removed} empty capture session{'s' if recorded_removed != 1 else ''} left by the previous run.")
        if recorded_interrupted:
            print(f"[Recovery] Marked {recorded_interrupted} unfinished capture session{'s' if recorded_interrupted != 1 else ''} from the previous run as interrupted.")
        for warning in recorded_warnings:
            common.print_warning(warning)
        metadata_root = self.output_path.parent if self.output_path is not None else self.output_root
        free_space = common.prepare_output_directory(metadata_root)
        if common.clear_stale_capture_temp(metadata_root):
            print("[Recovery] Removed stale temporary capture data from the previous session.")

        if self.output_path is not None:
            interrupted, warnings = 0, []
            if self.output_path.exists() or self.output_path.is_symlink():
                interrupted, warnings, _ = common.recover_stale_session(self.output_path)
        else:
            interrupted, warnings = common.recover_stale_sessions(self.output_root)
        if interrupted:
            print(
                f"[Recovery] Marked {interrupted} previous unfinished capture session"
                f"{'s' if interrupted != 1 else ''} as interrupted."
            )
        for warning in warnings:
            common.print_warning(warning)

        mode = str(self.options["capture_mode"])
        upstream: str | None = None
        upstream_auth: str | None = None
        if mode == "system-proxy":
            windows_proxy.ensure_port_available(self.proxy_port)
            self.previous_proxy = windows_proxy.get_proxy_settings()
            upstream, upstream_auth = windows_proxy.resolve_upstream_proxy(str(self.options["upstream_proxy"]), self.previous_proxy)
            if windows_proxy.upstream_points_to_local_proxy(upstream, self.proxy_port):
                raise RuntimeError("The selected upstream proxy points back to Ninja Capture Tool and would create a proxy loop.")

        if self.shutdown_requested.is_set() or self.cleaned_up:
            raise KeyboardInterrupt
        version_messages: list[tuple[str, str]] = []
        created_session: Path | None = None
        log_path: Path | None = None
        manifest_path: Path | None = None
        session_directory_created_by_tool = True
        try:
            if self.output_path is not None:
                session_id = common.allocate_session_identifier(self.output_path.parent)
                existed_before_claim = self.output_path.exists() or self.output_path.is_symlink()
                created_session = common.create_exact_session_directory(self.output_path)
                session_directory_created_by_tool = not existed_before_claim
                session_naming = "custom"
            else:
                created_session, session_id, session_naming = self._create_automatic_session_directory(
                    self.output_root,
                    version_info,
                    version_messages,
                )
            log_path, manifest_path = common.session_artifact_paths(created_session.parent, session_id)
            capture.initialize_session_manifest(
                created_session,
                self.options,
                manifest_path,
                session_directory_created_by_tool=session_directory_created_by_tool,
                warframe_version_info=version_info,
                session_naming=session_naming,
                cleanup_empty_startup=True,
            )
        except BaseException as exc:
            rollback_errors = _rollback_session_creation(
                created_session,
                manifest_path,
                log_path,
                session_directory_created_by_tool=session_directory_created_by_tool,
            )
            if rollback_errors:
                raise RuntimeError(
                    f"Could not fully roll back capture session creation after startup failed ({exc}): "
                    + "; ".join(rollback_errors)
                ) from exc
            raise
        assert created_session is not None and log_path is not None and manifest_path is not None
        self.session_root = created_session
        self.session_directory_created_by_tool = session_directory_created_by_tool
        self.temp_root = created_session.parent / ".temp"
        self.log_path, self.manifest_path = log_path, manifest_path
        self._write_session_recovery_record()
        self.logger = SessionLogger(self.log_path)
        self._flush_pending_live_status_logs()
        mode_label = "Local Capture" if mode == "local" else "System Proxy"
        assert self.logger is not None
        self.console(f"Session: {self.session_root}")
        self.console(f"Mode: {mode_label}")
        if mode != "local":
            self.log(f"Local proxy: 127.0.0.1:{self.proxy_port}")
            self.log(f"Upstream proxy: {upstream or 'Direct'}")
        debug_value = self.options["debug"]
        self.console(f"Debug: {'Global' if debug_value == 'global' else 'On' if bool(debug_value) else 'Off'}")
        if debug_value == "global":
            self.console(
                "Global debug can log hostnames and IP addresses from unrelated local applications; "
                "review the session capture log before sharing it."
            )
        if free_space <= 1024 * 1024 * 1024:
            self.log(f"WARNING: Only {common.format_bytes(free_space)} of free space remains on the output drive.")
        if runtime.ensure_mitmproxy_ca_trusted():
            self.setup_messages.append("HTTPS certificate installed successfully.")

        if self.shutdown_requested.is_set() or self.cleaned_up:
            raise KeyboardInterrupt
        self._start_worker(upstream, upstream_auth)
        self._wait_for_worker_ready()

        if mode == "system-proxy":
            assert self.previous_proxy is not None and self.session_root is not None
            if self.shutdown_requested.is_set() or self.cleaned_up:
                raise KeyboardInterrupt
            self.applied_proxy = windows_proxy.activate_local_proxy(self.previous_proxy, self.session_root, self.proxy_port)

        if self.shutdown_requested.is_set() or self.cleaned_up:
            raise KeyboardInterrupt
        self.started = True
        if self.setup_messages:
            self.console("")
            for message in self.setup_messages:
                self.log(message)
        if mode == "local":
            processes = [str(item) for item in self.options["processes"]]
            if {item.casefold() for item in processes} == {"launcher.exe", "warframe.x64.exe"}:
                active_message = "Capture is active. Start the Warframe Launcher or Warframe to capture downloaded assets."
            elif len(processes) == 1:
                active_message = "Capture is active. Start the selected process to capture downloaded assets."
            else:
                active_message = "Capture is active. Start one of the selected processes to capture downloaded assets."
        else:
            active_message = "Capture is active. Start the Warframe Launcher or Warframe to capture downloaded assets."
        self.console(f"\n{active_message}\nPress Ctrl+C when finished or Ctrl+R to start a new session.\n")
        if not self.console_closing:
            self.capture_active_announced = True
            # Save the active transition only after the message was displayed.
            # Pre-active console close needs no last-second disk write: the
            # original recovery record already identifies a pending startup.
            self._write_session_recovery_record()

    def _session_has_restartable_activity(self) -> bool:
        if self.session_root is None or self.manifest_path is None:
            return False
        with self.worker_activity_lock:
            if self.worker_active_captures > 0:
                return True
        try:
            manifest = common.read_json_object(self.manifest_path)
            return int(manifest.get("captured_files", 0)) > 0 or common.session_has_payload(self.session_root)
        except (OSError, RuntimeError, TypeError, ValueError):
            return common.session_has_payload(self.session_root)

    def _prompt_write(self, text: str, *, newline: bool = False) -> None:
        logger = self.logger
        if logger is not None:
            logger.clear_progress()
            lock = logger.console_lock
        else:
            lock = threading.Lock()
        with lock:
            try:
                sys.stdout.write(text + ("\n" if newline else ""))
                sys.stdout.flush()
            except (OSError, ValueError):
                pass

    def _begin_restart_prompt(self) -> None:
        if self.restart_prompt_state is not None:
            return
        if self.pending_rotation is not None:
            self.log(f"[Session] A new capture session has already been requested: {self.pending_rotation['session_root']}")
            return
        if not self._session_has_restartable_activity():
            return
        self.restart_prompt_previous_suppression = self.suppress_console_output
        with self.worker_console_condition:
            while self.worker_console_rendering:
                self.worker_console_condition.wait(0.05)
            self.suppress_console_output = True
            self.restart_prompt_state = "confirm"
            self.restart_prompt_text = ""
            self.worker_console_condition.notify_all()
        self._prompt_write("Start a new capture session? [y/N] ")

    def _cancel_restart_prompt(self) -> None:
        if self.restart_prompt_state is None:
            return
        self._prompt_write("", newline=True)
        self._close_restart_prompt()

    def _restart_path_prompt_text(self) -> str:
        automatic = "Warframe version" if bool(self.options["name_session_after_warframe_version"]) else "timestamp"
        return f"New session directory (optional, Enter = automatic {automatic}): "

    def _show_restart_path_prompt(self) -> None:
        self.restart_prompt_state = "path"
        self.restart_prompt_text = ""
        self._prompt_write("\n" + self._restart_path_prompt_text())

    def _prepare_rotation_target(self, entered: str) -> dict[str, object]:
        if self.session_root is None:
            raise RuntimeError("The current capture session is not available.")
        current_parent = self.session_root.parent
        text = entered
        session_directory_created_by_tool = True
        if text:
            try:
                target = common.resolve_session_output_path(
                    text,
                    current_parent,
                    "New session directory",
                    reject_existing_reparse=True,
                )
            except ValueError as exc:
                raise RuntimeError(str(exc)) from None
            current_session = self.session_root.resolve()
            current_temp = self.temp_root.resolve() if self.temp_root is not None else (current_parent / ".temp").resolve()
            if target == current_session or target.is_relative_to(current_session):
                raise RuntimeError("New session directory cannot be inside the current capture session.")
            if target == current_temp or target.is_relative_to(current_temp):
                raise RuntimeError("New session directory cannot be inside the current capture temporary directory.")
            metadata_root = target.parent
            free_space = common.prepare_output_directory(metadata_root)
            if metadata_root != current_parent:
                common.clear_stale_capture_temp(metadata_root)
        else:
            metadata_root = current_parent
            free_space = common.prepare_output_directory(metadata_root)

        version_info, version_messages = self._current_warframe_version_snapshot()
        self._start_warframe_status_query(announce_current=False)
        if text:
            session_id = common.allocate_session_identifier(metadata_root)
            existed_before_claim = target.exists() or target.is_symlink()
            target = common.create_exact_session_directory(target)
            session_directory_created_by_tool = not existed_before_claim
            session_naming = "custom"
        else:
            target, session_id, session_naming = self._create_automatic_session_directory(
                metadata_root,
                version_info,
                version_messages,
            )

        log_path, manifest_path = common.session_artifact_paths(metadata_root, session_id)
        try:
            capture.initialize_session_manifest(
                target,
                self.options,
                manifest_path,
                status="pending_rotation",
                session_directory_created_by_tool=session_directory_created_by_tool,
                warframe_version_info=version_info,
                session_naming=session_naming,
            )
        except BaseException as exc:
            rollback_errors = _rollback_session_creation(
                target,
                manifest_path,
                log_path,
                session_directory_created_by_tool=session_directory_created_by_tool,
            )
            if rollback_errors:
                raise RuntimeError(
                    f"Could not fully roll back new session creation after preparation failed ({exc}): "
                    + "; ".join(rollback_errors)
                ) from exc
            raise
        return {
            "token": hashlib.sha256(f"{time.time_ns()}:{target}".encode("utf-8")).hexdigest()[:24],
            "session_root": target,
            "session_directory_created_by_tool": session_directory_created_by_tool,
            "manifest_path": manifest_path,
            "log_path": log_path,
            "temp_root": metadata_root / ".temp",
            "old_session_root": self.session_root,
            "old_manifest_path": self.manifest_path,
            "old_log_path": self.log_path,
            "old_temp_root": self.temp_root,
            "old_logger": self.logger,
            "free_space": free_space,
            "warframe_version_messages": version_messages,
        }

    def _send_rotation_request(self, pending: dict[str, object]) -> None:
        process = self.process
        if process is None or process.stdin is None or process.poll() is not None:
            raise RuntimeError("Capture worker is not running.")
        process.stdin.write(
            common.encode_worker_message(
                "rotate",
                token=str(pending["token"]),
                session=str(pending["session_root"]),
                manifest=str(pending["manifest_path"]),
            )
            + "\n"
        )
        process.stdin.flush()

    def _discard_rotation_target(
        self,
        pending: dict[str, object],
        *,
        worker_stopped: bool = False,
        allow_pending_delete: bool = True,
    ) -> bool:
        session_root = Path(pending["session_root"])
        manifest_path = Path(pending["manifest_path"])
        old_temp = pending.get("old_temp_root")
        new_temp = Path(pending["temp_root"])
        manifest = common.load_capture_session_manifest(manifest_path)
        empty_pending = (
            manifest is not None
            and str(manifest.get("capture_directory", "")).casefold() == session_root.name.casefold()
            and manifest.get("status") == "pending_rotation"
            and int(manifest.get("captured_files", 0)) == 0
            and common.session_warning_count(manifest) == 0
            and not common.session_has_payload(session_root)
        )
        if not worker_stopped and not (allow_pending_delete and empty_pending):
            return False

        marked, warnings, removed = common.recover_stale_session_exact(session_root, manifest_path)
        for warning in warnings:
            self.log(f"WARNING: {warning}")

        post_manifest = common.load_capture_session_manifest(manifest_path)
        settled = removed or marked > 0 or (
            post_manifest is not None
            and post_manifest.get("status") not in {"pending_rotation", "starting", "running"}
        ) or (not session_root.exists() and not manifest_path.exists())
        if not settled:
            return False

        if old_temp is None or Path(old_temp) != new_temp:
            try:
                common.remove_capture_temp_root(new_temp)
            except Exception as exc:
                self.log(f"WARNING: Could not remove temporary data for the unused session target: {exc}")
                return False
        return True

    def _request_session_rotation(self, entered: str) -> None:
        pending = self._prepare_rotation_target(entered)
        with self.rotation_lock:
            if self.pending_rotation is not None:
                self._discard_rotation_target(pending)
                raise RuntimeError("A new capture session has already been requested.")
            self.pending_rotation = pending
        try:
            self._write_session_recovery_record()
            self._send_rotation_request(pending)
        except BaseException:
            with self.rotation_lock:
                if self.pending_rotation is pending:
                    self.pending_rotation = None
            process = self.process
            worker_stopped = process is None or process.poll() is not None
            settled = self._discard_rotation_target(
                pending,
                worker_stopped=worker_stopped,
                allow_pending_delete=worker_stopped,
            )
            if not settled:
                self.deferred_rotation_cleanup.append(pending)
            try:
                self._write_session_recovery_record()
            except OSError:
                pass
            raise

    @staticmethod
    def _session_duration(manifest: dict[str, object]) -> str | None:
        started_at = manifest.get("started_at")
        finished_at = manifest.get("finished_at")
        if not isinstance(started_at, str) or not isinstance(finished_at, str):
            return None
        try:
            seconds = (datetime.fromisoformat(finished_at) - datetime.fromisoformat(started_at)).total_seconds()
        except ValueError:
            return None
        return common.format_duration(seconds)

    @classmethod
    def _rotated_session_summary(cls, manifest: dict[str, object], session_root: Path) -> str:
        duration = cls._session_duration(manifest)
        duration_line = f"Duration: {duration}\n" if duration is not None else ""
        return (
            f"Files: {int(manifest.get('captured_files', 0))}\n"
            f"{duration_line}"
            f"Size: {common.format_bytes(int(manifest.get('captured_bytes', 0)))}\n"
            f"Duplicates: {int(manifest.get('duplicates', 0))}\n"
            f"Conflicts: {int(manifest.get('conflict_count', 0))}\n"
            f"Filtered root responses: {int(manifest.get('filtered_root_paths', 0))}\n"
            f"Partial responses skipped: {int(manifest.get('skipped_partial', 0))}\n"
            f"Other HTTP responses skipped: {int(manifest.get('skipped_http', 0))}\n"
            f"Incomplete responses: {int(manifest.get('incomplete_responses', 0))}\n"
            f"Capture errors: {int(manifest.get('capture_errors', 0))}\n"
            f"Extraction errors: {int(manifest.get('extraction_errors', 0))}\n"
            f"Cleanup errors: {int(manifest.get('cleanup_errors', 0))}\n"
            f"Output: {session_root}"
        )

    def _complete_session_rotation(self, token: str) -> None:
        with self.rotation_lock:
            pending = self.pending_rotation
            if pending is None or str(pending.get("token")) != token:
                return

        old_session = Path(pending["old_session_root"])
        old_manifest = Path(pending["old_manifest_path"])
        old_logger = pending.get("old_logger")
        old_temp_value = pending.get("old_temp_root")
        old_temp = Path(old_temp_value) if old_temp_value is not None else None
        new_session = Path(pending["session_root"])
        new_manifest = Path(pending["manifest_path"])
        new_log = Path(pending["log_path"])
        new_temp = Path(pending["temp_root"])

        # The worker has already switched by the time it sends "rotated". Open the
        # new parent-side logger before clearing pending_rotation so any handoff
        # failure remains recoverable and is propagated through the reader thread.
        new_logger = SessionLogger(new_log)

        recovery_needed = False
        cleanup_warning: str | None = None
        if old_temp is not None and old_temp != new_temp:
            try:
                common.remove_capture_temp_root(old_temp)
            except Exception as exc:
                recovery_needed = True
                cleanup_warning = str(exc)
                try:
                    manifest = common.read_json_object(old_manifest)
                    manifest["cleanup_errors"] = int(manifest.get("cleanup_errors", 0)) + 1
                    common.atomic_write_json(old_manifest, manifest)
                except Exception:
                    pass

        try:
            manifest = common.read_json_object(old_manifest)
            status = "completed_with_warnings" if common.session_warning_count(manifest) else "completed"
            manifest = capture.finalize_session_manifest(
                old_session,
                status,
                old_manifest,
                end_reason="session_rotation",
            )
            if isinstance(old_logger, SessionLogger):
                if cleanup_warning:
                    old_logger.write(f"WARNING: Could not remove temporary capture data: {cleanup_warning}", console=False)
                old_logger.write(self._rotated_session_summary(manifest, old_session), console=False)
        except Exception as exc:
            recovery_needed = True
            if isinstance(old_logger, SessionLogger):
                old_logger.write(f"WARNING: Could not finalize the previous session after rotation: {exc}", console=False)

        with self.rotation_lock:
            if self.pending_rotation is not pending:
                new_logger.close()
                return
            self.session_root = new_session
            self.session_directory_created_by_tool = bool(
                pending.get("session_directory_created_by_tool", True)
            )
            self.manifest_path = new_manifest
            self.log_path = new_log
            self.temp_root = new_temp
            self.logger = new_logger
            self.pending_rotation = None
            if recovery_needed:
                self._append_unique_recovery_entry(
                    self.unresolved_session_recovery,
                    self._session_recovery_entry(old_session, old_manifest),
                )

        if isinstance(old_logger, SessionLogger):
            old_logger.close()
        try:
            self._write_session_recovery_record()
        except OSError as exc:
            self.log(f"WARNING: Could not update session recovery data after starting the new session: {exc}")
        self.log(f"[Session] Started new capture session: {new_session}")

    def _fail_session_rotation(self, token: str, error: str) -> None:
        with self.rotation_lock:
            pending = self.pending_rotation
            if pending is None or str(pending.get("token")) != token:
                return
            self.pending_rotation = None
        settled = self._discard_rotation_target(pending)
        if not settled:
            self.deferred_rotation_cleanup.append(pending)
        try:
            self._write_session_recovery_record()
        except OSError as exc:
            self.log(f"WARNING: Could not update session recovery data after the failed rotation: {exc}")
        self.log(f"ERROR: Could not start a new capture session: {error}")

    def _finish_restart_path_entry(self) -> None:
        entered = self.restart_prompt_text
        try:
            self._request_session_rotation(entered)
        except Exception as exc:
            error = common.style_console_text(f"ERROR: {exc}", sys.stdout)
            self._prompt_write(f"\n{error}\n{self._restart_path_prompt_text()}")
            self.restart_prompt_text = ""
            return
        self._prompt_write("", newline=True)
        self._close_restart_prompt()
        pending = self.pending_rotation
        if pending is not None:
            messages = pending.get("warframe_version_messages")
            if isinstance(messages, list):
                self._emit_live_status_messages(messages)
            self.log(f"[Session] New capture session requested: {pending['session_root']}")
            with self.worker_activity_lock:
                active_captures = self.worker_active_captures
            if active_captures > 0:
                self.log(
                    f"[Session] Waiting for {active_captures} active capture"
                    f"{'s' if active_captures != 1 else ''} to finish before starting the new session."
                )
            free_space_value = pending.get("free_space")
            if isinstance(free_space_value, int) and free_space_value <= 1024 * 1024 * 1024:
                self.log(f"WARNING: Only {common.format_bytes(free_space_value)} of free space remains on the new session's output drive.")

    def _poll_restart_hotkey(self, *, defer_restart: bool = False) -> None:
        if not defer_restart and self.restart_prompt_deferred and self.restart_prompt_state is None:
            self.restart_prompt_deferred = False
            self._begin_restart_prompt()

        if sys.platform != "win32":
            return
        try:
            if not sys.stdin.isatty():
                return
            import msvcrt
        except (AttributeError, ImportError, OSError, ValueError):
            return

        while msvcrt.kbhit():
            character = msvcrt.getwch()
            if character in {"\x00", "\xe0"}:
                msvcrt.getwch()
                continue
            state = self.restart_prompt_state
            if state is not None and character == "\x03":
                self._cancel_restart_prompt()
                raise KeyboardInterrupt
            if state is None:
                if character == "\x12":  # Ctrl+R
                    if defer_restart:
                        if not self.restart_prompt_deferred and self._session_has_restartable_activity():
                            self.restart_prompt_deferred = True
                            self.log("[Session] New session request queued until restart completes.")
                    else:
                        self._begin_restart_prompt()
                continue
            if state == "confirm":
                if character in {"y", "Y"}:
                    self._show_restart_path_prompt()
                elif character in {"n", "N", "\r", "\n", "\x1b"}:
                    self._cancel_restart_prompt()
                continue
            if state != "path":
                continue
            if character in {"\r", "\n"}:
                self._finish_restart_path_entry()
            elif character == "\x1b":
                self._cancel_restart_prompt()
            elif character == "\b":
                if self.restart_prompt_text:
                    self.restart_prompt_text = self.restart_prompt_text[:-1]
                    self._prompt_write("\b \b")
            elif character.isprintable():
                self.restart_prompt_text += character
                self._prompt_write(character)

    def wait(self) -> None:
        if not self.config_reload_enabled and not (
            str(self.options["capture_mode"]) == "local" and bool(self.options["stop_on_exit"])
        ):
            while True:
                self._raise_reader_failure()
                self._poll_restart_hotkey()
                self._poll_live_status()
                if self.shutdown_requested.wait(0.1):
                    self._raise_reader_failure()
                    if self.end_reason is None:
                        self.end_reason = "shutdown_requested"
                    return
                process = self.process
                if process is None:
                    raise RuntimeError("Capture worker is not running.")
                return_code = process.poll()
                if return_code is None:
                    continue
                if return_code != 0 and not self.console_closing:
                    self.failed = True
                    raise RuntimeError(f"Capture worker stopped unexpectedly with exit code {return_code}.")
                if self.end_reason is None:
                    self.end_reason = "worker_exit"
                return

        seen_selected_process = False
        absent_since: float | None = None
        monitored_processes: tuple[str, ...] | None = None
        while True:
            self._raise_reader_failure()
            self._poll_restart_hotkey()
            self._poll_live_status()
            if self.shutdown_requested.is_set():
                self._raise_reader_failure()
                if self.end_reason is None:
                    self.end_reason = "shutdown_requested"
                return
            process = self.process
            if process is None:
                raise RuntimeError("Capture worker is not running.")
            return_code = process.poll()
            if return_code is not None:
                if return_code != 0 and not self.console_closing:
                    self.failed = True
                    raise RuntimeError(f"Capture worker stopped unexpectedly with exit code {return_code}.")
                if self.end_reason is None:
                    self.end_reason = "worker_exit"
                return

            if self.restart_prompt_state is None and self.pending_rotation is None and self._poll_config_reload():
                return
            if str(self.options["capture_mode"]) == "local" and bool(self.options["stop_on_exit"]):
                selected_names = tuple(str(name) for name in self.options["processes"])
                if selected_names != monitored_processes:
                    monitored_processes = selected_names
                    seen_selected_process = False
                    absent_since = None
                selected = {name.casefold() for name in selected_names}
                if selected.intersection(runtime.running_process_names()):
                    seen_selected_process = True
                    absent_since = None
                elif seen_selected_process:
                    moment = time.monotonic()
                    if absent_since is None:
                        absent_since = moment
                    else:
                        delay = int(self.options["stop_on_exit_delay"])
                        if moment - absent_since >= delay:
                            subject = "Selected process" if len(selected) == 1 else "Selected processes"
                            self.log(
                                f"[Stopping] {subject} remained absent for {delay} "
                                f"second{'s' if delay != 1 else ''}."
                            )
                            self.end_reason = "stop_on_exit"
                            return
            else:
                monitored_processes = None
                seen_selected_process = False
                absent_since = None
            if self.shutdown_requested.wait(0.25):
                return

    def _request_worker_shutdown(self, timeout: float) -> bool:
        process = self.process
        if process is None or process.poll() is not None:
            return True
        stdin = process.stdin
        if stdin is None:
            return False
        try:
            stdin.write(common.encode_worker_message("shutdown") + "\n")
            stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            return False
        try:
            process.wait(timeout=timeout)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return process.poll() is not None

    def _stop_worker(self, fast: bool = False) -> bool:
        process = self.process
        if process is None:
            runtime.close_worker_job(self.worker_job)
            self.worker_job = None
            return True

        if process.poll() is not None:
            runtime.close_worker_job(self.worker_job)
            self.worker_job = None
            return True

        # Ask the worker to release mitmproxy resources cleanly first. Local
        # Capture stages its native redirector/WinDivert runtime outside the
        # portable release so a still-loaded kernel driver cannot lock the release
        # directory. Console-window close has a tight Windows deadline, so its
        # grace period is short and quickly escalates to process-tree termination.
        # Mark this exact worker as retiring before requesting shutdown so the pipe
        # reader can distinguish mitmproxy's harmless late Local Capture teardown
        # race from the same error emitted by a live/replacement worker.
        with self.worker_retirement_lock:
            self.retiring_worker_ids.add(id(process))
        if self._request_worker_shutdown(0.2 if fast else 3.0):
            runtime.close_worker_job(self.worker_job)
            self.worker_job = None
            return True

        if self.worker_job is not None:
            # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE is the primary hard-stop path and
            # also covers descendants owned by the proxy worker.
            runtime.close_worker_job(self.worker_job)
            self.worker_job = None
            try:
                process.wait(timeout=0.2 if fast else 1.5)
                return True
            except (OSError, subprocess.TimeoutExpired):
                pass

        if sys.platform == "win32":
            runtime.terminate_process_tree(process, timeout=0.3 if fast else 2.0)
        else:
            try:
                process.terminate()
            except OSError:
                pass

        try:
            process.wait(timeout=0.2 if fast else 1.0)
            return True
        except (OSError, subprocess.TimeoutExpired):
            pass

        # Final direct TerminateProcess fallback. Give Windows enough time to
        # report the exit even when the storage/system is heavily stalled.
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=0.25 if fast else 1.5)
            return True
        except (OSError, subprocess.TimeoutExpired):
            return process.poll() is not None

    def _finalize_session_metadata(self) -> dict[str, object] | None:
        if self.session_root is None:
            return {}
        try:
            if self.manifest_path is None:
                raise RuntimeError("Session metadata path is unavailable.")
            manifest = common.read_json_object(self.manifest_path)
            if self.failed:
                status = "failed"
            elif not self.started:
                status = "aborted"
            elif common.session_warning_count(manifest):
                status = "completed_with_warnings"
            else:
                status = "completed"
            if status == "failed":
                end_reason = "failure"
            elif self.end_reason is not None:
                end_reason = self.end_reason
            elif status == "aborted":
                end_reason = "startup_aborted"
            else:
                end_reason = "shutdown"
            return capture.finalize_session_manifest(
                self.session_root,
                status,
                self.manifest_path,
                self.failure_reason,
                end_reason=end_reason,
            )
        except Exception as exc:
            self.log(f"WARNING: Could not finalize session metadata: {exc}")
            return None

    def _finish_manifest_and_summary(
        self,
        manifest: dict[str, object] | None = None,
        *,
        check_payload: bool = True,
    ) -> tuple[bool, bool]:
        if self.session_root is None:
            return False, True
        if manifest is None:
            manifest = self._finalize_session_metadata()
        if manifest is None:
            return False, False

        status = str(manifest.get("status", ""))
        if status == "completed_with_warnings":
            self.log("WARNING: Capture completed with warnings.")
        elif status == "failed":
            self.log("[Failed] Capture ended.")
            if self.failure_reason:
                self.log(f"ERROR: {self.failure_reason}", console=False)
        elif status == "aborted":
            self.log("[Aborted] Capture did not finish starting.")

        captured_files = int(manifest.get("captured_files", 0))
        has_payload = captured_files > 0 or not check_payload or common.session_has_payload(self.session_root)
        duration = self._session_duration(manifest)
        duration_line = f"Duration: {duration}\n" if duration is not None else ""
        summary = (
            f"Files: {captured_files}\n"
            f"{duration_line}"
            f"Size: {common.format_bytes(int(manifest.get('captured_bytes', 0)))}\n"
            f"Duplicates: {int(manifest.get('duplicates', 0))}\n"
            f"Conflicts: {int(manifest.get('conflict_count', 0))}\n"
            f"Filtered root responses: {int(manifest.get('filtered_root_paths', 0))}\n"
            f"Partial responses skipped: {int(manifest.get('skipped_partial', 0))}\n"
            f"Other HTTP responses skipped: {int(manifest.get('skipped_http', 0))}\n"
            f"Incomplete responses: {int(manifest.get('incomplete_responses', 0))}\n"
            f"Capture errors: {int(manifest.get('capture_errors', 0))}\n"
            f"Extraction errors: {int(manifest.get('extraction_errors', 0))}\n"
            f"H.Cache.bin validation errors: {int(manifest.get('h_cache_validation_errors', 0))}\n"
            f"Recovered files: {int(manifest.get('recovered_files', 0))}\n"
            f"Cleanup errors: {int(manifest.get('cleanup_errors', 0))}"
        )
        show_summary = not runtime.console_was_created_by_nct()
        if captured_files == 0 and not has_payload:
            self.log(summary, console=show_summary)
            return status in {"completed", "aborted"} and common.session_warning_count(manifest) == 0, True
        self.log(f"{summary}\nOutput: {self.session_root}", console=show_summary)
        return False, True

    def request_console_shutdown(self, reason: str = "console_close") -> None:
        self.console_closing = True
        self.suppress_console_output = True
        if self.end_reason is None:
            self.end_reason = reason
        self.shutdown_requested.set()

    def cleanup(self) -> None:
        closing = self.console_closing
        try:
            if self.cleaned_up:
                return
            self.shutdown_requested.set()
            self._stop_warframe_status_query()
            self._stop_steam_status_query()
            current_recovery_needed = False

            if self.applied_proxy is not None and self.previous_proxy is not None:
                try:
                    result = windows_proxy.deactivate_local_proxy(self.previous_proxy, self.applied_proxy)
                    if result:
                        self.log("[Restored] Previous Windows proxy settings restored.")
                        if result.recovery_cleanup_error is not None:
                            self.log(
                                "WARNING: Windows proxy settings were restored successfully, but the proxy recovery record could not be removed: "
                                f"{result.recovery_cleanup_error}"
                            )
                            self.log(f"[Recovery] Recovery data was kept at: {common.proxy_recovery_file()}")
                    else:
                        self.log(
                            "WARNING: Windows proxy settings changed after Ninja Capture Tool started, so Ninja Capture Tool did not overwrite the newer settings."
                        )
                        self.log(f"[Recovery] Ownership record kept at: {common.proxy_recovery_file()}")
                    # Either the previous settings were restored or Ninja Capture Tool deliberately
                    # left newer user settings untouched. In both cases there is no
                    # proxy action to repeat on a later cleanup attempt.
                    self.applied_proxy = None
                    self.previous_proxy = None
                except Exception as exc:
                    self.log(f"ERROR: Could not restore previous Windows proxy settings: {exc}")
                    self.log(f"[Recovery] Recovery data was kept at: {common.proxy_recovery_file()}")

            worker_stopped = self._stop_worker(fast=closing)
            worker_finalized = worker_stopped and self._finalize_worker_state(timeout=0.25 if closing else 1.5)
            if not worker_finalized:
                # Do not finalize metadata, remove temporary capture data, close
                # worker pipes, or discard rotation state while the worker may still
                # be alive. Leave cleanup incomplete so the normal finally/atexit
                # path can retry it before the frozen process exits. If Windows ends
                # the process before that retry succeeds, the recovery record lets
                # the next launch handle the still-running session as interrupted.
                try:
                    self._write_session_recovery_record(include_current=True)
                except OSError as exc:
                    self.log(f"WARNING: Could not update session recovery data for the next launch: {exc}")
                self.log(
                    "WARNING: Capture worker is still shutting down; cleanup will be retried before exit."
                )
                return

            # Commit the current session before any potentially slow filesystem
            # cleanup. Windows gives console-close handlers only a short lifetime;
            # finalizing here prevents a completed capture from being recovered as
            # interrupted if the drive is busy while later cleanup is still pending.
            finalized_manifest = self._finalize_session_metadata() if self.session_root is not None else {}
            if finalized_manifest is None:
                current_recovery_needed = True

            with self.rotation_lock:
                pending_rotation = self.pending_rotation
                self.pending_rotation = None
                deferred_rotation_cleanup = self.deferred_rotation_cleanup
                self.deferred_rotation_cleanup = []
            rotation_targets = list(deferred_rotation_cleanup)
            if pending_rotation is not None and all(item is not pending_rotation for item in rotation_targets):
                rotation_targets.append(pending_rotation)
            for target in rotation_targets:
                if closing:
                    self._remember_unresolved_session(
                        Path(target["session_root"]),
                        Path(target["manifest_path"]),
                    )
                elif not self._discard_rotation_target(target, worker_stopped=True):
                    self._remember_unresolved_session(
                        Path(target["session_root"]),
                        Path(target["manifest_path"]),
                    )

            clean_empty_on_close = False
            if closing and self.session_root is not None and finalized_manifest is not None:
                status = str(finalized_manifest.get("status", ""))
                clean_empty_on_close = (
                    status in {"completed", "aborted"}
                    and int(finalized_manifest.get("captured_files", 0)) == 0
                    and common.session_warning_count(finalized_manifest) == 0
                    and not common.session_has_payload(self.session_root)
                )

            # Once the capture worker is confirmed stopped, the temporary workspace
            # is no longer needed. Remove it on every normal shutdown, including an X
            # / console-window close, instead of deliberately leaving it for recovery
            # on the next launch.
            if self.session_root is not None and self.temp_root is not None:
                try:
                    common.remove_capture_temp_root(self.temp_root)
                except Exception as exc:
                    self.log(f"WARNING: Could not remove temporary capture data: {exc}")
                    if finalized_manifest is not None and self.manifest_path is not None:
                        try:
                            finalized_manifest["cleanup_errors"] = int(finalized_manifest.get("cleanup_errors", 0)) + 1
                            if finalized_manifest.get("status") == "completed":
                                finalized_manifest["status"] = "completed_with_warnings"
                            common.atomic_write_json(self.manifest_path, finalized_manifest)
                        except Exception as metadata_exc:
                            current_recovery_needed = True
                            self.log(
                                f"WARNING: Could not record the cleanup failure in session metadata: {metadata_exc}"
                            )

            remove_session = False
            if self.session_root is not None and finalized_manifest is not None:
                remove_session, finalized = self._finish_manifest_and_summary(
                    finalized_manifest, check_payload=not closing or clean_empty_on_close
                )
                if not finalized:
                    current_recovery_needed = True

            # Captured session payload is retained by design. A clean empty session
            # can still be removed immediately once the worker has stopped.
            if (not closing or clean_empty_on_close) and remove_session and self.session_root is not None:
                if self.logger is not None:
                    self.logger.close()
                    self.logger = None
                try:
                    common.remove_empty_capture_session_directory(
                        self.session_root,
                        remove_root=self.session_directory_created_by_tool,
                    )
                except OSError as exc:
                    current_recovery_needed = True
                    self.log(f"WARNING: Could not clean up the empty completed capture session: {exc}")
                else:
                    log_removed = True
                    if self.log_path is not None:
                        try:
                            self.log_path.unlink(missing_ok=True)
                        except OSError as exc:
                            log_removed = False
                            current_recovery_needed = True
                            self.log(f"WARNING: Could not remove the empty completed capture log: {exc}")
                    if log_removed and self.manifest_path is not None:
                        try:
                            self.manifest_path.unlink(missing_ok=True)
                        except OSError as exc:
                            current_recovery_needed = True
                            self.log(f"WARNING: Could not remove the empty completed session metadata: {exc}")

            try:
                self._write_session_recovery_record(include_current=current_recovery_needed)
            except OSError as exc:
                self.log(f"WARNING: Could not update session recovery data for the next launch: {exc}")
            else:
                with self.rotation_lock:
                    unresolved_count = len(self.unresolved_session_recovery)
                if current_recovery_needed or unresolved_count:
                    self.log(f"[Recovery] Session recovery data was kept for the next launch: {_session_recovery_path()}")

            self._stop_worker_console_dispatcher(timeout=0.25 if closing else 0.5)
            if self.logger is not None:
                self.logger.close()
            self.cleaned_up = True
        finally:
            # A console-close handler waits on this event before allowing Windows
            # to terminate the process. Only signal it after cleanup really
            # completed. An incomplete fast worker shutdown deliberately leaves
            # cleaned_up false so the normal finally/atexit path can retry while
            # the close handler keeps the process alive.
            if self.cleaned_up:
                self.shutdown_complete.set()
