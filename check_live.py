#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import time
from typing import NamedTuple

import common
import runtime
from check_steam import (
    collect_steam_query_subprocess,
    collect_warframe_query_subprocess,
    latest_steam_query_worker_stage,
    load_live_tracking_state,
    load_warframe_version_high_water,
    normalize_live_query_error,
    save_steam_tracking_state,
    save_warframe_version_high_water,
    start_steam_query_subprocess,
    start_warframe_query_subprocess,
    steam_manifest_with_cache_fallback,
    summarize_steam_live_query_error,
    summarize_warframe_live_query_error,
    terminate_steam_query_subprocess,
    terminate_warframe_query_subprocess,
)

_LIVE_QUERY_REQUEST_TIMEOUT_SECONDS = 30.0
_WARFRAME_STATUS_QUERY_DEADLINE_SECONDS = 35.0
_STEAM_STATUS_QUERY_DEADLINE_SECONDS = 35.0

class SteamManifestObservation(NamedTuple):
    manifest_id: int
    status: str
    size: int | None
    source_kind: str

class LiveTrackingMixin:
    @staticmethod
    def _content_branch(version: str) -> tuple[int, int]:
        parts = tuple(int(part) for part in version.split("."))
        return parts[0], parts[1]

    def _live_debug_enabled(self) -> bool:
        return bool(self.options.get("debug"))

    def _record_live_debug(self, message: str) -> None:
        if self._live_debug_enabled():
            self._record_live_status_log(f"[Debug] {message}")

    @staticmethod
    def _warframe_live_failure_detail(error: str) -> str:
        error = normalize_live_query_error(error)
        summary = summarize_warframe_live_query_error(error)
        return f"{summary} ({error})" if summary != error else error

    def _load_warframe_version_state(
        self,
        messages: list[tuple[str, str]],
    ) -> tuple[str | None, str | None]:
        saved_version: str | None = None
        try:
            saved_version = load_warframe_version_high_water()
        except Exception as exc:
            messages.append(("warning", f"[Warframe] Could not read the saved version state: {exc}"))

        previous = saved_version
        if self.warframe_version_high_water is not None:
            if previous is None or common.compare_versions(self.warframe_version_high_water, previous) > 0:
                previous = self.warframe_version_high_water
        if previous is not None and (
            self.warframe_version_high_water is None
            or common.compare_versions(previous, self.warframe_version_high_water) > 0
        ):
            self.warframe_version_high_water = previous
        return saved_version, previous

    def _current_warframe_version_snapshot(self) -> tuple[dict[str, object], list[tuple[str, str]]]:
        messages: list[tuple[str, str]] = []
        _, previous = self._load_warframe_version_state(messages)
        if self.live_warframe_version is not None and self.live_warframe_error is None:
            version = self.live_warframe_version
            status = "current"
        elif previous is not None:
            version = previous
            status = "cached"
        else:
            version = None
            status = "unavailable"
        return {
            "version": version,
            "checked_at": None,
            "status": status,
            "previous_version": previous,
            "content_update": False,
        }, messages

    def _apply_current_warframe_version_result(
        self,
        version: str | None,
        error: str | None,
        *,
        announce_current: bool,
        checked_at: str | None = None,
    ) -> tuple[dict[str, object], list[tuple[str, str]]]:
        checked_at = checked_at or common.current_timestamp()
        messages: list[tuple[str, str]] = []
        saved_version, previous = self._load_warframe_version_state(messages)

        if version is None:
            error = normalize_live_query_error(error, "unknown Warframe version query failure")
            changed = error != self.live_warframe_error
            self.live_warframe_error = error
            if announce_current or changed:
                messages.append(("info", self._current_warframe_status_line()))
            return {
                "version": None,
                "checked_at": checked_at,
                "status": "unavailable",
                "previous_version": previous,
                "content_update": False,
            }, messages

        last_live = self.live_warframe_version
        self.live_warframe_version = version
        self.live_warframe_error = None
        if announce_current or last_live != version:
            messages.append(("info", f"[Warframe] Live version: U{version}"))

        status = "current"
        content_update = False
        if previous is not None:
            comparison = common.compare_versions(version, previous)
            if comparison > 0:
                status = "newer"
                content_update = self._content_branch(version) != self._content_branch(previous)
            elif comparison < 0:
                status = "backwards"
                messages.append(("warning", f"Reported Warframe version changed backwards: U{previous} -> U{version}"))
        persist_version = status != "backwards" and (
            saved_version is None or common.compare_versions(version, saved_version) > 0
        )
        if status != "backwards" and (
            self.warframe_version_high_water is None
            or common.compare_versions(version, self.warframe_version_high_water) > 0
        ):
            self.warframe_version_high_water = version
        if persist_version:
            if content_update:
                self._persist_pending_content_update(version, messages, checked_at=checked_at)
            else:
                try:
                    save_warframe_version_high_water(version, checked_at=checked_at)
                except Exception as exc:
                    messages.append(("warning", f"Could not save the current Warframe version state: {exc}"))
        return {
            "version": version,
            "checked_at": checked_at,
            "status": status,
            "previous_version": previous,
            "content_update": content_update,
        }, messages

    def _start_warframe_status_query(self, *, announce_current: bool) -> None:
        with self.warframe_status_lock:
            self.warframe_status_pending_announce = self.warframe_status_pending_announce or announce_current
            process = self.warframe_status_process
            if process is not None:
                return
            self.warframe_status_started_at = time.monotonic()
            self.warframe_status_checked_at = common.current_timestamp()
            try:
                self.warframe_status_process = start_warframe_query_subprocess(
                    timeout=_LIVE_QUERY_REQUEST_TIMEOUT_SECONDS,
                    entry_script=common.TOOL_DIR / "ninja_capture_tool.py",
                )
            except Exception as exc:
                started_at = self.warframe_status_started_at
                checked_at = self.warframe_status_checked_at
                announce = self.warframe_status_pending_announce
                self.warframe_status_started_at = None
                self.warframe_status_checked_at = None
                self.warframe_status_pending_announce = False
                elapsed = time.monotonic() - started_at if started_at is not None else 0.0
                error = f"worker startup: {exc}"
                self._record_live_debug(
                    f"[Warframe] Live check failed after {elapsed:.2f}s: {self._warframe_live_failure_detail(error)}"
                )
                _, messages = self._apply_current_warframe_version_result(
                    None,
                    error,
                    announce_current=announce,
                    checked_at=checked_at,
                )
                self._refresh_warframe_status_header()
                if messages:
                    self._emit_live_status_messages(messages)

    def _consume_warframe_status_result(self) -> None:
        with self.warframe_status_lock:
            process = self.warframe_status_process
            started_at = self.warframe_status_started_at
            checked_at = self.warframe_status_checked_at
            if process is None:
                return
            timed_out = (
                process.poll() is None
                and started_at is not None
                and time.monotonic() - started_at >= _WARFRAME_STATUS_QUERY_DEADLINE_SECONDS
            )
            if process.poll() is None and not timed_out:
                return
            self.warframe_status_process = None
            self.warframe_status_started_at = None
            self.warframe_status_checked_at = None
            announce_current = self.warframe_status_pending_announce
            self.warframe_status_pending_announce = False

        elapsed = time.monotonic() - started_at if started_at is not None else 0.0
        if timed_out:
            terminate_warframe_query_subprocess(process)
            version = None
            error = f"Warframe live query timed out after {_WARFRAME_STATUS_QUERY_DEADLINE_SECONDS:g} seconds"
        else:
            try:
                version, error = collect_warframe_query_subprocess(process)
            except Exception as exc:
                version, error = None, str(exc)

        if version is None:
            error = error or "unknown Warframe version query failure"
            self._record_live_debug(
                f"[Warframe] Live check failed after {elapsed:.2f}s: {self._warframe_live_failure_detail(error)}"
            )
        else:
            self._record_live_debug(f"[Warframe] Live check succeeded in {elapsed:.2f}s: U{version}")
        version_info, messages = self._apply_current_warframe_version_result(
            version,
            error,
            announce_current=announce_current,
            checked_at=checked_at,
        )
        if bool(version_info.get("content_update")):
            with self.steam_status_lock:
                steam_query_active = self.steam_status_process is not None
                if steam_query_active:
                    self.steam_status_pending_content_update = True
            if not steam_query_active:
                self._start_steam_status_query(announce_current=False, content_update=True)
        self._refresh_warframe_status_header()
        if messages:
            self._emit_live_status_messages(messages)

    def _stop_warframe_status_query(self) -> None:
        with self.warframe_status_lock:
            process = self.warframe_status_process
            self.warframe_status_process = None
            self.warframe_status_started_at = None
            self.warframe_status_checked_at = None
            self.warframe_status_pending_announce = False
        if process is not None:
            terminate_warframe_query_subprocess(process, timeout=0.0 if self.console_closing else 1.0)

    def _load_persisted_steam_tracking_state(self, messages: list[tuple[str, str]]) -> None:
        if self.steam_tracking_state_loaded:
            return
        self.steam_tracking_state_loaded = True
        try:
            state = load_live_tracking_state()
        except Exception as exc:
            messages.append(("warning", f"[Steam] Could not read the saved manifest tracking state: {exc}"))
            return
        manifest_id = state.get("last_valid_steam_manifest_id")
        manifest_size = state.get("last_valid_steam_manifest_size")
        branch = state.get("awaiting_content_branch")
        awaiting_from = state.get("awaiting_from_manifest_id")
        candidate_id = state.get("pre_transition_manifest_id")
        candidate_size = state.get("pre_transition_manifest_size")
        candidate_branch = state.get("pre_transition_content_branch")
        self.last_valid_steam_manifest_id = manifest_id if isinstance(manifest_id, int) else None
        self.last_valid_steam_manifest_size = manifest_size if isinstance(manifest_size, int) else None
        self.awaiting_content_branch = branch if isinstance(branch, str) else None
        self.awaiting_from_manifest_id = awaiting_from if isinstance(awaiting_from, int) else None
        self.pre_transition_manifest_id = candidate_id if isinstance(candidate_id, int) else None
        self.pre_transition_manifest_size = candidate_size if isinstance(candidate_size, int) else None
        self.pre_transition_content_branch = candidate_branch if isinstance(candidate_branch, str) else None

    def _persist_pending_content_update(
        self,
        version: str,
        messages: list[tuple[str, str]],
        *,
        checked_at: str,
    ) -> None:
        self._load_persisted_steam_tracking_state(messages)
        branch = self._content_branch_label(version)
        if branch is None:
            return

        previous_awaiting_branch = self.awaiting_content_branch
        if (
            self.pre_transition_manifest_id is not None
            and self.pre_transition_content_branch is not None
            and self.pre_transition_content_branch != branch
        ):
            baseline_id = self.pre_transition_manifest_id
        elif previous_awaiting_branch != branch or self.awaiting_from_manifest_id is None:
            baseline_id = self.last_valid_steam_manifest_id
        else:
            baseline_id = self.awaiting_from_manifest_id
        self._set_pending_steam_base(branch, baseline_id)
        self._persist_steam_tracking_state(messages, high_water_observed_at=checked_at)

    def _persist_steam_tracking_state(
        self,
        messages: list[tuple[str, str]],
        *,
        high_water_observed_at: str | None = None,
    ) -> None:
        if self.warframe_version_high_water is None:
            return
        try:
            save_steam_tracking_state(
                last_valid_steam_manifest_id=self.last_valid_steam_manifest_id,
                last_valid_steam_manifest_size=self.last_valid_steam_manifest_size,
                awaiting_content_branch=self.awaiting_content_branch,
                awaiting_from_manifest_id=self.awaiting_from_manifest_id,
                pre_transition_manifest_id=self.pre_transition_manifest_id,
                pre_transition_manifest_size=self.pre_transition_manifest_size,
                pre_transition_content_branch=self.pre_transition_content_branch,
                high_water_version=self.warframe_version_high_water,
                high_water_observed_at=high_water_observed_at,
            )
        except Exception as exc:
            messages.append(("warning", f"[Steam] Could not save the manifest tracking state: {exc}"))

    def _clear_pre_transition_candidate(self) -> None:
        self.pre_transition_manifest_id = None
        self.pre_transition_manifest_size = None
        self.pre_transition_content_branch = None

    def _steam_tracking_state_snapshot(self) -> tuple[object, ...]:
        return (
            self.last_valid_steam_manifest_id,
            self.last_valid_steam_manifest_size,
            self.awaiting_content_branch,
            self.awaiting_from_manifest_id,
            self.pre_transition_manifest_id,
            self.pre_transition_manifest_size,
            self.pre_transition_content_branch,
        )

    def _set_pending_steam_base(self, branch: str, baseline_id: int | None) -> None:
        self.awaiting_content_branch = branch
        self.awaiting_from_manifest_id = baseline_id

    def _record_valid_steam_manifest(self, manifest_id: int, size: int | None) -> None:
        self.last_valid_steam_manifest_id = manifest_id
        self.last_valid_steam_manifest_size = size

    def _resolve_steam_base(self, manifest_id: int, size: int | None) -> None:
        self._record_valid_steam_manifest(manifest_id, size)
        self.awaiting_content_branch = None
        self.awaiting_from_manifest_id = None
        self._clear_pre_transition_candidate()

    @staticmethod
    def _manifest_size_suffix(size: int | None, *, status: str = "valid") -> str:
        return f" ({common.format_bytes(size)})" if status == "valid" and size is not None else ""

    @staticmethod
    def _steam_manifest_status_line(
        manifest_id: int,
        status: str,
        size: int | None,
        *,
        source_kind: str,
        fallback_reason: str | None = None,
    ) -> str:
        if source_kind not in {"live", "cache"}:
            raise ValueError(f"Unsupported Steam manifest source kind: {source_kind!r}")
        source_label = "Live" if source_kind == "live" else "Cached"
        if status == "valid":
            line = f"[Steam] {source_label} manifest: {manifest_id}{LiveTrackingMixin._manifest_size_suffix(size)}"
        elif status == "invalid":
            line = f"[Steam] {source_label} manifest candidate: {manifest_id} (invalid)"
        else:
            line = f"[Steam] {source_label} manifest candidate: {manifest_id} (size unavailable)"
        if source_kind == "cache":
            reason = fallback_reason or "unknown error"
            line += f" — live query unavailable ({reason})."
        return line

    @staticmethod
    def _content_branch_label(version: str | None) -> str | None:
        if version is None:
            return None
        major, minor = LiveTrackingMixin._content_branch(version)
        return f"{major}.{minor}"

    def _handle_content_update_manifest(
        self,
        observation: SteamManifestObservation,
        messages: list[tuple[str, str]],
        *,
        branch: str,
        baseline_id: int | None,
        pre_transition_crossed: bool,
    ) -> None:
        manifest_id, status, size, source_kind = observation
        direct_live = source_kind == "live"
        pre_transition_matches = pre_transition_crossed and direct_live and status == "valid" and self.pre_transition_manifest_id == manifest_id
        valid_direct_replacement = direct_live and status == "valid" and baseline_id is not None and manifest_id != baseline_id
        if pre_transition_matches:
            self._record_valid_steam_manifest(manifest_id, size)
            self._set_pending_steam_base(branch, manifest_id)
            suffix = self._manifest_size_suffix(size)
            messages.append((
                "info",
                f"[Steam] Pre-transition manifest candidate {manifest_id}{suffix} is still live for U{branch}, but it was published while "
                f"U{self.pre_transition_content_branch} was live. Its association with the new content update is uncertain; monitoring for a later manifest change.",
            ))
        elif valid_direct_replacement:
            self._resolve_steam_base(manifest_id, size)
            messages.append(("info", f"[Steam] New original Steam manifest base available: {manifest_id}{self._manifest_size_suffix(size)}"))
        elif baseline_id is None and direct_live and status == "valid":
            self._resolve_steam_base(manifest_id, size)
            messages.append((
                "info",
                f"[Steam] Previous manifest baseline is unknown; current live manifest: {manifest_id}{self._manifest_size_suffix(size)}. "
                "Future manifest changes will be tracked from this point.",
            ))
        else:
            waiting_from = self.pre_transition_manifest_id if pre_transition_crossed else self.awaiting_from_manifest_id
            if waiting_from is None:
                waiting_from = baseline_id
            self._set_pending_steam_base(branch, waiting_from)
            if status == "invalid" and direct_live:
                messages.append(("info", f"[Steam] New content update detected — live manifest candidate {manifest_id} is invalid; waiting for a valid original base."))
            elif pre_transition_crossed and not direct_live:
                messages.append((
                    "info",
                    f"[Steam] Manifest {self.pre_transition_manifest_id} was published while U{self.pre_transition_content_branch} was still live; "
                    f"its association with U{branch} is uncertain, and cached Steam data cannot confirm it. Monitoring for a later direct manifest change.",
                ))
            elif not direct_live:
                messages.append(("info", "[Steam] New content update detected — a new original, unupdated Steam manifest base is required; the live Steam query is unavailable, so cached data is not used to confirm it."))
            else:
                messages.append(("info", "[Steam] New content update detected — a new original, unupdated Steam manifest base is required and may not be available yet."))

    def _handle_pending_manifest(
        self,
        observation: SteamManifestObservation,
        messages: list[tuple[str, str]],
        *,
        changed: bool,
        source_recovered: bool,
        announce_current: bool,
        fallback_reason: str,
    ) -> None:
        manifest_id, status, size, source_kind = observation
        waiting_from = self.awaiting_from_manifest_id
        uncertain_pre_transition = (
            waiting_from is not None
            and self.pre_transition_manifest_id == waiting_from
            and self.pre_transition_content_branch is not None
            and self.pre_transition_content_branch != self.awaiting_content_branch
        )
        direct_live = source_kind == "live"
        if direct_live and status == "valid" and waiting_from is None:
            self._resolve_steam_base(manifest_id, size)
            messages.append((
                "info",
                f"[Steam] Previous manifest baseline is unknown; current live manifest: {manifest_id}{self._manifest_size_suffix(size)}. "
                "Future manifest changes will be tracked from this point.",
            ))
        elif direct_live and status == "valid" and manifest_id != waiting_from:
            self._resolve_steam_base(manifest_id, size)
            messages.append(("info", f"[Steam] New original Steam manifest base available: {manifest_id}{self._manifest_size_suffix(size)}"))
        elif changed and direct_live and status == "invalid":
            messages.append(("info", f"[Steam] Invalid live manifest candidate ignored: {manifest_id}"))
        elif changed and direct_live and status != "valid":
            messages.append(("info", f"[Steam] New live manifest candidate detected: {manifest_id} (size unavailable)"))
        elif source_recovered and uncertain_pre_transition and manifest_id == waiting_from:
            messages.append((
                "info",
                f"[Steam] Direct live query recovered; pre-transition manifest candidate {manifest_id}{self._manifest_size_suffix(size, status=status)} remains live, "
                f"but its association with U{self.awaiting_content_branch} is still uncertain. Monitoring for a later manifest change.",
            ))
        elif source_recovered:
            self._record_live_status_log(
                f"[Steam] Direct live query recovered; live manifest remains {manifest_id}{self._manifest_size_suffix(size, status=status)}."
            )
        elif announce_current:
            if uncertain_pre_transition and direct_live and manifest_id == waiting_from:
                messages.append((
                    "info",
                    f"[Steam] Pre-transition manifest candidate {manifest_id}{self._manifest_size_suffix(size, status=status)} remains live; "
                    f"its association with U{self.awaiting_content_branch} is still uncertain. Monitoring for a later manifest change.",
                ))
            else:
                messages.append(("info", self._steam_manifest_status_line(
                    manifest_id, status, size, source_kind=source_kind, fallback_reason=fallback_reason
                )))

    def _handle_idle_manifest(
        self,
        observation: SteamManifestObservation,
        messages: list[tuple[str, str]],
        *,
        branch: str | None,
        id_changed: bool,
        metadata_changed: bool,
        source_recovered: bool,
        announce_current: bool,
        fallback_reason: str,
    ) -> None:
        manifest_id, status, size, source_kind = observation
        accepted_before = self.last_valid_steam_manifest_id
        direct_live = source_kind == "live"
        recovered_to_accepted = source_recovered and status == "valid" and accepted_before is not None and manifest_id == accepted_before
        recovered_initial_baseline = source_recovered and status == "valid" and accepted_before is None
        accepted_changed = direct_live and status == "valid" and accepted_before is not None and manifest_id != accepted_before
        if accepted_changed:
            self.pre_transition_manifest_id = manifest_id
            self.pre_transition_manifest_size = size
            self.pre_transition_content_branch = branch
            self._record_valid_steam_manifest(manifest_id, size)
        elif direct_live and status == "valid":
            self._record_valid_steam_manifest(manifest_id, size)

        if announce_current:
            messages.append(("info", self._steam_manifest_status_line(
                manifest_id, status, size, source_kind=source_kind, fallback_reason=fallback_reason
            )))
        elif accepted_changed:
            messages.append(("info", f"[Steam] Live manifest changed: {manifest_id}{self._manifest_size_suffix(size)} — recorded as a pre-transition candidate while Warframe remains on U{branch}."))
        elif recovered_to_accepted:
            self._record_live_status_log(
                f"[Steam] Direct live query recovered; live manifest remains {manifest_id}{self._manifest_size_suffix(size)}."
            )
        elif recovered_initial_baseline:
            messages.append(("info", f"[Steam] Direct live query recovered; live manifest: {manifest_id}{self._manifest_size_suffix(size)}."))
        elif id_changed:
            if direct_live and status == "invalid":
                messages.append(("info", f"[Steam] Invalid live manifest candidate ignored: {manifest_id}"))
            elif direct_live:
                messages.append(("info", f"[Steam] New live manifest candidate detected: {manifest_id} (size unavailable)"))
        elif metadata_changed and direct_live:
            messages.append(("info", f"[Steam] Live manifest metadata updated: {manifest_id}{self._manifest_size_suffix(size, status=status)}"))
        elif source_recovered:
            self._record_live_status_log(
                f"[Steam] Direct live query recovered; live manifest remains {manifest_id}{self._manifest_size_suffix(size, status=status)}."
            )

    def _apply_current_steam_manifest_result(
        self,
        info: dict[str, object] | None,
        error: str | None,
        *,
        announce_current: bool = True,
        content_update: bool = False,
    ) -> tuple[dict[str, object], list[tuple[str, str]]]:
        messages: list[tuple[str, str]] = []
        self._load_persisted_steam_tracking_state(messages)
        previous = self.live_steam_manifest
        state_before = self._steam_tracking_state_snapshot()
        branch = self._content_branch_label(self.live_warframe_version or self.warframe_version_high_water)
        if content_update and branch is None:
            raise RuntimeError("Content update tracking requires a known Warframe content branch.")

        if info is not None and info.get("source_kind") not in {"live", "cache"}:
            error = "invalid Steam manifest source"
            info = None

        if info is None:
            error = normalize_live_query_error(error, "unknown Steam query failure")
            self.live_steam_error = error
            if content_update:
                crossed_candidate = (
                    self.pre_transition_manifest_id is not None
                    and self.pre_transition_content_branch is not None
                    and self.pre_transition_content_branch != branch
                )
                baseline_id = self.pre_transition_manifest_id if crossed_candidate else self.last_valid_steam_manifest_id
                self._set_pending_steam_base(branch, baseline_id)
                if crossed_candidate:
                    messages.append((
                        "info",
                        f"[Steam] Manifest {self.pre_transition_manifest_id} was published while U{self.pre_transition_content_branch} was still live; "
                        f"its association with U{branch} is uncertain, and the direct live query is currently unavailable. Monitoring for a later manifest change.",
                    ))
                else:
                    messages.append((
                        "info",
                        "[Steam] New content update detected — a new original, unupdated Steam manifest base is required and may not be available yet.",
                    ))
            if self._steam_tracking_state_snapshot() != state_before:
                self._persist_steam_tracking_state(messages)
            return {
                "manifest_id": None,
                "status": "unavailable",
                "size": None,
                "source": None,
                "source_kind": None,
            }, messages

        observation = SteamManifestObservation(
            manifest_id=int(info["manifest_id"]),
            status=str(info["status"]),
            size=info.get("size") if isinstance(info.get("size"), int) else None,
            source_kind=str(info["source_kind"]),
        )
        direct_live = observation.source_kind == "live"
        fallback_error = info.get("live_error") if isinstance(info.get("live_error"), str) else None
        self.live_steam_error = None if direct_live else normalize_live_query_error(fallback_error, "unknown Steam query failure")
        fallback_reason = summarize_steam_live_query_error(self.live_steam_error)
        id_changed = previous is not None and observation.manifest_id != previous.manifest_id
        metadata_changed = (
            previous is not None
            and (observation.status, observation.size) != (previous.status, previous.size)
        )
        source_recovered = previous is not None and previous.source_kind != "live" and direct_live
        changed = id_changed or metadata_changed
        self.live_steam_manifest = observation

        baseline_id = self.awaiting_from_manifest_id or self.last_valid_steam_manifest_id
        pre_transition_crossed = (
            content_update
            and self.pre_transition_manifest_id is not None
            and self.pre_transition_content_branch is not None
            and self.pre_transition_content_branch != branch
        )
        if content_update:
            self._handle_content_update_manifest(
                observation,
                messages,
                branch=branch,
                baseline_id=baseline_id,
                pre_transition_crossed=pre_transition_crossed,
            )
        elif self.awaiting_content_branch is not None:
            self._handle_pending_manifest(
                observation,
                messages,
                changed=changed,
                source_recovered=source_recovered,
                announce_current=announce_current,
                fallback_reason=fallback_reason,
            )
        else:
            self._handle_idle_manifest(
                observation,
                messages,
                branch=branch,
                id_changed=id_changed,
                metadata_changed=metadata_changed,
                source_recovered=source_recovered,
                announce_current=announce_current,
                fallback_reason=fallback_reason,
            )

        if self._steam_tracking_state_snapshot() != state_before:
            self._persist_steam_tracking_state(messages)

        result = dict(info)
        result["changed"] = changed
        result["id_changed"] = id_changed
        return result, messages

    def _record_steam_query_debug(
        self,
        info: dict[str, object] | None,
        error: str | None,
        elapsed: float,
    ) -> None:
        if not self._live_debug_enabled():
            return
        if info is not None and info.get("source_kind") == "live":
            manifest_id = info.get("manifest_id")
            size = info.get("size") if isinstance(info.get("size"), int) else None
            suffix = self._manifest_size_suffix(size, status=str(info.get("status", "unvalidated")))
            self._record_live_debug(
                f"[Steam] Live query succeeded in {elapsed:.2f}s: manifest {manifest_id}{suffix}"
            )
            return
        if info is not None and info.get("source_kind") == "cache":
            detail = info.get("live_error") if isinstance(info.get("live_error"), str) else error or "unknown Steam query failure"
            manifest_id = info.get("manifest_id")
            size = info.get("size") if isinstance(info.get("size"), int) else None
            suffix = self._manifest_size_suffix(size, status=str(info.get("status", "unvalidated")))
            self._record_live_debug(
                f"[Steam] Live query failed after {elapsed:.2f}s: {detail}; using cached manifest {manifest_id}{suffix}"
            )
            return
        self._record_live_debug(
            f"[Steam] Live query failed after {elapsed:.2f}s: {error or 'unknown Steam query failure'}"
        )

    def _start_steam_status_query(self, *, announce_current: bool, content_update: bool) -> None:
        with self.steam_status_lock:
            self.steam_status_pending_announce = self.steam_status_pending_announce or announce_current
            self.steam_status_pending_content_update = self.steam_status_pending_content_update or content_update
            process = self.steam_status_process
            if process is not None and process.poll() is None:
                return
            if process is not None:
                # A completed result is consumed by the normal polling path before
                # another query is started. Keep it intact until then.
                return
            self.steam_status_started_at = time.monotonic()
            try:
                self.steam_status_process = start_steam_query_subprocess(
                    timeout=_LIVE_QUERY_REQUEST_TIMEOUT_SECONDS,
                    entry_script=common.TOOL_DIR / "ninja_capture_tool.py",
                )
            except Exception as exc:
                elapsed = time.monotonic() - self.steam_status_started_at
                self.steam_status_started_at = None
                info, error = steam_manifest_with_cache_fallback(None, f"worker startup: {exc}")
                self._record_steam_query_debug(info, error, elapsed)
                _, messages = self._apply_current_steam_manifest_result(
                    info,
                    error,
                    announce_current=self.steam_status_pending_announce,
                    content_update=self.steam_status_pending_content_update,
                )
                self.steam_status_pending_announce = False
                self.steam_status_pending_content_update = False
                self._refresh_steam_status_header()
                if messages:
                    self._emit_live_status_messages(messages)

    def _finish_steam_status_process(self, process: subprocess.Popen) -> tuple[dict[str, object] | None, str | None]:
        try:
            info, error = collect_steam_query_subprocess(process)
        except Exception as exc:
            info, error = None, str(exc)
        return steam_manifest_with_cache_fallback(info, error)

    def _consume_steam_status_result(self) -> None:
        with self.steam_status_lock:
            process = self.steam_status_process
            started_at = self.steam_status_started_at
            if process is None:
                return
            timed_out = (
                process.poll() is None
                and started_at is not None
                and time.monotonic() - started_at >= _STEAM_STATUS_QUERY_DEADLINE_SECONDS
            )
            if process.poll() is None and not timed_out:
                return

            self.steam_status_process = None
            self.steam_status_started_at = None
            announce_current = self.steam_status_pending_announce
            content_update = self.steam_status_pending_content_update
            self.steam_status_pending_announce = False
            self.steam_status_pending_content_update = False

        elapsed = time.monotonic() - started_at if started_at is not None else 0.0
        if timed_out:
            worker_output = terminate_steam_query_subprocess(process)
            stage = latest_steam_query_worker_stage(worker_output)
            timeout_detail = f"Steam live query timed out after {_STEAM_STATUS_QUERY_DEADLINE_SECONDS:g} seconds"
            if stage is not None:
                timeout_detail += f" during {stage}"
            info, error = steam_manifest_with_cache_fallback(None, timeout_detail)
        else:
            info, error = self._finish_steam_status_process(process)

        self._record_steam_query_debug(info, error, elapsed)
        _, messages = self._apply_current_steam_manifest_result(
            info,
            error,
            announce_current=announce_current,
            content_update=content_update,
        )
        self._refresh_steam_status_header()
        if messages:
            self._emit_live_status_messages(messages)

    def _stop_steam_status_query(self) -> None:
        with self.steam_status_lock:
            process = self.steam_status_process
            self.steam_status_process = None
            self.steam_status_started_at = None
            self.steam_status_pending_announce = False
            self.steam_status_pending_content_update = False
        if process is not None:
            terminate_steam_query_subprocess(process, timeout=0.0 if self.console_closing else 1.0)

    def _record_live_status_log(self, message: str) -> None:
        if self.logger is None:
            if not self.pending_live_status_log_messages or self.pending_live_status_log_messages[-1] != message:
                self.pending_live_status_log_messages.append(message)
            return
        self.logger.write(message, console=False)

    def _flush_pending_live_status_logs(self) -> None:
        if self.logger is None or not self.pending_live_status_log_messages:
            return
        pending = self.pending_live_status_log_messages
        self.pending_live_status_log_messages = []
        for message in pending:
            self.logger.write(message, console=False)

    def _render_live_status_line(self, key: str, text: str, *, initial: bool = False) -> None:
        previous_text = self.live_status_texts.get(key)
        if not initial and previous_text == text:
            return
        logger = self.logger
        lock = logger.console_lock if logger is not None else self.live_status_console_lock
        with lock:
            if logger is not None:
                logger._clear_progress_locked()
            row = self.live_status_rows.get(key)
            if not initial and row is not None and previous_text is not None and not self.suppress_console_output:
                rewritten_row = runtime.rewrite_console_status_row(row, previous_text, text)
                if rewritten_row is not None:
                    self.live_status_rows[key] = rewritten_row
                    self.live_status_texts[key] = text
                    return
            self.live_status_texts[key] = text
            if self.suppress_console_output:
                return
            new_row = runtime.console_status_row(text)
            common.print_console(text, flush=True)
            self.live_status_rows[key] = new_row

    def _set_live_status_line(self, key: str, text: str, *, initial: bool = False) -> None:
        if not self.live_status_header_initialized and not initial:
            return
        if initial:
            self._render_live_status_line(key, text, initial=True)
            return
        with self.worker_console_condition:
            if self.live_status_texts.get(key) == text and key not in self.pending_live_status_updates:
                return
            if self.pending_live_status_updates.get(key) == text:
                return
            self.pending_live_status_updates[key] = text
        self._start_worker_console_dispatcher()
        with self.worker_console_condition:
            self.worker_console_condition.notify()

    def _current_warframe_status_line(self) -> str:
        if self.live_warframe_error:
            reason = summarize_warframe_live_query_error(self.live_warframe_error)
            if self.warframe_version_high_water is not None:
                return f"[Warframe] Cached version: U{self.warframe_version_high_water} — live query unavailable ({reason})."
            return f"[Warframe] Live version unavailable ({reason})."
        if self.live_warframe_version is not None:
            return f"[Warframe] Live version: U{self.live_warframe_version}"
        if self.warframe_version_high_water is not None:
            return f"[Warframe] Cached version: U{self.warframe_version_high_water} — checking live version..."
        return "[Warframe] Checking live version..."

    def _initialize_live_status_header(self, version_info: dict[str, object]) -> None:
        self.live_status_header_initialized = True
        version = version_info.get("version")
        status = version_info.get("status")
        if status == "cached" and isinstance(version, str):
            self.warframe_version_high_water = version
        elif isinstance(version, str) and status not in {"unavailable", "cached"}:
            self.live_warframe_version = version
        self._set_live_status_line("warframe", self._current_warframe_status_line(), initial=True)
        self._set_live_status_line("steam", "[Steam] Checking live manifest...", initial=True)

    def _refresh_warframe_status_header(self) -> None:
        if not self.live_status_header_initialized:
            return
        self._set_live_status_line("warframe", self._current_warframe_status_line())

    def _current_steam_status_line(self) -> str:
        current = self.live_steam_manifest
        if current is None:
            if self.live_steam_error:
                reason = summarize_steam_live_query_error(self.live_steam_error)
                return f"[Steam] Live manifest unavailable ({reason})."
            return "[Steam] Checking live manifest..."
        reason = summarize_steam_live_query_error(self.live_steam_error) if current.source_kind == "cache" else None
        return self._steam_manifest_status_line(
            current.manifest_id,
            current.status,
            current.size,
            source_kind=current.source_kind,
            fallback_reason=reason,
        )

    def _refresh_steam_status_header(self) -> None:
        if not self.live_status_header_initialized:
            return
        self._set_live_status_line("steam", self._current_steam_status_line())

    @staticmethod
    def _live_status_message_is_header_only(message: str) -> bool:
        return message.startswith((
            "[Warframe] Live version:",
            "[Warframe] Cached version:",
            "[Warframe] Live version unavailable (",
            "[Warframe] Checking live version...",
            "[Steam] Live manifest:",
            "[Steam] Live manifest candidate:",
            "[Steam] Cached manifest:",
            "[Steam] Cached manifest candidate:",
            "[Steam] Live manifest unavailable (",
        ))

    def _emit_live_status_messages(self, messages: list[tuple[str, str]]) -> None:
        for severity, message in messages:
            rendered = f"WARNING: {message}" if severity == "warning" else message
            if message.startswith((
                "[Warframe] Live version:",
                "[Warframe] Cached version:",
                "[Warframe] Live version unavailable (",
                "[Warframe] Checking live version...",
            )):
                self._set_live_status_line("warframe", message)
            if self._live_status_message_is_header_only(message):
                self._record_live_status_log(rendered)
                continue
            if self.logger is None:
                if severity == "warning":
                    common.print_warning(message)
                else:
                    common.print_console(message, flush=True)
            else:
                self.log(rendered)

    def _schedule_next_live_check(self) -> None:
        interval = int(self.options["live_check_interval_seconds"])
        self.next_live_check_at = time.monotonic() + interval

    def _poll_live_status(self) -> None:
        self._consume_warframe_status_result()
        self._consume_steam_status_result()
        interval = int(self.options["live_check_interval_seconds"])
        if self.next_live_check_at is None:
            return
        now = time.monotonic()
        if now < self.next_live_check_at:
            return
        self.next_live_check_at = now + interval
        self._start_warframe_status_query(announce_current=False)
        self._start_steam_status_query(announce_current=False, content_update=False)
