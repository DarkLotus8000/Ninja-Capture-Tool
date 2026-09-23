# Run from the project root with: py -B -m unittest discover -s tests
from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import io
import json
import lzma
import os
import re
import struct
import subprocess
import sys
import tempfile
import types
import threading
import time
import unittest
import zipfile
import xml.etree.ElementTree as ET
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest import mock

import build_release
import capture
import common
import config as nct_config
import elevation
import check_live as live_tracking
import instance_lock
import ninja_capture_tool as nct
import runtime as nct_runtime
import session as nct_session
import check_steam as steam_tracking
import update
import windows_proxy

def worker_messages(text: str) -> list[dict[str, object]]:
    return [
        message
        for line in text.splitlines()
        if (message := common.parse_worker_message(line)) is not None
    ]

def make_shcc_container(payload: bytes = b"compressed-manifest", *, chunk_type: int = 2) -> bytes:
    raw = bytearray(b"SHCC\x1f\x00\x00\x00")
    raw += bytes([chunk_type])
    raw += struct.pack("<II", max(1, len(payload) * 2), len(payload))
    raw += payload
    raw += (
        b"\x00\xff\xff\xff\xff"
        b"\x00\x00\x00\x00\x00"
        b"\xff\xff\xff\xff"
        b"\x00\x00\x00\x00\x52"
    )
    raw += struct.pack("<I", capture.crc32c(bytes(raw)))
    return bytes(raw)

def make_steam_appinfo_v41(manifest_id: int, size: int, download: int = 1) -> bytes:
    keys = ["appinfo", "depots", "230411", "manifests", "public", "gid", "size", "download"]
    indexes = {key: index for index, key in enumerate(keys)}

    def obj(key: str, content: bytes) -> bytes:
        return b"\x00" + indexes[key].to_bytes(4, "little") + content + b"\x08"

    def string(key: str, value: object) -> bytes:
        return b"\x01" + indexes[key].to_bytes(4, "little") + str(value).encode("ascii") + b"\0"

    public = string("gid", manifest_id) + string("size", size) + string("download", download)
    payload = obj("appinfo", obj("depots", obj("230411", obj("manifests", obj("public", public))))) + b"\x08"
    fixed_header = (
        (1).to_bytes(4, "little")
        + (123).to_bytes(4, "little")
        + (456).to_bytes(8, "little")
        + b"0" * 20
        + (789).to_bytes(4, "little")
        + b"1" * 20
    )
    entry_size = 60 + len(payload)
    entry = (230410).to_bytes(4, "little") + entry_size.to_bytes(4, "little") + fixed_header + payload
    string_table_offset = 16 + len(entry) + 4
    header = (
        (0x07564429).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + string_table_offset.to_bytes(8, "little")
    )
    string_table = len(keys).to_bytes(4, "little") + b"".join(key.encode("utf-8") + b"\0" for key in keys)
    return header + entry + b"\0" * 4 + string_table

class FakeSteamQueryProcess:
    def __init__(self, *, running: bool = False, returncode: int = 0):
        self.running = running
        self.returncode = None if running else returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self.running else self.returncode

    def wait(self, timeout=None):
        if self.running:
            raise subprocess.TimeoutExpired("steam-worker", timeout)
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.running = False
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.running = False
        self.returncode = -9

    def communicate(self, timeout=None):
        return "", None

class NctTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._local_app_data_tmp = tempfile.TemporaryDirectory()
        self._local_app_data_root = Path(self._local_app_data_tmp.name) / "DarkLotus" / "Ninja Capture Tool"
        self._local_app_data_patch = mock.patch.object(common, "nct_local_app_data_root", return_value=self._local_app_data_root)
        self._local_app_data_patch.start()
        self._session_recovery_tmp = tempfile.TemporaryDirectory()
        recovery_path = Path(self._session_recovery_tmp.name) / ".session-recovery.json"
        self._session_recovery_patch = mock.patch.object(nct_session, "_SESSION_RECOVERY_FILE", recovery_path)
        self._session_recovery_patch.start()
        self._warframe_version_load_patch = mock.patch.object(
            live_tracking,
            "load_warframe_version_high_water",
            return_value=None,
        )
        self._warframe_version_save_patch = mock.patch.object(live_tracking, "save_warframe_version_high_water")
        self._live_tracking_load_patch = mock.patch.object(live_tracking, "load_live_tracking_state", return_value={})
        self._steam_tracking_save_patch = mock.patch.object(live_tracking, "save_steam_tracking_state")
        self._warframe_process_patch = mock.patch.object(
            live_tracking, "start_warframe_query_subprocess", return_value=FakeSteamQueryProcess()
        )
        self._warframe_collect_patch = mock.patch.object(
            live_tracking, "collect_warframe_query_subprocess", return_value=("43.5.4", None)
        )
        self._warframe_terminate_patch = mock.patch.object(live_tracking, "terminate_warframe_query_subprocess")
        self._steam_process_patch = mock.patch.object(
            live_tracking, "start_steam_query_subprocess", return_value=FakeSteamQueryProcess()
        )
        self._steam_collect_patch = mock.patch.object(
            live_tracking,
            "collect_steam_query_subprocess",
            return_value=(
                {
                    "app_id": 230410,
                    "depot_id": 230411,
                    "manifest_id": 4895911296145320793,
                    "size": 52 * 1024**3,
                    "download_size": 30 * 1024**3,
                    "status": "valid",
                    "last_updated": 0,
                    "change_number": 0,
                    "source": "Steam live query",
                    "source_kind": "live",
                },
                None,
            ),
        )
        self._steam_terminate_patch = mock.patch.object(live_tracking, "terminate_steam_query_subprocess")
        self._warframe_version_load_patch.start()
        self._warframe_version_save_patch.start()
        self._live_tracking_load_patch.start()
        self._steam_tracking_save_patch.start()
        self._warframe_process_patch.start()
        self._warframe_collect_patch.start()
        self._warframe_terminate_patch.start()
        self._steam_process_patch.start()
        self._steam_collect_patch.start()
        self._steam_terminate_patch.start()

    def tearDown(self) -> None:
        self._steam_terminate_patch.stop()
        self._steam_collect_patch.stop()
        self._steam_process_patch.stop()
        self._warframe_terminate_patch.stop()
        self._warframe_collect_patch.stop()
        self._warframe_process_patch.stop()
        self._steam_tracking_save_patch.stop()
        self._live_tracking_load_patch.stop()
        self._warframe_version_save_patch.stop()
        self._warframe_version_load_patch.stop()
        self._session_recovery_patch.stop()
        self._session_recovery_tmp.cleanup()
        self._local_app_data_patch.stop()
        self._local_app_data_tmp.cleanup()

    def make_sidecar_session_metadata(
        self,
        session: Path,
        options: dict[str, object],
        session_id: str = "2026-08-24_16-10-23",
    ) -> tuple[Path, Path]:
        log_path, manifest_path = common.session_artifact_paths(session.parent, session_id)
        capture.initialize_session_manifest(session, options, manifest_path)
        return log_path, manifest_path

    @staticmethod
    def manifest_path_for(session: Path) -> Path:
        return session.parent / f"{session.name}_session.json"

    def make_release_stage(self, root: Path) -> Path:
        stage = root / "stage"
        licenses = stage / "data" / "licenses"
        licenses.mkdir(parents=True)
        runtime = stage / common.FROZEN_RUNTIME_DIR_NAME
        runtime.mkdir()
        (runtime / "python314.dll").write_bytes(b"runtime")
        (stage / "NinjaCaptureTool.exe").write_bytes(b"exe")
        (stage / "config.json").write_text(json.dumps(nct_config.DEFAULT_CONFIG), encoding="utf-8")
        (stage / "README.txt").write_text("readme", encoding="utf-8")
        (licenses / build_release.NCT_LICENSE_RELEASE_NAME).write_text("license", encoding="utf-8")
        (licenses / "dependency-LICENSE.txt").write_text("license", encoding="utf-8")
        build_release.write_release_manifest(stage)
        return stage

    def _write_stage_release_manifest(self, stage: Path, version: str = common.VERSION) -> None:
        files: dict[str, str] = {}
        for path in sorted(stage.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(stage).as_posix()
            if relative == common.RELEASE_MANIFEST_FILE or relative in common.PRESERVED_RELEASE_FILES:
                continue
            files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        (stage / common.RELEASE_MANIFEST_FILE).parent.mkdir(parents=True, exist_ok=True)
        (stage / common.RELEASE_MANIFEST_FILE).write_text(
            json.dumps(
                {
                    "format_version": common.RELEASE_MANIFEST_VERSION,
                    "application_version": version,
                    "files": files,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def make_session(self, root: Path) -> Path:
        session = root / "session"
        session.mkdir()
        capture.initialize_session_manifest(
            session,
            dict(nct_config.DEFAULT_CONFIG, output_root=root, output_path=None),
            self.manifest_path_for(session),
        )
        return session

    def make_addon(self, root: Path, **kwargs) -> capture.CaptureAddon:
        session = self.make_session(root)
        return capture.CaptureAddon(session, self.manifest_path_for(session), **kwargs)

    def fake_flow(self, status: int, host: str = "content.warframe.com", url: str = "https://content.warframe.com/a.bin", content_length: str | None = None):
        headers = {}
        if content_length is not None:
            headers["content-length"] = content_length
        return SimpleNamespace(
            request=SimpleNamespace(pretty_host=host, pretty_url=url, method="GET"),
            response=SimpleNamespace(status_code=status, headers=headers, stream=None),
            metadata={},
        )

    def proxy_settings(self, **values):
        result = {name: None for name in windows_proxy.PROXY_SETTING_NAMES}
        for name, value in values.items():
            result[name] = value
        return result

    def _write_fake_release_archive(self, archive: Path, version: str, extra: dict[str, bytes] | None = None) -> None:
        prefix = f"NinjaCaptureTool-v{version}/"
        files = {
            "NinjaCaptureTool.exe": b"main",
            "config.json": json.dumps(nct_config.DEFAULT_CONFIG).encode(),
            "README.txt": b"readme",
            f"{common.FROZEN_RUNTIME_DIR_NAME}/python314.dll": b"runtime",
            "data/licenses/Ninja-Capture-Tool-LICENSE.txt": b"GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007",
            "data/licenses/test-LICENSE.txt": b"license",
        }
        if extra:
            files.update(extra)
        managed = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in files.items()
            if name not in common.PRESERVED_RELEASE_FILES and name != common.RELEASE_MANIFEST_FILE
        }
        files[common.RELEASE_MANIFEST_FILE] = (
            json.dumps(
                {
                    "format_version": common.RELEASE_MANIFEST_VERSION,
                    "application_version": version,
                    "files": managed,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
        with zipfile.ZipFile(archive, "w") as zf:
            for name, content in files.items():
                zf.writestr(prefix + name, content)
