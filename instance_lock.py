#!/usr/bin/env python3
from __future__ import annotations

import os
import threading
from contextlib import contextmanager

from common import (
    FileLockBusyError,
    TOOL_DIR,
    capture_activity_lock_path,
    user_capture_activity_lock_path,
    windows_file_lock,
)

_PROCESS_LOCK = threading.Lock()
_PROCESS_LOCK_HELD = False

class CaptureBusyError(RuntimeError):
    pass

def another_capture_is_active() -> bool:
    with _PROCESS_LOCK:
        if _PROCESS_LOCK_HELD:
            return True
    if os.name != "nt":
        return False
    try:
        with windows_file_lock(
            user_capture_activity_lock_path(),
            0,
            "Another Ninja Capture Tool capture is already running.",
        ):
            with windows_file_lock(
                capture_activity_lock_path(TOOL_DIR),
                0,
                "Another Ninja Capture Tool capture is already running.",
            ):
                return False
    except FileLockBusyError:
        return True

@contextmanager
def capture_lock():
    global _PROCESS_LOCK_HELD
    with _PROCESS_LOCK:
        if _PROCESS_LOCK_HELD:
            raise CaptureBusyError("Another Ninja Capture Tool capture is already running.")
        _PROCESS_LOCK_HELD = True
    try:
        if os.name != "nt":
            yield
            return
        try:
            with windows_file_lock(
                user_capture_activity_lock_path(),
                0,
                "Another Ninja Capture Tool capture is already running.",
            ):
                with windows_file_lock(
                    capture_activity_lock_path(TOOL_DIR),
                    0,
                    "Another Ninja Capture Tool capture is already running.",
                ):
                    yield
        except FileLockBusyError as exc:
            raise CaptureBusyError(str(exc)) from exc
    finally:
        with _PROCESS_LOCK:
            _PROCESS_LOCK_HELD = False
