#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import asyncio
import ctypes
import hashlib
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

import capture
import elevation
import config as nct_config
import runtime as nct_runtime
import check_steam
import windows_proxy

from common import (
    ALLOW_HOSTS_REGEX,
    mitmproxy_conf_directory,
    MITMPROXY_VERSION,
    RELEASE_BUILD_ENV,
    encode_worker_message,
    nct_local_app_data_root,
    parse_worker_message,
    print_console,
    print_error,
    print_warning,
    validate_mitmproxy_installation,
    validate_windows_capture_package,
)
from update import (
    UPDATE_INSTALLER_ARGUMENT,
    handle_automatic_update,
    handle_early_update_request,
    run_update_installer,
    stale_update_recovery_backups,
)
from instance_lock import CaptureBusyError, another_capture_is_active, capture_lock
_CONSOLE_HANDLER = None
_LOCAL_CAPTURE_RUNTIME_REQUIRED_FILES = ("windows-redirector.exe", "WinDivert.dll", "WinDivert64.sys")

def _is_windivert_prior_unload_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        for attribute in ("winerror", "errno"):
            try:
                if int(getattr(current, attribute)) == 654:
                    return True
            except (AttributeError, TypeError, ValueError):
                pass
        for value in getattr(current, "args", ()):
            if isinstance(value, int) and not isinstance(value, bool) and value == 654:
                return True
        text = str(current).casefold()
        if (
            "error_driver_failed_prior_unload" in text
            or "failed prior unload" in text
            or "prior unload" in text
            or re.search(r"\bwinerror\s*[:=]?\s*654\b", text)
            or re.search(r"\b(?:windows|os)\s+error\s*[:=]?\s*654\b", text)
            or re.search(r"\berror\s+code\s*[:=]?\s*654\b", text)
        ):
            return True
        current = current.__cause__ if current.__cause__ is not None else current.__context__
    return False

def _windivert_prior_unload_message() -> str:
    return (
        "Local Capture could not start because an incompatible WinDivert driver is still loaded "
        "(Windows error 654). Restart Windows, or close other applications using WinDivert and run "
        '"sc.exe stop WinDivert" from an elevated terminal, then try again.'
    )

def _local_capture_runtime_root() -> Path:
    return nct_local_app_data_root() / "runtime" / "mitmproxy-windows"

def _local_capture_runtime_sources(executable: Path) -> tuple[Path, ...]:
    source_dir = executable.parent
    by_name = {path.name.casefold(): path for path in source_dir.iterdir() if path.is_file()}
    sources: list[Path] = []
    for name in _LOCAL_CAPTURE_RUNTIME_REQUIRED_FILES:
        path = by_name.get(name.casefold())
        if path is None:
            raise RuntimeError(f"mitmproxy-windows Local Capture runtime is missing {name} next to {executable.name}.")
        sources.append(path)
    return tuple(sources)

def _local_capture_runtime_fingerprint(sources: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for source in sorted(sources, key=lambda path: path.name.casefold()):
        digest.update(source.name.casefold().encode("utf-8"))
        digest.update(b"\0")
        with source.open("rb") as file:
            digest.update(hashlib.file_digest(file, "sha256").digest())
        digest.update(b"\0")
    return digest.hexdigest()

def _local_capture_runtime_matches(sources: tuple[Path, ...], destination: Path) -> bool:
    if not destination.is_dir():
        return False
    for source in sources:
        target = destination / source.name
        try:
            if not target.is_file() or target.stat().st_size != source.stat().st_size:
                return False
            with source.open("rb") as source_file, target.open("rb") as target_file:
                if hashlib.file_digest(source_file, "sha256").digest() != hashlib.file_digest(target_file, "sha256").digest():
                    return False
        except OSError:
            return False
    return True

def _remove_local_capture_runtime_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)

def _windivert_driver_loaded() -> bool:
    if sys.platform != "win32":
        return False
    try:
        result = subprocess.run(
            ["sc.exe", "query", "WinDivert"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        # Cleanup is optional. If driver state cannot be established safely,
        # leave all cached runtimes intact rather than risk partially deleting
        # the directory backing a loaded kernel driver.
        return True
    output = result.stdout + result.stderr
    if result.returncode != 0:
        # ERROR_SERVICE_DOES_NOT_EXIST: no WinDivert driver service is loaded.
        return not (result.returncode == 1060 or re.search(rb"\b1060\b", output))
    match = re.search(rb"\bSTATE\s*:\s*(\d+)\b", output, re.IGNORECASE)
    if match is None:
        return True
    return int(match.group(1)) != 1  # SERVICE_STOPPED

def _cleanup_old_local_capture_runtimes(root: Path, current: Path) -> None:
    if _windivert_driver_loaded():
        return
    try:
        candidates = tuple(root.iterdir())
    except OSError:
        return
    for candidate in candidates:
        if candidate == current:
            continue
        try:
            _remove_local_capture_runtime_path(candidate)
        except OSError:
            # Cleanup is best-effort. A file can still become busy between the
            # driver-state check and deletion, so retry it on a later launch.
            pass

def prepare_windows_local_capture_runtime() -> Path | None:
    if sys.platform != "win32":
        return None
    try:
        import mitmproxy_windows
    except ImportError as exc:
        raise RuntimeError(
            "mitmproxy-windows is required for process-local capture on Windows. "
            f"Reinstall mitmproxy {MITMPROXY_VERSION}."
        ) from exc

    try:
        source_executable = Path(mitmproxy_windows.executable_path()).resolve()
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise RuntimeError("Could not locate the mitmproxy-windows Local Capture redirector.") from exc
    if not source_executable.is_file():
        raise RuntimeError(f"mitmproxy-windows Local Capture redirector was not found: {source_executable}")

    sources = _local_capture_runtime_sources(source_executable)
    fingerprint = _local_capture_runtime_fingerprint(sources)
    runtime_root = _local_capture_runtime_root()
    runtime_root.mkdir(parents=True, exist_ok=True)
    destination = runtime_root / f"{MITMPROXY_VERSION}-{fingerprint}"

    if destination.exists() and not _local_capture_runtime_matches(sources, destination):
        if _windivert_driver_loaded():
            raise RuntimeError(
                "Cached Local Capture runtime is invalid while WinDivert is still loaded. "
                "Ninja Capture Tool left the runtime untouched. Restart Windows, or close other applications "
                'using WinDivert and run "sc.exe stop WinDivert" from an elevated terminal, then try again.'
            )
        try:
            _remove_local_capture_runtime_path(destination)
        except OSError as exc:
            raise RuntimeError(
                f"Cached Local Capture runtime is invalid and could not be refreshed: {destination}"
            ) from exc

    if not destination.exists():
        staging = runtime_root / f".stage-{fingerprint[:16]}-{os.getpid()}-{time.time_ns()}"
        try:
            staging.mkdir()
            for source in sources:
                shutil.copy2(source, staging / source.name)
            try:
                staging.replace(destination)
            except OSError as exc:
                if not _local_capture_runtime_matches(sources, destination):
                    raise RuntimeError(f"Could not publish the Local Capture runtime: {destination}") from exc
        finally:
            shutil.rmtree(staging, ignore_errors=True)

    if not _local_capture_runtime_matches(sources, destination):
        raise RuntimeError(f"Local Capture runtime verification failed: {destination}")

    staged_executable = destination / source_executable.name
    mitmproxy_windows.executable_path = lambda target=staged_executable: target
    _cleanup_old_local_capture_runtimes(runtime_root, destination)
    return staged_executable

def patch_mitmproxy_1223_quic_host_filter() -> bool:
    if MITMPROXY_VERSION != "12.2.3":
        return True
    try:
        from mitmproxy.addons import next_layer as mitm_next_layer
    except ImportError:
        return False

    current = mitm_next_layer.NextLayer._get_client_hello
    if getattr(current, "_nct_quic_host_filter_fix", False):
        return True

    def fixed_get_client_hello(context, data_client: bytes):
        if context.client.transport_protocol != "udp":
            return current(context, data_client)
        if mitm_next_layer._starts_like_quic(data_client, context.server.address):
            try:
                client_hello = mitm_next_layer.quic_parse_client_hello_from_datagrams([data_client])
            except ValueError:
                pass
            else:
                if client_hello is None:
                    raise mitm_next_layer.NeedsMoreData
                return client_hello
        if mitm_next_layer.starts_like_dtls_record(data_client):
            try:
                client_hello = mitm_next_layer.dtls_parse_client_hello(data_client)
            except ValueError:
                pass
            else:
                if client_hello is None:
                    raise mitm_next_layer.NeedsMoreData
                return client_hello
        return None

    fixed_get_client_hello._nct_quic_host_filter_fix = True
    mitm_next_layer.NextLayer._get_client_hello = staticmethod(fixed_get_client_hello)
    return True

def patch_mitmproxy_1223_local_process_metadata() -> bool:
    if MITMPROXY_VERSION != "12.2.3":
        return True
    try:
        from mitmproxy.proxy import server as mitm_server
    except ImportError:
        return False

    current = mitm_server.LiveConnectionHandler.__init__
    if getattr(current, "_nct_local_process_metadata", False):
        return True

    def init_with_process_metadata(self, reader, writer, options, mode):
        current(self, reader, writer, options, mode)
        try:
            process_pid = writer.get_extra_info("pid")
            process_name = writer.get_extra_info("process_name")
        except Exception:
            return
        client = getattr(self, "client", None)
        if client is None:
            return
        if isinstance(process_pid, int) and not isinstance(process_pid, bool) and process_pid > 0:
            client._nct_process_pid = process_pid
        if isinstance(process_name, str) and process_name.strip():
            client._nct_process_name = process_name

    init_with_process_metadata._nct_local_process_metadata = True
    mitm_server.LiveConnectionHandler.__init__ = init_with_process_metadata
    return True

async def run_proxy_worker(
    session: Path,
    mode: str,
    listen_port: int,
    debug: str,
    *,
    manifest_path: Path,
) -> None:
    local_mode = mode == "local" or mode.startswith("local:")
    if local_mode:
        prepare_windows_local_capture_runtime()
    try:
        from mitmproxy import options as mitm_options
        from mitmproxy.tools.dump import DumpMaster
    except ImportError as exc:
        raise RuntimeError(
            "mitmproxy is not installed. Install the source dependency with: py -3.14 -m pip install -r requirements.txt"
        ) from exc

    quic_host_filter_ready = patch_mitmproxy_1223_quic_host_filter()
    global_debug = debug == "global"
    if local_mode:
        patch_mitmproxy_1223_local_process_metadata()
    if global_debug and mode != "local":
        raise RuntimeError("Global debug requires unrestricted Local Capture mode.")
    if global_debug and not quic_host_filter_ready:
        raise RuntimeError("Could not activate the mitmproxy QUIC passthrough compatibility fix required by Global debug.")
    mitmproxy_conf_dir = mitmproxy_conf_directory()
    mitmproxy_conf_dir.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, object] = {
        "mode": [mode],
        "confdir": str(mitmproxy_conf_dir),
    }
    kwargs["allow_hosts"] = [ALLOW_HOSTS_REGEX]
    if not local_mode:
        kwargs["listen_host"] = "127.0.0.1"
        kwargs["listen_port"] = listen_port
    upstream = mode.removeprefix("upstream:") if mode.startswith("upstream:") else None
    upstream_auth = os.environ.pop(UPSTREAM_AUTH_ENV, None) if upstream is not None else None
    if upstream_auth:
        kwargs["upstream_auth"] = upstream_auth

    opts = mitm_options.Options(**kwargs)
    master = DumpMaster(opts, with_termlog=False, with_dumper=False)
    drain_requested = threading.Event()
    capture_addon = capture.CaptureAddon(
        session,
        manifest_path=manifest_path,
        debug=False if debug == "off" else debug,
        drain_requested=drain_requested,
        worker_protocol_enabled=True,
        manual_fetch_upstream=upstream,
        manual_fetch_upstream_auth=upstream_auth,
    )
    master.addons.add(capture_addon)
    event_loop = asyncio.get_running_loop()

    def worker_control_loop() -> None:
        try:
            for line in sys.stdin:
                try:
                    message = parse_worker_message(line.rstrip("\r\n"))
                except ValueError:
                    continue
                if message is None:
                    continue
                message_type = message.get("type")
                if message_type == "drain":
                    capture_addon.store.request_drain()
                elif message_type == "shutdown":
                    return
                elif message_type == "rotate":
                    token = str(message.get("token", ""))
                    session_value = message.get("session")
                    manifest_value = message.get("manifest")
                    if not token or not isinstance(session_value, str) or not isinstance(manifest_value, str):
                        print(encode_worker_message("rotation_failed", token=token, error="Malformed session rotation request."), flush=True)
                        continue
                    capture_addon.request_session_rotation(Path(session_value).resolve(), Path(manifest_value).resolve(), token)
                elif message_type == "config_metadata":
                    token = str(message.get("token", ""))
                    capture_mode = message.get("capture_mode")
                    processes = message.get("processes")
                    debug = message.get("debug")
                    proxy_port = message.get("proxy_port")
                    upstream_proxy = message.get("upstream_proxy")
                    stop_on_exit = message.get("stop_on_exit")
                    stop_on_exit_delay = message.get("stop_on_exit_delay")
                    valid_processes = (
                        isinstance(processes, list)
                        and bool(processes)
                        and all(isinstance(item, str) and bool(item.strip()) for item in processes)
                    )
                    if (
                        not token
                        or capture_mode not in {"local", "system-proxy"}
                        or debug not in {"off", "on", "global"}
                        or not valid_processes
                        or not isinstance(proxy_port, int)
                        or isinstance(proxy_port, bool)
                        or not (1 <= proxy_port <= 65535)
                        or not isinstance(upstream_proxy, str)
                        or not upstream_proxy.strip()
                        or not isinstance(stop_on_exit, bool)
                        or not isinstance(stop_on_exit_delay, int)
                        or isinstance(stop_on_exit_delay, bool)
                        or not (1 <= stop_on_exit_delay <= 3600)
                    ):
                        print(
                            encode_worker_message(
                                "config_metadata_updated",
                                token=token,
                                error="Malformed capture configuration metadata request.",
                            ),
                            flush=True,
                        )
                        continue
                    try:
                        capture_addon.store.update_capture_config_metadata(
                            str(capture_mode),
                            [str(item) for item in processes],
                            str(debug),
                            int(proxy_port),
                            str(upstream_proxy),
                            bool(stop_on_exit),
                            int(stop_on_exit_delay),
                        )
                    except Exception as exc:
                        print(
                            encode_worker_message("config_metadata_updated", token=token, error=str(exc)),
                            flush=True,
                        )
                    else:
                        print(encode_worker_message("config_metadata_updated", token=token), flush=True)
        except (OSError, ValueError):
            pass
        finally:
            # EOF means the parent process/control pipe disappeared. Shut down the
            # proxy as well so the worker cannot survive an abrupt parent exit when
            # Job Object setup was unavailable.
            try:
                event_loop.call_soon_threadsafe(master.shutdown)
            except RuntimeError:
                pass

    threading.Thread(target=worker_control_loop, name="nct-worker-control", daemon=True).start()

    await master.run()

def install_worker_stop_handler() -> None:
    if sys.platform != "win32" or not hasattr(signal, "SIGBREAK"):
        return

    def handle_sigbreak(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGBREAK, handle_sigbreak)

def worker_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--proxy-worker", action="store_true")
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--debug-worker", choices=("off", "on", "global"), required=True)
    args = parser.parse_args(argv)
    try:
        nct_runtime.join_worker_job_from_environment()
        install_worker_stop_handler()
        asyncio.run(
            run_proxy_worker(
                args.session.resolve(),
                args.mode,
                args.listen_port,
                args.debug_worker,
                manifest_path=args.manifest.resolve(),
            )
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except BaseException as exc:
        if (args.mode == "local" or args.mode.startswith("local:")) and _is_windivert_prior_unload_error(exc):
            print(
                encode_worker_message(
                    "startup_error",
                    reason=_windivert_prior_unload_message(),
                    detail=str(exc),
                    traceback=traceback.format_exc(),
                ),
                flush=True,
            )
            return 1
        print_console(f"ERROR: Capture worker failed: {exc}", flush=True, status_tokens=True)
        for line in traceback.format_exc().rstrip().splitlines():
            print(f"[Traceback] {line}", flush=True)
        return 1

from session import CaptureSession, UPSTREAM_AUTH_ENV

def install_termination_handlers(session: CaptureSession) -> None:
    global _CONSOLE_HANDLER
    if hasattr(signal, "SIGTERM"):
        def handle_sigterm(signum, frame):
            if session.end_reason is None:
                session.end_reason = "sigterm"
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, handle_sigterm)

    if sys.platform != "win32":
        return

    handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

    @handler_type
    def handler(event):
        if event == 0:  # CTRL_C_EVENT
            # Ninja Capture Tool is bundled as a windowed executable and attaches/allocates its
            # console at runtime. Windows resets the process control-handler table
            # when a console is attached or allocated, so falling through to the
            # default handler here can terminate the process before finally/atexit
            # cleanup runs. Convert Ctrl+C into the normal main-thread shutdown path.
            if session.end_reason is None:
                session.end_reason = "ctrl_c"
            session.shutdown_requested.set()
            return True
        if event in {2, 5, 6}:  # console close, logoff, system shutdown
            # Windows invokes this handler on a dedicated callback thread. Do not
            # tear down worker/process state from that thread while the main thread
            # is still inside start()/wait(). Request shutdown, then keep the handler
            # alive while the main thread performs the normal deterministic cleanup.
            reason = {2: "console_close", 5: "logoff", 6: "system_shutdown"}[event]
            session.request_console_shutdown(reason)
            session.shutdown_complete.wait(4.0)
            return True
        return False

    if not ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True):
        raise ctypes.WinError()
    _CONSOLE_HANDLER = handler

_STARTUP_CONFIG_POLL_SECONDS = 0.1
_STARTUP_CONFIG_DEBOUNCE_SECONDS = 0.5

def _load_startup_config_and_options(
    args: argparse.Namespace,
    *,
    path: Path = nct_config.CONFIG_FILE,
    poll_seconds: float = _STARTUP_CONFIG_POLL_SECONDS,
    debounce_seconds: float = _STARTUP_CONFIG_DEBOUNCE_SECONDS,
) -> tuple[dict[str, object], str, dict[str, object]]:
    """Wait for a broken config.json to become valid during an interactive capture launch."""
    wait_for_runtime_resolution = not nct_config.runtime_locked_config_keys(args)
    waiting = False
    candidate_signature = nct_config.config_file_signature(path)
    candidate_since = time.monotonic()
    last_attempted_signature: object = object()
    first_attempt = True

    while True:
        if not first_attempt:
            while True:
                time.sleep(poll_seconds)
                current_signature = nct_config.config_file_signature(path)
                now = time.monotonic()
                if current_signature != candidate_signature:
                    candidate_signature = current_signature
                    candidate_since = now
                if (
                    now - candidate_since >= debounce_seconds
                    and candidate_signature != last_attempted_signature
                ):
                    break
        first_attempt = False
        attempted_signature = candidate_signature
        stage = "load"
        try:
            config, startup_config_signature = nct_config.load_stable_config_snapshot(
                path,
                allow_empty_processes=args.process is not None,
            )
            stage = "resolve"
            options = nct_config.resolve_runtime_options(args, config)
        except (OSError, RuntimeError) as exc:
            if stage == "resolve" and not wait_for_runtime_resolution:
                raise
            nct_runtime.show_console_window()
            for detail in nct_config.describe_config_errors(exc):
                print_error(detail)
            if not waiting:
                print_console(
                    "[Config] Startup is paused until config.json is valid. "
                    "Changes are detected automatically."
                )
                waiting = True
            last_attempted_signature = attempted_signature
            continue

        if waiting:
            print_console("[Config] Configuration is valid. Continuing startup.")
            print_console("")
        return config, startup_config_signature, options

def _restore_interrupted_system_proxy() -> None:
    recovery = windows_proxy.restore_stale_recovery()
    if recovery == "restored":
        nct_runtime.show_console_window()
        print("[Recovery] Restored Windows proxy settings left by a previous interrupted System Proxy session.")
    elif recovery == "restored-kept":
        nct_runtime.show_console_window()
        print(
            "WARNING: Previous Windows proxy settings were restored successfully, but the proxy recovery record could not be removed.\n"
            f"[Recovery] Recovery data was kept at: {common.proxy_recovery_file()}"
        )
    elif recovery and recovery.startswith("unowned:"):
        nct_runtime.show_console_window()
        print(
            "[Recovery] Previous proxy recovery data no longer matched the current Windows proxy settings, so nothing was overwritten.\n"
            f"[Recovery] The old record was preserved at: {recovery.split(':', 1)[1]}"
        )

def _warn_stale_update_recovery_backups() -> None:
    preserved = stale_update_recovery_backups()
    if not preserved:
        return
    nct_runtime.show_console_window()
    for work in preserved:
        print_warning(
            "Preserved updater recovery data from a possible interrupted installation. "
            f"Review before deleting: {work}"
        )

def main(argv: list[str] | None = None) -> int:
    nct_runtime.restore_redirected_standard_streams()
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    warframe_worker_result = check_steam.handle_warframe_query_worker_request(actual_argv)
    if warframe_worker_result is not None:
        return warframe_worker_result
    steam_worker_result = check_steam.handle_steam_query_worker_request(actual_argv)
    if steam_worker_result is not None:
        return steam_worker_result
    invoked_from_elevation_task = False
    elevation_request_id: str | None = None
    elevation_acknowledged = False
    task_installed_now = False
    task_setup_messages: list[str] = []

    internal_arguments = {
        elevation.ELEVATION_TASK_RUN_ARGUMENT,
        elevation.INSTALL_ELEVATION_TASK_ARGUMENT,
    }
    if actual_argv[:1] == [elevation.ELEVATION_TASK_RUN_ARGUMENT]:
        if len(actual_argv) != 1:
            nct_runtime.show_console_window()
            print_error("Invalid elevation task arguments.")
            return 1
        try:
            invoked_from_elevation_task = True
            elevation_request_id = elevation.current_elevation_request_id()
            if sys.platform != "win32" or not elevation.is_elevated():
                raise RuntimeError("The Ninja Capture Tool elevation task did not start with administrator privileges.")
            actual_argv, task_installed_now, elevation_request_id = elevation.consume_elevation_request()
        except Exception as exc:
            if elevation_request_id is not None:
                try:
                    elevation.acknowledge_elevation_request(
                        elevation_request_id,
                        status="failed",
                        message=str(exc),
                    )
                    elevation_acknowledged = True
                except Exception:
                    pass
            nct_runtime.show_console_window()
            print_error(exc)
            return 1
    elif actual_argv == [elevation.INSTALL_ELEVATION_TASK_ARGUMENT]:
        try:
            if sys.platform != "win32" or not elevation.is_elevated():
                raise RuntimeError("Administrator privileges are required to install the elevation task.")
            elevation.install_elevation_task()
            return 0
        except Exception as exc:
            print_error(exc)
            return 1
    elif any(argument in internal_arguments for argument in actual_argv):
        nct_runtime.show_console_window()
        print_error("Invalid internal elevation arguments.")
        return 1

    if actual_argv[:1] == [UPDATE_INSTALLER_ARGUMENT]:
        return run_update_installer(actual_argv[1:])
    if UPDATE_INSTALLER_ARGUMENT in actual_argv:
        print_error("Invalid internal updater arguments.")
        return 1
    if "--proxy-worker" in actual_argv:
        return worker_main(actual_argv)
    smoke_test = os.environ.get("NCT_SMOKE_TEST") if os.environ.get(RELEASE_BUILD_ENV) == "1" else None
    if smoke_test == "frozen-capture":
        try:
            return capture.run_frozen_capture_smoke_test()
        except Exception as exc:
            print_error(f"Frozen capture smoke test failed: {exc}")
            return 1
    if sys.platform != "win32":
        print_error("Ninja Capture Tool currently supports Windows only.")
        return 1
    if any(
        argument in {
            "-h", "--help", "-U", "--check-update", "-v", "--version",
        }
        for argument in actual_argv
    ):
        nct_runtime.show_console_window()
    if any(argument in {"-r", "--remove-elevation-task"} for argument in actual_argv) and actual_argv not in (["-r"], ["--remove-elevation-task"]):
        nct_config.build_argument_parser().error("--remove-elevation-task must be used without other arguments")
    if any(argument in {"-C", "--remove-https-certificate"} for argument in actual_argv) and actual_argv not in (["-C"], ["--remove-https-certificate"]):
        nct_config.build_argument_parser().error("--remove-https-certificate must be used without other arguments")
    early_update_result = handle_early_update_request(actual_argv)
    if early_update_result is not None:
        return early_update_result

    parser = nct_config.build_argument_parser()
    args = parser.parse_args(actual_argv)
    try:
        if args.remove_elevation_task:
            nct_runtime.show_console_window()
            task_exists = elevation.elevation_task_exists()
            if task_exists and not elevation.is_elevated():
                return elevation.run_elevated_and_wait(
                    ["--remove-elevation-task"],
                    show_window=True,
                )
            if elevation.remove_elevation_task():
                print("Elevation task removed successfully.")
            else:
                print("Elevation task is not installed.")
            return 0

        if args.remove_https_certificate:
            nct_runtime.show_console_window()
            if not elevation.is_elevated():
                if another_capture_is_active():
                    raise RuntimeError(
                        "Cannot remove Ninja Capture Tool's HTTPS certificate while another capture is running."
                    )
                if elevation.elevation_task_is_current():
                    # For one-shot maintenance, the task acknowledgement is
                    # deliberately published only after CA removal completes.
                    elevation.launch_via_elevation_task(["--remove-https-certificate"])
                    return 0
                return elevation.run_elevated_and_wait(
                    ["--remove-https-certificate"],
                    show_window=True,
                )

            try:
                with capture_lock():
                    removed, had_files = nct_runtime.remove_mitmproxy_ca()

                    # Normal capture startup acknowledges as soon as the elevated
                    # process owns the capture lock because it is long-running.
                    # CA removal is a one-shot maintenance command, so its handoff
                    # acknowledgement means the requested operation actually
                    # completed successfully.
                    if invoked_from_elevation_task:
                        if elevation_request_id is None:
                            raise RuntimeError("Missing elevation handoff request identifier.")
                        elevation.acknowledge_elevation_request(elevation_request_id)
                        elevation_acknowledged = True
            except CaptureBusyError as exc:
                raise RuntimeError(
                    "Cannot remove Ninja Capture Tool's HTTPS certificate while another capture is running."
                ) from exc

            if not had_files:
                print("Shared HTTPS certificate files are not present; no exact Ninja Capture Tool certificate could be identified for removal.")
            elif removed:
                print("HTTPS certificate trust and shared CA files removed successfully.")
            else:
                print("Shared HTTPS CA files removed; the certificate was not present in the Windows trusted root stores.")
            return 0

        # Every interactive capture runtime is elevated, independent of the
        # selected capture mode. This happens before config.json is read so an
        # invalid config can remain visible, wait for edits, and later switch to
        # any capture mode without crossing a privilege boundary.
        if not elevation.is_elevated():
            if another_capture_is_active():
                return 0
            if elevation.elevation_task_is_current():
                try:
                    elevation.launch_via_elevation_task(actual_argv)
                    return 0
                except RuntimeError as exc:
                    print_warning(f"Elevation task could not start; falling back to UAC: {exc}")
            # First run, a stale task, or a task that could not be launched: run the
            # actual capture process through UAC. The elevated runtime repairs the
            # convenience task for future launches, but task setup is never allowed
            # to prevent the current capture from starting.
            return elevation.run_elevated_and_wait(actual_argv, show_window=True)

        try:
            with capture_lock():
                # The task launcher trusts only a matching acknowledgement.
                # Publish it immediately after the elevated process owns the capture
                # lock, before config validation can intentionally wait for the user.
                if invoked_from_elevation_task:
                    if elevation_request_id is None:
                        raise RuntimeError("Missing elevation handoff request identifier.")
                    elevation.acknowledge_elevation_request(elevation_request_id)
                    elevation_acknowledged = True

                if not invoked_from_elevation_task and not elevation.elevation_task_is_current():
                    try:
                        elevation.install_elevation_task()
                    except RuntimeError as exc:
                        task_setup_messages.append(
                            "WARNING: Could not install the Ninja Capture Tool elevation task; "
                            f"future launches may require UAC: {exc}"
                        )
                    else:
                        task_installed_now = True

                # Repair a proxy left by an interrupted System Proxy capture before
                # config validation, update checks, or live Warframe/Steam network
                # activity. The capture lock guarantees another Ninja Capture Tool capture cannot
                # own this per-user recovery record concurrently.
                _restore_interrupted_system_proxy()

                _warn_stale_update_recovery_backups()

                try:
                    config, startup_config_signature, options = _load_startup_config_and_options(args)
                except KeyboardInterrupt:
                    return 0

                mode = str(options["capture_mode"])
                nct_runtime.show_console_window()
                session = None
                try:
                    # Classic Windows QuickEdit can pause any synchronous console write. Suspend
                    # it from the moment the capture console becomes visible until the worker is
                    # fully ready, then restore the user's exact original console mode. Once the
                    # worker is active, its output is already decoupled from console rendering.
                    with nct_runtime.suspend_console_quick_edit():
                        duplicate_count, cleaned_config_signature = nct_config.clean_duplicate_config_processes(
                            nct_config.CONFIG_FILE,
                            expected_signature=startup_config_signature,
                        )
                        if cleaned_config_signature is not None:
                            startup_config_signature = cleaned_config_signature
                        if duplicate_count:
                            print_console("")
                        nct_runtime.set_console_title(mode)
                        nct_runtime.ensure_local_capture_compatible(options)
                        update_result = handle_automatic_update(
                            args, actual_argv, bool(config["auto_update"])
                        )
                        if update_result is not None:
                            return update_result

                        validate_mitmproxy_installation()
                        validate_windows_capture_package()

                        setup_messages = list(task_setup_messages)
                        if task_installed_now:
                            setup_messages.insert(0, "Elevation task installed successfully.")
                        session = CaptureSession(
                            options,
                            setup_messages or None,
                        )
                        session.enable_config_reload(
                            args,
                            initial_signature=startup_config_signature,
                        )
                        atexit.register(session.cleanup)
                        install_termination_handlers(session)
                        session.start()
                    session.wait()
                except KeyboardInterrupt:
                    if session is None:
                        raise
                    if session.end_reason is None:
                        session.end_reason = "ctrl_c"
                except Exception as exc:
                    if session is not None:
                        session.failed = True
                        session.failure_reason = str(exc)
                    raise
                finally:
                    if session is not None:
                        session.cleanup()
                if session.failed is True:
                    return 1
        except CaptureBusyError:
            if invoked_from_elevation_task and elevation_request_id is not None:
                elevation.acknowledge_elevation_request(elevation_request_id, status="busy")
                elevation_acknowledged = True
            return 0
        return 0
    except Exception as exc:
        if invoked_from_elevation_task and elevation_request_id is not None and not elevation_acknowledged:
            try:
                elevation.acknowledge_elevation_request(
                    elevation_request_id,
                    status="failed",
                    message=str(exc),
                )
            except Exception:
                pass
        nct_runtime.show_console_window()
        print_error(exc)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
