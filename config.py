#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
import time
import json
import sys
from pathlib import Path

from common import TOOL_DIR, display_version, parse_json

DEFAULT_CONFIG: dict[str, object] = {
    "capture_mode": "local",
    "processes": ["Launcher.exe", "Warframe.x64.exe"],
    "stop_on_exit": False,
    "stop_on_exit_delay": 15,
    "proxy_port": 8080,
    "debug": False,
    "output_root": "output",
    "name_session_after_warframe_version": False,
    "live_check_interval_seconds": 300,
    "upstream_proxy": "auto",
    "auto_update": True,
}

def validate_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError
    if not 1 <= value <= 65535:
        raise ValueError
    return value

def validate_stop_on_exit_delay(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError
    if not 1 <= value <= 3600:
        raise ValueError
    return value

def validate_live_check_interval_seconds(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError
    try:
        float(value)
    except OverflowError:
        raise ValueError from None
    return value

def validate_processes(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ValueError
        process = item.strip()
        if not process or "," in process or "/" in process or "\\" in process:
            raise ValueError
        # Process names are user data, not config keywords. Preserve their exact
        # spelling/casing and only collapse exact duplicates.
        if process not in seen:
            seen.add(process)
            result.append(process)
    if not result:
        raise ValueError
    return result

def _canonical_config_keyword(value: object, accepted: set[str]) -> object:
    if not isinstance(value, str):
        return value
    normalized = value.strip().casefold()
    return normalized if normalized in accepted else value

def canonicalize_upstream_proxy_keyword(value: object) -> object:
    if not isinstance(value, str):
        return value
    normalized = value.strip().casefold()
    if normalized in {"auto", "direct"}:
        return normalized
    return value

def normalize_config_keywords(config: dict[str, object]) -> None:
    config["capture_mode"] = _canonical_config_keyword(config.get("capture_mode"), {"local", "system-proxy"})
    config["debug"] = _canonical_config_keyword(config.get("debug"), {"global"})
    config["upstream_proxy"] = canonicalize_upstream_proxy_keyword(config.get("upstream_proxy"))

def _casefold_cli_keyword(value: str) -> str:
    return value.strip().casefold()

class ConfigValidationError(RuntimeError):
    def __init__(self, messages: list[str] | tuple[str, ...]) -> None:
        self.messages = tuple(str(message) for message in messages if str(message).strip())
        super().__init__("\n".join(self.messages))

def validate_config(config: dict[str, object], *, allow_empty_processes: bool = False) -> None:
    from common import validate_session_path_syntax
    errors: list[str] = []

    if config.get("capture_mode") not in {"local", "system-proxy"}:
        errors.append('config.json \"capture_mode\" must be \"local\" or \"system-proxy\".')

    processes = config.get("processes")
    if not (allow_empty_processes and processes == []):
        try:
            validate_processes(processes)
        except ValueError:
            errors.append('config.json "processes" must contain at least one executable.')

    stop_on_exit = config.get("stop_on_exit")
    if not isinstance(stop_on_exit, bool):
        errors.append("config.json stop_on_exit must be true or false.")

    try:
        validate_stop_on_exit_delay(config.get("stop_on_exit_delay"))
    except ValueError:
        errors.append("config.json stop_on_exit_delay must be a number from 1 to 3600 seconds.")

    try:
        validate_port(config.get("proxy_port"))
    except ValueError:
        errors.append("config.json proxy_port must be a number from 1 to 65535.")

    debug = config.get("debug")
    if not isinstance(debug, bool) and debug != "global":
        errors.append('config.json debug must be true, false, or "global".')

    output = config.get("output_root")
    if not isinstance(output, str) or not output.strip():
        errors.append("config.json output_root must be a non-empty string.")
    else:
        try:
            validate_session_path_syntax(
                output,
                "config.json output_root",
                require_child=False,
                reserve_temp_name=False,
            )
        except ValueError as exc:
            errors.append(str(exc))

    version_naming = config.get("name_session_after_warframe_version")
    if not isinstance(version_naming, bool):
        errors.append("config.json name_session_after_warframe_version must be true or false.")

    try:
        validate_live_check_interval_seconds(config.get("live_check_interval_seconds"))
    except ValueError:
        errors.append("config.json live_check_interval_seconds must be a positive number.")

    upstream = config.get("upstream_proxy")
    if not isinstance(upstream, str) or not upstream.strip():
        errors.append("config.json upstream_proxy must be 'auto', 'direct', or a proxy address.")

    if not isinstance(config.get("auto_update"), bool):
        errors.append("config.json auto_update must be true or false.")

    if errors:
        raise ConfigValidationError(errors)

def load_config_content(
    data: str | bytes,
    *,
    path: Path | None = None,
    allow_empty_processes: bool = False,
) -> dict[str, object]:
    if path is None:
        from common import TOOL_DIR as common_tool_dir
        path = common_tool_dir / "config.json"
    try:
        value = parse_json(data)
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError(f"Could not read config file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("config.json must contain a JSON object.")
    errors: list[str] = []
    unknown = sorted(set(value) - set(DEFAULT_CONFIG))
    if unknown:
        errors.append(f"Unknown config option(s): {', '.join(unknown)}")
    config = dict(DEFAULT_CONFIG)
    config.update(value)
    normalize_config_keywords(config)
    try:
        validate_config(config, allow_empty_processes=allow_empty_processes)
    except ConfigValidationError as exc:
        errors.extend(exc.messages)
    if errors:
        raise ConfigValidationError(errors)
    return config

def load_config(path: Path | None = None, *, allow_empty_processes: bool = False, create_if_missing: bool = True) -> dict[str, object]:
    from common import atomic_write_json
    if path is None:
        from common import TOOL_DIR as common_tool_dir
        path = common_tool_dir / "config.json"
    if not path.exists():
        if not create_if_missing:
            raise RuntimeError(f"Config file does not exist: {path}")
        atomic_write_json(path, DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read config file {path}: {exc}") from exc
    return load_config_content(data, path=path, allow_empty_processes=allow_empty_processes)

def validate_cli_port(value: str) -> int:
    try:
        port = int(value)
        return validate_port(port)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("port must be a number from 1 to 65535") from None

def validate_cli_stop_on_exit_delay(value: str) -> int:
    try:
        seconds = int(value)
        return validate_stop_on_exit_delay(seconds)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("delay must be a number from 1 to 3600 seconds") from None

def validate_cli_live_check_interval(value: str) -> int:
    try:
        seconds = int(value)
        return validate_live_check_interval_seconds(seconds)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("interval must be a positive number") from None

class SingleUseStoreAction(argparse.Action):
    """Store an option value, but reject repeated use of either alias."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values, option_string: str | None = None) -> None:
        marker = f"_single_use_seen_{self.dest}"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} cannot be used more than once (including its short/long alias)")
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, values)

class SingleUseStoreTrueAction(argparse.Action):
    """Store True, but reject repeated use of either alias."""

    def __init__(self, option_strings, dest, default=False, required=False, help=None):
        super().__init__(option_strings=option_strings, dest=dest, nargs=0, default=default, required=required, help=help)

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values, option_string: str | None = None) -> None:
        marker = f"_single_use_seen_{self.dest}"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} cannot be used more than once (including its short/long alias)")
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, True)

class SingleUseStoreFalseAction(argparse.Action):
    """Store False, but reject repeated use of either alias."""

    def __init__(self, option_strings, dest, default=None, required=False, help=None):
        super().__init__(option_strings=option_strings, dest=dest, nargs=0, default=default, required=required, help=help)

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values, option_string: str | None = None) -> None:
        marker = f"_single_use_seen_{self.dest}"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} cannot be used more than once (including its short/long alias)")
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, False)

class CompactHelpFormatter(argparse.HelpFormatter):
    """Keep wrapped usage and option descriptions compact."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=37)

    def _format_usage(self, usage, actions, groups, prefix):
        text = super()._format_usage(usage, actions, groups, prefix)
        lines = text.splitlines(keepends=True)
        for index in range(1, len(lines)):
            if lines[index].strip():
                lines[index] = lines[index].lstrip()
        return "".join(lines)

    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        metavar = self._format_args(action, self._get_default_metavar_for_optional(action))
        return f"{', '.join(action.option_strings)} {metavar}"

class ErrorArgumentParser(argparse.ArgumentParser):
    """Keep argparse startup errors and help text consistent with Ninja Capture Tool's CLI style."""

    def __init__(self, *args, **kwargs) -> None:
        kwargs.setdefault("formatter_class", CompactHelpFormatter)
        super().__init__(*args, **kwargs)
        self.suggest_on_error = True
        self.color = False

    def add_version_argument(self) -> None:
        self.add_argument(
            "-v",
            "--version",
            action="version",
            version=f"Ninja Capture Tool v{display_version()}",
            help="Shows the Ninja Capture Tool version",
        )

    def add_help_argument(self) -> None:
        self.add_argument("-h", "--help", action="help", help="Shows this help message")

    def error(self, message: str) -> None:
        # Frozen Ninja Capture Tool uses PyInstaller's windowed mode, so an invalid command line
        # can reach argparse before a console has been attached. Make every parser
        # error visible before writing usage/error text instead of trying to predict
        # which invalid argument combinations need a console in the entry point.
        from runtime import show_console_window
        show_console_window()
        self.print_usage(sys.stderr)
        if message[:1].islower():
            message = message[0].upper() + message[1:]
        from common import print_error
        print_error(message)
        self.exit(2)

def build_argument_parser() -> argparse.ArgumentParser:
    parser = ErrorArgumentParser(
        description="Capture Warframe CDN responses for OpenWF.",
        add_help=False,
    )
    parser.add_argument(
        "-m",
        "--capture-mode",
        type=_casefold_cli_keyword,
        choices=("local", "system-proxy"),
        default=None,
        action=SingleUseStoreAction,
        help="Capture mode (overrides config.json; default config uses local)",
    )
    parser.add_argument(
        "-p",
        "--process",
        action="append",
        default=None,
        metavar="EXE",
        help="Executable to capture in local mode; use once per process (overrides config.json)",
    )
    stop_group = parser.add_mutually_exclusive_group()
    stop_group.add_argument(
        "-s",
        "--stop-on-exit",
        dest="stop_on_exit",
        action=SingleUseStoreTrueAction,
        default=None,
        help="Stop Local Capture after all selected processes remain absent for the configured delay (overrides config.json)",
    )
    stop_group.add_argument(
        "-S",
        "--no-stop-on-exit",
        dest="stop_on_exit",
        action=SingleUseStoreFalseAction,
        default=None,
        help="Disable automatic stopping when selected Local Capture processes exit (overrides config.json)",
    )
    parser.add_argument(
        "-w",
        "--stop-on-exit-delay",
        type=validate_cli_stop_on_exit_delay,
        default=None,
        action=SingleUseStoreAction,
        metavar="SECONDS",
        help="Seconds selected processes must remain absent before automatic stop, from 1 to 3600 (overrides config.json)",
    )
    parser.add_argument(
        "-P",
        "--port",
        dest="proxy_port",
        type=validate_cli_port,
        default=None,
        action=SingleUseStoreAction,
        metavar="PORT",
        help="Local proxy port for system-proxy mode (overrides config.json)",
    )
    naming_group = parser.add_mutually_exclusive_group()
    naming_group.add_argument(
        "-o",
        "--output",
        default=None,
        action=SingleUseStoreAction,
        metavar="DIRECTORY",
        help="Exact capture output directory for this run",
    )
    naming_group.add_argument(
        "-V",
        "--version-session-name",
        action=SingleUseStoreTrueAction,
        help="Name automatic session directories after the current Warframe version (overrides config.json)",
    )
    debug_group = parser.add_mutually_exclusive_group()
    debug_group.add_argument(
        "-d",
        "--debug",
        nargs="?",
        const=True,
        type=_casefold_cli_keyword,
        choices=("global",),
        default=None,
        action=SingleUseStoreAction,
        metavar="global",
        help='Enable normal debug logging, or use "global" in Local Capture to log all connections (overrides config.json)',
    )
    debug_group.add_argument(
        "-D",
        "--no-debug",
        dest="debug",
        action=SingleUseStoreFalseAction,
        default=None,
        help="Disable debug logging (overrides config.json)",
    )
    parser.add_argument(
        "-i",
        "--live-check-interval",
        dest="live_check_interval_seconds",
        type=validate_cli_live_check_interval,
        default=None,
        action=SingleUseStoreAction,
        metavar="SECONDS",
        help="Seconds between live Warframe/Steam checks (overrides config.json)",
    )
    parser.add_argument(
        "-u",
        "--upstream-proxy",
        default=None,
        action=SingleUseStoreAction,
        metavar="PROXY",
        help="System-proxy mode upstream: auto, direct, host:port, or http(s)://[user:pass@]host:port (overrides config.json)",
    )
    parser.add_argument(
        "-r",
        "--remove-elevation-task",
        action=SingleUseStoreTrueAction,
        help="Remove Ninja Capture Tool's elevation task and exit; must be used by itself",
    )
    parser.add_argument(
        "-C",
        "--remove-https-certificate",
        action=SingleUseStoreTrueAction,
        help="Remove Ninja Capture Tool's HTTPS certificate and related files and exit; must be used by itself",
    )
    update_group = parser.add_mutually_exclusive_group()
    update_group.add_argument(
        "-a",
        "--auto-update",
        action=SingleUseStoreTrueAction,
        help="Force an automatic update check/install for this run",
    )
    update_group.add_argument(
        "-n",
        "--no-auto-update",
        action=SingleUseStoreTrueAction,
        help="Disable automatic updating for this run",
    )
    update_group.add_argument(
        "-U",
        "--check-update",
        action=SingleUseStoreTrueAction,
        help="Check GitHub Releases for a newer version without installing it",
    )
    parser.add_version_argument()
    parser.add_help_argument()
    return parser

def runtime_locked_config_keys(args: argparse.Namespace) -> set[str]:
    """Return config fields whose live value is fixed by CLI arguments for this session."""
    locked: set[str] = set()
    if args.capture_mode is not None:
        locked.add("capture_mode")
    if args.process is not None:
        locked.add("processes")
    if args.stop_on_exit is not None:
        locked.add("stop_on_exit")
    if args.stop_on_exit_delay is not None:
        locked.add("stop_on_exit_delay")
    if args.proxy_port is not None:
        locked.add("proxy_port")
    if args.upstream_proxy is not None:
        locked.add("upstream_proxy")
    if args.debug is not None and args.debug != "global":
        locked.add("debug")
    if getattr(args, "live_check_interval_seconds", None) is not None:
        locked.add("live_check_interval_seconds")
    if args.output is not None:
        locked.update({"output_root", "name_session_after_warframe_version"})
    if getattr(args, "version_session_name", False):
        locked.add("name_session_after_warframe_version")
    return locked

def resolve_runtime_options(args: argparse.Namespace, config: dict[str, object]) -> dict[str, object]:
    from common import TOOL_DIR as common_tool_dir, resolve_session_output_path
    mode = args.capture_mode if args.capture_mode is not None else str(config["capture_mode"])
    mode_pinned = args.capture_mode is not None
    if args.stop_on_exit is False and args.stop_on_exit_delay is not None:
        raise RuntimeError("--stop-on-exit-delay cannot be used with --no-stop-on-exit.")
    if mode_pinned:
        if mode == "local":
            if args.proxy_port is not None:
                raise RuntimeError("--port can only be used with System Proxy mode.")
            if args.upstream_proxy is not None:
                raise RuntimeError("--upstream-proxy can only be used with System Proxy mode.")
        else:
            if args.process is not None:
                raise RuntimeError("--process can only be used with Local Capture mode.")
            if args.stop_on_exit is not None:
                option = "--stop-on-exit" if args.stop_on_exit else "--no-stop-on-exit"
                raise RuntimeError(f"{option} can only be used with Local Capture mode.")
            if args.stop_on_exit_delay is not None:
                raise RuntimeError("--stop-on-exit-delay can only be used with Local Capture mode.")

    try:
        processes = validate_processes(args.process if args.process is not None else config["processes"])
    except ValueError:
        raise RuntimeError(
            'No capture processes configured.\nAdd at least one executable to "processes" in config.json or use --process.'
        ) from None
    stop_on_exit = args.stop_on_exit if args.stop_on_exit is not None else bool(config["stop_on_exit"])
    stop_on_exit_delay = (
        args.stop_on_exit_delay
        if args.stop_on_exit_delay is not None
        else validate_stop_on_exit_delay(config["stop_on_exit_delay"])
    )
    if mode == "local" and args.stop_on_exit_delay is not None and not stop_on_exit:
        raise RuntimeError("--stop-on-exit-delay requires --stop-on-exit or config.json stop_on_exit=true.")
    proxy_port = args.proxy_port if args.proxy_port is not None else validate_port(config["proxy_port"])
    if args.debug == "global" and mode != "local" and not mode_pinned:
        debug = config["debug"]
    else:
        debug = args.debug if args.debug is not None else config["debug"]
    if debug == "global" and mode != "local":
        raise RuntimeError('Global debug requires Local Capture because System Proxy only observes applications that use the Windows proxy.')
    upstream = args.upstream_proxy if args.upstream_proxy is not None else str(config["upstream_proxy"])
    cli_live_check_interval = getattr(args, "live_check_interval_seconds", None)
    live_check_interval = (
        cli_live_check_interval
        if cli_live_check_interval is not None
        else validate_live_check_interval_seconds(config["live_check_interval_seconds"])
    )
    version_session_name = bool(
        getattr(args, "version_session_name", False)
        or (args.output is None and config["name_session_after_warframe_version"])
    )

    try:
        output_root = resolve_session_output_path(
            str(config["output_root"]),
            common_tool_dir,
            "config.json output_root",
            require_child=False,
            reserve_temp_name=False,
        )
    except (RuntimeError, ValueError) as exc:
        raise RuntimeError(str(exc)) from None

    output_path: Path | None = None
    if args.output is not None:
        try:
            output_path = resolve_session_output_path(
                args.output,
                common_tool_dir,
                "--output path",
                reject_existing_reparse=True,
            )
        except ValueError as exc:
            raise RuntimeError(str(exc)) from None

    return {
        "capture_mode": mode,
        "processes": processes,
        "stop_on_exit": stop_on_exit if mode == "local" else False,
        "stop_on_exit_delay": stop_on_exit_delay,
        "proxy_port": proxy_port,
        "debug": debug,
        "output_root": output_root.resolve(),
        "output_path": output_path,
        "name_session_after_warframe_version": version_session_name,
        "live_check_interval_seconds": live_check_interval,
        "upstream_proxy": canonicalize_upstream_proxy_keyword(upstream.strip()),
        "auto_update": bool(config["auto_update"]),
    }

CONFIG_FILE = TOOL_DIR / "config.json"

def describe_config_errors(exc: Exception) -> list[str]:
    """Return concise user-facing descriptions for one config load/reload failure."""
    if isinstance(exc, ConfigValidationError):
        return [message.strip().rstrip(".") for message in exc.messages]
    text = str(exc).strip()
    if text.startswith("Could not read config file"):
        cause = exc.__cause__
        if isinstance(cause, ValueError):
            detail = str(cause).strip()
            return [f"invalid JSON: {detail}" if detail else "invalid JSON"]
        return ["config.json could not be read"]
    if text.startswith("Config file does not exist"):
        return ["config.json is missing"]
    if text.startswith("No capture processes configured"):
        return ['"processes" must contain at least one executable']
    return [text.rstrip(".")]

class ConfigApplyError(RuntimeError):
    def __init__(self, message: str, *, rollback_restored: bool) -> None:
        super().__init__(message)
        self.rollback_restored = rollback_restored

def config_file_signature(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None

class ConfigSnapshotChanged(RuntimeError):
    pass

def load_exact_config_snapshot(
    path: Path,
    *,
    allow_empty_processes: bool = False,
    create_if_missing: bool = False,
) -> tuple[dict[str, object], str]:
    """Load, hash, and validate one exact byte snapshot of config.json."""
    from common import atomic_write_json
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        if not create_if_missing:
            raise RuntimeError(f"Config file does not exist: {path}") from None
        atomic_write_json(path, DEFAULT_CONFIG)
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"Could not read config file {path}: {exc}") from exc

    signature = hashlib.sha256(data).hexdigest()
    # Do not parse a snapshot that is already obsolete. This also avoids surfacing
    # transient invalid JSON from editors that write config.json in place.
    if config_file_signature(path) != signature:
        raise ConfigSnapshotChanged
    config = load_config_content(
        data,
        path=path,
        allow_empty_processes=allow_empty_processes,
    )
    # Validation can take long enough for another save to land. The parsed object
    # and returned signature are accepted only while these exact bytes remain current.
    if config_file_signature(path) != signature:
        raise ConfigSnapshotChanged
    return config, signature

def load_stable_config_snapshot(
    path: Path = CONFIG_FILE,
    *,
    allow_empty_processes: bool = False,
    create_if_missing: bool = True,
    max_attempts: int = 20,
) -> tuple[dict[str, object], str]:
    """Load a stable config snapshot whose parsed data and hash share the same bytes."""
    for _ in range(max_attempts):
        try:
            return load_exact_config_snapshot(
                path,
                allow_empty_processes=allow_empty_processes,
                create_if_missing=create_if_missing,
            )
        except ConfigSnapshotChanged:
            time.sleep(0.025)
    raise RuntimeError(
        "config.json kept changing while Ninja Capture Tool was starting. "
        "Wait for the file to finish saving and try again."
    )

def clean_duplicate_config_processes(
    path: Path,
    *,
    expected_signature: str,
    emit=None,
) -> tuple[int, str | None]:
    """Remove duplicate process entries without overwriting a newer config edit."""
    if emit is None:
        from common import print_console
        emit = print_console
    try:
        original_bytes = path.read_bytes()
    except OSError:
        return 0, None
    if hashlib.sha256(original_bytes).hexdigest() != expected_signature:
        return 0, None

    try:
        raw = parse_json(original_bytes)
    except (TypeError, ValueError):
        return 0, None
    if not isinstance(raw, dict) or "processes" not in raw:
        return 0, None
    original_processes = raw.get("processes")
    if not isinstance(original_processes, list):
        return 0, None
    try:
        cleaned_processes = validate_processes(original_processes)
    except ValueError:
        return 0, None
    duplicate_count = len(original_processes) - len(cleaned_processes)
    if duplicate_count <= 0:
        return 0, None

    noun = "entry" if duplicate_count == 1 else "entries"
    if duplicate_count == 1:
        emit("[Config] Duplicate process entry detected; cleaning config.json.")
    else:
        emit(f"[Config] {duplicate_count} duplicate process entries detected; cleaning config.json.")
    raw["processes"] = cleaned_processes
    serialized = (json.dumps(raw, indent=4, ensure_ascii=False) + "\n").encode("utf-8")
    temporary: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Prepare the replacement first, then make the last possible comparison
        # with the user's file immediately before the atomic replace. This cannot
        # eliminate an uncooperative editor race completely, but it minimizes the
        # compare-to-replace window.
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        if path.read_bytes() != original_bytes:
            emit("WARNING: config.json changed again before duplicate cleanup; leaving the newer file untouched.")
            return duplicate_count, None
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        emit(f"WARNING: Could not clean duplicate process {noun} from config.json: {exc}")
        return duplicate_count, None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    emit(f"[Config] Removed {duplicate_count} duplicate process {noun} from config.json.")
    return duplicate_count, hashlib.sha256(serialized).hexdigest()
