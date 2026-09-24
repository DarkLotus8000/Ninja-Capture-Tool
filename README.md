# Ninja Capture Tool

Capture Warframe CDN responses for OpenWF. Can be used to make **Update Patches** or capture **Stripped Assets**.

## Requirements

- Windows 10 (64-bit) or newer
- Python 3.14 (not required for release executable)

May not work on other operating systems through Wine.

```text
py -3.14 -m pip install -r requirements.txt
py -3.14 ninja_capture_tool.py
```

Building a release additionally requires PyInstaller.

## Usage

```text
NinjaCaptureTool.exe [options]
```

Local Capture is the default and captures `Launcher.exe` and `Warframe.x64.exe`. Captures are saved under `output/`. Press `Ctrl+R` to start a new capture session.

Don't use Process Monitor while using Local Capture, to prevent crashing. If Local Capture cannot be used or noticeably reduces network bandwidth on your system, use `-m system-proxy` instead.

Persistent settings are stored in `config.json`; command-line options override them for the current run.

For an **Update Patch**, start from the original, unupdated Steam manifest base for that content update and make sure to download files for all languages & DirectX versions by changing the launcher settings and letting it finish downloading. Consider keeping a separate untouched copy of the Steam base so it can be reused for later Update Patches without downloading the full base again. Capturing **Stripped Assets** from an already updated installation does not require an original Steam base. If needed, a registered base can be checked first with [Ninja Patch Tool's `verify_base`](https://github.com/DarkLotus8000/Ninja-Patch-Tool#verify-a-base) command.

## Options

- `-m, --capture-mode {local,system-proxy}` - Capture mode
- `-p, --process EXE` - Executable to capture in Local Capture; use once per process
- `-s, --stop-on-exit` - Stop after all selected Local Capture processes remain closed for the configured delay
- `-S, --no-stop-on-exit` - Disable automatic stopping when selected processes exit
- `-w, --stop-on-exit-delay SECONDS` - Automatic stop delay, from 1 to 3600 seconds
- `-P, --port PORT` - Local proxy port for System Proxy mode
- `-o, --output DIRECTORY` - Exact capture output directory for this run
- `-V, --version-session-name` - Name automatic session directories after the current Warframe version
- `-d, --debug [global]` - Enable debug logging; `global` logs all connections in Local Capture
- `-D, --no-debug` - Disable debug logging
- `-i, --live-check-interval SECONDS` - Seconds between live Warframe/Steam checks
- `-u, --upstream-proxy PROXY` - System Proxy upstream: `auto`, `direct`, `host:port`, or `http(s)://[user:pass@]host:port`
- `-r, --remove-elevation-task` - Remove Ninja Capture Tool's elevation task and exit; use by itself
- `-C, --remove-https-certificate` - Remove Ninja Capture Tool's HTTPS certificate and related files and exit; use by itself
- `-a, --auto-update` - Force an automatic update check/install for this run
- `-n, --no-auto-update` - Disable automatic updating for this run
- `-U, --check-update` - Check GitHub Releases for a newer version without installing it
- `-v, --version` - Show the Ninja Capture Tool version
- `-h, --help` - Show the help message

## Build a release

Set `VERSION` in `common.py`, then run:

```bat
py -3.14 -m pip install pyinstaller
py -3.14 build_release.py
```

Add `-e` / `--extract` to also extract the completed release ZIP beside the archive while still producing the normal ZIP and SHA-256 checksum:

```bat
py -3.14 build_release.py -e
```

Upload both generated files to the matching GitHub Release (`vVERSION`):

```text
NinjaCaptureTool-vVERSION-Windows-x64.zip
NinjaCaptureTool-vVERSION-Windows-x64.zip.sha256
```

The updater requires both release assets.
