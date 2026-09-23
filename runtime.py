#!/usr/bin/env python3
from __future__ import annotations

import atexit
import ctypes
import hashlib
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import common
import elevation

WORKER_JOB_ENV = "NCT_WORKER_JOB_NAME"
_CONSOLE_CREATED_BY_NCT = False
_CONSOLE_TITLE_ORIGINAL: str | None = None
_CONSOLE_TITLE_SET = False

class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]

class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]

class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]

def create_worker_job() -> tuple[object | None, str | None]:
    if sys.platform != "win32":
        return None, None
    job = None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        name = f"Local\\DarkLotus.NinjaCaptureTool.worker.{os.getpid()}.{time.time_ns()}"
        job = kernel32.CreateJobObjectW(None, name)
        if not job:
            return None, None
        info = _JobObjectExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.CloseHandle(job)
            return None, None
        return job, name
    except (AttributeError, OSError, TypeError, ValueError):
        if job:
            try:
                ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(job)
            except (AttributeError, OSError, TypeError, ValueError):
                pass
        return None, None

def join_worker_job_from_environment() -> None:
    name = os.environ.pop(WORKER_JOB_ENV, None)
    if not name or sys.platform != "win32":
        return
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenJobObjectW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenJobObjectW.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.OpenJobObjectW(0x0001, False, name)  # JOB_OBJECT_ASSIGN_PROCESS
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(job)

def close_worker_job(job) -> None:
    if sys.platform != "win32" or not job:
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle(job)
    except (AttributeError, OSError, TypeError, ValueError):
        pass

def terminate_process_tree(process: subprocess.Popen, timeout: float = 2.0) -> bool:
    if sys.platform != "win32" or process.poll() is not None:
        return process.poll() is not None
    try:
        result = subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return process.poll() is not None
    return result.returncode == 0 or process.poll() is not None

def mitmproxy_ca_certificate_path() -> Path | None:
    for name in ("mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.pem"):
        path = common.mitmproxy_conf_directory() / name
        if path.is_file():
            return path
    return None

def _mitmproxy_ca_private_path() -> Path:
    return common.mitmproxy_conf_directory() / "mitmproxy-ca.pem"

def _file_is_nonempty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False

def _mitmproxy_ca_file_status() -> tuple[str, Path | None]:
    certificate = mitmproxy_ca_certificate_path()
    private_ca = _mitmproxy_ca_private_path()
    if certificate is None and not private_ca.exists():
        return "missing", None
    if certificate is None or not _file_is_nonempty(certificate) or not _file_is_nonempty(private_ca):
        return "incomplete", certificate
    try:
        certificate_der = _certificate_der_bytes(certificate)
        private_der = _certificate_der_bytes(private_ca)
    except (OSError, UnicodeError, ValueError):
        return "incomplete", certificate
    if not certificate_der or not private_der or certificate_der != private_der:
        return "incomplete", certificate
    return "complete", certificate

def _raise_incomplete_mitmproxy_ca() -> None:
    conf_dir = common.mitmproxy_conf_directory()
    raise RuntimeError(
        "Ninja Capture Tool's shared HTTPS certificate files are incomplete or inconsistent.\n"
        f"Directory: {conf_dir}\n"
        "Run Ninja Capture Tool with --remove-https-certificate to remove the exact stored CA identity or identities safely, "
        "then start Ninja Capture Tool again to generate a new certificate."
    )

def _certificate_der_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        match = re.search(
            br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            data,
            flags=re.DOTALL,
        )
        if match is None:
            raise ValueError(f"HTTPS certificate PEM data is incomplete: {path}")
        return ssl.PEM_cert_to_DER_cert(match.group(0).decode("ascii"))
    return data

def _mitmproxy_ca_identity_paths() -> list[Path]:
    conf_dir = common.mitmproxy_conf_directory()
    candidates = [
        conf_dir / "mitmproxy-ca-cert.cer",
        conf_dir / "mitmproxy-ca-cert.pem",
        _mitmproxy_ca_private_path(),
    ]
    identities: dict[bytes, Path] = {}
    for path in candidates:
        if not _file_is_nonempty(path):
            continue
        try:
            encoded = _certificate_der_bytes(path)
        except (OSError, UnicodeError, ValueError):
            continue
        if encoded:
            identities.setdefault(encoded, path)
    return list(identities.values())

def _certificate_is_trusted_in_root_store(certificate: Path, location_flag: int) -> bool:
    encoded = _certificate_der_bytes(certificate)
    if not encoded:
        return False

    class _CryptHashBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    digest = hashlib.sha1(encoded, usedforsecurity=False).digest()
    digest_buffer = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
    blob = _CryptHashBlob(len(digest), digest_buffer)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CertOpenStore.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    crypt32.CertOpenStore.restype = wintypes.HANDLE
    crypt32.CertFindCertificateInStore.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt32.CertFreeCertificateContext.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    encoding = 0x00000001 | 0x00010000  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
    store_name = ctypes.c_wchar_p("ROOT")
    store = crypt32.CertOpenStore(
        ctypes.c_void_p(10),  # CERT_STORE_PROV_SYSTEM_W
        encoding,
        None,
        location_flag | 0x00004000,  # CERT_STORE_OPEN_EXISTING_FLAG
        ctypes.cast(store_name, ctypes.c_void_p),
    )
    if not store:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        context = crypt32.CertFindCertificateInStore(
            store,
            encoding,
            0,
            0x00010000,  # CERT_FIND_SHA1_HASH
            ctypes.byref(blob),
            None,
        )
        if not context:
            return False
        crypt32.CertFreeCertificateContext(context)
        return True
    finally:
        crypt32.CertCloseStore(store, 0)

def _remove_certificate_from_root_store(certificate: Path, location_flag: int) -> bool:
    encoded = _certificate_der_bytes(certificate)
    if not encoded:
        return False

    class _CryptHashBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    digest = hashlib.sha1(encoded, usedforsecurity=False).digest()
    digest_buffer = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
    blob = _CryptHashBlob(len(digest), digest_buffer)
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CertOpenStore.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    crypt32.CertOpenStore.restype = wintypes.HANDLE
    crypt32.CertFindCertificateInStore.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt32.CertDeleteCertificateFromStore.argtypes = [ctypes.c_void_p]
    crypt32.CertDeleteCertificateFromStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    encoding = 0x00000001 | 0x00010000  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
    store_name = ctypes.c_wchar_p("ROOT")
    store = crypt32.CertOpenStore(
        ctypes.c_void_p(10),  # CERT_STORE_PROV_SYSTEM_W
        encoding,
        None,
        location_flag | 0x00004000,  # CERT_STORE_OPEN_EXISTING_FLAG
        ctypes.cast(store_name, ctypes.c_void_p),
    )
    if not store:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        context = crypt32.CertFindCertificateInStore(
            store,
            encoding,
            0,
            0x00010000,  # CERT_FIND_SHA1_HASH
            ctypes.byref(blob),
            None,
        )
        if not context:
            return False
        if not crypt32.CertDeleteCertificateFromStore(context):
            raise ctypes.WinError(ctypes.get_last_error())
        return True
    finally:
        crypt32.CertCloseStore(store, 0)

def add_certificate_to_local_machine_root(certificate: Path) -> None:
    if sys.platform != "win32":
        raise RuntimeError("Windows certificate installation is only supported on Windows.")
    if not elevation.is_elevated():
        raise RuntimeError("Administrator privileges are required to install the HTTPS certificate.")

    encoded = _certificate_der_bytes(certificate)
    if not encoded:
        raise RuntimeError(f"Ninja Capture Tool's HTTPS certificate is empty: {certificate}")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CertOpenStore.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    crypt32.CertOpenStore.restype = wintypes.HANDLE
    crypt32.CertAddEncodedCertificateToStore.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    crypt32.CertAddEncodedCertificateToStore.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL

    encoding = 0x00000001 | 0x00010000  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
    store_name = ctypes.c_wchar_p("ROOT")
    store = crypt32.CertOpenStore(
        ctypes.c_void_p(10),  # CERT_STORE_PROV_SYSTEM_W
        encoding,
        None,
        0x00020000 | 0x00004000,  # CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG
        ctypes.cast(store_name, ctypes.c_void_p),
    )
    if not store:
        raise ctypes.WinError(ctypes.get_last_error())

    certificate_buffer = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
    try:
        if not crypt32.CertAddEncodedCertificateToStore(
            store,
            encoding,
            certificate_buffer,
            len(encoded),
            3,  # CERT_STORE_ADD_REPLACE_EXISTING
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        crypt32.CertCloseStore(store, 0)

def ensure_mitmproxy_ca_exists() -> Path:
    file_status, certificate = _mitmproxy_ca_file_status()
    if file_status == "complete" and certificate is not None:
        return certificate
    if file_status == "incomplete":
        _raise_incomplete_mitmproxy_ca()
    try:
        from mitmproxy import certs as mitmproxy_certs, options as mitmproxy_options

        conf_dir = common.mitmproxy_conf_directory()
        conf_dir.mkdir(parents=True, exist_ok=True)
        mitmproxy_certs.CertStore.from_store(
            path=conf_dir,
            basename="mitmproxy",
            key_size=mitmproxy_options.KEY_SIZE,
        )
    except Exception as exc:
        raise RuntimeError("Could not initialize Ninja Capture Tool's HTTPS certificate.") from exc
    file_status, certificate = _mitmproxy_ca_file_status()
    if file_status != "complete" or certificate is None:
        raise RuntimeError("Could not initialize Ninja Capture Tool's HTTPS certificate.")
    return certificate

def mitmproxy_ca_trust_status() -> tuple[str, Path | None]:
    if sys.platform != "win32":
        return "not-applicable", None
    file_status, certificate = _mitmproxy_ca_file_status()
    if file_status != "complete":
        return file_status, certificate
    assert certificate is not None

    probe_failed = False
    for location_flag in (
        0x00010000,  # CERT_SYSTEM_STORE_CURRENT_USER
        0x00020000,  # CERT_SYSTEM_STORE_LOCAL_MACHINE
    ):
        try:
            if _certificate_is_trusted_in_root_store(certificate, location_flag):
                return "trusted", certificate
        except (OSError, UnicodeError, ValueError):
            probe_failed = True
    if probe_failed:
        return "unknown", certificate
    return "untrusted", certificate

def _raise_unknown_mitmproxy_ca_trust() -> None:
    raise RuntimeError(
        "Could not determine whether Ninja Capture Tool's HTTPS certificate is trusted by Windows. "
        "No certificate changes were made."
    )

def ensure_mitmproxy_ca_trusted() -> bool:
    status, certificate = mitmproxy_ca_trust_status()
    if status in {"trusted", "not-applicable"}:
        return False
    if status == "unknown":
        _raise_unknown_mitmproxy_ca_trust()
    if status == "incomplete":
        _raise_incomplete_mitmproxy_ca()
    if certificate is None:
        certificate = ensure_mitmproxy_ca_exists()
        status, _ = mitmproxy_ca_trust_status()
        if status == "trusted":
            return False
        if status == "unknown":
            _raise_unknown_mitmproxy_ca_trust()
        if status == "incomplete":
            _raise_incomplete_mitmproxy_ca()

    if not elevation.is_elevated():
        raise RuntimeError("Ninja Capture Tool's capture runtime requires administrator privileges.")

    try:
        add_certificate_to_local_machine_root(certificate)
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        raise RuntimeError(
            f"Could not install Ninja Capture Tool's HTTPS certificate. Certificate: {certificate}"
        ) from exc

    verified, _ = mitmproxy_ca_trust_status()
    if verified == "unknown":
        raise RuntimeError(
            "Ninja Capture Tool installed its HTTPS certificate, but Windows trust could not be verified. "
            f"Certificate: {certificate}"
        )
    if verified != "trusted":
        raise RuntimeError(
            f"Windows did not retain Ninja Capture Tool's HTTPS certificate in the trusted root store. "
            f"Certificate: {certificate}"
        )
    return True

def remove_mitmproxy_ca() -> tuple[int, bool]:
    if sys.platform != "win32":
        raise RuntimeError("Windows certificate removal is only supported on Windows.")
    if not elevation.is_elevated():
        raise RuntimeError("Administrator privileges are required to remove the HTTPS certificate.")

    conf_dir = common.mitmproxy_conf_directory()
    if not conf_dir.exists():
        return 0, False
    identities = _mitmproxy_ca_identity_paths()
    if not identities:
        raise RuntimeError(
            "Ninja Capture Tool's shared HTTPS certificate directory exists, but no certificate identity could be read. "
            f"Directory was kept: {conf_dir}"
        )

    removed = 0
    store_errors: list[str] = []
    store_locations = (
        (0x00010000, "Current User Root"),  # CERT_SYSTEM_STORE_CURRENT_USER
        (0x00020000, "Local Machine Root"),  # CERT_SYSTEM_STORE_LOCAL_MACHINE
    )
    for certificate in identities:
        for location_flag, store_name in store_locations:
            try:
                if _remove_certificate_from_root_store(certificate, location_flag):
                    removed += 1
            except (OSError, UnicodeError, ValueError) as exc:
                store_errors.append(f"{store_name} for {certificate.name}: {exc}")

    if store_errors:
        raise RuntimeError(
            "Ninja Capture Tool could not fully inspect/remove its HTTPS certificate from every Windows trusted root store. "
            f"Any successful removals were kept, but shared certificate files were preserved at: {conf_dir}. "
            f"Retry --remove-https-certificate later. Errors: {'; '.join(store_errors)}"
        )

    try:
        shutil.rmtree(conf_dir)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RuntimeError(
            "The Windows HTTPS certificate trust was removed when present, but Ninja Capture Tool could not delete its shared "
            f"certificate files: {conf_dir}"
        ) from exc
    return removed, True

def restore_redirected_standard_streams() -> bool:
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        return False
    try:
        import msvcrt

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetStdHandle.argtypes = [ctypes.c_uint32]
        kernel32.GetStdHandle.restype = ctypes.c_void_p
        kernel32.GetFileType.argtypes = [ctypes.c_void_p]
        kernel32.GetFileType.restype = ctypes.c_uint32
        kernel32.DuplicateHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
        kernel32.DuplicateHandle.restype = ctypes.c_bool
        process = kernel32.GetCurrentProcess()
        restored = sys.stdout is not None or sys.stderr is not None
        for attribute, identifier, flags, mode in (("stdin", -10, os.O_RDONLY, "r"), ("stdout", -11, os.O_WRONLY, "w"), ("stderr", -12, os.O_WRONLY, "w")):
            if getattr(sys, attribute) is not None:
                continue
            handle = kernel32.GetStdHandle(identifier & 0xFFFFFFFF)
            if not handle or handle == ctypes.c_void_p(-1).value or kernel32.GetFileType(handle) not in {1, 3}:
                continue
            duplicate = ctypes.c_void_p()
            if not kernel32.DuplicateHandle(process, handle, process, ctypes.byref(duplicate), 0, True, 2):
                continue
            descriptor = msvcrt.open_osfhandle(int(duplicate.value), flags)
            setattr(sys, attribute, os.fdopen(descriptor, mode, encoding="utf-8", errors="replace", buffering=1))
            restored = True
        return restored
    except (AttributeError, OSError, ValueError):
        return False

def _restore_console_title() -> None:
    global _CONSOLE_TITLE_SET
    if sys.platform != "win32" or not _CONSOLE_TITLE_SET or _CONSOLE_TITLE_ORIGINAL is None:
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetConsoleTitleW.argtypes = [ctypes.c_wchar_p]
        kernel32.SetConsoleTitleW.restype = ctypes.c_bool
        kernel32.SetConsoleTitleW(_CONSOLE_TITLE_ORIGINAL)
    except (AttributeError, OSError, ValueError):
        pass
    _CONSOLE_TITLE_SET = False

def console_was_created_by_nct() -> bool:
    return _CONSOLE_CREATED_BY_NCT

def set_console_title(capture_mode: str | None = None) -> None:
    global _CONSOLE_TITLE_ORIGINAL, _CONSOLE_TITLE_SET
    if sys.platform != "win32":
        return
    if capture_mode == "local":
        display_title = f"Local Capture - Ninja Capture Tool (v{common.display_version()})"
    elif capture_mode == "system-proxy":
        display_title = f"System Proxy - Ninja Capture Tool (v{common.display_version()})"
    else:
        display_title = f"Ninja Capture Tool (v{common.display_version()})"
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetConsoleWindow.restype = ctypes.c_void_p
        kernel32.GetConsoleTitleW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
        kernel32.GetConsoleTitleW.restype = ctypes.c_uint32
        kernel32.SetConsoleTitleW.argtypes = [ctypes.c_wchar_p]
        kernel32.SetConsoleTitleW.restype = ctypes.c_bool
        if not kernel32.GetConsoleWindow():
            return
        if not _CONSOLE_TITLE_SET:
            buffer = ctypes.create_unicode_buffer(32768)
            kernel32.GetConsoleTitleW(buffer, len(buffer))
            _CONSOLE_TITLE_ORIGINAL = buffer.value
            if not kernel32.SetConsoleTitleW(display_title):
                return
            _CONSOLE_TITLE_SET = True
            atexit.register(_restore_console_title)
            return
        kernel32.SetConsoleTitleW(display_title)
    except (AttributeError, OSError, ValueError):
        pass

def show_console_window() -> None:
    global _CONSOLE_CREATED_BY_NCT
    if sys.platform != "win32":
        return
    if not getattr(sys, "frozen", False):
        set_console_title()
        return
    if os.environ.get("NCT_HEADLESS") == "1":
        return
    if restore_redirected_standard_streams():
        set_console_title()
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32.GetConsoleWindow.restype = ctypes.c_void_p
        kernel32.AttachConsole.argtypes = [ctypes.c_uint32]
        kernel32.AttachConsole.restype = ctypes.c_bool
        kernel32.AllocConsole.restype = ctypes.c_bool
        user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
        user32.ShowWindow.restype = ctypes.c_bool
        if not kernel32.GetConsoleWindow():
            if not kernel32.AttachConsole(0xFFFFFFFF):
                if not kernel32.AllocConsole():
                    return
                _CONSOLE_CREATED_BY_NCT = True
        try:
            sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace", buffering=1)
        except OSError:
            pass
        window = kernel32.GetConsoleWindow()
        if window:
            user32.ShowWindow(window, 5)
            set_console_title()
    except (AttributeError, OSError):
        pass

def console_status_row(text: str | None = None) -> int | None:
    """Return the current Windows console-buffer row when a status line will fit on one row."""
    if sys.platform != "win32":
        return None
    try:
        import msvcrt
        if not sys.stdout.isatty():
            return None
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(sys.stdout.fileno()))

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short), ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ("dwSize", COORD),
                ("dwCursorPosition", COORD),
                ("wAttributes", wintypes.WORD),
                ("srWindow", SMALL_RECT),
                ("dwMaximumWindowSize", COORD),
            ]

        info = CONSOLE_SCREEN_BUFFER_INFO()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetConsoleScreenBufferInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO)]
        kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL
        if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
            return None
        width = int(info.dwSize.X)
        if text is not None and ("\n" in text or "\r" in text or len(text) >= width):
            return None
        return int(info.dwCursorPosition.Y)
    except (AttributeError, ImportError, OSError, ValueError):
        return None

def rewrite_console_status_row(row: int, expected_text: str, text: str) -> int | None:
    """Rewrite a visible status row and return its current row after any console reflow."""
    if sys.platform != "win32" or row < 0 or "\n" in text or "\r" in text:
        return None
    try:
        import msvcrt
        if not sys.stdout.isatty():
            return None
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(sys.stdout.fileno()))

        class COORD(ctypes.Structure):
            _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

        class SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short), ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

        class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
            _fields_ = [
                ("dwSize", COORD),
                ("dwCursorPosition", COORD),
                ("wAttributes", wintypes.WORD),
                ("srWindow", SMALL_RECT),
                ("dwMaximumWindowSize", COORD),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetConsoleScreenBufferInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO)]
        kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL
        kernel32.ReadConsoleOutputCharacterW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, COORD, ctypes.POINTER(wintypes.DWORD)]
        kernel32.ReadConsoleOutputCharacterW.restype = wintypes.BOOL
        kernel32.FillConsoleOutputCharacterW.argtypes = [wintypes.HANDLE, wintypes.WCHAR, wintypes.DWORD, COORD, ctypes.POINTER(wintypes.DWORD)]
        kernel32.FillConsoleOutputCharacterW.restype = wintypes.BOOL
        kernel32.FillConsoleOutputAttribute.argtypes = [wintypes.HANDLE, wintypes.WORD, wintypes.DWORD, COORD, ctypes.POINTER(wintypes.DWORD)]
        kernel32.FillConsoleOutputAttribute.restype = wintypes.BOOL
        kernel32.WriteConsoleOutputCharacterW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD, COORD, ctypes.POINTER(wintypes.DWORD)]
        kernel32.WriteConsoleOutputCharacterW.restype = wintypes.BOOL
        kernel32.SetConsoleCursorPosition.argtypes = [wintypes.HANDLE, COORD]
        kernel32.SetConsoleCursorPosition.restype = wintypes.BOOL

        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(info)):
            return None
        width = int(info.dwSize.X)
        if len(text) >= width or len(expected_text) >= width:
            return None
        top = max(0, int(info.srWindow.Top))
        bottom = min(int(info.dwSize.Y) - 1, int(info.srWindow.Bottom))
        if bottom < top:
            return None

        def read_row(candidate: int) -> str | None:
            probe = ctypes.create_unicode_buffer(width + 1)
            read = wintypes.DWORD()
            origin = COORD(0, candidate)
            if not kernel32.ReadConsoleOutputCharacterW(handle, probe, width, origin, ctypes.byref(read)):
                return None
            return probe[: read.value].rstrip(" \x00")

        target_row: int | None = None
        if top <= row <= bottom and read_row(row) == expected_text:
            target_row = row
        else:
            # Windows can reflow existing console text when the window/buffer width
            # changes. The remembered numeric row then becomes stale even though the
            # previous status line is still visible. Relocate only an exact, unique
            # visible match; ambiguity keeps the existing safe print-a-new-row fallback.
            for candidate in range(top, bottom + 1):
                if candidate == row:
                    continue
                if read_row(candidate) != expected_text:
                    continue
                if target_row is not None:
                    return None
                target_row = candidate
            if target_row is None:
                return None

        saved_cursor = info.dwCursorPosition
        origin = COORD(0, target_row)
        written = wintypes.DWORD()
        if not kernel32.FillConsoleOutputCharacterW(handle, " ", width, origin, ctypes.byref(written)):
            return None
        kernel32.FillConsoleOutputAttribute(handle, info.wAttributes, width, origin, ctypes.byref(written))
        if not kernel32.WriteConsoleOutputCharacterW(handle, text, len(text), origin, ctypes.byref(written)):
            return None
        kernel32.SetConsoleCursorPosition(handle, saved_cursor)
        return target_row
    except (AttributeError, ImportError, OSError, TypeError, ValueError):
        return None

def worker_command(
    session: Path,
    options: dict[str, object],
    upstream: str | None = None,
    *,
    manifest_path: Path,
) -> list[str]:
    mode = str(options["capture_mode"])
    if mode == "local":
        if options["debug"] == "global":
            proxy_mode = "local"
        else:
            process_spec = ",".join(str(item) for item in options["processes"])
            proxy_mode = f"local:{process_spec}"
        listen_port = 0
    else:
        proxy_mode = f"upstream:{upstream}" if upstream is not None else "regular"
        listen_port = int(options["proxy_port"])

    command = [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, str(common.TOOL_DIR / "ninja_capture_tool.py")]
    command.extend(
        [
            "--proxy-worker",
            "--session",
            str(session),
            "--manifest",
            str(manifest_path),
            "--mode",
            proxy_mode,
            "--listen-port",
            str(listen_port),
            "--debug-worker",
            "global" if options["debug"] == "global" else "on" if bool(options["debug"]) else "off",
        ]
    )
    return command

def running_process_names() -> set[str]:
    if sys.platform != "win32":
        return set()

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)  # TH32CS_SNAPPROCESS
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            error = ctypes.get_last_error()
            if error == 18:  # ERROR_NO_MORE_FILES
                return set()
            raise ctypes.WinError(error)
        names: set[str] = set()
        while True:
            if entry.szExeFile:
                names.add(entry.szExeFile.casefold())
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                error = ctypes.get_last_error()
                if error != 18:  # ERROR_NO_MORE_FILES
                    raise ctypes.WinError(error)
                return names
    finally:
        kernel32.CloseHandle(snapshot)

def process_monitor_is_running() -> bool:
    if sys.platform != "win32":
        return False
    try:
        names = running_process_names()
    except (AttributeError, OSError):
        return False
    return bool({"procmon.exe", "procmon64.exe", "procmon64a.exe"}.intersection(names))

def ensure_local_capture_compatible(options: dict[str, object]) -> None:
    # Process Monitor can trigger an upstream mitmproxy-rs/Mio named-pipe crash
    # while Windows Local Capture is being initialized.
    if str(options["capture_mode"]) == "local" and process_monitor_is_running():
        raise RuntimeError(
            "Process Monitor is running and is incompatible with Local Capture. "
            "Close Process Monitor and try again."
        )
