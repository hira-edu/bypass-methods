"""
Utility injector for the UndownUnlock DirectX hook.

This helper is intended for development workflows: it discovers the freshly
built `UndownUnlockDXHook.dll`, locates a target process (either a running PID
or the demo client launched by the script), and performs a standard
LoadLibrary-based DLL injection.  The implementation keeps safety in mind
by validating inputs and surfacing actionable diagnostics instead of silently
failing.  Run `python test_injector.py --help` for usage details.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional

if os.name != "nt":  # pragma: no cover - Windows specific
    raise SystemExit("test_injector.py is only supported on Windows.")

from ctypes import wintypes

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - psutil is optional
    psutil = None

# Flags used when opening the remote process.  Only request the rights we need.
PROCESS_PERMISSIONS = (
    0x0002  # PROCESS_CREATE_THREAD
    | 0x0008  # PROCESS_VM_OPERATION
    | 0x0010  # PROCESS_VM_READ
    | 0x0020  # PROCESS_VM_WRITE
    | 0x0400  # PROCESS_QUERY_INFORMATION
)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
se_privilege_name = "SeDebugPrivilege"


class InjectorError(RuntimeError):
    """Specialised exception so callers can handle failures cleanly."""


def _win_error(message: str) -> InjectorError:
    """Wrap the last Windows error code in an InjectorError."""
    err = ctypes.get_last_error()
    return InjectorError(f"{message} (error {err:#x})")


def enable_debug_privileges() -> bool:
    """
    Enable SeDebugPrivilege when possible so the injector can attach to
    elevated targets during local testing.  Returns True on success.
    """

    token_handle = wintypes.HANDLE()
    TOKEN_ADJUST_PRIVILEGES = 0x20
    TOKEN_QUERY = 0x08

    if not kernel32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token_handle)
    ):
        return False

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, se_privilege_name, ctypes.byref(luid)):
        kernel32.CloseHandle(token_handle)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = 0x02  # SE_PRIVILEGE_ENABLED

    success = advapi32.AdjustTokenPrivileges(
        token_handle, False, ctypes.byref(tp), 0, None, None  # type: ignore[arg-type]
    )
    kernel32.CloseHandle(token_handle)
    return bool(success)


def discover_dll(explicit: Optional[str]) -> Path:
    """
    Resolve the DLL path supplied by the user or fall back to a set of sensible
    defaults (Release/Debug folders under build/bin).  Raises InjectorError
    when nothing can be found.
    """

    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        if not candidate.exists():
            raise InjectorError(f"Specified DLL not found: {candidate}")
        return candidate

    candidates: Iterable[Path] = [
        Path("build/bin/Release/UndownUnlockDXHook.dll"),
        Path("build/bin/Debug/UndownUnlockDXHook.dll"),
        Path("build/bin/UndownUnlockDXHook.dll"),
        Path("build/Release/UndownUnlockDXHook.dll"),
        Path("DLLHooks/Release/DLLHooks.dll"),
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()

    matches = list(Path(".").rglob("UndownUnlockDXHook.dll"))
    if matches:
        return matches[0].resolve()

    raise InjectorError("Unable to locate UndownUnlockDXHook.dll – build the project first.")


def find_process_id(args: argparse.Namespace) -> int:
    """
    Resolve the process ID from either --pid, --process-name, or --launch.
    """

    if args.pid is not None:
        return args.pid

    if args.launch:
        proc = subprocess.Popen(args.launch, shell=False)
        print(f"[info] Launched '{args.launch}' (PID {proc.pid})")
        # Give the process a moment to initialise before we inject.
        time.sleep(args.launch_delay)
        return proc.pid

    if not psutil:
        raise InjectorError("psutil is required to discover processes. Install it via 'pip install psutil'.")

    if args.process_name:
        processes = [p for p in psutil.process_iter(["pid", "name"]) if args.process_name.lower() in p.info["name"].lower()]
        if not processes:
            raise InjectorError(f"No running process contains '{args.process_name}'.")
        # Prefer the newest process to target freshly launched apps.
        processes.sort(key=lambda p: p.create_time(), reverse=True)
        return processes[0].pid

    raise InjectorError("One of --pid, --process-name, or --launch is required.")


def inject_dll(pid: int, dll_path: Path, wait_timeout: int, dry_run: bool = False) -> None:
    """
    Perform LoadLibrary-based injection into the provided PID.
    """

    dll_buffer = ctypes.create_unicode_buffer(str(dll_path))
    size_bytes = ctypes.sizeof(dll_buffer)

    if dry_run:
        print(f"[dry-run] Would inject '{dll_path}' into PID {pid}")
        return

    process = kernel32.OpenProcess(PROCESS_PERMISSIONS, False, pid)
    if not process:
        raise _win_error(f"Failed to open target process {pid}")

    remote_mem = kernel32.VirtualAllocEx(process, None, size_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote_mem:
        kernel32.CloseHandle(process)
        raise _win_error("VirtualAllocEx failed")

    written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(process, remote_mem, dll_buffer, size_bytes, ctypes.byref(written)):
        kernel32.VirtualFreeEx(process, remote_mem, 0, 0x8000)  # MEM_RELEASE
        kernel32.CloseHandle(process)
        raise _win_error("WriteProcessMemory failed")

    kernel_handle = kernel32.GetModuleHandleW("kernel32.dll")
    load_library_w = kernel32.GetProcAddress(kernel_handle, b"LoadLibraryW")
    if not load_library_w:
        kernel32.VirtualFreeEx(process, remote_mem, 0, 0x8000)
        kernel32.CloseHandle(process)
        raise _win_error("GetProcAddress(LoadLibraryW) failed")

    thread_id = ctypes.c_ulong(0)
    thread = kernel32.CreateRemoteThread(
        process, None, 0, load_library_w, remote_mem, 0, ctypes.byref(thread_id)
    )
    if not thread:
        kernel32.VirtualFreeEx(process, remote_mem, 0, 0x8000)
        kernel32.CloseHandle(process)
        raise _win_error("CreateRemoteThread failed")

    kernel32.WaitForSingleObject(thread, wait_timeout)
    kernel32.CloseHandle(thread)
    kernel32.VirtualFreeEx(process, remote_mem, 0, 0x8000)
    kernel32.CloseHandle(process)
    print(f"[success] Injected '{dll_path.name}' into PID {pid} (thread {thread_id.value}).")


def list_processes(filter_text: Optional[str] = None) -> None:
    """Print a lightweight process table so developers can pick a target."""
    if not psutil:
        print("psutil is not installed; unable to list processes.")
        return

    for proc in psutil.process_iter(["pid", "name", "exe"]):
        name = proc.info["name"] or "<unknown>"
        if filter_text and filter_text.lower() not in name.lower():
            continue
        print(f"{proc.info['pid']:>6}  {name}")


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Development injector for the UndownUnlock hook.")
    parser.add_argument("--dll", help="Path to UndownUnlockDXHook.dll (auto-discovered when omitted).")
    parser.add_argument("--pid", type=int, help="PID to inject.")
    parser.add_argument("--process-name", help="Substring of the process name to target.")
    parser.add_argument("--launch", help="Executable path to launch and inject.")
    parser.add_argument("--launch-delay", type=float, default=2.0, help="Seconds to wait before injecting a launched process.")
    parser.add_argument("--dry-run", action="store_true", help="Resolve the DLL and PID but skip the injection.")
    parser.add_argument("--list", action="store_true", help="List running processes and exit.")
    parser.add_argument("--filter", help="Filter string used with --list.")
    parser.add_argument("--wait-timeout", type=int, default=10_000, help="Milliseconds to wait for LoadLibrary to finish.")
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)

    if args.list:
        list_processes(args.filter)
        return 0

    try:
        dll_path = discover_dll(args.dll)
    except InjectorError as exc:
        print(f"[error] {exc}")
        return 1

    if enable_debug_privileges():
        print("[info] SeDebugPrivilege enabled.")

    try:
        pid = find_process_id(args)
    except InjectorError as exc:
        print(f"[error] {exc}")
        return 1

    print(f"[info] Using DLL: {dll_path}")
    print(f"[info] Target PID: {pid}")

    try:
        inject_dll(pid, dll_path, args.wait_timeout, dry_run=args.dry_run)
    except InjectorError as exc:
        print(f"[error] {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
