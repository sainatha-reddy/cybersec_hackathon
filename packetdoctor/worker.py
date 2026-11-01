"""Isolated analysis with a whole-job deadline, cancellation and memory supervision."""

from __future__ import annotations

import multiprocessing
import os
import sys
import time

from .config import DEFAULT_SETTINGS
from .ingest import CaptureError


def _resident_bytes(process_id):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class MemoryCounters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [(name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        memory_api = ctypes.WinDLL("psapi").GetProcessMemoryInfo
        memory_api.argtypes = [wintypes.HANDLE, ctypes.POINTER(MemoryCounters), wintypes.DWORD]
        handle = kernel.OpenProcess(0x0410, False, process_id)
        if not handle:
            return 0
        try:
            counters = MemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if memory_api(handle, ctypes.byref(counters), counters.cb):
                return max(counters.WorkingSetSize, counters.PagefileUsage)
            return 0
        finally:
            kernel.CloseHandle(handle)
    try:
        with open(f"/proc/{process_id}/statm", encoding="ascii") as stream:
            return int(stream.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return 0


def _execute(connection, path, settings, anonymize, import_paths):
    sys.path[:] = import_paths
    try:
        if os.name != "nt":
            import resource

            if hasattr(resource, "RLIMIT_AS"):
                maximum = settings.limits.max_memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (maximum, maximum))
        from .engine import analyze

        connection.send((True, analyze(path, settings, anonymize)))
    except CaptureError as error:
        connection.send((False, str(error)))
    except Exception:
        connection.send((False, "Capture analysis failed safely. Try a smaller capture or check its format."))
    finally:
        connection.close()


def analyze_isolated(path, settings=DEFAULT_SETTINGS, anonymize=False, cancelled=None, progress=None):
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_execute, args=(sender, str(path), settings, anonymize, list(sys.path)))
    process.daemon = True
    started = time.monotonic()
    process.start()
    sender.close()
    try:
        while True:
            if cancelled is not None and cancelled.is_set():
                raise CaptureError("Analysis cancelled.")
            elapsed = time.monotonic() - started
            if elapsed >= settings.limits.timeout_seconds:
                raise CaptureError("Analysis exceeded the whole-job time limit. Try a smaller capture.")
            if _resident_bytes(process.pid) > settings.limits.max_memory_mb * 1024 * 1024:
                raise CaptureError("Analysis exceeded its memory budget. Try a smaller capture.")
            if receiver.poll(0.05):
                try:
                    succeeded, result = receiver.recv()
                except EOFError:
                    raise CaptureError("Analysis worker stopped before producing a report.") from None
                if not succeeded:
                    raise CaptureError(result)
                return result
            if not process.is_alive():
                raise CaptureError("Analysis worker stopped before producing a report.")
            if progress:
                progress(elapsed)
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join()
        receiver.close()
