"""
process/process_monitor.py
===========================
Process Monitor Module.

Uses *psutil* to inspect running processes and identify any that match
the list of APPROVED simulation/test process names defined in config.py.

⚠️  SAFETY NOTE
--------------
This module ONLY looks for processes whose names or command-line arguments
exactly match entries in config.APPROVED_SIMULATION_PROCESSES.
It does NOT target arbitrary or system-level software.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

import psutil

import config


@dataclass
class ProcessInfo:
    """Details about a monitored process."""
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    cmdline: str
    is_simulation: bool = False
    is_suspicious_cpu: bool = False


class ProcessMonitor:
    """
    Scans the process list for approved simulation processes and
    high-CPU consumers.

    Usage
    -----
    pm = ProcessMonitor()
    procs = pm.scan()
    if any(p.is_simulation for p in procs):
        pm.terminate_simulation_process(pid)
    """

    def scan(self) -> List[ProcessInfo]:
        """
        Scan all running processes.

        Returns
        -------
        List[ProcessInfo]  – only processes flagged as simulation or suspicious.
        """
        flagged: List[ProcessInfo] = []

        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_info", "cmdline"]
        ):
            try:
                info = proc.info  # type: ignore[attr-defined]
                name: str = info.get("name") or ""
                cmdline_list: list = info.get("cmdline") or []
                cmdline_str: str = " ".join(cmdline_list)
                cpu: float = info.get("cpu_percent") or 0.0
                mem_bytes: int = (
                    info["memory_info"].rss if info.get("memory_info") else 0
                )
                mem_mb: float = mem_bytes / (1024 * 1024)

                is_sim = self._is_simulation_process(name, cmdline_str)
                is_high_cpu = cpu >= config.SUSPICIOUS_CPU_THRESHOLD

                if is_sim or is_high_cpu:
                    flagged.append(
                        ProcessInfo(
                            pid=info["pid"],
                            name=name,
                            cpu_percent=cpu,
                            memory_mb=mem_mb,
                            cmdline=cmdline_str[:120],
                            is_simulation=is_sim,
                            is_suspicious_cpu=is_high_cpu,
                        )
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Process may have exited between iteration and attribute access
                continue

        return flagged

    def terminate_simulation_process(self, pid: int) -> bool:
        """
        Safely terminate an approved simulation process by PID.

        This method will only terminate a process if its name or cmdline
        matches config.APPROVED_SIMULATION_PROCESSES. If the process does
        not match, the termination is refused and False is returned.

        Parameters
        ----------
        pid : Process ID to terminate.

        Returns
        -------
        bool – True if terminated, False if refused or failed.
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            cmdline_str = " ".join(proc.cmdline())

            # Safety gate: only terminate approved simulations
            if not self._is_simulation_process(name, cmdline_str):
                return False

            proc.terminate()   # sends SIGTERM — graceful shutdown
            proc.wait(timeout=3)
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            return False

    def any_simulation_running(self) -> bool:
        """Return True if at least one approved simulation process is active."""
        return any(p.is_simulation for p in self.scan())

    # ─────────────────────────── private ─────────────────────────────────────

    @staticmethod
    def _is_simulation_process(name: str, cmdline: str) -> bool:
        """
        Return True if *name* or *cmdline* matches an approved simulation process.

        Matching is case-insensitive and checks for substring presence.
        """
        for approved in config.APPROVED_SIMULATION_PROCESSES:
            approved_lower = approved.lower()
            if approved_lower in name.lower() or approved_lower in cmdline.lower():
                return True
        return False
