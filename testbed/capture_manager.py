"""
Packet Capture Manager for SentraIPS Testbed.
Manages tcpdump capture processes, handles graceful termination to ensure complete PCAP headers,
and extracts packet capture statistics.
"""

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, Optional


class CaptureManager:
    """Manages tcpdump lifecycle on network interfaces."""

    def __init__(self, interface: str = "eth0", output_path: str = "/captures/capture.pcap",
                 filter_expr: str = "esp or udp port 500 or udp port 4500"):
        self.interface = interface
        self.output_path = Path(output_path)
        self.filter_expr = filter_expr
        self.process: Optional[subprocess.Popen] = None
        self.start_time: Optional[float] = None

    def start(self) -> None:
        """Start tcpdump in background."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-n",
            "-s", "0",
            "-w", str(self.output_path),
        ]
        if self.filter_expr:
            cmd.extend(self.filter_expr.split())

        print(f"[Capture] Starting tcpdump on {self.interface} -> {self.output_path}...", flush=True)
        self.start_time = time.time()
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid if hasattr(os, "setsid") else None,
        )
        # Allow tcpdump 1 second to bind to interface and write initial pcap header
        time.sleep(1.0)

    def stop(self) -> Dict[str, Any]:
        """Gracefully stop tcpdump (SIGINT) so that the PCAP header and packets are flushed."""
        if not self.process:
            return {"status": "not_running"}

        elapsed = time.time() - (self.start_time or time.time())
        print(f"[Capture] Stopping tcpdump (captured for {elapsed:.2f}s)...", flush=True)

        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            else:
                self.process.send_signal(signal.SIGINT)
            self.process.wait(timeout=5)
        except Exception:
            self.process.kill()
            self.process.wait()

        stderr_output = ""
        if self.process.stderr:
            try:
                stderr_output = self.process.stderr.read().decode("utf-8", errors="replace")
            except Exception:
                pass

        file_size = self.output_path.stat().st_size if self.output_path.exists() else 0

        stats = {
            "status": "stopped",
            "file_path": str(self.output_path),
            "file_size_bytes": file_size,
            "duration_seconds": elapsed,
            "tcpdump_stderr": stderr_output,
        }
        self.process = None
        return stats
