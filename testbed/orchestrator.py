"""
Testbed Orchestrator for SentraIPS.
Executes the core Phase 1 flow:
  1. Generate strongSwan configuration
  2. Apply configuration to Gateway A and Gateway B
  3. Start packet capture (tcpdump)
  4. Establish IPsec tunnel
  5. Generate controlled traffic (ICMP, Web, Video/Bulk, VoIP)
  6. Stop capture and flush PCAP
  7. Generate ground-truth metadata (.json)
  8. Validate captured PCAP and verify ground truth
"""

import json
import os
from pathlib import Path
import subprocess
import time
from typing import Dict, Any, Optional

from .config_generator import IPsecConfig
from .capture_manager import CaptureManager
from .traffic_generator import run_traffic
from packet_analysis.validator import PCAPValidator


class TestbedOrchestrator:
    """Coordinates strongSwan VPN lifecycle, traffic generation, and PCAP capture."""

    def __init__(self, in_container: bool = False):
        self.in_container = in_container
        self.container_a = "ipsec-gateway-a"
        self.container_b = "ipsec-gateway-b"

    def _run_cmd(self, cmd_args: list[str], target: str = "host", detached: bool = False) -> tuple[int, str, str]:
        """Execute command either locally or inside a docker container."""
        if target == "gateway-a":
            docker_opts = ["-d"] if detached else []
            full_cmd = ["docker", "exec"] + docker_opts + [self.container_a] + cmd_args
        elif target == "gateway-b":
            docker_opts = ["-d"] if detached else []
            full_cmd = ["docker", "exec"] + docker_opts + [self.container_b] + cmd_args
        else:
            full_cmd = cmd_args

        proc = subprocess.run(full_cmd, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr

    def check_containers_running(self) -> bool:
        """Verify Gateway A and Gateway B containers are running."""
        code, stdout, _ = self._run_cmd(["docker", "ps", "--format", "{{.Names}}"])
        names = stdout.splitlines()
        return self.container_a in names and self.container_b in names

    def apply_config(self, config: IPsecConfig) -> None:
        """Apply ipsec.conf and ipsec.secrets to both gateways."""
        conf_a = config.generate_ipsec_conf(role="left")
        conf_b = config.generate_ipsec_conf(role="right")
        secrets = config.generate_ipsec_secrets()

        # Write to Gateway A
        self._write_file_to_gateway("gateway-a", "/etc/ipsec.conf", conf_a)
        self._write_file_to_gateway("gateway-a", "/etc/ipsec.secrets", secrets)

        # Write to Gateway B
        self._write_file_to_gateway("gateway-b", "/etc/ipsec.conf", conf_b)
        self._write_file_to_gateway("gateway-b", "/etc/ipsec.secrets", secrets)

        # Reload strongSwan configuration
        self._run_cmd(["ipsec", "rereadall"], target="gateway-a")
        self._run_cmd(["ipsec", "reload"], target="gateway-a")
        self._run_cmd(["ipsec", "rereadall"], target="gateway-b")
        self._run_cmd(["ipsec", "reload"], target="gateway-b")
        time.sleep(1.0)

    def _write_file_to_gateway(self, target: str, remote_path: str, content: str) -> None:
        """Write string content to remote path inside container."""
        # Use sh -c with heredoc or echo
        cmd = ["sh", "-c", f"cat << 'EOF' > {remote_path}\n{content}\nEOF\nchmod 600 {remote_path}"]
        self._run_cmd(cmd, target=target)

    def establish_tunnel(self) -> bool:
        """Bring up the IPsec tunnel from Gateway A."""
        print("[Orchestrator] Bringing up IPsec tunnel...", flush=True)
        # First ensure old connection is down
        self._run_cmd(["ipsec", "down", "ipsec-tunnel"], target="gateway-a")
        time.sleep(0.5)

        code, stdout, stderr = self._run_cmd(["ipsec", "up", "ipsec-tunnel"], target="gateway-a")
        output = stdout + stderr
        success = ("connection 'ipsec-tunnel' established successfully" in output or
                   "ESTABLISHED" in output or code == 0)
        print(f"[Orchestrator] Tunnel status: {'ESTABLISHED' if success else 'FAILED'}", flush=True)
        return success

    def teardown_tunnel(self) -> None:
        """Tear down the IPsec tunnel."""
        print("[Orchestrator] Tearing down IPsec tunnel...", flush=True)
        self._run_cmd(["ipsec", "down", "ipsec-tunnel"], target="gateway-a")

    def run_capture_session(self, config: IPsecConfig,
                            output_dir: Path,
                            filter_expr: str = "esp or udp port 500 or udp port 4500") -> Dict[str, Any]:
        """
        Executes a complete reproducible capture session:
        1. Apply configuration
        2. Start tcpdump
        3. Bring up tunnel
        4. Run traffic
        5. Stop tcpdump
        6. Tear down tunnel
        7. Save metadata and validate PCAP
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        pcap_file = output_dir / f"{config.capture_id}.pcap"
        meta_file = output_dir / f"{config.capture_id}.json"

        remote_pcap = f"/captures/{config.capture_id}.pcap"

        print(f"\n=======================================================", flush=True)
        print(f"Starting Capture Session: {config.capture_id}", flush=True)
        print(f"Configuration: {config.encryption} | PFS: {config.pfs} | DH: Group {config.dh_group} ({config.dh_name})", flush=True)
        print(f"Traffic Type: {config.traffic_type.upper()}", flush=True)
        print(f"=======================================================", flush=True)

        # 1. Apply config
        print("[1/6] Applying strongSwan cryptographic configuration...", flush=True)
        self.apply_config(config)

        # 2. Start capture on Gateway A
        print(f"[2/6] Starting tcpdump packet capture...", flush=True)
        self._run_cmd(["chmod", "777", "/captures"], target="gateway-a")
        self._run_cmd(["pkill", "-INT", "-f", "tcpdump"], target="gateway-a")
        time.sleep(0.5)

        tcpdump_args = ["tcpdump", "-Z", "root", "-i", "eth0", "-n", "-s", "0", "-w", remote_pcap]
        if filter_expr:
            tcpdump_args.extend(filter_expr.split())
        self._run_cmd(tcpdump_args, target="gateway-a", detached=True)
        time.sleep(1.5)  # Let tcpdump start and write header

        # 3. Establish tunnel
        print("[3/6] Establishing IPsec tunnel...", flush=True)
        tunnel_ok = self.establish_tunnel()

        # 4. Generate traffic
        print(f"[4/6] Generating {config.traffic_type} traffic through tunnel...", flush=True)
        traffic_cmd = [
            "python3", "/app/testbed/traffic_generator.py",
            "--type", config.traffic_type,
            "--target", "10.10.2.1",
            "--source", "10.10.1.1",
        ]
        t_code, t_stdout, t_stderr = self._run_cmd(traffic_cmd, target="gateway-a")
        traffic_result = {}
        try:
            traffic_result = json.loads(t_stdout)
        except Exception:
            traffic_result = {"raw_output": t_stdout, "error": t_stderr}

        time.sleep(1.5)  # Grace period for in-flight packets

        # 5. Stop capture
        print("[5/6] Stopping packet capture...", flush=True)
        self._run_cmd(["pkill", "-INT", "-f", "tcpdump"], target="gateway-a")
        time.sleep(2.0)  # Wait for file flush

        # Tear down tunnel
        self.teardown_tunnel()

        # Copy PCAP from container to host output_dir
        self._run_cmd(["docker", "cp", f"{self.container_a}:{remote_pcap}", str(pcap_file)])

        # 6. Generate metadata
        print("[6/6] Generating ground-truth metadata & validating capture...", flush=True)
        validation = PCAPValidator.analyze_pcap(pcap_file)

        extra_metadata = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "packet_count": validation.total_packets,
            "ike_packets": validation.ike_packets,
            "esp_packets": validation.esp_packets,
            "file_path": str(pcap_file.relative_to(output_dir.parent.parent) if output_dir.is_relative_to(output_dir.parent.parent) else pcap_file.name),
            "file_size_bytes": pcap_file.stat().st_size if pcap_file.exists() else 0,
            "tunnel_established": tunnel_ok,
            "traffic_generation_result": traffic_result,
        }
        metadata = config.generate_metadata(extra_metadata)

        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        print(f"[Summary] Captured {validation.total_packets} packets:")
        print(f"  - IKEv2 packets: {validation.ike_packets}")
        print(f"  - ESP encrypted packets: {validation.esp_packets}")
        print(f"  - Protocols detected: {validation.protocols_detected}")
        print(f"Saved PCAP: {pcap_file}")
        print(f"Saved Metadata: {meta_file}")

        return {
            "capture_id": config.capture_id,
            "pcap_file": str(pcap_file),
            "metadata_file": str(meta_file),
            "validation": validation.to_dict(),
            "metadata": metadata,
        }
