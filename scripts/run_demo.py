"""
Phase 1 Demo Runner for SentraIPS.
Executes the complete end-to-end workflow:
  1. Ensures testbed containers are up
  2. Configures strongSwan (AES-256-GCM, DH 19, PFS True, Tunnel Mode)
  3. Establishes IPsec tunnel
  4. Generates web-like HTTP traffic
  5. Captures raw IKEv2 & ESP packets via tcpdump
  6. Saves demo PCAP and ground-truth metadata in demo_data/ and dataset/captures/
  7. Validates packet contents with Scapy and prints detailed summary
"""

import os
from pathlib import Path
import subprocess
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from testbed.config_generator import IPsecConfig
from testbed.orchestrator import TestbedOrchestrator
from packet_analysis.validator import PCAPValidator


def main():
    print("=================================================================")
    print("  SentraIPS — Phase 1 Demonstration")
    print("  Smart India Hackathon 2026 Prototype")
    print("=================================================================")

    orchestrator = TestbedOrchestrator()

    # Step 1: Ensure containers are running
    print("\n[Step 1] Checking Testbed Container Status...")
    if not orchestrator.check_containers_running():
        print("[Step 1] Containers not found running. Starting Docker Compose...")
        res = subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=PROJECT_ROOT)
        if res.returncode != 0:
            print("ERROR: Failed to start docker-compose. Please verify Docker Desktop is running.")
            sys.exit(1)
        print("[Step 1] Waiting 5 seconds for containers and charon to initialize...")
        time.sleep(5)
    else:
        print("[Step 1] Containers (ipsec-gateway-a, ipsec-gateway-b) are active.")

    # Step 2: Define Phase 1 Demo Configuration
    config = IPsecConfig(
        capture_id="demo_001",
        vpn_mode="tunnel",
        ip_version="ipv4",
        encryption="AES-256-GCM",
        pfs=True,
        dh_group=19,
        traffic_type="web",
    )

    # Output directories
    captures_dir = PROJECT_ROOT / "dataset" / "captures"
    demo_dir = PROJECT_ROOT / "demo_data"
    captures_dir.mkdir(parents=True, exist_ok=True)
    demo_dir.mkdir(parents=True, exist_ok=True)

    # Step 3: Run full capture session
    result = orchestrator.run_capture_session(
        config=config,
        output_dir=captures_dir,
    )

    # Copy to demo_data directory as reference demo capture
    src_pcap = captures_dir / "demo_001.pcap"
    src_meta = captures_dir / "demo_001.json"
    dst_pcap = demo_dir / "demo_capture.pcap"
    dst_meta = demo_dir / "demo_capture.json"

    if src_pcap.exists():
        import shutil
        shutil.copyfile(src_pcap, dst_pcap)
        shutil.copyfile(src_meta, dst_meta)

    # Step 4: Verification and Summary
    val = PCAPValidator.analyze_pcap(dst_pcap, dst_meta)

    print("\n=================================================================")
    print("  DEMO EXECUTION RESULTS")
    print("=================================================================")
    print(f"Capture ID          : {config.capture_id}")
    print(f"VPN Mode            : {config.vpn_mode.upper()} (IPv4)")
    print(f"Cipher Suite        : {config.encryption}")
    print(f"Diffie-Hellman Group: {config.dh_group} ({config.dh_name})")
    print(f"PFS Enabled         : {config.pfs}")
    print(f"Traffic Generated   : {config.traffic_type.upper()} traffic")
    print("-----------------------------------------------------------------")
    print(f"Total Packets       : {val.total_packets}")
    print(f"IKEv2 Packets       : {val.ike_packets}")
    print(f"ESP Packets         : {val.esp_packets}")
    print(f"Detected Protocols  : {', '.join(val.protocols_detected)}")
    print(f"Metadata Valid      : {val.metadata_valid}")
    print(f"Demo PCAP Stored At : {dst_pcap}")
    print(f"Demo Metadata At    : {dst_meta}")
    print("=================================================================")
    print(" Phase 1 Demo Completed Successfully!")
    print("=================================================================\n")


if __name__ == "__main__":
    main()
