"""
Parameterized Capture Runner CLI for SentraIPS.
Allows running captures with custom combinations of:
- Encryption: AES-128-CBC, AES-256-GCM
- DH Groups: 14, 19, 5, 20
- PFS: enabled / disabled
- Traffic Types: icmp, web, video, voip
"""

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from testbed.config_generator import IPsecConfig, DH_GROUP_MAP
from testbed.orchestrator import TestbedOrchestrator


def main():
    parser = argparse.ArgumentParser(description="SentraIPS Automated Capture Runner")
    parser.add_argument("--id", default="capture_test", help="Capture identifier")
    parser.add_argument("--encryption", choices=["AES-256-GCM", "AES-128-CBC"], default="AES-256-GCM", help="IPsec cipher suite")
    parser.add_argument("--dh", type=int, choices=[14, 19, 5, 20], default=19, help="Diffie-Hellman group")
    parser.add_argument("--pfs", action="store_true", default=True, help="Enable Perfect Forward Secrecy")
    parser.add_argument("--no-pfs", action="store_false", dest="pfs", help="Disable Perfect Forward Secrecy")
    parser.add_argument("--traffic", choices=["icmp", "web", "video", "voip"], default="web", help="Traffic type to generate")
    parser.add_argument("--output", default="dataset/captures", help="Output directory for PCAP and metadata")

    args = parser.parse_args()

    orchestrator = TestbedOrchestrator()
    if not orchestrator.check_containers_running():
        print("ERROR: Testbed containers are not running. Run 'docker compose up -d' first.")
        sys.exit(1)

    config = IPsecConfig(
        capture_id=args.id,
        vpn_mode="tunnel",
        ip_version="ipv4",
        encryption=args.encryption,
        pfs=args.pfs,
        dh_group=args.dh,
        traffic_type=args.traffic,
    )

    output_dir = PROJECT_ROOT / args.output
    result = orchestrator.run_capture_session(config=config, output_dir=output_dir)

    print(f"\nCapture session complete. Stored at {result['pcap_file']}")


if __name__ == "__main__":
    main()
