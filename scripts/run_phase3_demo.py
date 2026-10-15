"""
Phase 3 Demonstration Script for SentraIPS.
Executes the full pipeline:
PCAP -> IPsec Parser -> Extracted Configuration -> Security Rules -> Findings -> Risk Score -> Recommendations.
Strictly prints real, deterministic values derived from packet parsing and security rules.
"""

import argparse
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_analysis.parser import IPsecPCAPParser
from security_engine import SecurityEngine


def run_pipeline(pcap_path: Path, engine: SecurityEngine):
    """Executes PCAP -> Parser -> Security Engine -> Assessment and prints clean report."""
    if not pcap_path.exists():
        print(f"Error: PCAP file not found at {pcap_path}")
        return None

    # Pipeline Step 1 & 2: PCAP -> Parser -> Extracted Configuration
    # Pipeline Step 3, 4, 5: Security Rules -> Findings -> Risk Score -> Recommendations
    report = engine.assess_pcap_file(pcap_path)
    cfg = report.observed_configuration
    pfs_val = cfg.get("pfs")
    if pfs_val is True:
        pfs_str = "Enabled"
    elif pfs_val is False:
        pfs_str = "Disabled"
    else:
        pfs_str = str(pfs_val)

    dh_grp = cfg.get("dh_group", "Unknown / Not Detected")
    dh_name = cfg.get("dh_group_name", "")
    dh_str = f"{dh_grp} ({dh_name})" if dh_name and dh_name != "Unknown / Not Detected" else str(dh_grp)

    print("========================================")
    print("SENTRAIPS PHASE 3 SECURITY ASSESSMENT")
    print("========================================")
    print(f"Target     : {pcap_path.name}")
    print(f"Encryption : {cfg.get('encryption', 'Unknown / Not Detected')}")
    print(f"DH Group   : {dh_str}")
    print(f"PFS        : {pfs_str}")
    print(f"IKE        : {cfg.get('ike_version', 'Unknown / Not Detected')}")
    print(f"VPN Mode   : {str(cfg.get('vpn_mode', 'Unknown / Not Detected')).capitalize()}")
    print()
    print(f"Risk Score : {report.risk_score}/100")
    print(f"Severity   : {report.severity}")
    print()
    print("Findings:")
    if not report.findings:
        print("  None (No security vulnerabilities detected)")
    else:
        for idx, f in enumerate(report.findings, 1):
            obs_field = f.evidence.observed_field if hasattr(f.evidence, "observed_field") else ""
            obs_val = f.evidence.observed_value if hasattr(f.evidence, "observed_value") else ""
            ev_str = f"Evidence: {obs_field}={obs_val}" if obs_field else f"Evidence: {f.evidence}"
            print(f"{idx}. [{f.severity}] {f.title} ({ev_str})")
            if f.impact:
                print(f"   Impact: {f.impact}")

    print()
    print("Recommendations:")
    if not report.recommendations:
        print("  None (No remedial actions required)")
    else:
        for idx, r in enumerate(report.recommendations, 1):
            print(f"{idx}. [{r.priority}] {r.title}")
            print(f"   Action: {r.action}")

    print("========================================\n")
    return report


def main():
    parser = argparse.ArgumentParser(description="SentraIPS Phase 3 Security Assessment Demo")
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Path to custom PCAP file (defaults to demo_capture.pcap and weak_capture.pcap)",
    )
    args = parser.parse_args()

    engine = SecurityEngine()
    demo_dir = PROJECT_ROOT / "demo_data"

    if args.pcap:
        target = Path(args.pcap)
        run_pipeline(target, engine)
    else:
        # Default: Run primary secure capture, then weak capture for comparison
        secure_pcap = demo_dir / "demo_capture.pcap"
        weak_pcap = demo_dir / "weak_capture.pcap"

        print("\n>>> RUNNING DEMO SCENARIO 1: SECURE CAPTURE <<<\n")
        run_pipeline(secure_pcap, engine)

        if weak_pcap.exists():
            print(">>> RUNNING DEMO SCENARIO 2: WEAK CAPTURE <<<\n")
            run_pipeline(weak_pcap, engine)


if __name__ == "__main__":
    main()
