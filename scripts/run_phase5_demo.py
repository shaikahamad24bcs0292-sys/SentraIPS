"""
Phase 5 Automated Security Reporting & Compliance Demonstration for SentraIPS.
Executes the end-to-end audit workflow:
  1. Analyze demo PCAP
  2. Run deterministic Security Engine
  3. Run Phase 4 AI/ML Traffic Classification
  4. Evaluate compliance against Knowledge Base (NIST SP 800-77 & RFC 8221/8247)
  5. Generate prioritized recommendations
  6. Generate machine-readable JSON report
  7. Generate standalone executive HTML report
  8. Save all reports to reports/
"""

import argparse
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reporting.report_generator import ReportGenerator


def run_phase5_demo(pcap_path: Path):
    if not pcap_path.exists():
        print(f"Error: PCAP file not found at {pcap_path}")
        sys.exit(1)

    print("=================================================================")
    print("  SentraIPS Phase 5 — Automated Security & Compliance Audit")
    print("  Smart India Hackathon 2026 Prototype")
    print("=================================================================")
    print(f"\n[Step 1] Loading capture: {pcap_path.name}")

    generator = ReportGenerator()

    print("[Step 2] Executing deterministic protocol parsing & ESP feature extraction...")
    print("[Step 3] Running deterministic Security Engine & risk scoring...")
    print("[Step 4] Running Phase 4 AI traffic classification...")
    print("[Step 5] Evaluating compliance against NIST SP 800-77 & RFC 8221/8247 Knowledge Base...")

    report = generator.generate_report_from_pcap(pcap_path)

    print("[Step 6] Compiling prioritized recommendations & audit disclaimers...")
    print("[Step 7] Serializing JSON and rendering standalone HTML reports...")

    json_path, html_path = generator.save_reports(report)

    # -------------------------------------------------------------
    # Formatted Console Display
    # -------------------------------------------------------------
    s = report.summary
    print("\n========================================")
    print("SENTRAIPS PHASE 5 EXECUTIVE SUMMARY")
    print("========================================")
    print(f"Report ID           : {report.report_id}")
    print(f"Timestamp           : {report.timestamp}")
    print(f"Overall Risk Score  : {s.overall_risk_score} / 100 ({s.severity})")
    print(f"Compliance Rating   : {s.compliance_rating}")
    print(f"Traffic Class       : {s.traffic_classification} ({s.traffic_confidence * 100:.1f}% confidence)")
    print("")
    print("Detected Cryptographic Baseline:")
    print(f"  * IKE Protocol    : {s.ike_version}")
    print(f"  * Encryption Suite: {s.encryption}")
    print(f"  * DH Key Exchange : {s.dh_group}")
    print(f"  * Forward Secrecy : PFS={s.pfs}")
    print("========================================")

    print("\nCompliance & Standards Matrix (NIST SP 800-77 & RFC 8221/8247):")
    for c in report.compliance:
        badge = f"[{c.status}]"
        print(f"  {badge:<10} {c.control_id:<12} {c.title:<38}: {c.observed_value}")

    print(f"\nCompliance Summary:")
    print(f"  Passed: {report.compliance_summary['passed']} | Warnings: {report.compliance_summary['warnings']} | Failed: {report.compliance_summary['failed']} | Unknown: {report.compliance_summary['unknown']}")

    if report.findings:
        print(f"\nVulnerability Findings Detected ({len(report.findings)}):")
        for f in report.findings:
            print(f"  * [{f.severity}] {f.id}: {f.title}")
            print(f"    Impact: {f.impact}")
            print(f"    Remediation: {f.recommendation}")
    else:
        print("\nVulnerability Findings: None (Configuration complies with best practice baselines).")

    if report.recommendations:
        print(f"\nPrioritized Remediation Roadmap ({len(report.recommendations)}):")
        for r in report.recommendations:
            print(f"  [{r.priority}] {r.title} -> {r.action}")

    print("\nGenerated Report Artifacts:")
    print(f"  * JSON Report : {json_path}")
    print(f"  * HTML Report : {html_path}")

    print("\nAudit Limitations & Security Boundaries:")
    for lim in report.limitations:
        print(f"  - {lim}")
    print("=================================================================\n")


def main():
    parser = argparse.ArgumentParser(description="SentraIPS Phase 5 Audit Demo Runner")
    parser.add_argument(
        "--pcap",
        type=str,
        default=str(PROJECT_ROOT / "demo_data" / "demo_capture.pcap"),
        help="Path to capture file (default: demo_data/demo_capture.pcap)",
    )
    args = parser.parse_args()
    run_phase5_demo(Path(args.pcap))


if __name__ == "__main__":
    main()
