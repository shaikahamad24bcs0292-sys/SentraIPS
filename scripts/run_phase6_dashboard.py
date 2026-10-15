"""
Phase 6 Dashboard Runner & Verification Script.
Allows launching the Streamlit web dashboard or running headless verification.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_headless_verification():
    """Validates that frontend/app.py and all underlying engines run cleanly without errors."""
    print("=" * 80)
    print("  SentraIPS - Phase 6: Headless Dashboard Component Verification")
    print("=" * 80)

    # 1. Test Streamlit import
    import streamlit as st
    print(f"  [+] Streamlit framework version: {st.__version__}")

    # 2. Test app module loading & syntax
    app_path = PROJECT_ROOT / "frontend" / "app.py"
    assert app_path.exists(), f"App file not found: {app_path}"
    print(f"  [+] Dashboard entrypoint confirmed: {app_path}")

    # 3. Test underlying pipeline integration
    from frontend.app import run_full_assessment
    target_pcap = PROJECT_ROOT / "demo_data" / "weak_capture.pcap"
    print(f"  [+] Testing assessment execution on: {target_pcap.name}")
    results = run_full_assessment(target_pcap)

    assert "sec_report" in results, "Assessment must return sec_report"
    assert "traffic_inference" in results, "Assessment must return traffic_inference"
    assert "enriched_findings" in results, "Assessment must return enriched_findings"
    assert "narrative" in results, "Assessment must return narrative"

    score = results["sec_report"].risk_score
    findings_count = len(results["enriched_findings"])
    inference = results["traffic_inference"].final_prediction
    print(f"  [+] Risk Score:           {score}/100 ({results['sec_report'].severity})")
    print(f"  [+] Enriched Findings:    {findings_count} items")
    print(f"  [+] Inferred Traffic:     {inference}")
    print(f"  [+] Narrative Summary:    {results['narrative'].executive_summary[:100]}...")

    print("=" * 80)
    print("  PHASE 6 VERIFICATION: SUCCESSFUL (Headless components verified)")
    print("=" * 80)


def launch_dashboard(port: int = 8501, headless: bool = True):
    """Launches the Streamlit dashboard on the specified port."""
    app_path = PROJECT_ROOT / "frontend" / "app.py"
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.port",
        str(port),
        f"--server.headless={'true' if headless else 'false'}",
        "--browser.gatherUsageStats=false",
    ]
    print(f"Launching Streamlit dashboard: {' '.join(cmd)}")
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(description="SentraIPS Phase 6 Dashboard Runner")
    parser.add_argument("--verify-only", action="store_true", help="Run headless pipeline verification without opening browser")
    parser.add_argument("--port", type=int, default=8501, help="Port to host Streamlit on (default: 8501)")
    parser.add_argument("--no-headless", action="store_true", help="Launch with browser auto-open")

    args = parser.parse_args()

    if args.verify_only:
        run_headless_verification()
    else:
        launch_dashboard(port=args.port, headless=not args.no_headless)


if __name__ == "__main__":
    main()
