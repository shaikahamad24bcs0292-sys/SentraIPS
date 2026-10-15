"""
Phase 4 AI Traffic Classification Demonstration for SentraIPS.
Demonstrates end-to-end traffic classification from encrypted ESP metadata:
  1. Load demo PCAP
  2. Extract ESP features (packet sizes, timing, bursts, flow dynamics)
  3. Load trained Random Forest model
  4. Predict traffic classification
  5. Display confidence & model details
  6. Display features used
  7. Display limitations and cryptographic boundaries
"""

import argparse
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_analysis.features import ESPFeatureExtractor
from models.model_manager import ModelManager
from models.predict import predict_traffic


def run_phase4_demo(pcap_path: Path):
    if not pcap_path.exists():
        print(f"Error: Demo PCAP not found at {pcap_path}")
        sys.exit(1)

    print(f"Loading capture: {pcap_path.name}")
    print("Extracting ESP traffic metadata features...")
    features = ESPFeatureExtractor.extract_from_pcap(pcap_path)

    if features.total_packets == 0:
        print("Error: No ESP packets found in capture file.")
        sys.exit(1)

    manager = ModelManager()
    if not manager.is_loaded:
        print("[Warning] Trained weights not found. Using statistical baseline.")

    prediction = predict_traffic(features, model_manager=manager)

    traffic_class = prediction.get("traffic_class", "Unknown")
    confidence = prediction.get("confidence", 0.0)
    model_name = prediction.get("model", "RandomForest")
    confidence_pct = f"{confidence * 100:.1f}%"

    print("\n========================================")
    print("SENTRAIPS PHASE 4 AI ANALYSIS")
    print("========================================")
    print(f"Traffic Type : {traffic_class}")
    print(f"Confidence   : {confidence_pct}")
    print(f"Model        : {model_name}")
    print("")
    print("Features Used:")
    print("* Packet count")
    print("* Flow duration")
    print("* Packet size statistics")
    print("* IAT statistics")
    print("* Burst count")
    print("========================================")

    # Detailed Probabilities
    probs = prediction.get("probabilities", {})
    if probs:
        print("\nClass Probability Distribution:")
        for cls_name, p_val in sorted(probs.items(), key=lambda x: x[1], reverse=True):
            bar = "#" * int(p_val * 30)
            print(f"  {cls_name:<20}: {p_val * 100:>5.1f}% | {bar}")

    # Flow Characteristics
    print("\nObserved Flow Metrics:")
    print(f"  Total ESP Packets  : {features.total_packets}")
    print(f"  Total ESP Bytes    : {features.total_bytes:,} bytes")
    print(f"  Flow Duration      : {features.flow_duration_sec:.2f} s")
    print(f"  Mean Packet Size   : {features.size_mean:.1f} bytes")
    print(f"  Mean Inter-Arrival : {features.iat_mean_ms:.2f} ms")
    print(f"  Burst Count        : {features.burst_count}")

    # Display Limitations & Cryptographic Boundary
    print("\nModel Limitations & Security Boundaries:")
    print("  * Zero Decryption       : Payloads are never decrypted; classification uses outer headers & timing only.")
    print("  * Inferred vs Observed  : Traffic type is an INFERRED statistical estimate, not a deterministic guarantee.")
    print("  * Strict Separation     : Cryptographic parameters (Ciphers, DH groups, PFS, IKE versions) are strictly")
    print("                            evaluated by the deterministic Security Engine, NEVER predicted by ML.")
    print("========================================\n")


def main():
    parser = argparse.ArgumentParser(description="SentraIPS Phase 4 Demo Runner")
    parser.add_argument(
        "--pcap",
        type=str,
        default=str(PROJECT_ROOT / "demo_data" / "demo_capture.pcap"),
        help="Path to demo PCAP file (default: demo_data/demo_capture.pcap)",
    )
    args = parser.parse_args()
    run_phase4_demo(Path(args.pcap))


if __name__ == "__main__":
    main()
