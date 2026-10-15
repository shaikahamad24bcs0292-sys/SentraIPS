"""
Phase 2 Demonstration Script for SentraIPS.
Demonstrates the complete Phase 2 pipeline:
  1. Validates and parses PCAP (demo_data/demo_capture.pcap)
  2. Identifies IPsec packets (IKEv2 & ESP)
  3. Extracts observable cryptographic parameters (Cipher, DH Group, PFS, SPIs)
  4. Extracts encrypted ESP metadata features (Packet sizes, IATs, bursts, sequences)
  5. Shows integration with DatasetBuilder and labels.csv
  6. Demonstrates POST /analyze-pcap API response structure
"""

import json
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_analysis.parser import IPsecPCAPParser
from packet_analysis.features import ESPFeatureExtractor
from dataset.builder import DatasetBuilder
from backend.main import app
from fastapi.testclient import TestClient


def main():
    print("=================================================================")
    print("  SentraIPS — Phase 2 Demonstration")
    print("  PCAP Parsing, Protocol Analysis, ESP Features & Dataset Pipeline")
    print("=================================================================")

    demo_pcap = PROJECT_ROOT / "demo_data" / "demo_capture.pcap"
    if not demo_pcap.exists():
        print(f"ERROR: Demo PCAP not found at {demo_pcap}")
        sys.exit(1)

    print(f"\n[Step 1] Loading and Validating PCAP...")
    is_valid, val_errors = IPsecPCAPParser.validate_file(demo_pcap)
    print(f"  - File: {demo_pcap.name} ({demo_pcap.stat().st_size} bytes)")
    print(f"  - Valid Magic Header: {is_valid}")
    if not is_valid:
        print(f"  - Validation Errors: {val_errors}")
        sys.exit(1)

    print(f"\n[Step 2] Dissecting Packets & Protocol Identification...")
    parse_res = IPsecPCAPParser.parse_pcap(demo_pcap)
    print(f"  - Total Packets        : {parse_res.total_packets}")
    print(f"  - IPsec Detected       : {parse_res.ipsec_detected}")
    print(f"  - IKEv2 Packets        : {parse_res.ike_packets}")
    print(f"  - ESP Packets          : {parse_res.esp_packets}")
    print(f"  - Non-IPsec Packets    : {parse_res.non_ipsec_packets}")
    print(f"  - Protocols Detected   : {', '.join(parse_res.protocols_detected)}")

    print(f"\n[Step 3] IKEv2 Cryptographic & Protocol Parameters...")
    ike = parse_res.ike
    print(f"  - IKE Version          : {ike.version}")
    print(f"  - Initiator SPI        : {ike.initiator_spi}")
    print(f"  - Responder SPI        : {ike.responder_spi}")
    print(f"  - Encryption Algorithm : {ike.encryption}")
    print(f"  - Key Length           : {ike.encryption_key_length} bits" if ike.encryption_key_length else "  - Key Length: N/A")
    print(f"  - Integrity / PRF      : {ike.authentication}")
    print(f"  - Diffie-Hellman Group : Group {ike.dh_group} ({ike.dh_group_name})")
    print(f"  - PFS (Forward Secrecy): {ike.pfs}")
    print(f"  - Exchange Types Seen  : {', '.join(ike.exchange_types_observed)}")

    print(f"\n[Step 4] Extracting Encrypted ESP Metadata Features (No Payload Decryption)...")
    feats = ESPFeatureExtractor.extract_from_pcap(demo_pcap)
    print(f"  - Total ESP Packets    : {feats.total_packets}")
    print(f"  - Flow Duration        : {feats.flow_duration_sec:.3f} seconds")
    print(f"  - Total Volume         : {feats.total_bytes:,} bytes")
    print(f"  - Forward / Backward   : {feats.forward_packets} pkts ({feats.forward_bytes} B) / {feats.backward_packets} pkts ({feats.backward_bytes} B)")
    print(f"  - Packet Size Mean     : {feats.size_mean:.2f} bytes (Min: {feats.size_min}, Max: {feats.size_max}, Std: {feats.size_std:.2f})")
    print(f"  - Inter-Arrival Time   : Mean: {feats.iat_mean_ms:.2f} ms (Min: {feats.iat_min_ms:.2f} ms, Max: {feats.iat_max_ms:.2f} ms)")
    print(f"  - Traffic Bursts       : {feats.burst_count} bursts (Avg burst size: {feats.mean_burst_size_pkts} pkts)")
    print(f"  - Temporal Sequence (First 8 pkts): {feats.packet_size_sequence[:8]}")

    print(f"\n[Step 5] Synchronizing Dataset & Ground-Truth Labels...")
    builder = DatasetBuilder(PROJECT_ROOT)
    builder.sync_from_sources()
    d_res = builder.build_dataset()
    print(f"  - Dataset Records Processed : {d_res['total_captures_processed']}")
    print(f"  - Labels CSV                : {d_res['labels_file']}")
    print(f"  - Processed Feature JSONs   : {d_res['processed_dir']}")

    print(f"\n[Step 6] Testing REST API (POST /analyze-pcap)...")
    client = TestClient(app)
    with open(demo_pcap, "rb") as f:
        api_res = client.post(
            "/analyze-pcap",
            files={"file": ("demo_capture.pcap", f, "application/vnd.tcpdump.pcap")},
        )
    print(f"  - HTTP Status Code : {api_res.status_code}")
    api_data = api_res.json()
    print("  - Response Payload Summary:")
    print(json.dumps({
        "capture_id": api_data["capture_id"],
        "ipsec_detected": api_data["ipsec_detected"],
        "ike_version": api_data["ike_version"],
        "encryption": api_data["encryption"],
        "dh_group": api_data["dh_group"],
        "pfs": api_data["pfs"],
        "esp_packets": api_data["esp_packets"],
        "features_extracted": api_data["features_extracted"],
        "flow_duration_sec": api_data["esp_features"]["flow_duration_sec"] if api_data.get("esp_features") else None,
        "packet_size_mean": api_data["esp_features"]["size_mean"] if api_data.get("esp_features") else None,
    }, indent=4))

    print("\n=================================================================")
    print(" Phase 2 Demonstration Completed Successfully!")
    print("=================================================================\n")


if __name__ == "__main__":
    main()
