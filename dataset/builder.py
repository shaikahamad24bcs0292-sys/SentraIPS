"""
Dataset Builder for SentraIPS.
Processes raw PCAP captures and metadata, extracts encrypted ESP feature vectors,
and compiles the ground-truth labeled dataset (dataset/labels.csv and dataset/processed/).
"""

import csv
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any, Dict, List, Optional
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_analysis.parser import IPsecPCAPParser
from packet_analysis.features import ESPFeatureExtractor


class DatasetBuilder:
    """Orchestrates dataset compilation, feature processing, and label synchronization."""

    LABEL_COLUMNS = [
        "capture_id",
        "vpn_mode",
        "encryption",
        "authentication",
        "dh_group",
        "pfs",
        "ip_version",
        "traffic_type",
        "total_packets",
        "esp_packets",
        "ike_packets",
        "flow_duration_sec",
        "raw_pcap",
        "processed_features_file",
    ]

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).resolve().parent.parent
        self.raw_dir = self.base_dir / "dataset" / "raw"
        self.processed_dir = self.base_dir / "dataset" / "processed"
        self.captures_dir = self.base_dir / "dataset" / "captures"
        self.demo_dir = self.base_dir / "demo_data"
        self.labels_file = self.base_dir / "dataset" / "labels.csv"

        # Ensure directories exist
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.captures_dir.mkdir(parents=True, exist_ok=True)

    def sync_from_sources(self) -> int:
        """Copies PCAP and metadata pairs from testbed captures and demo_data into dataset/raw/."""
        synced_count = 0
        search_dirs = [self.captures_dir, self.demo_dir]

        for sdir in search_dirs:
            if not sdir.exists():
                continue
            for pcap_file in sdir.glob("*.pcap"):
                dest_pcap = self.raw_dir / pcap_file.name
                if not dest_pcap.exists() or dest_pcap.stat().st_size != pcap_file.stat().st_size:
                    shutil.copyfile(pcap_file, dest_pcap)
                    synced_count += 1

                # Check for corresponding JSON metadata
                meta_file = pcap_file.with_suffix(".json")
                if meta_file.exists():
                    dest_meta = self.raw_dir / meta_file.name
                    if not dest_meta.exists() or dest_meta.stat().st_size != meta_file.stat().st_size:
                        shutil.copyfile(meta_file, dest_meta)

        return synced_count

    def build_dataset(self) -> Dict[str, Any]:
        """
        Parses all PCAPs in dataset/raw/, extracts features, writes processed JSONs,
        and regenerates dataset/labels.csv.
        """
        # Step 1: Sync any new files into dataset/raw
        self.sync_from_sources()

        records: List[Dict[str, Any]] = []
        pcap_files = sorted(list(self.raw_dir.glob("*.pcap")))

        for pcap_file in pcap_files:
            cid = pcap_file.stem

            # Load ground truth if JSON metadata exists
            meta_file = pcap_file.with_suffix(".json")
            ground_truth = None
            if meta_file.exists():
                try:
                    with open(meta_file, "r", encoding="utf-8") as f:
                        ground_truth = json.load(f)
                except Exception:
                    pass

            # Parse PCAP
            parse_res = IPsecPCAPParser.parse_pcap(pcap_file, capture_id=cid, ground_truth=ground_truth)

            # Extract ESP features
            features = ESPFeatureExtractor.extract_from_pcap(pcap_file)

            # Save processed features JSON
            proc_file = self.processed_dir / f"{cid}_features.json"
            feature_payload = {
                "capture_id": cid,
                "pcap_file": pcap_file.name,
                "summary": parse_res.model_dump(),
                "features": features.model_dump(),
            }
            with open(proc_file, "w", encoding="utf-8") as f:
                json.dump(feature_payload, f, indent=2)

            # Determine ground truth values, preferring verified metadata, then parsed values
            vpn_mode = (ground_truth.get("vpn_mode") if ground_truth else None) or "tunnel"
            encryption = (ground_truth.get("encryption") if ground_truth else None) or parse_res.ike.encryption
            auth = (ground_truth.get("authentication") if ground_truth else None) or parse_res.ike.authentication
            dh = (ground_truth.get("dh_group") if ground_truth else None) or parse_res.ike.dh_group
            pfs = (ground_truth.get("pfs") if ground_truth else None) if ground_truth is not None else parse_res.ike.pfs
            ip_ver = (ground_truth.get("ip_version") if ground_truth else None) or "ipv4"
            traffic_type = (ground_truth.get("traffic_type") if ground_truth else None) or "Unknown / Not Detected"

            row = {
                "capture_id": cid,
                "vpn_mode": vpn_mode,
                "encryption": encryption,
                "authentication": auth,
                "dh_group": dh if dh is not None else "Unknown / Not Detected",
                "pfs": pfs if pfs is not None else "Unknown / Not Detected",
                "ip_version": ip_ver,
                "traffic_type": traffic_type,
                "total_packets": parse_res.total_packets,
                "esp_packets": parse_res.esp_packets,
                "ike_packets": parse_res.ike_packets,
                "flow_duration_sec": features.flow_duration_sec,
                "raw_pcap": f"dataset/raw/{pcap_file.name}",
                "processed_features_file": f"dataset/processed/{proc_file.name}",
            }
            records.append(row)

        # Write labels.csv
        df = pd.DataFrame(records, columns=self.LABEL_COLUMNS)
        df.to_csv(self.labels_file, index=False)

        return {
            "total_captures_processed": len(records),
            "labels_file": str(self.labels_file),
            "processed_dir": str(self.processed_dir),
            "captures": [r["capture_id"] for r in records],
        }


def main():
    print("=======================================================")
    print("  SentraIPS Dataset Builder")
    print("=======================================================")
    builder = DatasetBuilder()
    synced = builder.sync_from_sources()
    print(f"Synced {synced} new capture(s) into dataset/raw/")
    res = builder.build_dataset()
    print(f"Successfully processed {res['total_captures_processed']} capture(s).")
    print(f"Labels saved to: {res['labels_file']}")
    print(f"Processed feature vectors saved to: {res['processed_dir']}")
    print("=======================================================")


if __name__ == "__main__":
    main()
