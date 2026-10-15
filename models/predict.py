"""
Traffic Prediction Interface for SentraIPS (Phase 4).
Performs inference over encrypted ESP traffic metadata and returns structured predictions:
{
    "traffic_class": "Web",
    "confidence": 0.91,
    "model": "RandomForest"
}
If confidence falls below threshold (default 0.50), safely returns 'Unknown' without forcing a label.
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Union

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_analysis.features import ESPFeatureExtractor, ESPTrafficFeatures
from models.feature_schema import TrafficPredictionOutput
from models.model_manager import ModelManager

# Shared singleton ModelManager
_default_manager: Optional[ModelManager] = None


def get_model_manager() -> ModelManager:
    """Returns or lazily initializes the default ModelManager singleton."""
    global _default_manager
    if _default_manager is None:
        _default_manager = ModelManager()
    return _default_manager


def predict_traffic(
    input_data: Union[ESPTrafficFeatures, Dict[str, Any], Path, str],
    confidence_threshold: float = 0.50,
    model_manager: Optional[ModelManager] = None,
) -> Dict[str, Any]:
    """
    Infers traffic classification strictly from encrypted ESP traffic features.

    Args:
        input_data: An ESPTrafficFeatures object, a feature dictionary, or a path to a .pcap / .json file.
        confidence_threshold: Cutoff score below which the output becomes 'Unknown'.
        model_manager: Optional custom ModelManager instance.

    Returns:
        {
            "traffic_class": str,
            "confidence": float,
            "model": "RandomForest",
            "probabilities": Dict[str, float]
        }
    """
    manager = model_manager or get_model_manager()

    # 1. Resolve input data to ESPTrafficFeatures or feature dict
    if isinstance(input_data, (str, Path)):
        p = Path(input_data)
        if not p.exists():
            return {
                "traffic_class": "Unknown",
                "confidence": 0.0,
                "model": "RandomForest",
                "error": f"File not found: {p}",
            }

        suffix = p.suffix.lower()
        if suffix in (".pcap", ".pcapng", ".cap"):
            if p.stat().st_size == 0:
                return {
                    "traffic_class": "Unknown",
                    "confidence": 0.0,
                    "model": "RandomForest",
                    "note": "Empty capture file (0 bytes)",
                }
            try:
                features = ESPFeatureExtractor.extract_from_pcap(p)
            except Exception as e:
                return {
                    "traffic_class": "Unknown",
                    "confidence": 0.0,
                    "model": "RandomForest",
                    "error": f"Failed to parse PCAP: {str(e)}",
                }
            if features.total_packets == 0:
                return {
                    "traffic_class": "Unknown",
                    "confidence": 0.0,
                    "model": "RandomForest",
                    "note": "No ESP packets detected in PCAP",
                }
            feat_dict = features.to_flat_dict()
        elif suffix == ".json":
            with open(p, "r", encoding="utf-8") as f:
                feat_dict = json.load(f)
        else:
            return {
                "traffic_class": "Unknown",
                "confidence": 0.0,
                "model": "RandomForest",
                "error": f"Unsupported file type: {suffix}",
            }
    elif isinstance(input_data, ESPTrafficFeatures):
        feat_dict = input_data.to_flat_dict()
    elif isinstance(input_data, dict):
        feat_dict = input_data
    else:
        return {
            "traffic_class": "Unknown",
            "confidence": 0.0,
            "model": "RandomForest",
            "error": f"Invalid input type: {type(input_data)}",
        }

    # 2. Run prediction via ModelManager
    res = manager.predict(feat_dict, confidence_threshold=confidence_threshold)

    # 3. Format response conforming strictly to Phase 4 specifications
    out = {
        "traffic_class": res.get("traffic_class", "Unknown"),
        "confidence": res.get("confidence", 0.0),
        "model": "RandomForest",
    }
    if "probabilities" in res:
        out["probabilities"] = res["probabilities"]
    if "error" in res:
        out["error"] = res["error"]

    return out


def main():
    parser = argparse.ArgumentParser(description="SentraIPS Traffic Prediction CLI (Phase 4)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", type=str, help="Path to PCAP file")
    group.add_argument("--features", type=str, help="Path to features JSON file")
    parser.add_argument("--threshold", type=float, default=0.50, help="Confidence threshold (default: 0.50)")

    args = parser.parse_args()
    target = args.pcap or args.features

    result = predict_traffic(target, confidence_threshold=args.threshold)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
