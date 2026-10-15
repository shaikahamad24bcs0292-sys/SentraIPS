"""
Phase 4 Feature Schema and Validation for SentraIPS AI Traffic Classification.
Defines canonical target classes, observable encrypted ESP feature definitions,
and feature vector validation functions.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from pydantic import BaseModel, Field

# Target classes specified for Phase 4
TARGET_CLASSES: List[str] = [
    "Web",
    "Video",
    "VoIP",
    "ICMP",
    "Bulk/Data Transfer",
    "Unknown",
]

# Canonical classes recognized by the trained classifier
MODEL_CLASSES: List[str] = [
    "Web",
    "Video",
    "VoIP",
    "ICMP",
    "Bulk/Data Transfer",
]

# Observable features strictly derived from encrypted ESP metadata (outer headers and flow dynamics)
FEATURE_NAMES: List[str] = [
    # Volume and Direction
    "total_packets",
    "total_bytes",
    "forward_packets",
    "backward_packets",
    "packet_ratio_fwd_bwd",
    "byte_ratio_fwd_bwd",
    # Timing and Throughput
    "flow_duration_sec",
    "packets_per_sec",
    "bytes_per_sec",
    # Packet Size Statistics (bytes)
    "size_min",
    "size_max",
    "size_mean",
    "size_median",
    "size_std",
    "size_p25",
    "size_p75",
    "size_p90",
    "size_skewness",
    # Inter-Arrival Time Statistics (milliseconds)
    "iat_min_ms",
    "iat_max_ms",
    "iat_mean_ms",
    "iat_median_ms",
    "iat_std_ms",
    # Burst Dynamics (threshold = 50ms)
    "burst_count",
    "mean_burst_size_pkts",
    "mean_burst_duration_ms",
    "mean_burst_bytes",
]


class TrafficClass(str, Enum):
    WEB = "Web"
    VIDEO = "Video"
    VOIP = "VoIP"
    ICMP = "ICMP"
    BULK = "Bulk/Data Transfer"
    UNKNOWN = "Unknown"


class TrafficPredictionOutput(BaseModel):
    """Standardized Phase 4 traffic prediction response schema."""
    traffic_class: str = Field(..., description="Inferred traffic type, e.g. Web, Video, VoIP, ICMP, Bulk/Data Transfer, Unknown")
    confidence: float = Field(..., description="Model confidence score in range [0.0, 1.0]")
    model: str = Field(default="RandomForest", description="Classifier identifier")
    probabilities: Dict[str, float] = Field(default_factory=dict, description="Class probability distribution")


class TrafficAnalysisSummary(BaseModel):
    """Unified API response element for traffic classification."""
    classification: str
    confidence: float
    model: str = "RandomForest"


def normalize_traffic_class(label: str) -> str:
    """Normalizes raw ground-truth traffic type strings into canonical target classes."""
    if not label:
        return "Unknown"
    s = str(label).lower().strip()
    if "voip" in s or "rtp" in s:
        return "VoIP"
    if "icmp" in s or "ping" in s:
        return "ICMP"
    if "bulk" in s or "data transfer" in s or "file_download" in s or "scp" in s or "ftp" in s:
        return "Bulk/Data Transfer"
    if "video" in s or "stream" in s or "youtube" in s:
        return "Video"
    if "web" in s or "http" in s or "browse" in s:
        return "Web"
    return "Unknown"


def validate_feature_vector(
    features: Union[Dict[str, Any], Any],
) -> Tuple[bool, List[str], Optional[np.ndarray]]:
    """
    Validates a feature dictionary or ESPTrafficFeatures instance.
    Checks for:
    - Presence of required numerical feature keys
    - Absence of NaNs, infinities, or invalid non-numeric types
    - Valid non-negative counts and durations

    Returns:
        (is_valid, error_list, feature_array_1d)
    """
    errors: List[str] = []

    # If an ESPTrafficFeatures object is passed, convert to flat dict
    if hasattr(features, "to_flat_dict"):
        feat_dict = features.to_flat_dict()
    elif isinstance(features, dict):
        feat_dict = features
    else:
        return False, ["Input features must be a dictionary or ESPTrafficFeatures instance."], None

    if not feat_dict:
        return False, ["Feature vector is empty."], None

    values: List[float] = []
    for name in FEATURE_NAMES:
        if name not in feat_dict:
            errors.append(f"Missing required feature: '{name}'")
            continue

        raw_val = feat_dict[name]
        try:
            val = float(raw_val)
        except (ValueError, TypeError):
            errors.append(f"Feature '{name}' has non-numeric value: {raw_val}")
            continue

        if np.isnan(val):
            errors.append(f"Feature '{name}' contains NaN.")
            continue
        if np.isinf(val):
            errors.append(f"Feature '{name}' contains Infinity.")
            continue

        # Check for logically impossible negative values
        if name in ("total_packets", "total_bytes", "flow_duration_sec", "size_min", "size_max", "burst_count"):
            if val < 0:
                errors.append(f"Feature '{name}' cannot be negative: {val}")
                continue

        values.append(val)

    if errors:
        return False, errors, None

    arr = np.array(values, dtype=np.float32)
    return True, [], arr
