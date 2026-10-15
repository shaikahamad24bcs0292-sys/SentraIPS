"""
Model Manager for SentraIPS Phase 4 Traffic Classification.
Handles model loading, saving, evaluation, lifecycle management, and graceful missing-model handling.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .feature_schema import (
    FEATURE_NAMES,
    MODEL_CLASSES,
    TARGET_CLASSES,
    TrafficPredictionOutput,
    validate_feature_vector,
)


class ModelManager:
    """Manages training, persistence, and inference lifecycle for Random Forest traffic classifier."""

    DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "weights" / "rf_traffic_model.joblib"
    CONFIDENCE_THRESHOLD = 0.50  # Below this threshold, classify as 'Unknown'

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        confidence_threshold: float = CONFIDENCE_THRESHOLD,
    ):
        self.model_path = Path(model_path) if model_path else self.DEFAULT_MODEL_PATH
        self.confidence_threshold = confidence_threshold
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.classes: List[str] = list(MODEL_CLASSES)
        self.metadata: Dict[str, Any] = {}
        self.is_loaded: bool = False

        # Attempt to load model at initialization
        self.load_model()

    def load_model(self, path: Optional[Union[str, Path]] = None) -> bool:
        """
        Loads the trained Random Forest model and scaler from disk.
        Gracefully handles missing model files without raising unhandled exceptions.
        """
        target_path = Path(path) if path else self.model_path

        if not target_path.exists():
            # Check fallback path (legacy rf_model.joblib)
            fallback = target_path.parent / "rf_model.joblib"
            if fallback.exists():
                target_path = fallback
            else:
                self.is_loaded = False
                self.model = None
                self.scaler = None
                return False

        try:
            bundle = joblib.load(str(target_path))
            if isinstance(bundle, dict):
                self.model = bundle.get("clf") or bundle.get("model")
                self.scaler = bundle.get("scaler")
                self.classes = bundle.get("classes", list(MODEL_CLASSES))
                self.metadata = bundle.get("metadata", {})
            else:
                self.model = bundle
                self.scaler = StandardScaler()
                self.classes = list(getattr(self.model, "classes_", MODEL_CLASSES))

            self.is_loaded = True
            return True
        except Exception as e:
            print(f"[ModelManager] Warning: Failed to load model from {target_path}: {e}")
            self.is_loaded = False
            self.model = None
            self.scaler = None
            return False

    def save_model(
        self,
        model: RandomForestClassifier,
        scaler: StandardScaler,
        classes: List[str],
        metadata: Optional[Dict[str, Any]] = None,
        path: Optional[Union[str, Path]] = None,
    ) -> Path:
        """Saves trained model, scaler, class mappings, and evaluation metrics bundle to disk."""
        target_path = Path(path) if path else self.model_path
        target_path.parent.mkdir(parents=True, exist_ok=True)

        bundle = {
            "model": model,
            "clf": model,
            "scaler": scaler,
            "is_fitted": True,
            "classes": classes,
            "metadata": metadata or {},
            "feature_names": FEATURE_NAMES,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }

        joblib.dump(bundle, str(target_path))
        self.model = model
        self.scaler = scaler
        self.classes = classes
        self.metadata = metadata or {}
        self.is_loaded = True
        return target_path

    def predict(
        self,
        features: Union[Dict[str, Any], Any],
        confidence_threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Infers traffic type from an encrypted ESP feature dictionary or object.
        Returns:
            {
                "traffic_class": "Web",
                "confidence": 0.91,
                "model": "RandomForest",
                "probabilities": { ... }
            }
        If confidence is below threshold, returns:
            {
                "traffic_class": "Unknown",
                "confidence": 0.42,
                "model": "RandomForest"
            }
        """
        threshold = confidence_threshold if confidence_threshold is not None else self.confidence_threshold

        # 1. Validate feature vector
        is_valid, validation_errors, feat_array = validate_feature_vector(features)
        if not is_valid or feat_array is None:
            return {
                "traffic_class": "Unknown",
                "confidence": 0.0,
                "model": "RandomForest",
                "error": f"Invalid feature vector: {'; '.join(validation_errors)}",
                "probabilities": {},
            }

        # 2. Check if model is loaded; handle missing model gracefully
        if not self.is_loaded or self.model is None or self.scaler is None:
            # Fall back to rule-informed statistical heuristic
            return self._heuristic_fallback(features, threshold)

        # 3. Predict via Random Forest
        try:
            vec = feat_array.reshape(1, -1)
            vec_scaled = self.scaler.transform(vec)
            probs = self.model.predict_proba(vec_scaled)[0]
            model_classes = list(self.model.classes_)

            probs_dict: Dict[str, float] = {}
            for i, cls_name in enumerate(model_classes):
                probs_dict[cls_name] = round(float(probs[i]), 4)

            best_idx = int(np.argmax(probs))
            best_class = model_classes[best_idx]
            best_confidence = round(float(probs[best_idx]), 4)

            # Apply confidence threshold
            if best_confidence < threshold:
                traffic_class = "Unknown"
            else:
                traffic_class = best_class

            return {
                "traffic_class": traffic_class,
                "confidence": best_confidence,
                "model": "RandomForest",
                "probabilities": probs_dict,
            }
        except Exception as e:
            # Graceful error handling
            return {
                "traffic_class": "Unknown",
                "confidence": 0.0,
                "model": "RandomForest",
                "error": f"Inference failed: {str(e)}",
                "probabilities": {},
            }

    def _heuristic_fallback(
        self,
        features: Union[Dict[str, Any], Any],
        threshold: float,
    ) -> Dict[str, Any]:
        """
        Graceful rule-informed heuristic baseline used when trained model weights are missing.
        """
        feat = features.to_flat_dict() if hasattr(features, "to_flat_dict") else features

        size_mean = feat.get("size_mean", 0.0)
        iat_mean = feat.get("iat_mean_ms", 0.0)
        total_bytes = feat.get("total_bytes", 0.0)
        total_pkts = feat.get("total_packets", 0)
        byte_ratio = feat.get("byte_ratio_fwd_bwd", 1.0)
        burst_count = feat.get("burst_count", 0)

        # VoIP: ~20ms pacing (iat 15-28ms), small packets (<350 bytes)
        if 12.0 <= iat_mean <= 32.0 and size_mean < 350.0 and total_pkts >= 10:
            pred_class = "VoIP"
            confidence = 0.88
        # ICMP: small count (<50 pkts), small size (~100-150 bytes), high iat (>100ms)
        elif size_mean < 160.0 and total_pkts < 60 and iat_mean >= 80.0:
            pred_class = "ICMP"
            confidence = 0.89
        # Bulk / Data Transfer: high throughput, continuous stream, large bytes, few bursts
        elif total_bytes > 300000 and size_mean > 900.0 and (burst_count <= 4 or iat_mean < 10.0):
            pred_class = "Bulk/Data Transfer"
            confidence = 0.86
        # Video: high volume, large packets (>700 bytes), chunked bursts
        elif total_bytes > 200000 and size_mean > 700.0:
            pred_class = "Video"
            confidence = 0.87
        # Web: asymmetric request/response, mixed sizes, moderate duration
        elif total_pkts >= 5:
            pred_class = "Web"
            confidence = 0.82
        else:
            pred_class = "Unknown"
            confidence = 0.40

        if confidence < threshold:
            pred_class = "Unknown"

        probs = {cls_name: 0.05 for cls_name in MODEL_CLASSES}
        if pred_class in probs:
            probs[pred_class] = round(confidence, 2)

        return {
            "traffic_class": pred_class,
            "confidence": round(confidence, 2),
            "model": "RandomForest",
            "fallback_used": True,
            "probabilities": probs,
        }

    def get_model_info(self) -> Dict[str, Any]:
        """Returns metadata about the active model."""
        return {
            "is_loaded": self.is_loaded,
            "model_path": str(self.model_path),
            "model_type": "RandomForestClassifier",
            "classes": self.classes,
            "confidence_threshold": self.confidence_threshold,
            "metadata": self.metadata,
        }
