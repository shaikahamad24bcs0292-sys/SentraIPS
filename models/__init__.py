"""
SentraIPS AI Traffic Inference Models & Machine Learning Package (Phase 4).
Includes Random Forest traffic classification, feature schemas, model manager,
and dual-model uncertainty ensemble.
"""

from models.cnn_model import ESP1DCNN, CLASSES, SEQUENCE_LENGTH, NUM_CHANNELS
from models.statistical_model import ESPStatisticalModel
from models.ensemble import ESPEnsembleClassifier, EnsemblePredictionResult
from models.feature_schema import (
    FEATURE_NAMES,
    MODEL_CLASSES,
    TARGET_CLASSES,
    TrafficAnalysisSummary,
    TrafficClass,
    TrafficPredictionOutput,
    normalize_traffic_class,
    validate_feature_vector,
)
from models.model_manager import ModelManager
from models.predict import predict_traffic

__all__ = [
    "ESP1DCNN",
    "ESPStatisticalModel",
    "ESPEnsembleClassifier",
    "EnsemblePredictionResult",
    "ModelManager",
    "predict_traffic",
    "CLASSES",
    "SEQUENCE_LENGTH",
    "NUM_CHANNELS",
    "FEATURE_NAMES",
    "TARGET_CLASSES",
    "MODEL_CLASSES",
    "TrafficClass",
    "TrafficPredictionOutput",
    "TrafficAnalysisSummary",
    "normalize_traffic_class",
    "validate_feature_vector",
]
