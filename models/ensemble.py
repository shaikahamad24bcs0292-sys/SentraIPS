"""
ESP AI Ensemble & Uncertainty Engine for SentraIPS.
Combines 1D-CNN temporal sequence model with Random Forest statistical model.
Explicitly treats disagreement as UNCERTAIN (analyst signal) rather than forcing a label.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field

from packet_analysis.features import ESPFeatureExtractor, ESPTrafficFeatures
from models.cnn_model import ESP1DCNN, CLASSES
from models.statistical_model import ESPStatisticalModel


class EnsemblePredictionResult(BaseModel):
    """Structured output schema matching SentraIPS Phase 4 specification."""

    cnn_prediction: str
    cnn_confidence: float
    statistical_prediction: str
    statistical_confidence: float
    agreement: bool
    final_prediction: str
    final_confidence: Optional[float] = None
    status: str  # 'classified' or 'investigation_required'
    explanation: str
    cnn_probabilities: Dict[str, float] = Field(default_factory=dict)
    statistical_probabilities: Dict[str, float] = Field(default_factory=dict)


class ESPEnsembleClassifier:
    """
    Dual-model inference coordinator implementing agreement checking and uncertainty arbitration.
    """

    def __init__(
        self,
        cnn_weights_path: Optional[Union[str, Path]] = None,
        stat_weights_path: Optional[Union[str, Path]] = None,
    ):
        self.cnn = ESP1DCNN()
        self.stat_model = ESPStatisticalModel()

        # Load weights if present
        default_dir = Path(__file__).resolve().parent / "weights"
        self.cnn_weights = Path(cnn_weights_path) if cnn_weights_path else default_dir / "cnn_weights.pt"
        self.stat_weights = Path(stat_weights_path) if stat_weights_path else default_dir / "rf_model.joblib"

        if self.cnn_weights.exists():
            try:
                self.cnn.load_weights(self.cnn_weights)
            except Exception as e:
                print(f"[Ensemble] Warning: Could not load CNN weights from {self.cnn_weights}: {e}")

        if self.stat_weights.exists():
            try:
                self.stat_model.load(self.stat_weights)
            except Exception as e:
                print(f"[Ensemble] Warning: Could not load Statistical model from {self.stat_weights}: {e}")

    def predict_features(self, features: ESPTrafficFeatures) -> EnsemblePredictionResult:
        """
        Runs both models independently on extracted ESP features and computes ensemble agreement.
        """
        # Model 1: 1D-CNN on temporal sequence
        cnn_tensor = self.cnn.features_to_tensor(features)
        cnn_pred, cnn_conf, cnn_probs = self.cnn.predict(cnn_tensor)

        # Model 2: Statistical model on flat aggregate statistics
        stat_pred, stat_conf, stat_probs = self.stat_model.predict_features(features)

        # Standardize class naming
        cnn_pred_clean = cnn_pred.capitalize() if cnn_pred.lower() not in ("icmp", "voip") else cnn_pred.upper() if cnn_pred.lower() == "icmp" else "VoIP"
        stat_pred_clean = stat_pred.capitalize() if stat_pred.lower() not in ("icmp", "voip") else stat_pred.upper() if stat_pred.lower() == "icmp" else "VoIP"

        agreement = (cnn_pred_clean == stat_pred_clean)

        if agreement:
            final_pred = cnn_pred_clean
            final_conf = round(float((cnn_conf + stat_conf) / 2.0), 4)
            status = "classified"
            explanation = (
                f"Concordant traffic inference: Both the 1D-CNN temporal sequence model "
                f"(confidence: {cnn_conf:.1%}) and Random Forest statistical model "
                f"(confidence: {stat_conf:.1%}) agree that this encrypted ESP session exhibits "
                f"characteristics of '{final_pred}' traffic."
            )
        else:
            final_pred = "UNCERTAIN"
            final_conf = None
            status = "investigation_required"
            explanation = (
                f"Model disagreement detected: 1D-CNN temporal model predicts '{cnn_pred_clean}' "
                f"({cnn_conf:.1%}), while Random Forest statistical model predicts '{stat_pred_clean}' "
                f"({stat_conf:.1%}). In accordance with SentraIPS security design principles, conflicting "
                f"architectural perspectives are treated as an UNCERTAINTY signal requiring analyst review "
                f"rather than forcing an unverified automated classification."
            )

        return EnsemblePredictionResult(
            cnn_prediction=cnn_pred_clean,
            cnn_confidence=round(cnn_conf, 4),
            statistical_prediction=stat_pred_clean,
            statistical_confidence=round(stat_conf, 4),
            agreement=agreement,
            final_prediction=final_pred,
            final_confidence=final_conf,
            status=status,
            explanation=explanation,
            cnn_probabilities=cnn_probs,
            statistical_probabilities=stat_probs,
        )

    def predict_pcap(self, pcap_path: Union[str, Path]) -> EnsemblePredictionResult:
        """
        End-to-end inference from a raw PCAP file.
        """
        features = ESPFeatureExtractor.extract_from_pcap(pcap_path)
        return self.predict_features(features)

    infer_pcap = predict_pcap


EnsembleArbiter = ESPEnsembleClassifier
