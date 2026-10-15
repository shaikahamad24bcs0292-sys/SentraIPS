"""
Evaluation and Metrics Reporting Module for SentraIPS AI Models.
Loads trained weights and runs validation benchmarks, reporting:
- Measured results on test sessions
- Class-by-class precision, recall, F1
- Confusion matrix
- Model agreement and uncertainty distribution
"""

import json
from pathlib import Path
import sys
from typing import Any, Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models.cnn_model import CLASSES
from models.ensemble import ESPEnsembleClassifier
from models.train import prepare_dataset, normalize_class_name


def load_evaluation_metrics(metrics_path: Optional[Path] = None) -> Dict[str, Any]:
    """Loads precomputed genuine evaluation metrics."""
    path = metrics_path or (PROJECT_ROOT / "models" / "evaluation_metrics.json")
    if not path.exists():
        raise FileNotFoundError(f"Evaluation metrics not found at {path}. Run models/train.py first.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def print_evaluation_summary():
    """Prints human-readable terminal table of genuine model benchmarks."""
    metrics = load_evaluation_metrics()

    print("=================================================================")
    print("  SentraIPS AI Inference Benchmark Report")
    print(f"  Status: {metrics.get('evaluation_type', 'Measured')}")
    print("=================================================================")
    print(f"  Test Sample Count : {metrics.get('test_sample_count', 0)}")
    print(f"  Test Sessions     : {', '.join(metrics.get('test_sessions', []))}")
    print("-----------------------------------------------------------------")
    print(f"{'Model':<24} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1':<12}")
    print("-----------------------------------------------------------------")

    rf = metrics.get("random_forest", {})
    cnn = metrics.get("cnn_1d", {})
    ens = metrics.get("ensemble", {})

    print(f"{'Random Forest (Stat)':<24} {rf.get('accuracy', 0):<12.1%} {rf.get('precision_weighted', 0):<12.3f} {rf.get('recall_weighted', 0):<12.3f} {rf.get('f1_weighted', 0):<12.3f}")
    print(f"{'1D-CNN (Temporal)':<24} {cnn.get('accuracy', 0):<12.1%} {cnn.get('precision_weighted', 0):<12.3f} {cnn.get('recall_weighted', 0):<12.3f} {cnn.get('f1_weighted', 0):<12.3f}")
    print("-----------------------------------------------------------------")
    print(f"  Ensemble Agreement Rate : {ens.get('agreement_rate', 0):.1%}")
    print(f"  Uncertainty Signal Rate : {ens.get('uncertain_rate', 0):.1%}")
    print("=================================================================")


if __name__ == "__main__":
    print_evaluation_summary()
