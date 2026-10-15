"""
Phase 4 Model Training Pipeline for SentraIPS.
Trains and evaluates a Random Forest classifier over encrypted ESP traffic metadata:
- Strictly observable flow metadata (packet counts, durations, packet sizes, IATs, bursts)
- Zero payload decryption
- Computes genuine evaluation metrics (accuracy, precision, recall, F1, confusion matrix)
- Saves model bundle to models/weights/rf_traffic_model.joblib and metrics to models/evaluation_metrics.json
"""

import json
from pathlib import Path
import random
import sys
from typing import Any, Dict, List, Tuple
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP
from scapy.layers.ipsec import ESP
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from packet_analysis.features import ESPFeatureExtractor, ESPTrafficFeatures
from models.feature_schema import (
    FEATURE_NAMES,
    MODEL_CLASSES,
    normalize_traffic_class,
    validate_feature_vector,
)
from models.model_manager import ModelManager


def extract_session_samples(
    pcap_path: Path,
    traffic_type: str,
    window_sizes: List[int] = [16, 32, 48],
    max_samples_per_window: int = 10,
) -> List[ESPTrafficFeatures]:
    """
    Extracts diverse sub-flow temporal window samples from an ESP capture session.
    Preserves ground truth while varying packet volumes and observation windows.
    """
    if not pcap_path.exists():
        return []

    try:
        packets = rdpcap(str(pcap_path))
    except Exception:
        return []

    esp_packets = [
        pkt for pkt in packets
        if pkt.haslayer(ESP) or (pkt.haslayer(IP) and pkt[IP].proto == 50)
    ]

    if not esp_packets:
        return []

    samples: List[ESPTrafficFeatures] = []
    # 1. Full session feature
    samples.append(ESPFeatureExtractor.extract_from_packets(esp_packets))

    # 2. Multi-scale sub-flow temporal windows
    for w_size in window_sizes:
        if len(esp_packets) <= w_size:
            continue
        step = max(4, w_size // 2)
        count = 0
        for start_idx in range(0, len(esp_packets) - 4, step):
            chunk = esp_packets[start_idx : start_idx + w_size]
            if len(chunk) >= 4:
                samples.append(ESPFeatureExtractor.extract_from_packets(chunk))
                count += 1
            if count >= max_samples_per_window:
                break

    return samples


def load_and_prepare_dataset(
    base_dir: Path,
) -> Tuple[np.ndarray, List[str], List[str], Dict[str, Any]]:
    """
    Loads labeled captures from dataset/labels.csv and dataset/processed/.
    Extracts validated feature vectors and returns (X, y, feature_names, dataset_summary).
    """
    labels_csv = base_dir / "dataset" / "labels.csv"
    if not labels_csv.exists():
        raise ValueError(f"Insufficient dataset: labels.csv not found at {labels_csv}. Run DatasetBuilder first.")

    df = pd.read_csv(labels_csv)
    raw_dir = base_dir / "dataset" / "raw"
    processed_dir = base_dir / "dataset" / "processed"

    X_list: List[np.ndarray] = []
    y_list: List[str] = []
    class_counts: Dict[str, int] = {}
    skipped_records = 0

    for _, row in df.iterrows():
        cid = str(row["capture_id"])
        raw_label = str(row.get("traffic_type", ""))
        canonical_class = normalize_traffic_class(raw_label)

        # Skip unlabeled or unknown testbed captures for supervised training
        if canonical_class not in MODEL_CLASSES:
            skipped_records += 1
            continue

        pcap_path = raw_dir / f"{cid}.pcap"
        proc_json = processed_dir / f"{cid}_features.json"

        features_candidates: List[ESPTrafficFeatures] = []

        # 1. Load processed features file if present
        if proc_json.exists():
            try:
                with open(proc_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                feat_dict = data.get("features", {})
                is_valid, errs, arr = validate_feature_vector(feat_dict)
                if is_valid and arr is not None:
                    X_list.append(arr)
                    y_list.append(canonical_class)
                    class_counts[canonical_class] = class_counts.get(canonical_class, 0) + 1
            except Exception:
                pass

        # 2. Extract diverse sub-flow windowed samples from the raw PCAP
        if pcap_path.exists():
            window_samples = extract_session_samples(pcap_path, canonical_class)
            for sample in window_samples:
                is_valid, errs, arr = validate_feature_vector(sample.to_flat_dict())
                if is_valid and arr is not None:
                    X_list.append(arr)
                    y_list.append(canonical_class)
                    class_counts[canonical_class] = class_counts.get(canonical_class, 0) + 1

    if not X_list:
        raise ValueError("Insufficient dataset: No valid feature vectors could be loaded.")

    X = np.vstack(X_list).astype(np.float32)
    summary = {
        "total_samples": len(y_list),
        "class_distribution": class_counts,
        "skipped_unknown_or_corrupt": skipped_records,
        "feature_count": len(FEATURE_NAMES),
    }

    return X, y_list, FEATURE_NAMES, summary


def train_and_evaluate(
    test_size: float = 0.25,
    random_state: int = 42,
    n_estimators: int = 100,
    max_depth: int = 10,
) -> Dict[str, Any]:
    """
    Executes full Phase 4 training and genuine evaluation:
    1. Load and validate features
    2. Split train/test data
    3. Train Random Forest
    4. Calculate genuine accuracy, precision, recall, F1, confusion matrix
    5. Save model and metrics
    """
    print("=" * 65)
    print("  SentraIPS Phase 4 — Random Forest Traffic Classifier Training")
    print("=" * 65)

    # Step 1: Load and validate dataset
    X, y, feature_names, summary = load_and_prepare_dataset(PROJECT_ROOT)
    total_samples = len(y)
    print(f"\n[1. Dataset Summary]")
    print(f"  - Total Samples Loaded : {total_samples}")
    print(f"  - Features Per Sample  : {summary['feature_count']}")
    print(f"  - Class Distribution   :")
    for cls_name, count in sorted(summary["class_distribution"].items()):
        print(f"      * {cls_name:<20}: {count} samples")

    # Step 2: Handle insufficient dataset check
    if total_samples < 15:
        print("\n[WARNING] Dataset contains fewer than 15 samples. Metrics may have high variance.")

    # Step 3: Train / Test Split
    # Check if all classes have at least 2 samples for stratified split
    min_class_count = min(summary["class_distribution"].values()) if summary["class_distribution"] else 0
    stratify = y if min_class_count >= 2 else None

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )
    print(f"\n[2. Data Split]")
    print(f"  - Training Set Size    : {len(y_train)} samples")
    print(f"  - Test Set Size        : {len(y_test)} samples")

    # Step 4: Scale Features & Train Random Forest
    print(f"\n[3. Training Random Forest Model]")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_state,
        class_weight="balanced",
    )
    clf.fit(X_train_scaled, y_train)
    print(f"  - Model fitted successfully with {n_estimators} trees (max_depth={max_depth}).")

    # Step 5: Evaluate on Test Set
    print(f"\n[4. Model Evaluation on Unseen Test Split]")
    y_pred = clf.predict(X_test_scaled)

    acc = float(accuracy_score(y_test, y_pred))
    p_weighted, r_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted", zero_division=0
    )
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )

    # Class list ordered by classifier classes
    active_classes = list(clf.classes_)
    cm = confusion_matrix(y_test, y_pred, labels=active_classes).tolist()

    # Per-class metrics
    p_per_class, r_per_class, f1_per_class, support = precision_recall_fscore_support(
        y_test, y_pred, labels=active_classes, zero_division=0
    )
    per_class_metrics = {}
    for i, c_name in enumerate(active_classes):
        per_class_metrics[c_name] = {
            "precision": round(float(p_per_class[i]), 4),
            "recall": round(float(r_per_class[i]), 4),
            "f1_score": round(float(f1_per_class[i]), 4),
            "support": int(support[i]),
        }

    # Feature importances
    importances = clf.feature_importances_
    top_indices = np.argsort(importances)[::-1][:8]
    top_features = [
        {"feature": feature_names[idx], "importance": round(float(importances[idx]), 4)}
        for idx in top_indices
    ]

    print(f"  - Accuracy             : {acc:.2%}")
    print(f"  - Precision (Weighted) : {p_weighted:.2%}")
    print(f"  - Recall (Weighted)    : {r_weighted:.2%}")
    print(f"  - F1-Score (Weighted)  : {f1_weighted:.2%}")
    print(f"  - Macro F1-Score       : {f1_macro:.2%}")

    print("\n  Per-Class Performance:")
    print(f"  {'Class':<20} {'Precision':<12} {'Recall':<12} {'F1':<12} {'Support':<10}")
    print("  " + "-" * 60)
    for c_name, m in per_class_metrics.items():
        print(f"  {c_name:<20} {m['precision']:<12.2%} {m['recall']:<12.2%} {m['f1_score']:<12.2%} {m['support']:<10}")

    print("\n  Top Feature Importances:")
    for rank, f_item in enumerate(top_features, 1):
        print(f"  {rank}. {f_item['feature']:<25} ({f_item['importance']:.4f})")

    # Step 6: Save Model and Metrics
    print(f"\n[5. Persisting Model & Evaluation Artifacts]")
    manager = ModelManager()
    metrics_bundle = {
        "accuracy": round(acc, 4),
        "precision_weighted": round(float(p_weighted), 4),
        "recall_weighted": round(float(r_weighted), 4),
        "f1_weighted": round(float(f1_weighted), 4),
        "f1_macro": round(float(f1_macro), 4),
        "confusion_matrix": cm,
        "classes": active_classes,
        "per_class": per_class_metrics,
        "top_features": top_features,
        "dataset_summary": summary,
        "test_size": test_size,
    }

    # Save to standard Phase 4 model path
    model_path = manager.save_model(
        model=clf,
        scaler=scaler,
        classes=active_classes,
        metadata=metrics_bundle,
    )
    print(f"  - Model saved to       : {model_path}")

    # Also update legacy statistical model weights path for backward compatibility
    legacy_path = PROJECT_ROOT / "models" / "weights" / "rf_model.joblib"
    manager.save_model(
        model=clf,
        scaler=scaler,
        classes=active_classes,
        metadata=metrics_bundle,
        path=legacy_path,
    )
    print(f"  - Legacy bridge saved to: {legacy_path}")

    # Save metrics JSON
    metrics_path = PROJECT_ROOT / "models" / "evaluation_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics_bundle, f, indent=2)
    print(f"  - Metrics saved to     : {metrics_path}")

    print("\n" + "=" * 65)
    print("  Phase 4 Training & Evaluation Completed Successfully!")
    print("=" * 65 + "\n")

    return metrics_bundle


if __name__ == "__main__":
    train_and_evaluate()
