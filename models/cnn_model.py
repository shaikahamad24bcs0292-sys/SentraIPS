"""
1D-CNN Temporal Sequence Model for SentraIPS.
Classifies encrypted ESP traffic based on packet size, direction, and inter-arrival
time sequences WITHOUT decrypting payloads.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

from packet_analysis.features import ESPTrafficFeatures

# Canonical traffic classes
CLASSES: List[str] = ["Web", "VoIP", "ICMP", "Video"]
CLASS_TO_IDX: Dict[str, int] = {cls_name: i for i, cls_name in enumerate(CLASSES)}
IDX_TO_CLASS: Dict[int, str] = {i: cls_name for i, cls_name in enumerate(CLASSES)}
SEQUENCE_LENGTH = 64
NUM_CHANNELS = 3


class ESP1DCNN(nn.Module):
    """
    Lightweight 1D-CNN for temporal packet feature sequences.
    Input shape: (batch_size, 3, 64)
      - Channel 0: Normalized packet sizes (size / 1500.0)
      - Channel 1: Packet directions (+1.0 fwd, -1.0 bwd, 0.0 pad)
      - Channel 2: Normalized inter-arrival times (log1p(iat_ms) / 5.0)
    """

    def __init__(self, num_classes: int = len(CLASSES), in_channels: int = NUM_CHANNELS, seq_len: int = SEQUENCE_LENGTH):
        super().__init__()
        self.num_classes = num_classes
        self.seq_len = seq_len

        # Block 1: local temporal patterns (e.g. request-response pairs, bursts)
        self.conv1 = nn.Conv1d(in_channels, 32, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(32)
        self.pool1 = nn.MaxPool1d(2)  # 64 -> 32

        # Block 2: mid-range temporal sequence patterns
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(64)
        self.pool2 = nn.AdaptiveAvgPool1d(8)  # -> 8

        # Classification head
        self.fc1 = nn.Linear(64 * 8, 64)
        self.dropout = nn.Dropout(0.2)
        self.fc2 = nn.Linear(64, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.
        Args:
            x: Tensor of shape (batch_size, 3, seq_len)
        Returns:
            Logits of shape (batch_size, num_classes)
        """
        x = F.relu(self.bn1(self.conv1(x)))
        x = self.pool1(x)
        x = F.relu(self.bn2(self.conv2(x)))
        x = self.pool2(x)
        x = torch.flatten(x, 1)
        x = F.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.fc2(x)
        return x

    @staticmethod
    def features_to_tensor(features: ESPTrafficFeatures, seq_len: int = SEQUENCE_LENGTH) -> torch.Tensor:
        """
        Converts ESPTrafficFeatures sequences into a normalized 3-channel PyTorch tensor.
        Returns tensor of shape (1, 3, seq_len).
        """
        raw_sizes = features.packet_size_sequence or []
        raw_iats = features.iat_sequence_ms or []
        raw_dirs = features.direction_sequence or []

        sizes = np.zeros(seq_len, dtype=np.float32)
        dirs = np.zeros(seq_len, dtype=np.float32)
        iats = np.zeros(seq_len, dtype=np.float32)

        n = min(len(raw_sizes), seq_len)
        if n > 0:
            for i in range(n):
                # Channel 0: Normalized size (MTU 1500)
                sizes[i] = min(float(raw_sizes[i]), 1500.0) / 1500.0

                # Channel 1: Direction (+1 fwd, -1 bwd)
                dirs[i] = float(raw_dirs[i]) if i < len(raw_dirs) else 1.0

                # Channel 2: Log-normalized IAT (ms)
                iat_val = float(raw_iats[i]) if i < len(raw_iats) else 0.0
                iats[i] = min(np.log1p(max(0.0, iat_val)) / 5.0, 1.0)
        elif features.total_packets > 0:
            # Fallback if raw sequence not present, synthesize average representation
            sizes[:min(features.total_packets, seq_len)] = min(features.size_mean, 1500.0) / 1500.0
            dirs[:min(features.total_packets, seq_len)] = 1.0
            iats[:min(features.total_packets, seq_len)] = min(np.log1p(features.iat_mean_ms) / 5.0, 1.0)

        # Shape: (3, seq_len) -> (1, 3, seq_len)
        stacked = np.stack([sizes, dirs, iats], axis=0)
        return torch.tensor(stacked, dtype=torch.float32).unsqueeze(0)

    def predict(self, x: torch.Tensor) -> Tuple[str, float, Dict[str, float]]:
        """
        Runs inference on input tensor.
        Args:
            x: Tensor of shape (1, 3, seq_len)
        Returns:
            Tuple of (predicted_class_name, confidence, all_probabilities_dict)
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=1).squeeze(0).cpu().numpy()

        pred_idx = int(np.argmax(probs))
        pred_class = IDX_TO_CLASS.get(pred_idx, "Web")
        confidence = float(probs[pred_idx])
        probs_dict = {IDX_TO_CLASS[i]: round(float(probs[i]), 4) for i in range(len(CLASSES))}

        return pred_class, round(confidence, 4), probs_dict

    def save_weights(self, path: Union[str, Path]) -> None:
        """Saves model state dict."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.state_dict(), str(path))

    def load_weights(self, path: Union[str, Path]) -> None:
        """Loads model state dict if available."""
        p = Path(path)
        if p.exists():
            self.load_state_dict(torch.load(str(p), map_location=torch.device("cpu"), weights_only=True))
            self.eval()
