"""
ESP Encrypted Traffic Feature Extractor for SentraIPS.
Extracts statistical, temporal, directional, and burst characteristics strictly from
observable ESP outer headers, timestamps, and packet sizes WITHOUT decrypting payloads.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from pydantic import BaseModel, Field
from scapy.all import rdpcap, IP, IPv6
from scapy.layers.ipsec import ESP


class ESPTrafficFeatures(BaseModel):
    """Structured feature vector representing encrypted ESP flow dynamics."""

    # Volume & Counts
    total_packets: int = 0
    total_bytes: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    packet_ratio_fwd_bwd: float = 0.0
    byte_ratio_fwd_bwd: float = 0.0

    # Flow Timing
    flow_duration_sec: float = 0.0
    packets_per_sec: float = 0.0
    bytes_per_sec: float = 0.0

    # Packet Size Statistics (bytes)
    size_min: int = 0
    size_max: int = 0
    size_mean: float = 0.0
    size_median: float = 0.0
    size_std: float = 0.0
    size_p25: float = 0.0
    size_p75: float = 0.0
    size_p90: float = 0.0
    size_skewness: float = 0.0

    # Inter-Arrival Time (IAT) Statistics (milliseconds)
    iat_min_ms: float = 0.0
    iat_max_ms: float = 0.0
    iat_mean_ms: float = 0.0
    iat_median_ms: float = 0.0
    iat_std_ms: float = 0.0

    # Burst Dynamics (threshold = 50ms)
    burst_count: int = 0
    mean_burst_size_pkts: float = 0.0
    mean_burst_duration_ms: float = 0.0
    mean_burst_bytes: float = 0.0

    # Sequential Features for Deep Learning (1D-CNN in Phase 4)
    packet_size_sequence: List[int] = Field(default_factory=list)
    iat_sequence_ms: List[float] = Field(default_factory=list)
    direction_sequence: List[int] = Field(default_factory=list)

    def to_flat_dict(self) -> Dict[str, float]:
        """Returns 1D statistical feature dictionary suitable for tabular ML models."""
        return {
            "total_packets": float(self.total_packets),
            "total_bytes": float(self.total_bytes),
            "forward_packets": float(self.forward_packets),
            "backward_packets": float(self.backward_packets),
            "packet_ratio_fwd_bwd": self.packet_ratio_fwd_bwd,
            "byte_ratio_fwd_bwd": self.byte_ratio_fwd_bwd,
            "flow_duration_sec": self.flow_duration_sec,
            "packets_per_sec": self.packets_per_sec,
            "bytes_per_sec": self.bytes_per_sec,
            "size_min": float(self.size_min),
            "size_max": float(self.size_max),
            "size_mean": self.size_mean,
            "size_median": self.size_median,
            "size_std": self.size_std,
            "size_p25": self.size_p25,
            "size_p75": self.size_p75,
            "size_p90": self.size_p90,
            "size_skewness": self.size_skewness,
            "iat_min_ms": self.iat_min_ms,
            "iat_max_ms": self.iat_max_ms,
            "iat_mean_ms": self.iat_mean_ms,
            "iat_median_ms": self.iat_median_ms,
            "iat_std_ms": self.iat_std_ms,
            "burst_count": float(self.burst_count),
            "mean_burst_size_pkts": self.mean_burst_size_pkts,
            "mean_burst_duration_ms": self.mean_burst_duration_ms,
            "mean_burst_bytes": self.mean_burst_bytes,
        }


class ESPFeatureExtractor:
    """Reusable feature extraction engine for encrypted ESP network traffic."""

    BURST_THRESHOLD_SEC = 0.050  # 50 ms idle defines a new burst
    SEQUENCE_MAX_LENGTH = 64     # First 64 packets for temporal sequence models

    @classmethod
    def extract_from_pcap(
        cls, pcap_path: Union[str, Path], max_packets: Optional[int] = None
    ) -> ESPTrafficFeatures:
        """Loads PCAP, filters ESP packets, and extracts features."""
        packets = rdpcap(str(pcap_path))
        esp_pkts = []
        for pkt in packets:
            is_esp = False
            if IP in pkt and pkt[IP].proto == 50:
                is_esp = True
            elif IPv6 in pkt and pkt[IPv6].nh == 50:
                is_esp = True
            elif ESP in pkt:
                is_esp = True

            if is_esp:
                esp_pkts.append(pkt)
                if max_packets and len(esp_pkts) >= max_packets:
                    break

        return cls.extract_from_packets(esp_pkts)

    @classmethod
    def extract_from_packets(cls, packets: List[Any]) -> ESPTrafficFeatures:
        """Extracts statistical and temporal features from a list of ESP Scapy packets."""
        if not packets:
            return ESPTrafficFeatures()

        timestamps = []
        sizes = []
        directions = []  # +1: forward (client->server), -1: backward (server->client)
        client_ip = None

        for pkt in packets:
            t = float(getattr(pkt, "time", 0.0))
            sz = len(pkt)
            timestamps.append(t)
            sizes.append(sz)

            # Determine direction based on source IP of the first packet
            ip_src = None
            if IP in pkt:
                ip_src = pkt[IP].src
            elif IPv6 in pkt:
                ip_src = pkt[IPv6].src

            if ip_src:
                if client_ip is None:
                    client_ip = ip_src
                direction = 1 if ip_src == client_ip else -1
            else:
                direction = 1

            directions.append(direction)

        n = len(sizes)
        np_sizes = np.array(sizes, dtype=np.float64)
        np_times = np.array(timestamps, dtype=np.float64)

        # Sort by timestamp in case packets are out of order
        sort_idx = np.argsort(np_times)
        np_times = np_times[sort_idx]
        np_sizes = np_sizes[sort_idx]
        directions = [directions[i] for i in sort_idx]

        # Counts and byte sums
        fwd_mask = np.array([d == 1 for d in directions])
        bwd_mask = ~fwd_mask

        fwd_count = int(np.sum(fwd_mask))
        bwd_count = int(np.sum(bwd_mask))
        fwd_bytes = int(np.sum(np_sizes[fwd_mask])) if fwd_count > 0 else 0
        bwd_bytes = int(np.sum(np_sizes[bwd_mask])) if bwd_count > 0 else 0
        total_bytes = int(np.sum(np_sizes))

        pkt_ratio = round(fwd_count / (bwd_count + 1e-6), 4)
        byte_ratio = round(fwd_bytes / (bwd_bytes + 1e-6), 4)

        # Duration & Rates
        duration = float(np_times[-1] - np_times[0]) if n > 1 else 0.0
        duration = max(duration, 0.0)
        pkts_per_sec = round(n / (duration + 1e-6), 2) if duration > 0 else float(n)
        bytes_per_sec = round(total_bytes / (duration + 1e-6), 2) if duration > 0 else float(total_bytes)

        # Packet Size Statistics
        size_min = int(np.min(np_sizes))
        size_max = int(np.max(np_sizes))
        size_mean = round(float(np.mean(np_sizes)), 2)
        size_median = round(float(np.median(np_sizes)), 2)
        size_std = round(float(np.std(np_sizes)), 2)
        size_p25 = round(float(np.percentile(np_sizes, 25)), 2)
        size_p75 = round(float(np.percentile(np_sizes, 75)), 2)
        size_p90 = round(float(np.percentile(np_sizes, 90)), 2)

        # Skewness
        if size_std > 0 and n > 2:
            m3 = np.mean((np_sizes - size_mean) ** 3)
            size_skew = round(float(m3 / (size_std ** 3)), 4)
        else:
            size_skew = 0.0

        # Inter-Arrival Times (IAT)
        if n > 1:
            iats = np.diff(np_times) * 1000.0  # Convert to ms
            iats = np.maximum(iats, 0.0)       # Non-negative
            iat_min = round(float(np.min(iats)), 3)
            iat_max = round(float(np.max(iats)), 3)
            iat_mean = round(float(np.mean(iats)), 3)
            iat_median = round(float(np.median(iats)), 3)
            iat_std = round(float(np.std(iats)), 3)
            iat_seq = [round(float(x), 3) for x in iats[: cls.SEQUENCE_MAX_LENGTH]]
        else:
            iat_min = 0.0
            iat_max = 0.0
            iat_mean = 0.0
            iat_median = 0.0
            iat_std = 0.0
            iat_seq = []

        # Burst Characteristics
        burst_count, burst_sizes, burst_durations, burst_bytes_list = cls._compute_bursts(
            np_times, np_sizes
        )

        # Sequences for Deep Learning
        seq_sizes = [int(s) for s in np_sizes[: cls.SEQUENCE_MAX_LENGTH]]
        seq_dirs = directions[: cls.SEQUENCE_MAX_LENGTH]

        return ESPTrafficFeatures(
            total_packets=n,
            total_bytes=total_bytes,
            forward_packets=fwd_count,
            backward_packets=bwd_count,
            forward_bytes=fwd_bytes,
            backward_bytes=bwd_bytes,
            packet_ratio_fwd_bwd=pkt_ratio,
            byte_ratio_fwd_bwd=byte_ratio,
            flow_duration_sec=round(duration, 4),
            packets_per_sec=pkts_per_sec,
            bytes_per_sec=bytes_per_sec,
            size_min=size_min,
            size_max=size_max,
            size_mean=size_mean,
            size_median=size_median,
            size_std=size_std,
            size_p25=size_p25,
            size_p75=size_p75,
            size_p90=size_p90,
            size_skewness=size_skew,
            iat_min_ms=iat_min,
            iat_max_ms=iat_max,
            iat_mean_ms=iat_mean,
            iat_median_ms=iat_median,
            iat_std_ms=iat_std,
            burst_count=burst_count,
            mean_burst_size_pkts=round(float(np.mean(burst_sizes)), 2) if burst_sizes else 0.0,
            mean_burst_duration_ms=round(float(np.mean(burst_durations)), 2) if burst_durations else 0.0,
            mean_burst_bytes=round(float(np.mean(burst_bytes_list)), 2) if burst_bytes_list else 0.0,
            packet_size_sequence=seq_sizes,
            iat_sequence_ms=iat_seq,
            direction_sequence=seq_dirs,
        )

    @classmethod
    def _compute_bursts(
        cls, times: np.ndarray, sizes: np.ndarray
    ) -> Tuple[int, List[int], List[float], List[int]]:
        """Identifies bursts separated by idle intervals >= BURST_THRESHOLD_SEC."""
        if len(times) == 0:
            return 0, [], [], []

        burst_sizes = []
        burst_durations = []
        burst_bytes = []

        cur_burst_pkts = 1
        cur_burst_start = times[0]
        cur_burst_bytes = sizes[0]

        for i in range(1, len(times)):
            delta = times[i] - times[i - 1]
            if delta >= cls.BURST_THRESHOLD_SEC:
                # End previous burst
                burst_sizes.append(cur_burst_pkts)
                burst_durations.append((times[i - 1] - cur_burst_start) * 1000.0)
                burst_bytes.append(cur_burst_bytes)

                # Start new burst
                cur_burst_pkts = 1
                cur_burst_start = times[i]
                cur_burst_bytes = sizes[i]
            else:
                cur_burst_pkts += 1
                cur_burst_bytes += sizes[i]

        # Append the final burst
        burst_sizes.append(cur_burst_pkts)
        burst_durations.append((times[-1] - cur_burst_start) * 1000.0)
        burst_bytes.append(cur_burst_bytes)

        return len(burst_sizes), burst_sizes, burst_durations, burst_bytes
