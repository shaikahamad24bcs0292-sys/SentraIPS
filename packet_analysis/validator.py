"""
PCAP Validator and Metadata Inspector for SentraIPS.
Inspects captured PCAP files for IPsec artifacts (IKEv2, ESP) and validates ground-truth metadata.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from scapy.all import rdpcap, IP, UDP, ESP, Raw


@dataclass
class PCAPValidationResult:
    is_valid: bool
    total_packets: int = 0
    ike_packets: int = 0
    esp_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    protocols_detected: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metadata_valid: bool = False
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "total_packets": self.total_packets,
            "ike_packets": self.ike_packets,
            "esp_packets": self.esp_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,
            "protocols_detected": self.protocols_detected,
            "errors": self.errors,
            "metadata_valid": self.metadata_valid,
            "metadata": self.metadata,
        }


class PCAPValidator:
    """Validates PCAP files and verifies their correspondence to ground-truth metadata."""

    REQUIRED_METADATA_FIELDS = [
        "capture_id",
        "vpn_mode",
        "ip_version",
        "encryption",
        "pfs",
        "dh_group",
        "traffic_type",
    ]

    @classmethod
    def validate_metadata(cls, metadata_path: str | Path) -> tuple[bool, Dict[str, Any], List[str]]:
        """Validate the ground-truth metadata JSON file."""
        path = Path(metadata_path)
        errors = []
        if not path.exists():
            return False, {}, [f"Metadata file not found: {path}"]

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return False, {}, [f"Invalid JSON in metadata: {e}"]

        for req in cls.REQUIRED_METADATA_FIELDS:
            if req not in data:
                errors.append(f"Missing required metadata field: '{req}'")

        return len(errors) == 0, data, errors

    @classmethod
    def analyze_pcap(cls, pcap_path: str | Path, metadata_path: Optional[str | Path] = None) -> PCAPValidationResult:
        """Parse PCAP file, count protocols, and verify metadata if provided."""
        path = Path(pcap_path)
        result = PCAPValidationResult(is_valid=False)

        if not path.exists():
            result.errors.append(f"PCAP file does not exist: {path}")
            return result

        if path.stat().st_size == 0:
            result.errors.append(f"PCAP file is empty (0 bytes): {path}")
            return result

        try:
            packets = rdpcap(str(path))
            result.total_packets = len(packets)
        except Exception as e:
            result.errors.append(f"Failed to parse PCAP with Scapy: {e}")
            return result

        if result.total_packets == 0:
            result.errors.append("PCAP contains 0 packets")
            return result

        detected_protos = set()
        for pkt in packets:
            if IP in pkt:
                ip_layer = pkt[IP]
                # Check for ESP (IP Protocol 50)
                if ip_layer.proto == 50 or ESP in pkt:
                    result.esp_packets += 1
                    detected_protos.add("ESP (Proto 50)")

                # Check for IKE (UDP port 500 or 4500)
                if UDP in pkt:
                    result.udp_packets += 1
                    udp_layer = pkt[UDP]
                    if udp_layer.sport in (500, 4500) or udp_layer.dport in (500, 4500):
                        result.ike_packets += 1
                        detected_protos.add("IKEv2 (UDP 500/4500)")
                    else:
                        detected_protos.add("UDP")

                # Check for ICMP (Proto 1)
                if ip_layer.proto == 1:
                    result.icmp_packets += 1
                    detected_protos.add("ICMP")

                # Check for TCP (Proto 6)
                if ip_layer.proto == 6:
                    result.tcp_packets += 1
                    detected_protos.add("TCP")

        result.protocols_detected = sorted(list(detected_protos))

        # Check metadata if path given or if neighboring .json exists
        target_meta_path = metadata_path
        if not target_meta_path:
            possible_meta = path.with_suffix(".json")
            if possible_meta.exists():
                target_meta_path = possible_meta

        if target_meta_path:
            meta_ok, meta_data, meta_errors = cls.validate_metadata(target_meta_path)
            result.metadata_valid = meta_ok
            result.metadata = meta_data
            result.errors.extend(meta_errors)

        result.is_valid = (len(result.errors) == 0 and result.total_packets > 0)
        return result
