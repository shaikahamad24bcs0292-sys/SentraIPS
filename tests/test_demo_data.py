"""
Test demo data existence and offline parsing capability.
Ensures the platform can analyze the reference demo PCAP without live VPN testbed.
"""

from pathlib import Path
from packet_analysis.validator import PCAPValidator


def test_demo_data_exists(project_root: Path):
    """Verify demo PCAP and metadata files exist in demo_data/."""
    demo_pcap = project_root / "demo_data" / "demo_capture.pcap"
    demo_meta = project_root / "demo_data" / "demo_capture.json"

    assert demo_pcap.exists(), f"Missing demo PCAP at {demo_pcap}"
    assert demo_pcap.stat().st_size > 0, "Demo PCAP is empty"
    assert demo_meta.exists(), f"Missing demo metadata at {demo_meta}"


def test_demo_data_offline_parsing(project_root: Path):
    """Verify demo PCAP can be fully parsed and validated offline."""
    demo_pcap = project_root / "demo_data" / "demo_capture.pcap"
    demo_meta = project_root / "demo_data" / "demo_capture.json"

    result = PCAPValidator.analyze_pcap(demo_pcap, demo_meta)

    assert result.is_valid is True, f"Demo PCAP failed validation: {result.errors}"
    assert result.total_packets > 0, "Demo PCAP has 0 packets"
    assert result.metadata_valid is True, "Demo metadata failed validation"
    assert result.metadata["capture_id"] == "demo_001"
    assert result.metadata["vpn_mode"] == "tunnel"
    assert result.metadata["ip_version"] == "ipv4"
    assert result.metadata["encryption"] in ("AES-256-GCM", "AES-128-CBC")
