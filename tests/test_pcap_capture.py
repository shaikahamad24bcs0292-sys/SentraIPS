"""
Test PCAP packet capture and ground-truth metadata generation.
"""

from pathlib import Path
from testbed.config_generator import IPsecConfig
from packet_analysis.validator import PCAPValidator


def test_pcap_and_metadata_generation(orchestrator, project_root: Path):
    """Verify tcpdump captures real IKE and ESP packets and writes valid metadata."""
    captures_dir = project_root / "dataset" / "captures"
    config = IPsecConfig(
        capture_id="pytest_capture_01",
        vpn_mode="tunnel",
        ip_version="ipv4",
        encryption="AES-256-GCM",
        pfs=True,
        dh_group=19,
        traffic_type="icmp",
    )

    result = orchestrator.run_capture_session(config=config, output_dir=captures_dir)

    pcap_path = Path(result["pcap_file"])
    meta_path = Path(result["metadata_file"])

    assert pcap_path.exists(), f"PCAP file was not created: {pcap_path}"
    assert pcap_path.stat().st_size > 0, "PCAP file is empty"
    assert meta_path.exists(), f"Metadata file was not created: {meta_path}"

    val = PCAPValidator.analyze_pcap(pcap_path, meta_path)
    assert val.is_valid, f"PCAP validation failed: {val.errors}"
    assert val.total_packets > 0, "No packets captured"
    assert val.esp_packets > 0 or val.ike_packets > 0, f"Expected IPsec packets (IKE/ESP), found: {val.protocols_detected}"
    assert val.metadata_valid is True, "Metadata JSON failed schema validation"
