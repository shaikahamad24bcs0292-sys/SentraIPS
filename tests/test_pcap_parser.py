"""
Unit and integration tests for IPsec PCAP Parser (Phase 2).
"""

from pathlib import Path
import tempfile
import pytest

from packet_analysis.parser import IPsecPCAPParser, PCAPParseResult


@pytest.fixture
def demo_pcap(project_root: Path) -> Path:
    pcap = project_root / "demo_data" / "demo_capture.pcap"
    assert pcap.exists(), f"Demo PCAP not found at {pcap}"
    return pcap


def test_valid_pcap_parsing(demo_pcap: Path):
    """Verify parser successfully parses a valid IPsec PCAP."""
    result = IPsecPCAPParser.parse_pcap(demo_pcap)

    assert result.is_valid is True
    assert result.total_packets > 0
    assert result.ipsec_detected is True
    assert len(result.errors) == 0


def test_ike_detection_and_crypto(demo_pcap: Path):
    """Verify IKEv2 handshake, SPIs, cipher suite, and DH group extraction."""
    result = IPsecPCAPParser.parse_pcap(demo_pcap)

    assert result.ike_detected is True
    assert result.ike_packets > 0
    assert result.ike.version == "IKEv2"
    assert result.ike.initiator_spi != "Unknown / Not Detected"
    assert result.ike.responder_spi != "Unknown / Not Detected"
    assert "AES-256-GCM" in result.ike.encryption
    assert result.ike.dh_group == 19
    assert result.ike.dh_group_name == "ecp256"


def test_esp_detection_and_packets(demo_pcap: Path):
    """Verify ESP packets are correctly identified with sequence numbers and SPIs."""
    result = IPsecPCAPParser.parse_pcap(demo_pcap)

    assert result.esp_detected is True
    assert result.esp_packets > 0
    assert len(result.esp.spis_observed) > 0
    assert result.esp.total_bytes > 0


def test_nonexistent_file_handling():
    """Verify parser gracefully handles non-existent files."""
    bogus_path = Path("does_not_exist_xyz123.pcap")
    result = IPsecPCAPParser.parse_pcap(bogus_path)

    assert result.is_valid is False
    assert any("not found" in err.lower() for err in result.errors)


def test_empty_pcap_file(tmp_path: Path):
    """Verify parser gracefully handles 0-byte files."""
    empty_file = tmp_path / "empty.pcap"
    empty_file.write_bytes(b"")

    result = IPsecPCAPParser.parse_pcap(empty_file)
    assert result.is_valid is False
    assert any("empty" in err.lower() for err in result.errors)


def test_invalid_magic_bytes(tmp_path: Path):
    """Verify parser rejects corrupt or non-pcap files."""
    corrupt_file = tmp_path / "corrupt.pcap"
    corrupt_file.write_bytes(b"THIS_IS_NOT_A_VALID_PCAP_MAGIC_HEADER_AT_ALL_1234567890")

    result = IPsecPCAPParser.parse_pcap(corrupt_file)
    assert result.is_valid is False
    assert any("magic" in err.lower() for err in result.errors)


def test_missing_fields_no_fabrication(tmp_path: Path):
    """Verify that unobservable protocol parameters default to 'Unknown / Not Detected'."""
    from scapy.all import wrpcap, Ether, IP, TCP
    # Create a PCAP with plain TCP packets only
    plain_pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80)
    plain_pcap = tmp_path / "plain_tcp.pcap"
    wrpcap(str(plain_pcap), [plain_pkt])

    result = IPsecPCAPParser.parse_pcap(plain_pcap)
    assert result.is_valid is True
    assert result.ipsec_detected is False
    assert result.ike_detected is False
    assert result.esp_detected is False
    assert result.ike.version == "Unknown / Not Detected"
    assert result.ike.encryption == "Unknown / Not Detected"
    assert result.ike.dh_group_name == "Unknown / Not Detected"
    assert result.ike.pfs == "Unknown / Not Detected"
