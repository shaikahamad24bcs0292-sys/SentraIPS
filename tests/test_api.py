"""
Unit and integration tests for Backend REST API (Phase 2).
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_api_health_endpoint():
    """Verify /health returns 200 and healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "Phase" in data["phase"]


def test_api_analyze_pcap_endpoint(project_root: Path):
    """Verify POST /analyze-pcap accepts PCAP upload and returns structured analysis."""
    pcap_path = project_root / "demo_data" / "demo_capture.pcap"
    assert pcap_path.exists()

    with open(pcap_path, "rb") as f:
        response = client.post(
            "/analyze-pcap",
            files={"file": ("demo_capture.pcap", f, "application/vnd.tcpdump.pcap")},
        )

    assert response.status_code == 200
    data = response.json()

    assert data["capture_id"] == "demo_capture"
    assert data["ipsec_detected"] is True
    assert data["ike_detected"] is True
    assert data["esp_detected"] is True
    assert data["ike_version"] == "IKEv2"
    assert "AES-256-GCM" in data["encryption"]
    assert data["dh_group"] == 19
    assert data["dh_group_name"] == "ecp256"
    assert data["esp_packets"] > 0
    assert data["features_extracted"] is True
    assert "esp_features" in data
    assert data["esp_features"]["size_mean"] > 0


def test_api_analyze_invalid_extension():
    """Verify POST /analyze-pcap rejects files with invalid extensions."""
    response = client.post(
        "/analyze-pcap",
        files={"file": ("test.txt", b"not a pcap", "text/plain")},
    )
    assert response.status_code == 400
    assert "unsupported file extension" in response.json()["detail"].lower()


def test_api_analyze_corrupt_pcap():
    """Verify POST /analyze-pcap rejects files with corrupt magic bytes."""
    response = client.post(
        "/analyze-pcap",
        files={"file": ("corrupt.pcap", b"INVALID_BYTES_NOT_A_PCAP", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "validation failed" in response.json()["detail"].lower()


def test_api_list_captures():
    """Verify GET /captures returns registered dataset captures."""
    response = client.get("/captures")
    assert response.status_code == 200
    data = response.json()
    assert "total_captures" in data
    assert "captures" in data
    assert data["total_captures"] > 0


def test_api_get_specific_capture():
    """Verify GET /captures/{id} retrieves details for demo_001."""
    response = client.get("/captures/demo_001")
    assert response.status_code == 200
    data = response.json()
    assert data["capture_id"] == "demo_001"
    assert "summary" in data
    assert "features" in data
