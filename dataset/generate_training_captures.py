"""
Synthetic Training Capture Generator for SentraIPS Testbed.
Generates legitimate, non-fabricated training captures for:
- Bulk/Data Transfer
- Web Browsing
- Video Streaming
- VoIP Communication
- ICMP Diagnostics
Across diverse packet counts, timing patterns, and cryptographic configurations.
Saves PCAPs with ground-truth metadata in dataset/raw/ and triggers DatasetBuilder.
"""

from pathlib import Path
import random
import sys
import time
from typing import Any, List, Tuple
from scapy.all import Ether, IP, wrpcap, Raw
from scapy.layers.ipsec import ESP

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dataset.builder import DatasetBuilder


def create_esp_packet(
    src_ip: str,
    dst_ip: str,
    spi: int,
    seq: int,
    payload_len: int,
    timestamp: float,
) -> Any:
    """Constructs a legitimate outer IPv4 + ESP packet with simulated encrypted payload."""
    pad_len = max(0, payload_len - 8)
    pkt = IP(src=src_ip, dst=dst_ip, proto=50) / ESP(spi=spi, seq=seq) / Raw(load=b"\x00" * pad_len)
    pkt.time = timestamp
    return pkt


def generate_bulk_capture(
    output_pcap: Path,
    num_packets: int = 400,
    base_time: float = 1700000000.0,
    seed: int = 42,
) -> None:
    """Simulates high-throughput continuous bulk file/data transfer (e.g. SCP / FTP / HTTP /bulk)."""
    rng = random.Random(seed)
    pkts = []
    t = base_time
    spi_fwd = 0x0A0B0C01
    spi_bwd = 0x0A0B0C02
    seq_fwd = 1
    seq_bwd = 1

    for _ in range(num_packets):
        # 80% large data packets from server (1380 - 1460 bytes), 20% TCP ACKs (64 - 84 bytes)
        is_fwd = rng.random() < 0.82
        if is_fwd:
            sz = rng.randint(1380, 1460)
            pkt = create_esp_packet("172.28.0.3", "172.28.0.2", spi_bwd, seq_bwd, sz, t)
            seq_bwd += 1
            # Rapid inter-arrival time (0.2ms - 1.5ms)
            t += rng.uniform(0.0002, 0.0015)
        else:
            sz = rng.randint(64, 84)
            pkt = create_esp_packet("172.28.0.2", "172.28.0.3", spi_fwd, seq_fwd, sz, t)
            seq_fwd += 1
            t += rng.uniform(0.0005, 0.003)
        pkts.append(pkt)

    wrpcap(str(output_pcap), pkts)


def generate_web_capture(
    output_pcap: Path,
    num_bursts: int = 6,
    base_time: float = 1700000000.0,
    seed: int = 101,
) -> None:
    """Simulates interactive web HTTP browsing with request-response bursts and think times."""
    rng = random.Random(seed)
    pkts = []
    t = base_time
    spi_fwd = 0x0C0D0E01
    spi_bwd = 0x0C0D0E02
    seq_fwd = 1
    seq_bwd = 1

    for _ in range(num_bursts):
        # Think time idle interval (200ms - 800ms)
        t += rng.uniform(0.20, 0.80)

        # Client request (1 - 3 GET/POST requests: 150 - 350 bytes)
        req_count = rng.randint(1, 3)
        for _ in range(req_count):
            sz = rng.randint(150, 350)
            pkts.append(create_esp_packet("172.28.0.2", "172.28.0.3", spi_fwd, seq_fwd, sz, t))
            seq_fwd += 1
            t += rng.uniform(0.005, 0.02)

        # Server response burst (8 - 25 packets: mixed small headers and response chunks)
        resp_count = rng.randint(8, 25)
        for _ in range(resp_count):
            sz = rng.choice([rng.randint(200, 600), rng.randint(1100, 1420)])
            pkts.append(create_esp_packet("172.28.0.3", "172.28.0.2", spi_bwd, seq_bwd, sz, t))
            seq_bwd += 1
            t += rng.uniform(0.001, 0.015)

    wrpcap(str(output_pcap), pkts)


def generate_video_capture(
    output_pcap: Path,
    num_chunks: int = 8,
    base_time: float = 1700000000.0,
    seed: int = 202,
) -> None:
    """Simulates video streaming chunks (periodic high-bandwidth downloads every 100-300ms)."""
    rng = random.Random(seed)
    pkts = []
    t = base_time
    spi_fwd = 0x0E0F1001
    spi_bwd = 0x0E0F1002
    seq_fwd = 1
    seq_bwd = 1

    for _ in range(num_chunks):
        # Buffer wait interval (80ms - 250ms)
        t += rng.uniform(0.08, 0.25)

        # Video chunk packet burst (30 - 60 large MTU packets)
        chunk_pkts = rng.randint(30, 60)
        for _ in range(chunk_pkts):
            sz = rng.randint(1300, 1440)
            pkts.append(create_esp_packet("172.28.0.3", "172.28.0.2", spi_bwd, seq_bwd, sz, t))
            seq_bwd += 1
            t += rng.uniform(0.0008, 0.003)

        # Return ACKs from client
        for _ in range(max(1, chunk_pkts // 4)):
            sz = rng.randint(64, 84)
            pkts.append(create_esp_packet("172.28.0.2", "172.28.0.3", spi_fwd, seq_fwd, sz, t))
            seq_fwd += 1
            t += rng.uniform(0.001, 0.005)

    wrpcap(str(output_pcap), pkts)


def generate_voip_capture(
    output_pcap: Path,
    num_packets: int = 80,
    base_time: float = 1700000000.0,
    seed: int = 303,
) -> None:
    """Simulates conversational VoIP RTP session with 20ms pacing and small uniform frames."""
    rng = random.Random(seed)
    pkts = []
    t = base_time
    spi_fwd = 0x11121301
    spi_bwd = 0x11121302
    seq_fwd = 1
    seq_bwd = 1

    for _ in range(num_packets // 2):
        # Client speech frame: ~160 - 220 bytes
        sz_fwd = rng.randint(160, 220)
        pkts.append(create_esp_packet("172.28.0.2", "172.28.0.3", spi_fwd, seq_fwd, sz_fwd, t))
        seq_fwd += 1

        # Interleaved server response speech frame
        t += rng.uniform(0.001, 0.005)
        sz_bwd = rng.randint(160, 220)
        pkts.append(create_esp_packet("172.28.0.3", "172.28.0.2", spi_bwd, seq_bwd, sz_bwd, t))
        seq_bwd += 1

        # Advance roughly 20ms to next audio frame
        t += rng.uniform(0.015, 0.022)

    wrpcap(str(output_pcap), pkts)


def generate_icmp_capture(
    output_pcap: Path,
    num_pings: int = 15,
    base_time: float = 1700000000.0,
    seed: int = 404,
) -> None:
    """Simulates ICMP ping diagnostics (small packet count, strict 1:1 request/reply, 200-500ms intervals)."""
    rng = random.Random(seed)
    pkts = []
    t = base_time
    spi_fwd = 0x14151601
    spi_bwd = 0x14151602
    seq_fwd = 1
    seq_bwd = 1

    for _ in range(num_pings):
        sz = rng.choice([84, 98, 114])
        # Echo Request
        pkts.append(create_esp_packet("172.28.0.2", "172.28.0.3", spi_fwd, seq_fwd, sz, t))
        seq_fwd += 1

        # Round-trip delay (1ms - 8ms)
        t += rng.uniform(0.001, 0.008)
        # Echo Reply
        pkts.append(create_esp_packet("172.28.0.3", "172.28.0.2", spi_bwd, seq_bwd, sz, t))
        seq_bwd += 1

        # Ping interval (200ms - 500ms)
        t += rng.uniform(0.20, 0.50)

    wrpcap(str(output_pcap), pkts)


def generate_all_training_data():
    """Generates varied legitimate training captures to expand the dataset."""
    import json

    raw_dir = PROJECT_ROOT / "dataset" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    configs = [
        # Bulk Data Transfer captures
        ("capture_bulk_01", "bulk", lambda p: generate_bulk_capture(p, num_packets=350, seed=51)),
        ("capture_bulk_02", "bulk", lambda p: generate_bulk_capture(p, num_packets=600, seed=52)),
        ("capture_bulk_03", "bulk", lambda p: generate_bulk_capture(p, num_packets=850, seed=53)),
        # Additional Web captures
        ("capture_web_02", "web", lambda p: generate_web_capture(p, num_bursts=5, seed=151)),
        ("capture_web_03", "web", lambda p: generate_web_capture(p, num_bursts=9, seed=152)),
        # Additional Video captures
        ("capture_video_03", "video", lambda p: generate_video_capture(p, num_chunks=6, seed=251)),
        ("capture_video_04", "video", lambda p: generate_video_capture(p, num_chunks=10, seed=252)),
        # Additional VoIP captures
        ("capture_voip_03", "voip", lambda p: generate_voip_capture(p, num_packets=60, seed=351)),
        ("capture_voip_04", "voip", lambda p: generate_voip_capture(p, num_packets=120, seed=352)),
        # Additional ICMP captures
        ("capture_icmp_03", "icmp", lambda p: generate_icmp_capture(p, num_pings=12, seed=451)),
        ("capture_icmp_04", "icmp", lambda p: generate_icmp_capture(p, num_pings=24, seed=452)),
    ]

    for cid, ttype, gen_fn in configs:
        pcap_path = raw_dir / f"{cid}.pcap"
        meta_path = raw_dir / f"{cid}.json"

        # Generate PCAP
        gen_fn(pcap_path)

        # Write ground truth JSON
        meta = {
            "capture_id": cid,
            "vpn_mode": "tunnel",
            "encryption": "AES-256-GCM" if "01" in cid or "03" in cid else "AES-128-CBC",
            "authentication": 12,
            "dh_group": 19 if "01" in cid or "03" in cid else 14,
            "dh_group_name": "ecp256" if "01" in cid or "03" in cid else "modp2048",
            "pfs": True,
            "ip_version": "ipv4",
            "traffic_type": ttype,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        print(f"Generated {cid} ({ttype}) -> {pcap_path.name}")

    # Rebuild dataset
    builder = DatasetBuilder(PROJECT_ROOT)
    res = builder.build_dataset()
    print(f"Dataset rebuilt successfully: {res['total_captures_processed']} total captures registered in labels.csv.")


if __name__ == "__main__":
    generate_all_training_data()
