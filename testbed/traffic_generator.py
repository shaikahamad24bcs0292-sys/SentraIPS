"""
Traffic Generator for SentraIPS Testbed.
Generates reproducible, offline traffic through the IPsec tunnel:
1. ICMP (ping echo requests)
2. Web-like HTTP traffic (GET / POST with realistic headers and payloads)
3. Video / Bulk streaming (chunked media stream / high-throughput transfer)
4. VoIP (RTP-like UDP packet stream at 20ms intervals)

All traffic originates from 10.10.1.1 (Gateway A subnet) to 10.10.2.1 (Gateway B subnet).
"""

import argparse
import http.client
import json
import os
import random
import socket
import struct
import sys
import time
from typing import Dict, Any, List, Optional, Tuple

DEFAULT_TARGET_IP = "10.10.2.1"
DEFAULT_SOURCE_IP = "10.10.1.1"


class BoundHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that binds to a specific source IP (for loopback routing)."""
    def __init__(self, host, port=None, source_address=None, timeout=5):
        super().__init__(host, port, timeout=timeout, source_address=source_address)


def generate_icmp(target_ip: str = DEFAULT_TARGET_IP, count: int = 10, interval: float = 0.2) -> Dict[str, Any]:
    """Generates ICMP ping packets using system ping tool."""
    import subprocess
    cmd = ["ping", "-c", str(count), "-i", str(interval), target_ip]
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    duration = time.time() - start_time
    success = (result.returncode == 0)
    return {
        "traffic_type": "icmp",
        "packets_sent": count,
        "success": success,
        "duration_seconds": round(duration, 3),
        "target_ip": target_ip,
    }


def generate_web_traffic(target_ip: str = DEFAULT_TARGET_IP, port: int = 8080,
                         requests_count: int = 15, source_ip: str = DEFAULT_SOURCE_IP) -> Dict[str, Any]:
    """Generates realistic HTTP GET and POST requests against Gateway B responder."""
    print(f"[Traffic:Web] Sending {requests_count} HTTP requests to {target_ip}:{port}...", file=sys.stderr, flush=True)
    start_time = time.time()
    successful_requests = 0
    bytes_transferred = 0

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentraIPS-Client/1.0",
        "Accept": "text/html,application/json,*/*",
        "Connection": "keep-alive",
    }

    endpoints = ["/", "/api/data", "/status"]

    for i in range(num_requests):
        try:
            conn = BoundHTTPConnection(target_ip, port, source_address=(source_ip, 0), timeout=5)
            # Alternate GET and POST
            if i % 3 == 0:
                payload = json.dumps({"client_query": f"request_{i}", "metric_id": i * 100})
                post_headers = {**headers, "Content-Type": "application/json"}
                conn.request("POST", "/api/data", body=payload, headers=post_headers)
            else:
                ep = endpoints[i % len(endpoints)]
                conn.request("GET", ep, headers=headers)

            resp = conn.getresponse()
            data = resp.read()
            bytes_transferred += len(data)
            if resp.status == 200:
                successful_requests += 1
            conn.close()
            time.sleep(0.15)  # Realistic inter-request delay
        except Exception as e:
            print(f"[Traffic:Web] Request {i} failed: {e}", file=sys.stderr, flush=True)

    duration = time.time() - start_time
    print(f"[Traffic:Web] Completed: {successful_requests}/{num_requests} ok, {bytes_transferred} bytes in {duration:.2f}s", file=sys.stderr, flush=True)
    return {
        "traffic_type": "web",
        "target_ip": target_ip,
        "port": port,
        "requests_sent": num_requests,
        "successful_requests": successful_requests,
        "bytes_transferred": bytes_transferred,
        "duration_seconds": duration,
        "success": successful_requests > 0,
    }


def generate_video(target_ip: str = DEFAULT_TARGET_IP, source_ip: str = DEFAULT_SOURCE_IP,
                   port: int = 8080, streams: int = 2) -> Dict[str, Any]:
    """Simulate video/bulk chunk streaming over HTTP."""
    print(f"[Traffic:Video] Streaming chunked media from {target_ip}:{port} ({streams} streams)...", file=sys.stderr, flush=True)
    start_time = time.time()
    total_bytes = 0
    successful_streams = 0

    headers = {
        "User-Agent": "SentraIPS-MediaStreamer/1.0 (VLC/ExoPlayer simulation)",
        "Accept": "video/mp4,application/octet-stream",
    }

    for s in range(streams):
        try:
            conn = BoundHTTPConnection(target_ip, port, source_address=(source_ip, 0), timeout=10)
            conn.request("GET", "/stream/video", headers=headers)
            resp = conn.getresponse()
            if resp.status == 200:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                successful_streams += 1
            conn.close()
        except Exception as e:
            print(f"[Traffic:Video] Stream {s} failed: {e}", file=sys.stderr, flush=True)

    # Also perform a bulk transfer
    try:
        conn = BoundHTTPConnection(target_ip, port, source_address=(source_ip, 0), timeout=10)
        conn.request("GET", "/bulk", headers=headers)
        resp = conn.getresponse()
        bulk_data = resp.read()
        total_bytes += len(bulk_data)
        conn.close()
    except Exception as e:
        print(f"[Traffic:Video] Bulk transfer failed: {e}", file=sys.stderr, flush=True)

    duration = time.time() - start_time
    print(f"[Traffic:Video] Completed: {total_bytes} bytes transferred in {duration:.2f}s", file=sys.stderr, flush=True)
    return {
        "traffic_type": "video",
        "target_ip": target_ip,
        "port": port,
        "successful_streams": successful_streams,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
        "success": total_bytes > 0,
    }


def generate_voip(target_ip: str = DEFAULT_TARGET_IP, source_ip: str = DEFAULT_SOURCE_IP,
                  port: int = 5004, num_packets: int = 50, interval: float = 0.02) -> Dict[str, Any]:
    """
    Simulate VoIP RTP stream:
    Sends 160-byte UDP packets (standard G.711 20ms payload) at 20ms intervals.
    """
    print(f"[Traffic:VoIP] Sending {num_packets} RTP-like UDP packets to {target_ip}:{port} at {interval*1000:.0f}ms...", file=sys.stderr, flush=True)
    start_time = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((source_ip, 0))
    sock.settimeout(0.5)

    packets_sent = 0
    packets_received = 0

    for seq in range(num_packets):
        # 12-byte pseudo-RTP header + 160-byte payload
        rtp_header = bytearray(12)
        rtp_header[0] = 0x80  # V=2
        rtp_header[1] = 0x00  # Payload type: PCMU (0)
        rtp_header[2] = (seq >> 8) & 0xFF
        rtp_header[3] = seq & 0xFF
        ts = int(time.time() * 8000) & 0xFFFFFFFF
        rtp_header[4:8] = ts.to_bytes(4, byteorder="big")
        rtp_header[8:12] = (0x12345678).to_bytes(4, byteorder="big")  # SSRC

        payload = rtp_header + b"\x7F" * 160
        sock.sendto(payload, (target_ip, port))
        packets_sent += 1

        try:
            resp, _ = sock.recvfrom(512)
            if resp:
                packets_received += 1
        except socket.timeout:
            pass

        time.sleep(interval)

    sock.close()
    duration = time.time() - start_time
    print(f"[Traffic:VoIP] Sent: {packets_sent}, Echoed: {packets_received} in {duration:.2f}s", file=sys.stderr, flush=True)
    return {
        "traffic_type": "voip",
        "target_ip": target_ip,
        "port": port,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "duration_seconds": duration,
        "success": packets_sent > 0,
    }


def run_traffic(traffic_type: str, target_ip: str = DEFAULT_TARGET_IP, source_ip: str = DEFAULT_SOURCE_IP) -> Dict[str, Any]:
    """Dispatcher for traffic generation types."""
    t_type = traffic_type.lower()
    if t_type == "icmp":
        return generate_icmp(target_ip, source_ip)
    elif t_type == "web":
        return generate_web(target_ip, source_ip)
    elif t_type in ("video", "bulk"):
        return generate_video(target_ip, source_ip)
    elif t_type == "voip":
        return generate_voip(target_ip, source_ip)
    else:
        raise ValueError(f"Unknown traffic type: {traffic_type}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentraIPS Traffic Generator")
    parser.add_argument("--type", choices=["icmp", "web", "video", "bulk", "voip"], default="web", help="Traffic type")
    parser.add_argument("--target", default=DEFAULT_TARGET_IP, help="Target IP address")
    parser.add_argument("--source", default=DEFAULT_SOURCE_IP, help="Source IP address")
    args = parser.parse_args()

    res = run_traffic(args.type, args.target, args.source)
    print(json.dumps(res, indent=2))
