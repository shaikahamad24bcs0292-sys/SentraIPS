# SentraIPS Dataset Engine

This directory contains raw PCAP network captures, extracted behavioral feature vectors, and ground-truth labels used to train and evaluate the SentraIPS security assessment models.

## Directory Structure

```text
dataset/
├── raw/                   # Raw network captures (.pcap, .pcapng) and associated .json metadata
├── processed/             # Extracted statistical & sequence feature vectors (.json)
├── captures/              # Target directory for live testbed orchestrator captures
├── labels.csv             # Central ground-truth label registry
└── builder.py             # Pipeline script to sync raw files, extract features, and regenerate labels.csv
```

## Ground-Truth Labels (`labels.csv`)

| Column | Type | Description |
|---|---|---|
| `capture_id` | string | Unique capture identifier (e.g. `demo_001`, `capture_cbc_dh14`) |
| `vpn_mode` | string | VPN topology mode (`tunnel`, `transport`) |
| `encryption` | string | IPsec cipher suite (`AES-256-GCM`, `AES-128-CBC`, etc.) |
| `authentication` | string | PRF / HMAC integrity algorithm (`HMAC-SHA256`, `HMAC-SHA384`, etc.) |
| `dh_group` | integer / string | Diffie-Hellman Group (`19` = ecp256, `14` = modp2048, etc.) |
| `pfs` | boolean / string | Perfect Forward Secrecy (`True`, `False`) |
| `ip_version` | string | IP version (`ipv4`, `ipv6`) |
| `traffic_type` | string | Ground-truth simulated traffic (`web`, `voip`, `video`, `icmp`) |
| `total_packets` | integer | Total packets in the capture |
| `esp_packets` | integer | Total Encapsulating Security Payload packets |
| `ike_packets` | integer | Total Internet Key Exchange (IKEv2) packets |
| `flow_duration_sec` | float | Time between first and last ESP packet (seconds) |
| `raw_pcap` | string | Relative path to raw `.pcap` |
| `processed_features_file` | string | Relative path to processed `.json` feature vector |

## Extracted Features (`processed/*.json`)

Each capture has a processed JSON file containing:
- **Volume**: Packet counts, byte counts, forward/backward direction ratios.
- **Packet Size Statistics**: Min, max, mean, median, standard deviation, 25th/75th/90th percentiles, skewness.
- **Timing Statistics**: Inter-arrival time (IAT) min, max, mean, median, standard deviation.
- **Burst Dynamics**: Burst count, mean burst size (pkts), mean burst duration (ms).
- **Temporal Sequences**: Fixed-length (first 64) sequences of packet sizes, IATs, and directions for temporal deep learning (1D-CNN in Phase 4).

## Rebuilding Dataset

Run the automated builder script:
```powershell
python dataset/builder.py
```
