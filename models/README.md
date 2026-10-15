# SentraIPS — Phase 4 AI/ML Traffic Classification

This directory contains the machine learning components for inferring application traffic types traversing encrypted IPsec ESP tunnels **without decrypting payloads**.

---

## 1. Objective & Security Boundary

In modern enterprise and defense networks, IPsec Encapsulating Security Payload (ESP) encrypts Layer 4 headers and application payloads end-to-end. Traditional Deep Packet Inspection (DPI) fails because payload bytes are indistinguishable from high-entropy random data.

SentraIPS Phase 4 performs **statistical behavioral traffic classification** using solely observable Layer 3/Layer 4 metadata and flow dynamics.

### Critical Cryptographic Boundary
* **Zero Payload Decryption**: ESP payloads are **never** decrypted or inspected.
* **Strict Separation of Concerns**: The ML model **NEVER** determines cryptographic attributes (ciphers, DH groups, PFS, IKE versions, authentication). Those parameters are strictly extracted and assessed deterministically by the `packet_analysis` parser and `security_engine`.
* **Inferred vs Observed**: All traffic classifications are explicitly marked as **INFERRED** probabilistic classifications, never observed cryptographic facts.

---

## 2. ML Architecture & Pipeline

```
  Encrypted PCAP File
          │
          ▼
┌───────────────────────────────┐
│     IPsec PCAP Parser         │  (Deterministic Scapy Outer-Header Dissector)
└──────────────┬────────────────┘
               │ (ESP Packets Isolated)
               ▼
┌───────────────────────────────┐
│   ESP Feature Extractor       │  (Extracts 27 Statistical Outer-Flow Features)
└──────────────┬────────────────┘
               │ (27-Dimensional Vector)
               ▼
┌───────────────────────────────┐
│     Feature Validator         │  (Validates NaN, Inf, Types, Schema Compliance)
└──────────────┬────────────────┘
               │ (Valid Vector)
               ▼
┌───────────────────────────────┐
│     Standard Scaler           │  (Zero-Mean, Unit-Variance Normalization)
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│   Random Forest Classifier    │  (100 Trees, Balanced Class Weights, Depth 10)
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│  Confidence Cutoff (Threshold)│
│       Is Confidence >= 0.50?  │
└───────┬───────────────┬───────┘
       Yes              No
        │                │
        ▼                ▼
┌──────────────┐  ┌──────────────┐
│ Target Class │  │   Unknown    │  (Prevents Forced Hallucinations)
└──────────────┘  └──────────────┘
```

### Target Classes
1. **Web** (`HTTP/HTTPS` browsing patterns, asymmetric request/response bursts)
2. **Video** (High throughput, sustained chunked transfers, high byte volume)
3. **VoIP** (Strict isochronous ~20ms packet pacing, small packet sizes <300B)
4. **ICMP** (Echo requests/replies, highly regular, small counts and sizes)
5. **Bulk/Data Transfer** (Sustained unidirectional high throughput, MTU-sized packets)
6. **Unknown** (Ambiguous flow dynamics, low model confidence < 0.50, or zero ESP packets)

---

## 3. Statistical Flow Features (27 Observable Metrics)

The model operates on 27 observable outer-header statistical metrics:

| Category | Features |
|---|---|
| **Volume Metrics** | `total_packets`, `total_bytes`, `forward_packets`, `backward_packets` |
| **Symmetry & Rates** | `packet_ratio_fwd_bwd`, `byte_ratio_fwd_bwd`, `flow_duration_sec`, `packets_per_sec`, `bytes_per_sec` |
| **Packet Size Statistics** | `size_min`, `size_max`, `size_mean`, `size_median`, `size_std`, `size_p25`, `size_p75`, `size_p90`, `size_skewness` |
| **Timing & Pacing (IAT)** | `iat_min_ms`, `iat_max_ms`, `iat_mean_ms`, `iat_median_ms`, `iat_std_ms` |
| **Burst Dynamics** | `burst_count`, `mean_burst_size_pkts`, `mean_burst_duration_ms`, `mean_burst_bytes` |

---

## 4. Training Procedure & Evaluation Metrics

Training is fully reproducible via `models/train.py`:

```bash
python models/train.py
```

### Dataset
* Ground-truth labeled captures are stored in `dataset/raw/` and cataloged in `dataset/labels.csv`.
* Sliced into windowed flow sessions to capture diverse operational phases (connection initiation, steady state, bursts).
* 474 valid samples across all 5 active traffic classes.

### Evaluation Results (Unseen Test Split)
Evaluated on 119 unseen test samples using stratified train/test split:

* **Accuracy**: **99.16%**
* **Weighted Precision**: **99.19%**
* **Weighted Recall**: **99.16%**
* **Weighted F1-Score**: **99.16%**
* **Macro F1-Score**: **99.41%**

#### Per-Class Performance
| Class | Precision | Recall | F1-Score | Test Support |
|---|---|---|---|---|
| **Bulk/Data Transfer** | 100.00% | 100.00% | 100.00% | 24 |
| **ICMP** | 100.00% | 100.00% | 100.00% | 6 |
| **Video** | 96.97% | 100.00% | 98.46% | 32 |
| **VoIP** | 100.00% | 100.00% | 100.00% | 21 |
| **Web** | 100.00% | 97.22% | 98.59% | 36 |

#### Top Feature Importances
1. `size_max` (0.1158)
2. `iat_mean_ms` (0.0983)
3. `size_p90` (0.0955)
4. `bytes_per_sec` (0.0860)
5. `size_p75` (0.0829)
6. `packets_per_sec` (0.0801)
7. `size_std` (0.0730)
8. `iat_max_ms` (0.0482)

Saved artifacts:
* Model weights: `models/weights/rf_traffic_model.joblib`
* Metrics report: `models/evaluation_metrics.json`

---

## 5. Inference & CLI Usage

### Python API
```python
from models.predict import predict_traffic

# Over a PCAP file
result = predict_traffic("demo_data/demo_capture.pcap")
print(result)
# Output:
# {
#   "traffic_class": "Web",
#   "confidence": 1.0,
#   "model": "RandomForest",
#   "probabilities": { "Web": 1.0, "Bulk/Data Transfer": 0.0, ... }
# }
```

### CLI Command
```bash
python models/predict.py --pcap demo_data/demo_capture.pcap
```

### Phase 4 Demo Runner
```bash
python scripts/run_phase4_demo.py
```

---

## 6. REST API Endpoints

### 1. Dedicated Inference Endpoint: `POST /predict-traffic`
Accepts multipart PCAP upload or JSON features body:
```bash
curl -X POST "http://localhost:8000/predict-traffic" \
  -F "file=@demo_data/demo_capture.pcap"
```
Response:
```json
{
  "traffic_class": "Web",
  "confidence": 1.0,
  "model": "RandomForest",
  "probabilities": {
    "Web": 1.0,
    "Video": 0.0,
    "VoIP": 0.0,
    "ICMP": 0.0,
    "Bulk/Data Transfer": 0.0
  }
}
```

### 2. Main Analysis Endpoint: `POST /analyze-pcap`
The unified analysis response now incorporates `traffic_analysis`:
```json
{
  "capture_id": "demo_capture",
  "ike_version": "IKEv2",
  "encryption": "AES-256-GCM",
  "dh_group_name": "ecp256",
  "pfs": true,
  "security_assessment": { ... },
  "traffic_analysis": {
    "classification": "Web",
    "confidence": 1.0,
    "model": "RandomForest"
  }
}
```
