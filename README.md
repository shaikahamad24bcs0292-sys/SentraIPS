# SentraIPS — AI-Driven IPsec VPN Security Assessment Platform

**Smart India Hackathon 2026 Prototype — Phases 1, 2, 3, 4 & 5**

SentraIPS is an AI-driven security assessment and auditing platform for IPsec VPNs. This repository contains the reproducible strongSwan testbed (Phase 1), PCAP parsing, ESP feature extraction, and dataset pipeline (Phase 2), deterministic security assessment and explainable risk engine (Phase 3), AI/ML traffic classification over encrypted ESP metadata (Phase 4), and structured standards knowledge base, compliance evaluation, and publication-ready automated security reporting (Phase 5).

---

## Phase 1 Core Architecture & Flow

```
+---------------------------------------------------------------------------------------+
| strongSwan IPsec VPN (Gateway A <---> Gateway B)                                      |
|    - IKEv2 Key Exchange (UDP 500/4500)                                                |
|    - Configurable Ciphers (AES-256-GCM, AES-128-CBC)                                 |
|    - Configurable DH Groups (14 - modp2048, 19 - ecp256)                             |
|    - PFS Enabled / Disabled                                                           |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
| Controlled Traffic Generation (Offline & Reproducible)                                |
|    - ICMP (Ping sweeps & bursts)                                                      |
|    - Web-like HTTP (GET/POST with realistic headers, API calls, dynamic payloads)     |
|    - Video / Bulk Streaming (Chunked media playback & high-throughput transfers)      |
|    - VoIP Simulation Structure (RTP-like UDP frames with 20ms pacing)                 |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
| PCAP Capture Engine (tcpdump)                                                         |
|    - Interface: eth0 (Transit Network 172.28.0.0/24)                                  |
|    - Captures raw IKEv2 handshake & ESP encrypted packets                             |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
| Ground-Truth Configuration Metadata (.json)                                           |
|    - Stores exact cryptographic parameters, traffic type, and packet counters         |
+---------------------------------------------------------------------------------------+
```

---

## Project Structure

```
SentraIPS/
├── backend/                   # FastAPI Backend REST API
│   ├── __init__.py
│   ├── main.py                # Analysis endpoints (POST /analyze-pcap, /predict-traffic, /security-assessment)
│   └── README.md
├── frontend/                  # Streamlit UI dashboard
│   ├── app.py
│   └── README.md
├── testbed/                   # Core Phase 1 Testbed Engine
│   ├── Dockerfile             # Container definition (Debian, strongSwan 5.9.8, tcpdump)
│   ├── entrypoint.sh          # Node entrypoint, loopback IP assignment & routing
│   ├── config_generator.py    # Generates strongSwan config & metadata dynamically
│   ├── traffic_generator.py   # Traffic simulation (ICMP, Web HTTP, Video, VoIP)
│   ├── responder_service.py   # HTTP / bulk streaming & UDP echo responder (Gateway B)
│   ├── capture_manager.py     # tcpdump process lifecycle manager
│   └── orchestrator.py        # Complete session orchestrator
├── packet_analysis/           # Packet inspection, protocol parser & feature extractor
│   ├── __init__.py
│   ├── validator.py           # Scapy PCAP inspector & metadata schema validator
│   ├── parser.py              # IKEv2 & ESP protocol dissector & parameter extractor
│   └── features.py            # Encrypted ESP metadata feature extraction engine (27 features)
├── dataset/
│   ├── raw/                   # Raw PCAPs and ground-truth metadata
│   ├── processed/             # Extracted ESP feature vectors (.json)
│   ├── captures/              # Generated PCAP captures from live testbed
│   ├── labels.csv             # Central ground-truth dataset registry
│   ├── builder.py             # Dataset sync, feature processing, & label compiler
│   ├── generate_training_captures.py # Generator for multi-class ESP training PCAPs
│   └── README.md              # Dataset documentation
├── demo_data/                 # Pre-generated known-good demo dataset
│   ├── demo_capture.pcap      # Compliant capture (AES-256-GCM, DH 19, PFS True, Web)
│   ├── demo_capture.json      # Ground-truth configuration metadata
│   ├── weak_capture.pcap      # Vulnerable capture (AES-128-CBC, DH 5, PFS False)
│   └── ambiguous_capture.pcap # Discordant capture (AI temporal/volume conflict)
├── knowledge_base/            # NIST & RFC verified standards & compliance rules (Phase 5)
│   ├── knowledge_base.json    # Machine-readable standards baseline (NIST SP 800-77, RFC 8221/8247)
│   ├── compliance_engine.py   # Deterministic standards evaluation engine (PASS, WARNING, FAIL, UNKNOWN)
│   ├── rag_engine.py          # Standards RAG retrieval & semantic indexing engine
│   ├── nist/                  # Authoritative NIST special publications
│   ├── rfc/                   # Authoritative IETF RFC standards
│   └── README.md
├── models/                    # Phase 4 AI / ML Traffic Classification Models
│   ├── train.py               # Random Forest training & evaluation pipeline
│   ├── predict.py             # Inference CLI & programmatic API
│   ├── model_manager.py       # Model lifecycle, serialization, & fallback manager
│   ├── feature_schema.py      # 27-feature schema, validation, & output schemas
│   ├── evaluation_metrics.json# Genuine test evaluation metrics (99.16% Acc, 99.19% Prec)
│   ├── weights/               # Trained model artifacts (rf_traffic_model.joblib, cnn_weights.pt)
│   └── README.md              # Machine learning documentation
├── security_engine/           # Deterministic Security Engine & Compliance Rules (Phase 3)
│   ├── schemas.py             # Pydantic models for findings, configuration, and reports
│   ├── rules.py               # Deterministic security rules (Ciphers, DH, PFS, IKE, ESP)
│   ├── risk_scoring.py        # Transparent 0-100 risk score engine & itemized breakdown
│   ├── recommendations.py     # Prioritized remediation engine (CRITICAL to LOW)
│   ├── security_engine.py     # Central assessment orchestrator
│   ├── config.yaml            # Weights, severity thresholds, and baseline standards
│   └── README.md              # Security engine documentation
├── reporting/                 # Automated Audit Reporting Pipeline (Phase 5)
│   ├── report_schema.py       # Unified Pydantic models for executive summary, VPN, ML, & compliance
│   ├── report_generator.py    # Master pipeline orchestrator (PCAP -> Security -> ML -> Compliance)
│   ├── json_report.py         # Formatted JSON audit record serialization
│   ├── html_report.py         # Publication-grade, self-contained offline HTML audit report renderer
│   └── README.md              # Reporting architecture and format reference
├── reports/                   # Generated JSON and HTML audit reports
├── tests/                     # Comprehensive automated test suite (104+ tests)
│   ├── conftest.py
│   ├── test_phase5_reporting.py # 12 Phase 5 compliance engine, JSON/HTML report & API tests
│   ├── test_phase4_ml.py      # 17 Phase 4 ML validation, prediction & API tests
│   ├── test_phase3_security.py # 14 mandatory Phase 3 compliance & API tests
│   ├── test_security_engine.py # Deterministic risk scoring & threat matrix tests
│   ├── test_ensemble.py       # Dual-model ensemble & uncertainty arbitration tests
│   ├── test_dashboard.py      # Streamlit dashboard tests
│   ├── test_api.py            # FastAPI REST API integration tests
│   ├── test_pcap_parser.py    # PCAP parsing & crypto extraction tests
│   └── test_feature_extraction.py # ESP feature extraction tests
├── scripts/                   # CLI and automation scripts
│   ├── run_demo.py            # Single-command Phase 1 demonstration
│   ├── run_phase2_demo.py     # Single-command Phase 2 demonstration
│   ├── run_phase3_demo.py     # Single-command Phase 3 security assessment demo
│   ├── run_phase4_demo.py     # Single-command Phase 4 AI traffic classification demo
│   ├── run_phase5_demo.py     # Single-command Phase 5 automated audit & reporting demo
│   ├── run_capture.py         # Parameterized capture runner CLI
│   └── verify_testbed.py      # Testbed health check & diagnostic tool
├── docker-compose.yml         # Container topology for Gateway A and Gateway B
├── requirements.txt           # Python dependencies
└── README.md                  # Documentation
```

---

## Phase 1 VPN Configuration Support

The testbed natively supports dynamic generation and live reloading of the following configurations:

| Parameter | Supported Options |
|---|---|
| **VPN Mode** | `tunnel` (site-to-site / gateway-to-gateway) |
| **IP Version** | `IPv4` |
| **Encryption Suites** | `AES-256-GCM` (`aes256gcm16`), `AES-128-CBC` (`aes128-sha256`) |
| **PFS (Perfect Forward Secrecy)** | Enabled (`true`), Disabled (`false`) |
| **Diffie-Hellman Groups** | Group 14 (`modp2048`), Group 19 (`ecp256`), Group 5 (`modp1536`), Group 20 (`ecp384`) |

---

## Prerequisites

- **Operating System**: Windows 10/11 (with WSL2), Linux, or macOS
- **Docker Desktop**: Version 20.10+ (with Compose v2+)
- **Python**: Version 3.10+

---

## Installation & Setup

1. **Clone or navigate to the repository:**
   ```powershell
   cd c:\Users\sktan\OneDrive\Desktop\IPsecIQ\SIH_prototype
   ```

2. **Install Python dependencies:**
   ```powershell
   python -m pip install -r requirements.txt
   ```

3. **Build and start the testbed containers:**
   ```powershell
   docker compose up -d --build
   ```

4. **Verify container and VPN daemon health:**
   ```powershell
   python scripts/verify_testbed.py
   ```

---

## Running the Phase 1 Demo

To run the complete end-to-end Phase 1 flow with a single command:

```powershell
python scripts/run_demo.py
```

### What this command does:
1. Verifies testbed containers are up (boots them if needed).
2. Generates and loads an `AES-256-GCM` strongSwan configuration with DH Group 19 (`ecp256`) and PFS enabled.
3. Starts packet capture (`tcpdump`) on transit interface `eth0`.
4. Establishes the IPsec tunnel between Gateway A (`172.28.0.10`) and Gateway B (`172.28.0.20`).
5. Generates 15 web-like HTTP requests through the encrypted tunnel.
6. Stops the packet capture, ensuring complete buffer flush.
7. Saves the resulting capture to:
   - `demo_data/demo_capture.pcap`
   - `demo_data/demo_capture.json`
   - `dataset/captures/demo_001.pcap`
   - `dataset/captures/demo_001.json`
8. Validates the PCAP with Scapy, verifying both raw IKEv2 negotiation and ESP encrypted packets.

---

## Running Custom Captures

To generate captures with different combinations of ciphers, DH groups, PFS, and traffic:

```powershell
# Capture 1: AES-128-CBC with DH Group 14, PFS disabled, ICMP traffic
python scripts/run_capture.py --id capture_cbc_dh14 --encryption AES-128-CBC --dh 14 --no-pfs --traffic icmp

# Capture 2: AES-256-GCM with DH Group 19, PFS enabled, Video streaming traffic
python scripts/run_capture.py --id capture_gcm_video --encryption AES-256-GCM --dh 19 --pfs --traffic video

# Capture 3: AES-256-GCM with VoIP traffic structure (RTP-like UDP stream)
python scripts/run_capture.py --id capture_voip_test --encryption AES-256-GCM --dh 19 --pfs --traffic voip
```

---

## Ground-Truth Metadata Format

Each capture produces a matching `.json` file containing the exact ground truth:

```json
{
  "capture_id": "demo_001",
  "vpn_mode": "tunnel",
  "ip_version": "ipv4",
  "encryption": "AES-256-GCM",
  "pfs": true,
  "dh_group": 19,
  "dh_group_name": "ecp256",
  "traffic_type": "web",
  "ike_proposal": "aes256gcm16-sha256-ecp256,aes256-sha256-ecp256",
  "esp_proposal": "aes256gcm16-ecp256!",
  "timestamp": "2026-09-16T13:32:29Z",
  "packet_count": 194,
  "ike_packets": 4,
  "esp_packets": 190,
  "file_path": "dataset/captures/demo_001.pcap",
  "file_size_bytes": 40748,
  "tunnel_established": true,
  "traffic_generation_result": {
    "traffic_type": "web",
    "target_ip": "10.10.2.1",
    "port": 8080,
    "requests_sent": 15,
    "successful_requests": 15,
    "bytes_transferred": 6316,
    "success": true
  }
}
```

---

## Offline Analysis (No Live VPN Required)

The platform can parse and inspect pre-existing PCAP files without running Docker:

```python
from packet_analysis.validator import PCAPValidator

result = PCAPValidator.analyze_pcap("demo_data/demo_capture.pcap", "demo_data/demo_capture.json")
print(f"Total Packets: {result.total_packets}")
print(f"IKE Packets:   {result.ike_packets}")
print(f"ESP Packets:   {result.esp_packets}")
print(f"Metadata Valid: {result.metadata_valid}")
```

---

## Phase 2: PCAP Analysis, Feature Extraction, Dataset & API

Phase 2 builds the core analysis engine and data ingestion layer.

### 1. Running the Phase 2 Demo
Demonstrates PCAP validation, IKE/ESP parsing, encrypted ESP feature extraction, dataset generation, and REST API invocation in a single run:

```powershell
python scripts/run_phase2_demo.py
```

### 2. Launching the Backend REST API
Launch the FastAPI server with Uvicorn:

```powershell
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger API documentation will be available at `http://localhost:8000/docs`.

### 3. API Endpoints
- **`POST /analyze-pcap`**: Accepts `.pcap` or `.pcapng` upload via multipart form-data. Validates magic bytes, extracts observable cryptographic parameters, computes statistical and temporal features over encrypted ESP traffic, and returns structured JSON.
- **`GET /health`**: Health check and roadmap phase info.
- **`GET /captures`**: Lists all captures indexed in `dataset/labels.csv`.
- **`GET /captures/{capture_id}`**: Retrieves parsed summary and feature vectors for a capture.
- **`POST /dataset/rebuild`**: Re-runs feature extraction and regenerates `dataset/labels.csv`.

### Example `POST /analyze-pcap` Response:
```json
{
  "capture_id": "demo_capture",
  "filename": "demo_capture.pcap",
  "file_size_bytes": 41024,
  "ipsec_detected": true,
  "ike_detected": true,
  "esp_detected": true,
  "ah_detected": false,
  "ike_version": "IKEv2",
  "encryption": "AES-256-GCM",
  "encryption_key_length": 256,
  "authentication": "12",
  "dh_group": 19,
  "dh_group_name": "ecp256",
  "pfs": "Unknown / Not Detected",
  "initiator_spi": "0x4036c450df28250c",
  "responder_spi": "0xb8206f62744fb232",
  "total_packets": 196,
  "ike_packets": 6,
  "esp_packets": 190,
  "features_extracted": true,
  "esp_features": {
    "total_packets": 190,
    "flow_duration_sec": 2.1309,
    "size_mean": 187.14,
    "size_std": 188.1,
    "iat_mean_ms": 11.28,
    "burst_count": 15,
    "packet_size_sequence": [130, 130, 122, 386, 122, 166, 122, 266]
  }
}
```

---

## Phase 3 — Security Assessment & Deterministic Rule Engine

Phase 3 converts parsed IPsec/ESP protocol metadata and packet flows into an auditable, deterministic, and explainable cybersecurity assessment compliant with **NIST SP 800-77 Rev. 1**, **RFC 7296 (IKEv2)**, **RFC 8221 (ESP Cryptographic Suites)**, and **RFC 4301**.

### Phase 3 Pipeline
```
PCAP
  │
  ▼
IPsec PCAP Parser
  │
  ▼
Extracted Configuration (OBSERVED / INFERRED / UNKNOWN)
  │
  ▼
Security Rules (NIST / RFC Baseline Criteria)
  │
  ▼
Findings (Evidence, Severity, Impact, Action)
  │
  ▼
Risk Score (0–100 Scale & Itemized Score Breakdown)
  │
  ▼
Prioritized Recommendations (CRITICAL -> HIGH -> MEDIUM -> LOW)
```

### Deterministic Security Rules Matrix
- **Encryption Suites**:
  - `AES-256-GCM`: Strong / Recommended (0 risk pts).
  - `AES-128-GCM`: Acceptable (0 risk pts).
  - `AES-128-CBC` / non-AEAD CBC: Warning (`CRYPTO_LEGACY_NON_AEAD`, Medium, +20 pts).
  - `DES` / `3DES` / `NULL` / `Blowfish` / `RC4`: Critical (`CRYPTO_WEAK_CIPHER`, Critical, +30 pts).
  - `Unknown`: Reported as unobserved without penalty (0 pts).
- **Diffie-Hellman Key Exchange**:
  - `Group 19 (ecp256)` & `Group 20 (ecp384)`: Strong / Recommended (0 pts).
  - `Group 14 (modp2048)`: Acceptable (0 pts).
  - `Group 5 (modp1536)`: Legacy Warning (`DH_GROUP_LEGACY`, Medium, +20 pts).
  - `Group 1 (modp768)` & `Group 2 (modp1024)`: Insecure Critical (`DH_GROUP_INSECURE`, Critical, +25 pts).
  - `Unknown`: Reported as unobserved without penalty (0 pts).
- **Perfect Forward Secrecy (PFS)**:
  - Enabled (`True`): Positive / Recommended (0 pts).
  - Disabled (`False`): Warning (`PFS_DISABLED`, Medium, +20 pts).
  - `Unknown`: Reported as unobserved without penalty (0 pts).
- **IKE Protocol Version**:
  - `IKEv2`: Recommended (0 pts).
  - `IKEv1`: Deprecated Warning (`IKE_VERSION_DEPRECATED`, High, +20 pts).
  - `Unknown`: Reported as unobserved without penalty (0 pts).
- **VPN Mode**:
  - `Tunnel` / `Transport`: Reported as detected (`OBSERVED` / `INFERRED`).
- **ESP Traffic & Anomalies**:
  - Evaluates presence, packet counts, SPIs, and sequence number progression.
  - Non-monotonic sequences, replay, or zero SPI (0x00000000) trigger `REPLAY_PROTECTION_ANOMALY` (+15 pts).
  - Payloads remain 100% encrypted and are never decrypted.

### Auditable Finding Schema
Every finding conforms strictly to:
```json
{
  "id": "VPN-001",
  "title": "Perfect Forward Secrecy (PFS) Disabled",
  "severity": "MEDIUM",
  "category": "Key Management",
  "description": "Perfect Forward Secrecy is disabled for Child SAs.",
  "evidence": {
    "pfs": false
  },
  "impact": "Compromise of long-term private key enables retroactive decryption of recorded traffic.",
  "recommendation": "Enable Perfect Forward Secrecy (PFS) in the ESP Child SA configuration.",
  "confidence": 1.0,
  "source": "Child SA Proposal / Testbed Configuration"
}
```

### Transparent 0–100 Risk Score
- **0–24** : **LOW / SECURE**
- **25–49** : **LOW-MEDIUM**
- **50–74** : **MEDIUM**
- **75–89** : **HIGH**
- **90–100** : **CRITICAL**

### REST API Integration
`POST /security-assessment` accepts either multipart PCAP file uploads or JSON configuration payloads and returns:
- `configuration`: Extracted parameters with explicit `OBSERVED`, `INFERRED`, or `UNKNOWN` provenance.
- `findings`: Concrete findings with auditable evidence, impact, and recommendations.
- `risk_score`: Additive 0–100 score.
- `severity`: Qualitative rating band.
- `score_breakdown`: Itemized point contributions per triggered rule.
- `recommendations`: Prioritized remediation tasks (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `limitations`: Transparent audit disclaimers.

### Phase 3 Demo
Run the single-command Phase 3 demonstration script:
```powershell
python scripts/run_phase3_demo.py
```

---

## Phase 4 — AI/ML Traffic Classification

Phase 4 classifies application traffic traversing encrypted IPsec ESP tunnels **without decrypting the payload**.

### 1. Classification Pipeline
```
PCAP Upload / Live Capture
         │
         ▼
ESP Outer-Header Feature Extraction (27 Features)
         │
         ▼
Feature Vector Validation (Schema & Physical Constraints)
         │
         ▼
Standard Scaler Normalization
         │
         ▼
Random Forest Classifier (100 Trees, Depth 10)
         │
         ▼
Confidence Thresholding (Cutoff: 0.50)
  ├── Confidence >= 0.50 ──> Predicted Class
  └── Confidence <  0.50 ──> "Unknown" (Prevents Hallucinations)
```

### 2. Target Classes
- **Web**: HTTP/HTTPS browsing, asymmetric request/response bursts.
- **Video**: High-volume, continuous streaming, large MTU packet sizes.
- **VoIP**: Isochronous ~20ms packet pacing, small UDP frame sizes (<350 bytes).
- **ICMP**: Ping sweeps, small symmetric request/reply payloads.
- **Bulk/Data Transfer**: High sustained unidirectional throughput, file downloads.
- **Unknown**: Ambiguous dynamics, unobserved ESP traffic, or confidence below 0.50 threshold.

### 3. Observable ESP Features (27 Dimensions)
The classifier uses strictly Layer 3/Layer 4 metadata and flow dynamics:
- **Packet & Byte Volumes**: `total_packets`, `total_bytes`, `forward_packets`, `backward_packets`
- **Symmetry & Rates**: `packet_ratio_fwd_bwd`, `byte_ratio_fwd_bwd`, `flow_duration_sec`, `packets_per_sec`, `bytes_per_sec`
- **Packet Size Statistics**: `size_min`, `size_max`, `size_mean`, `size_median`, `size_std`, `size_p25`, `size_p75`, `size_p90`, `size_skewness`
- **Inter-Arrival Time (IAT)**: `iat_min_ms`, `iat_max_ms`, `iat_mean_ms`, `iat_median_ms`, `iat_std_ms`
- **Burst Dynamics**: `burst_count`, `mean_burst_size_pkts`, `mean_burst_duration_ms`, `mean_burst_bytes`

### 4. Training & Real Evaluation Metrics
Run training reproducibly:
```powershell
python models/train.py
```

Evaluation on 119 unseen test samples (stratified split):
- **Accuracy**: **99.16%**
- **Weighted Precision**: **99.19%**
- **Weighted Recall**: **99.16%**
- **Weighted F1-Score**: **99.16%**
- **Macro F1-Score**: **99.41%**

| Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| Bulk/Data Transfer | 100.00% | 100.00% | 100.00% | 24 |
| ICMP | 100.00% | 100.00% | 100.00% | 6 |
| Video | 96.97% | 100.00% | 98.46% | 32 |
| VoIP | 100.00% | 100.00% | 100.00% | 21 |
| Web | 100.00% | 97.22% | 98.59% | 36 |

### 5. Critical Cryptographic Separation Rule
> [!IMPORTANT]
> The ML model **NEVER** determines cryptographic attributes (`encryption`, `dh_group`, `pfs`, `ike_version`, or `authentication`).
> All cryptographic parameters are deterministically parsed and assessed by the Security Engine. ML is strictly restricted to traffic classification.

### 6. Phase 4 Demo Runner
Run the single-command Phase 4 demonstration:
```powershell
python scripts/run_phase4_demo.py
```
Output:
```
========================================
SENTRAIPS PHASE 4 AI ANALYSIS
========================================
Traffic Type : Web
Confidence   : 100.0%
Model        : RandomForest

Features Used:
* Packet count
* Flow duration
* Packet size statistics
* IAT statistics
* Burst count
========================================
```

### 7. REST API Integration
- `POST /predict-traffic`: Dedicated traffic prediction accepting PCAP file upload or JSON feature vector.
- `POST /analyze-pcap`: Unified response includes deterministic security assessment and `traffic_analysis`:
```json
{
  "traffic_analysis": {
    "classification": "Web",
    "confidence": 1.0,
    "model": "RandomForest"
  }
}
```

---

## Automated Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

---

## Phase 5 — Knowledge Base, Compliance Evaluation & Automated Reporting

Phase 5 converts raw technical parsing, deterministic security findings, and AI traffic predictions into publication-grade security assessment and compliance audit reports (both machine-readable JSON and fully self-contained offline HTML).

### Pipeline Flow:
```
PCAP Capture
  ↓
Protocol Parser & ESP Feature Extractor
  ↓
Deterministic Security Engine (0–100 Risk Score)
  ↓
Phase 4 AI Traffic Classifier (Random Forest)
  ↓
Compliance Engine (Evaluated against NIST SP 800-77 Rev. 1 & RFC 8221/8247 Knowledge Base)
  ↓
Prioritized Recommendations Engine (CRITICAL → LOW)
  ↓
Unified Report Generator (Pydantic Schema Validation)
  ↓
JSON Audit Record & Standalone Offline HTML Report
```

### 1. Verified Standards Knowledge Base
Located in `knowledge_base/knowledge_base.json`, indexing 14 structured, machine-readable baseline standards with authentic, verified citations:
- **NIST SP 800-77 Rev. 1**: *Guide to IPsec VPNs* (Section 4.2 Ciphers, Section 4.3 DH Groups, Section 4.4 IKE & PFS).
- **NIST SP 800-131A Rev. 2**: *Transitioning the Use of Cryptographic Algorithms and Key Lengths* (Deprecates MD5/SHA-1).
- **RFC 7296**: *Internet Key Exchange Protocol Version 2 (IKEv2)*.
- **RFC 8221**: *Cryptographic Algorithm Implementation Requirements and Usage Guidance for Encapsulating Security Payload (ESP) and Authentication Header (AH)*.
- **RFC 8247**: *Cryptographic Algorithm Implementation Requirements and Usage Guidance for Internet Key Exchange Protocol Version 2 (IKEv2)*.
- **RFC 4301 & RFC 4303**: *Security Architecture for IPsec & IP Encapsulating Security Payload*.

### 2. Deterministic Compliance Engine
Evaluates observed VPN configurations without LLM hallucinations into auditable control statuses:
- **`PASS`**: Parameter satisfies modern MUST/RECOMMENDED standards (e.g. AES-256-GCM, DH Group 19/20, PFS active, IKEv2, Tunnel mode).
- **`WARNING`**: Parameter uses legacy or suboptimal mechanisms (e.g. AES-128-CBC, DH Group 5, PFS disabled, Transport mode).
- **`FAIL`**: Parameter uses broken, disallowed, or non-compliant mechanisms (e.g. 3DES, DES, NULL cipher, DH Group 1/2, MD5, IKEv1, Zero SPI).
- **`UNKNOWN`**: Parameter unobserved in unencrypted negotiation (does not falsely penalize configurations).

Overall compliance rating is categorized as:
- `COMPLIANT`
- `COMPLIANT_WITH_WARNINGS`
- `NON_COMPLIANT`
- `INSUFFICIENT_DATA`

### 3. Unified Schemas & Generators (`reporting/`)
- `report_schema.py`: Strongly typed Pydantic models: `ReportExecutiveSummary`, `ReportVPNConfiguration`, `ReportTrafficAnalysis`, `ReportFinding`, `ReportComplianceItem`, `ReportRecommendation`, and `SecurityAssessmentReportUnified`.
- `json_report.py`: `JSONReportGenerator` producing auditable, structured JSON files.
- `html_report.py`: `HTMLReportGenerator` rendering publication-grade HTML with embedded, responsive styling, risk chips, and probability distribution bars. **Works 100% offline** with zero external network or CDN dependencies (no Google Fonts, no external JS/CSS).
- `report_generator.py`: `ReportGenerator` orchestrating the end-to-end evaluation and artifact output.

### 4. REST API Reporting Endpoints
- `POST /reports/generate`: Accepts PCAP file upload (multipart/form-data) or JSON capture reference, executes complete analysis pipeline, saves artifacts, and returns unified report JSON.
- `GET /reports/{report_id}`: Retrieves machine-readable JSON report.
- `GET /reports/{report_id}/html`: Serves standalone publication HTML audit report directly to browser.
- `GET /reports`: Lists all generated reports on disk with summary risk scores and direct artifact links.

### 5. Running the Phase 5 Demonstration
Execute the automated audit and reporting demo:
```powershell
python scripts/run_phase5_demo.py
```
Output:
```
=================================================================
  SentraIPS Phase 5 — Automated Security & Compliance Audit
  Smart India Hackathon 2026 Prototype
=================================================================
[Step 1] Loading capture: demo_capture.pcap
[Step 2] Executing deterministic protocol parsing & ESP feature extraction...
[Step 3] Running deterministic Security Engine & risk scoring...
[Step 4] Running Phase 4 AI traffic classification...
[Step 5] Evaluating compliance against NIST SP 800-77 & RFC 8221/8247 Knowledge Base...
[Step 6] Compiling prioritized recommendations & audit disclaimers...
[Step 7] Serializing JSON and rendering standalone HTML reports...

========================================
SENTRAIPS PHASE 5 EXECUTIVE SUMMARY
========================================
Report ID           : audit_demo_capture_1791273149
Timestamp           : 2026-10-06T07:52:29.556187+00:00
Overall Risk Score  : 15 / 100 (LOW)
Compliance Rating   : COMPLIANT
Traffic Class       : Web (100.0% confidence)

Detected Cryptographic Baseline:
  * IKE Protocol    : IKEv2
  * Encryption Suite: AES-256-GCM
  * DH Key Exchange : ecp256 (19)
  * Forward Secrecy : PFS=Unknown / Not Detected
========================================
Generated Report Artifacts:
  * JSON Report : reports/audit_demo_capture_1791273149.json
  * HTML Report : reports/audit_demo_capture_1791273149.html
=================================================================
```

---

## Automated Tests

Run the complete test suite:

```powershell
python -m pytest -v
```

### Test Coverage (Comprehensive Suite Across Phases 1, 2, 3, 4 & 5 — 104+ Tests):
1. **Phase 5 Knowledge Base & Automated Reporting (`tests/test_phase5_reporting.py` — 12 Tests)**:
   - `test_knowledge_base_loading`: Validates knowledge base rules and schema integrity.
   - `test_knowledge_base_standards_references`: Asserts genuine NIST, RFC, and IANA references.
   - `test_knowledge_base_lookup`: Verifies rule retrieval by ID and Category.
   - `test_compliance_evaluation_strong_config`: Validates PASS evaluation for modern AEAD/DH19 VPNs.
   - `test_compliance_evaluation_weak_config`: Validates FAIL/WARNING on deprecated 3DES/DH5 configurations.
   - `test_compliance_evaluation_unknown_parameters`: Asserts graceful UNKNOWN evaluation without false positives.
   - `test_json_report_generation`: Validates JSON report serialization and schema conformance.
   - `test_html_report_generation_offline`: Validates 100% offline standalone HTML rendering with zero external CDN dependencies.
   - `test_e2e_report_generation`: Verifies end-to-end report generation pipeline from raw PCAP.
   - `test_api_generate_report`: Tests `POST /reports/generate` with PCAP upload.
   - `test_api_get_nonexistent_report`: Tests HTTP 404 on invalid report ID.
   - `test_api_list_reports`: Tests `GET /reports` registry listing.
2. **Phase 4 AI/ML Traffic Classification (`tests/test_phase4_ml.py` — 17 Tests)**:
   - `test_valid_feature_vector`: Validates 27-feature vector parsing.
   - `test_invalid_feature_vector_missing_feature`: Catches missing required features.
   - `test_invalid_feature_vector_nan_inf`: Rejects NaN / Inf numerical corruptions.
   - `test_invalid_feature_vector_negative_counts`: Rejects non-physical negative counts/durations.
   - `test_invalid_feature_vector_empty_and_types`: Rejects empty or invalid input structures.
   - `test_model_loading`: Verifies joblib loading of trained Random Forest bundle.
   - `test_model_missing_graceful_fallback`: Tests graceful fallback when weights are missing.
   - `test_prediction_from_demo_pcap`: Verifies end-to-end prediction from PCAP file.
   - `test_prediction_from_dict`: Verifies prediction over feature dictionaries.
   - `test_low_confidence_threshold_returns_unknown`: Cutoff threshold (< 0.50) safely returns "Unknown".
   - `test_unknown_classification_for_empty_capture`: Zero-ESP captures return "Unknown" (0.0 conf).
   - `test_cryptographic_separation_rule`: Asserts zero cryptographic keys leaked in ML output.
   - `test_api_predict_traffic_pcap_upload`: Verifies `POST /predict-traffic` with PCAP.
   - `test_api_predict_traffic_json_body`: Verifies `POST /predict-traffic` with JSON.
   - `test_api_predict_traffic_invalid_extension`: Verifies HTTP 400 on non-pcap files.
   - `test_api_analyze_pcap_includes_traffic_analysis`: Verifies unified `POST /analyze-pcap` output.
   - `test_insufficient_dataset_handling`: Asserts clear `ValueError` on empty or insufficient dataset.
3. **Phase 3 Deterministic Compliance (`tests/test_phase3_security.py` & `tests/test_security_engine.py`)**:
   - 22+ tests verifying ciphers, DH groups, PFS, IKEv2/v1, unknown parameters, and scoring bands.
4. **Phase 2 PCAP & Features (`tests/test_pcap_parser.py`, `tests/test_feature_extraction.py`, `tests/test_dataset.py`)**:
   - 20+ tests verifying Scapy dissection, ESP feature extraction, and `DatasetBuilder`.
5. **API & Dashboard Integration (`tests/test_api.py`, `tests/test_dashboard.py`, `tests/test_ensemble.py`)**:
   - End-to-end endpoints, Streamlit AppTest simulation, and dual-model uncertainty arbitration.

---

## Known Limitations & Security Boundaries

1. **Unencrypted Payloads Only for IKE**: IKE SA proposals and DH key exchange are extracted from initial plaintext negotiation (`IKE_SA_INIT`). Parameters exchanged exclusively within encrypted `IKE_AUTH` or `CREATE_CHILD_SA` without pre-shared keys remain unobservable by design and are safely labeled `"Unknown / Not Detected"`.
2. **Encrypted ESP Payload Integrity**: ESP traffic is analyzed strictly via outer metadata (packet sizes, inter-arrival times, sequence progression, burst characteristics) without payload decryption. SentraIPS never claims or attempts to decrypt ESP payloads.
3. **Observation Provenance**: Security assessments strictly differentiate between `OBSERVED`, `INFERRED`, and `UNKNOWN` parameters. Unobserved fields are never penalized as vulnerable.
4. **Probabilistic Traffic Classification**: ML traffic classifications are statistical inferences. While accuracy is 99.16% on known test sessions, confidence below 0.50 triggers `"Unknown"` rather than forcing an unverified label.
5. **Cryptographic Parameter Boundary**: Machine learning models never classify cryptographic attributes. Ciphers, key lengths, DH groups, and PFS are strictly audited by deterministic rules.
6. **Libreswan Cross-Testing**: strongSwan is the primary VPN engine for the current prototype; Libreswan cross-implementation testing is planned as a stretch objective.
