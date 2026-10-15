# SentraIPS — Automated Security Reporting Engine (Phase 5)

The Reporting Engine converts raw protocol analysis, deterministic vulnerability findings, and machine learning traffic classifications into comprehensive, publication-grade security audit reports.

---

## 1. Reporting Pipeline

```
  PCAP Upload / Capture Stream
              │
              ▼
    IPsec Protocol Parser  ──> Extracted Configuration
              │
              ▼
    ESP Feature Extractor  ──> 27 Statistical Outer-Flow Features
              │
              ▼
   Security Engine Rules   ──> Deterministic Threat Findings & Risk Score
              │
              ▼
  AI Traffic Classification──> Encrypted Profile (Web, VoIP, Video, etc.)
              │
              ▼
  Knowledge Base Baseline  ──> NIST SP 800-77 & RFC 8221/8247 Controls
              │                 (Evaluated as PASS, WARNING, FAIL, UNKNOWN)
              ▼
      Report Generator
       ├──> Structured JSON Audit Record (Machine-Readable)
       └──> Standalone HTML Audit Report (Self-Contained Executive Dashboard)
```

---

## 2. Report Sections

Every report contains:

1. **Executive Summary**:
   - Analysis ID & Timestamp
   - Transparent 0–100 Risk Score & Severity Band (LOW, LOW-MEDIUM, MEDIUM, HIGH, CRITICAL)
   - Cryptographic parameter summary (IKE version, Symmetric cipher, DH group, PFS)
   - AI traffic profile & inference confidence
   - Overall compliance rating
2. **Observed VPN Protocol Configuration**:
   - Tabular parameter breakdown with explicit `OBSERVED`, `INFERRED`, or `UNKNOWN` provenance
   - Packet counters (IKE, ESP, total)
   - SPI identifiers and handshake characteristics
3. **Encrypted ESP Traffic Metadata Classification**:
   - Profile class (Web, Video, VoIP, ICMP, Bulk/Data Transfer, Unknown)
   - ML model confidence & probability distribution bars
   - Observable metrics: flow duration, packet sizes, inter-arrival time (IAT), burst count
4. **Deterministic Security Findings**:
   - Unique Finding ID (e.g., `VPN-001`, `VPN-002`)
   - Severity badge & category
   - Evidence snippet directly observed from capture
   - Technical and business threat impact
   - Actionable remediation advice
   - Authoritative standards citations (NIST SP 800-77, RFC 7296, RFC 8221, RFC 8247)
5. **Compliance & Best Practice Matrix**:
   - Itemized controls mapped against NIST SP 800-77 Rev. 1 & RFC 8221/8247
   - Status indicators: `PASS`, `WARNING`, `FAIL`, `UNKNOWN`
6. **Prioritized Remediation Roadmap**:
   - Ranked remedial actions (Critical -> High -> Medium -> Low)
7. **Audit Limitations & Disclaimers**:
   - Reassurance of zero payload decryption
   - Boundary definition between observed facts and statistical inferences

---

## 3. Formats & Generators

### JSON Report (`reporting/json_report.py`)
Produces machine-readable JSON:
```json
{
  "report_id": "audit_demo_capture_1728212345",
  "timestamp": "2026-10-06T12:00:00Z",
  "summary": { ... },
  "vpn_configuration": { ... },
  "traffic_analysis": { ... },
  "security_assessment": { ... },
  "findings": [ ... ],
  "compliance": [ ... ],
  "recommendations": [ ... ],
  "limitations": [ ... ]
}
```

### Standalone HTML Report (`reporting/html_report.py`)
- Self-contained single-file HTML with embedded responsive CSS.
- Renders completely offline without external web servers, CDNs, or internet access.
- Color-coded severity chips, visual probability bars, and responsive tables.

---

## 4. REST API Integration

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/reports/generate` | Generates unified JSON & HTML reports from PCAP upload or analysis body |
| `GET` | `/reports/{report_id}` | Retrieves generated machine-readable JSON report |
| `GET` | `/reports/{report_id}/html` | Serves standalone executive HTML report directly to browser |

---

## 5. CLI & Demo Usage

Run the single-command Phase 5 demonstration:
```bash
python scripts/run_phase5_demo.py
```
Reports are automatically saved to `reports/`.
