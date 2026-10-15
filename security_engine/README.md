# SentraIPS Security Assessment & Rule Engine (Phase 3)

The **SentraIPS Security Engine** converts raw packet captures and parsed IPsec/ESP protocol metadata into an auditable, deterministic, and explainable cybersecurity posture evaluation.

It implements cryptographic and architectural compliance auditing against **NIST SP 800-77 Rev. 1**, **RFC 7296 (IKEv2)**, **RFC 8221 (ESP Cryptographic Suites)**, and **RFC 4301/4303**.

---

## 1. Assessment Pipeline

```
PCAP / Network Capture
   │
   ▼
IPsec PCAP Parser (IKE / ESP Dissection)
   │
   ▼
Extracted Configuration (OBSERVED / INFERRED / UNKNOWN)
   │
   ▼
Deterministic Security Rules (NIST / RFC Baseline Criteria)
   │
   ▼
Auditable Findings (Evidence, Impact, Recommendations)
   │
   ▼
Transparent Risk Score (0–100 Scale & Itemized Score Breakdown)
   │
   ▼
Prioritized Recommendations (CRITICAL -> HIGH -> MEDIUM -> LOW)
```

---

## 2. Parameter Provenance & Reliability

To prevent hallucinations and false security assurances, every configuration parameter is strictly classified under an auditable provenance status:

| Status | Meaning | Treatment |
| :--- | :--- | :--- |
| **`OBSERVED`** | Directly parsed from packet headers (e.g. `IKE_SA_INIT` transforms, ESP headers) or verified ground truth. | Full deterministic rule evaluation (Confidence: 1.0). |
| **`INFERRED`** | Deduced from observable traffic dynamics or protocol behavior (e.g. outer IP encapsulation mode). | Evaluated with conservative weight (Confidence: 0.8–0.9). Explicitly labeled as inferred. |
| **`UNKNOWN`** | Parameter was not captured in the PCAP (e.g. handshake occurred before capture start, or negotiated inside encrypted payloads). | **Never assumed weak or vulnerable.** Risk contribution is 0 pts. Generates an informational visibility recommendation. |

---

## 3. Security Rules Catalog

### 3.1 Encryption Cipher Suites
- **AES-256-GCM**: Modern AEAD cipher providing combined confidentiality and integrity. Evaluated as **Strong / Recommended** (0 risk points).
- **AES-128-GCM**: Modern AEAD cipher. Evaluated as **Acceptable** (0 risk points).
- **AES-128-CBC / AES-256-CBC**: Non-AEAD cipher mode. Generates a **Warning** (`CRYPTO_LEGACY_NON_AEAD`, Severity: `MEDIUM`, +20 risk points) due to susceptibility to padding oracle attacks when integrity verification is flawed.
- **DES / 3DES / NULL / Blowfish / RC4**: Broken or obsolete ciphers. Generates a **Critical** finding (`CRYPTO_WEAK_CIPHER`, Severity: `CRITICAL`, +30 risk points) due to small 64-bit block sizes (Sweet32) or lack of cryptographic strength.
- **Unknown / Not Detected**: Reported as unobserved without vulnerability penalty (0 risk points).

### 3.2 Key Exchange & Diffie-Hellman Groups
- **Group 19 (ecp256) & Group 20 (ecp384)**: Elliptic curve Diffie-Hellman. Evaluated as **Strong / Recommended** (0 risk points).
- **Group 14 (modp2048)**: 2048-bit MODP. Evaluated as **Acceptable** (0 risk points).
- **Group 5 (modp1536)**: 1536-bit MODP. Deprecated by NIST SP 800-77. Generates a **Warning** (`DH_GROUP_LEGACY`, Severity: `MEDIUM`, +20 risk points).
- **Group 1 (modp768) & Group 2 (modp1024)**: Sub-2048 bit MODP breakable by modern compute. Generates a **Critical** finding (`DH_GROUP_INSECURE`, Severity: `CRITICAL`, +25 risk points).
- **Unknown / Not Detected**: Reported as unobserved without vulnerability penalty (0 risk points).

### 3.3 Perfect Forward Secrecy (PFS)
- **Enabled (`True`)**: Child SA rekeying performs independent Diffie-Hellman exchange. Evaluated as **Positive / Recommended** (0 risk points).
- **Disabled (`False`)**: Long-term private key compromise enables retroactive session decryption. Generates a **Warning** (`PFS_DISABLED`, Severity: `MEDIUM`, +20 risk points).
- **Unknown / Not Detected**: Reported as unobserved without vulnerability penalty (0 risk points).

### 3.4 IKE Protocol Version
- **IKEv2**: RFC 7296 standard. Evaluated as **Recommended** (0 risk points).
- **IKEv1**: Legacy protocol lacking native cookie-based DoS defense and modern negotiation modes. Generates a **Warning** (`IKE_VERSION_DEPRECATED`, Severity: `HIGH`, +20 risk points).
- **Unknown / Not Detected**: Reported as unobserved without vulnerability penalty (0 risk points).

### 3.5 VPN Mode
- **Tunnel Mode**: Reported as detected (`OBSERVED` or `INFERRED`).
- **Transport Mode**: Reported as detected (`OBSERVED` or `INFERRED`).
- **Unknown / Not Detected**: Reported as unobserved (0 risk points).

### 3.6 Encapsulating Security Payload (ESP)
- Evaluates ESP presence, total packet count, observed SPIs, and sequence number progression.
- Monotonic sequence numbers confirm healthy tunnel operation.
- Non-monotonic progressions, repeated sequence numbers, or invalid reserved SPIs (0x00000000) trigger `REPLAY_PROTECTION_ANOMALY` (+15 risk points).
- **Confidentiality Guarantee**: SentraIPS strictly analyzes outer IP/ESP headers and flow metadata; ESP payloads remain encrypted and are never decrypted.

---

## 4. Standard Finding Format

Every security finding contains the following mandatory schema fields:

```json
{
  "id": "VPN-001",
  "title": "Perfect Forward Secrecy (PFS) Disabled",
  "severity": "MEDIUM",
  "category": "Key Management",
  "description": "Perfect Forward Secrecy is disabled for Child SAs. If the long-term private key or IKE SA master key is ever compromised, all previously recorded session traffic can be retroactively decrypted.",
  "evidence": {
    "pfs": false
  },
  "impact": "Compromise of the long-term private key allows retroactive decryption of all recorded past sessions.",
  "recommendation": "Enable Perfect Forward Secrecy (PFS) in the ESP Child SA configuration (e.g., specify esp=aes256gcm16-ecp256!).",
  "confidence": 1.0,
  "source": "Child SA Proposal / Testbed Configuration"
}
```

---

## 5. Transparent Risk Score (0–100 Scale)

Risk scoring is additive, bounded, and explainable:

$$\text{Raw Score} = \sum_{f \in \text{Findings}} \text{risk\_contribution}(f)$$
$$\text{Risk Score} = \min(100, \max(0, \text{Raw Score}))$$

### Severity Rating Bands
- **0–24** : **LOW / SECURE**
- **25–49** : **LOW-MEDIUM**
- **50–74** : **MEDIUM**
- **75–89** : **HIGH**
- **90–100** : **CRITICAL**

### Response Payload Structure
```json
{
  "risk_score": 75,
  "severity": "HIGH",
  "score_breakdown": [
    {
      "finding_id": "VPN-001",
      "rule_id": "CRYPTO_LEGACY_NON_AEAD",
      "title": "Legacy Non-AEAD Cipher Mode (CBC)",
      "severity": "MEDIUM",
      "points": 20,
      "category": "Cryptography",
      "reason": "The VPN uses CBC mode rather than modern AEAD."
    }
  ],
  "findings": [...]
}
```

---

## 6. Prioritized Remediation Recommendations

Recommendations are categorized into four strict priority tiers:

1. **`CRITICAL`**: Immediate security remediation (e.g. migrate off 3DES, DES, NULL ciphers, or 1024-bit DH groups).
2. **`HIGH`**: Important hardening actions (e.g. upgrade from IKEv1 to IKEv2, replace MD5/SHA1 integrity hashes).
3. **`MEDIUM`**: Best-practice modernization (e.g. migrate from CBC to AEAD, upgrade DH Group 5 to Group 19, enable PFS).
4. **`LOW`**: Metadata exposure mitigations (e.g. evaluate IPsec TFC padding RFC 4303) and visibility guidance for unobserved parameters.

---

## 7. Package Modules

- **`schemas.py`**: Pydantic data models for observation statuses, configuration, findings, score breakdowns, and assessment reports.
- **`rules.py`**: `SecurityRuleEvaluator` implementing cryptographic, protocol, and metadata rules.
- **`risk_scoring.py`**: `RiskScoringEngine` calculating transparent 0–100 scores and breakdowns.
- **`recommendations.py`**: `RecommendationEngine` generating prioritized remediation guidance.
- **`security_engine.py`**: Central `SecurityEngine` coordinating the end-to-end evaluation pipeline.
- **`findings.py` & `scoring.py`**: Backward compatibility bridges for Phase 4/5/6 components.
- **`config.yaml`**: Rule definitions, weights, and score thresholds.

---

## 8. CLI & API Usage

### Running Phase 3 Demo CLI
```powershell
python scripts/run_phase3_demo.py
```

### Direct API Evaluation
```bash
# Upload a PCAP file
curl -X POST "http://localhost:8000/security-assessment" \
     -F "file=@demo_data/demo_capture.pcap"

# Evaluate a JSON configuration payload
curl -X POST "http://localhost:8000/security-assessment" \
     -H "Content-Type: application/json" \
     -d '{"encryption": "AES-128-CBC", "dh_group": 5, "pfs": false, "ike_version": "IKEv2"}'
```
