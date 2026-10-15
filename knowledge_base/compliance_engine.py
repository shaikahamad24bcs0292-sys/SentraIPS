"""
Compliance & Best Practice Evaluation Engine for SentraIPS (Phase 5).
Evaluates observed IPsec VPN configurations against authoritative standards:
- NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs)
- RFC 7296 (IKEv2)
- RFC 8221 (ESP Cryptographic Algorithm Requirements)
- RFC 8247 (IKEv2 Cryptographic Algorithm Requirements)
- RFC 4301 & RFC 4303 (IPsec & ESP Architecture)

Returns transparent, auditable control evaluations: PASS, WARNING, FAIL, or UNKNOWN.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import BaseModel, Field


class StandardCitation(BaseModel):
    source: str
    section: str
    title: str
    guidance: str


class KnowledgeBaseRule(BaseModel):
    id: str
    category: str
    condition: str
    severity: str
    title: str
    description: str
    recommendation: str
    references: List[StandardCitation] = Field(default_factory=list)


class ComplianceCheckItem(BaseModel):
    control_id: str
    category: str
    title: str
    status: str  # PASS, WARNING, FAIL, UNKNOWN
    observed_value: Any
    expected_standard: str
    framework: str = "NIST SP 800-77 Rev. 1 & RFC 8221/8247"
    references: List[Dict[str, Any]] = Field(default_factory=list)
    rationale: str
    parameter: Optional[str] = None


class ComplianceEvaluationResult(BaseModel):
    framework_name: str = "NIST SP 800-77 Rev. 1 & RFC 8221/8247 Security Baseline"
    total_checks: int
    passed: int
    warnings: int
    failed: int
    unknown: int
    overall_status: str  # COMPLIANT, COMPLIANT_WITH_WARNINGS, NON_COMPLIANT, INSUFFICIENT_DATA
    checks: List[ComplianceCheckItem]

    @property
    def summary(self) -> Dict[str, int]:
        return {
            "passed": self.passed,
            "warnings": self.warnings,
            "failed": self.failed,
            "unknown": self.unknown,
            "total": self.total_checks,
        }

    @property
    def items(self) -> List[ComplianceCheckItem]:
        return self.checks



class ComplianceEngine:
    """
    Evaluates analyzed VPN parameters against the structured standards knowledge base.
    """

    def __init__(self, kb_path: Optional[Union[str, Path]] = None):
        default_path = Path(__file__).resolve().parent / "knowledge_base.json"
        self.kb_path = Path(kb_path) if kb_path else default_path
        self.rules: Dict[str, KnowledgeBaseRule] = {}
        self.rules_by_condition: Dict[str, KnowledgeBaseRule] = {}
        self._load_knowledge_base()

    def _load_knowledge_base(self) -> None:
        """Loads and indexes structured knowledge base JSON."""
        if not self.kb_path.exists():
            return

        try:
            with open(self.kb_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            raw_rules = data.get("rules", [])
            for r_data in raw_rules:
                rule = KnowledgeBaseRule(**r_data)
                self.rules[rule.id] = rule
                self.rules_by_condition[rule.condition] = rule
        except Exception as e:
            print(f"[ComplianceEngine] Warning: Failed to load knowledge base from {self.kb_path}: {e}")

    def get_rule_by_id(self, rule_id: str) -> Optional[KnowledgeBaseRule]:
        """Looks up a knowledge base rule by ID."""
        return self.rules.get(rule_id)

    def get_rule_by_condition(self, condition: str) -> Optional[KnowledgeBaseRule]:
        """Looks up a knowledge base rule by trigger condition."""
        return self.rules_by_condition.get(condition)

    def get_all_rules(self) -> List[KnowledgeBaseRule]:
        """Returns all loaded knowledge base rules."""
        return list(self.rules.values())

    def get_rules_by_category(self, category: str) -> List[KnowledgeBaseRule]:
        """Returns knowledge base rules filtered by category (case-insensitive substring match)."""
        cat_lower = category.lower()
        return [r for r in self.rules.values() if cat_lower in r.category.lower()]

    def evaluate_configuration(
        self,
        config: Dict[str, Any],
        findings: Optional[List[Any]] = None,
    ) -> ComplianceEvaluationResult:
        """
        Evaluates an observed VPN configuration against standard controls.

        Controls Evaluated:
        1. Encryption Suite (AEAD requirement, legacy CBC deprecation, weak cipher elimination)
        2. Diffie-Hellman Group (Key strength >= 2048-bit / ECP-256)
        3. Perfect Forward Secrecy (PFS enabled for Child SAs)
        4. IKE Version (IKEv2 requirement, IKEv1 deprecation)
        5. Authentication / Integrity Suite (Collision resistance)
        6. VPN Mode (Gateway encapsulation architecture)
        7. ESP Replay Protection & SPI Hygiene (Non-zero SPI, monotonic sequence)
        """
        checks: List[ComplianceCheckItem] = []

        # -------------------------------------------------------------
        # Control 1: Encryption Algorithm
        # -------------------------------------------------------------
        enc = str(config.get("encryption", "Unknown")).strip()
        enc_upper = enc.upper()
        if any(weak in enc_upper for weak in ("DES", "3DES", "NULL", "BLOWFISH", "RC4")):
            r = self.get_rule_by_condition("insecure_cipher")
            checks.append(ComplianceCheckItem(
                control_id="COMP-ENC-01",
                category="Cryptography",
                title="Symmetric Encryption Algorithm",
                status="FAIL",
                observed_value=enc,
                expected_standard="AES-256-GCM or AES-128-GCM (AEAD)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="The detected cipher is obsolete, weak, or unencrypted, violating NIST SP 800-77 Section 4.2.",
                parameter="encryption",
            ))
        elif "CBC" in enc_upper:
            r = self.get_rule_by_condition("legacy_non_aead_cipher")
            checks.append(ComplianceCheckItem(
                control_id="COMP-ENC-01",
                category="Cryptography",
                title="Symmetric Encryption Algorithm",
                status="WARNING",
                observed_value=enc,
                expected_standard="AES-256-GCM or AES-128-GCM (AEAD)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Legacy CBC mode is susceptible to padding oracle attacks if integrity verification fails. AEAD mode is strongly recommended (NIST SP 800-77).",
                parameter="encryption",
            ))
        elif "GCM" in enc_upper or "CHACHA" in enc_upper:
            r = self.get_rule_by_condition("recommended_aead_cipher")
            checks.append(ComplianceCheckItem(
                control_id="COMP-ENC-01",
                category="Cryptography",
                title="Symmetric Encryption Algorithm",
                status="PASS",
                observed_value=enc,
                expected_standard="AES-256-GCM or AES-128-GCM (AEAD)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Complies with NIST SP 800-77 Rev. 1 Table 4-1 and RFC 8221 MUST requirements.",
                parameter="encryption",
            ))
        else:
            checks.append(ComplianceCheckItem(
                control_id="COMP-ENC-01",
                category="Cryptography",
                title="Symmetric Encryption Algorithm",
                status="UNKNOWN",
                observed_value="Unknown / Not Detected",
                expected_standard="AES-256-GCM or AES-128-GCM (AEAD)",
                references=[],
                rationale="Encryption algorithm was not observed in unencrypted handshake packets.",
                parameter="encryption",
            ))

        # -------------------------------------------------------------
        # Control 2: Diffie-Hellman Key Exchange Group
        # -------------------------------------------------------------
        dh_raw = config.get("dh_group")
        dh_name = str(config.get("dh_group_name", "")).lower()

        dh_num = None
        if isinstance(dh_raw, int):
            dh_num = dh_raw
        elif isinstance(dh_raw, str) and dh_raw.isdigit():
            dh_num = int(dh_raw)

        if dh_num in (1, 2) or "modp768" in dh_name or "modp1024" in dh_name:
            r = self.get_rule_by_condition("insecure_dh_group")
            checks.append(ComplianceCheckItem(
                control_id="COMP-DH-01",
                category="Key Exchange",
                title="Diffie-Hellman Key Exchange Group",
                status="FAIL",
                observed_value=f"Group {dh_num} ({dh_name})" if dh_num else dh_name,
                expected_standard="Group 19 (ecp256), Group 20 (ecp384), or Group 14 (modp2048)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Sub-1536 bit MODP groups are vulnerable to precomputation attacks (Logjam). RFC 8247 classifies Groups 1 and 2 as MUST NOT.",
                parameter="dh_group",
            ))
        elif dh_num == 5 or "modp1536" in dh_name:
            r = self.get_rule_by_condition("legacy_dh_group")
            checks.append(ComplianceCheckItem(
                control_id="COMP-DH-01",
                category="Key Exchange",
                title="Diffie-Hellman Key Exchange Group",
                status="WARNING",
                observed_value=f"Group {dh_num} ({dh_name})" if dh_num else dh_name,
                expected_standard="Group 19 (ecp256), Group 20 (ecp384), or Group 14 (modp2048)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Group 5 (1536-bit MODP) provides inadequate security margin. Deprecated by NIST SP 800-77 and RFC 8247 (SHOULD NOT).",
                parameter="dh_group",
            ))
        elif dh_num in (14, 19, 20, 21) or any(k in dh_name for k in ("ecp256", "ecp384", "modp2048", "modp3072")):
            r = self.get_rule_by_condition("recommended_dh_group")
            checks.append(ComplianceCheckItem(
                control_id="COMP-DH-01",
                category="Key Exchange",
                title="Diffie-Hellman Key Exchange Group",
                status="PASS",
                observed_value=f"Group {dh_num} ({dh_name})" if dh_num else dh_name,
                expected_standard="Group 19 (ecp256), Group 20 (ecp384), or Group 14 (modp2048)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Complies with RFC 8247 MUST/RECOMMENDED requirements and NIST SP 800-77 Section 4.3 guidance.",
                parameter="dh_group",
            ))
        else:
            checks.append(ComplianceCheckItem(
                control_id="COMP-DH-01",
                category="Key Exchange",
                title="Diffie-Hellman Key Exchange Group",
                status="UNKNOWN",
                observed_value="Unknown / Not Detected",
                expected_standard="Group 19 (ecp256), Group 20 (ecp384), or Group 14 (modp2048)",
                references=[],
                rationale="Diffie-Hellman transform proposal was not observed in packet capture.",
                parameter="dh_group",
            ))

        # -------------------------------------------------------------
        # Control 3: Perfect Forward Secrecy (PFS)
        # -------------------------------------------------------------
        pfs_val = config.get("pfs")
        if pfs_val is True or str(pfs_val).lower() == "true":
            r = self.get_rule_by_condition("pfs_enabled")
            checks.append(ComplianceCheckItem(
                control_id="COMP-PFS-01",
                category="Key Management",
                title="Perfect Forward Secrecy (PFS)",
                status="PASS",
                observed_value="Enabled (True)",
                expected_standard="Enabled for all Child SAs",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="PFS provides session key isolation via independent Diffie-Hellman renegotiation (NIST SP 800-77 Section 4.4).",
                parameter="pfs",
            ))
        elif pfs_val is False or str(pfs_val).lower() == "false":
            r = self.get_rule_by_condition("pfs_disabled")
            checks.append(ComplianceCheckItem(
                control_id="COMP-PFS-01",
                category="Key Management",
                title="Perfect Forward Secrecy (PFS)",
                status="WARNING",
                observed_value="Disabled (False)",
                expected_standard="Enabled for all Child SAs",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Disabling PFS creates vulnerability where compromise of master key cascades to all past sessions.",
                parameter="pfs",
            ))
        else:
            checks.append(ComplianceCheckItem(
                control_id="COMP-PFS-01",
                category="Key Management",
                title="Perfect Forward Secrecy (PFS)",
                status="UNKNOWN",
                observed_value="Unknown / Not Detected",
                expected_standard="Enabled for all Child SAs",
                references=[],
                rationale="Child SA renegotiation exchange was not observed in capture.",
                parameter="pfs",
            ))

        # -------------------------------------------------------------
        # Control 4: IKE Protocol Version
        # -------------------------------------------------------------
        ike_ver = str(config.get("ike_version") or config.get("ike") or "Unknown").strip()
        if "IKEv1" in ike_ver:
            r = self.get_rule_by_condition("ikev1_deprecated")
            checks.append(ComplianceCheckItem(
                control_id="COMP-IKE-01",
                category="Key Management",
                title="IKE Protocol Version",
                status="FAIL",
                observed_value="IKEv1 (Legacy)",
                expected_standard="IKEv2 (RFC 7296)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="IKEv1 is deprecated due to structural handshake vulnerabilities and lack of modern anti-DoS mechanisms (NIST SP 800-77).",
                parameter="ike_version",
            ))
        elif "IKEv2" in ike_ver:
            r = self.get_rule_by_condition("ikev2_recommended")
            checks.append(ComplianceCheckItem(
                control_id="COMP-IKE-01",
                category="Key Management",
                title="IKE Protocol Version",
                status="PASS",
                observed_value="IKEv2 (RFC 7296)",
                expected_standard="IKEv2 (RFC 7296)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Complies with RFC 7296 and NIST SP 800-77 recommendations.",
                parameter="ike_version",
            ))
        else:
            checks.append(ComplianceCheckItem(
                control_id="COMP-IKE-01",
                category="Key Management",
                title="IKE Protocol Version",
                status="UNKNOWN",
                observed_value="Unknown / Not Detected",
                expected_standard="IKEv2 (RFC 7296)",
                references=[],
                rationale="IKE handshake packets were not captured on standard ports (UDP 500/4500).",
                parameter="ike_version",
            ))

        # -------------------------------------------------------------
        # Control 5: Authentication / Integrity Algorithm
        # -------------------------------------------------------------
        auth = str(config.get("authentication") or config.get("auth") or "Unknown").strip()
        auth_upper = auth.upper()
        if any(w in auth_upper for w in ("MD5", "SHA1", "SHA-1")):
            r = self.get_rule_by_condition("weak_auth_algorithm")
            checks.append(ComplianceCheckItem(
                control_id="COMP-AUTH-01",
                category="Integrity",
                title="Integrity / Authentication Algorithm",
                status="FAIL",
                observed_value=auth,
                expected_standard="SHA-256, SHA-384, or AEAD ICV",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="MD5 and SHA-1 are deprecated by NIST SP 800-131A due to practical collision attacks.",
                parameter="auth",
            ))
        elif any(s in auth_upper for s in ("SHA2", "SHA256", "SHA-256", "SHA384", "SHA-384", "SHA512", "AEAD", "12", "14")):
            checks.append(ComplianceCheckItem(
                control_id="COMP-AUTH-01",
                category="Integrity",
                title="Integrity / Authentication Algorithm",
                status="PASS",
                observed_value=auth if auth not in ("12", "14") else f"SHA-256 (IANA ID {auth})",
                expected_standard="SHA-256, SHA-384, or AEAD ICV",
                references=[],
                rationale="Complies with RFC 8247 Section 2.3 MUST requirements.",
                parameter="auth",
            ))
        elif "GCM" in enc_upper:
            # AEAD ciphers incorporate integrity tag implicitly
            checks.append(ComplianceCheckItem(
                control_id="COMP-AUTH-01",
                category="Integrity",
                title="Integrity / Authentication Algorithm",
                status="PASS",
                observed_value="Integrated AEAD 128-bit Authentication Tag (AES-GCM)",
                expected_standard="SHA-256, SHA-384, or AEAD ICV",
                references=[],
                rationale="AEAD ciphers natively incorporate authenticated integrity tags (RFC 4106).",
                parameter="auth",
            ))
        else:
            checks.append(ComplianceCheckItem(
                control_id="COMP-AUTH-01",
                category="Integrity",
                title="Integrity / Authentication Algorithm",
                status="UNKNOWN",
                observed_value="Unknown / Not Detected",
                expected_standard="SHA-256, SHA-384, or AEAD ICV",
                references=[],
                rationale="Integrity transform was not directly observable.",
                parameter="auth",
            ))

        # -------------------------------------------------------------
        # Control 6: VPN Encapsulation Mode
        # -------------------------------------------------------------
        mode = str(config.get("vpn_mode") or config.get("mode") or "Unknown").strip()
        mode_lower = mode.lower()
        if "tunnel" in mode_lower:
            r = self.get_rule_by_condition("tunnel_mode_gateway")
            checks.append(ComplianceCheckItem(
                control_id="COMP-MODE-01",
                category="Architecture",
                title="VPN Encapsulation Architecture",
                status="PASS",
                observed_value="Tunnel Mode (Site-to-Site / Gateway)",
                expected_standard="Tunnel Mode for Gateway-to-Gateway",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Complies with RFC 4301 Section 4.1 gateway encapsulation requirements.",
                parameter="mode",
            ))
        elif "transport" in mode_lower:
            checks.append(ComplianceCheckItem(
                control_id="COMP-MODE-01",
                category="Architecture",
                title="VPN Encapsulation Architecture",
                status="WARNING",
                observed_value="Transport Mode (Host-to-Host)",
                expected_standard="Tunnel Mode for Gateway Protection",
                references=[],
                rationale="Transport mode does not hide inner IP headers. RFC 4301 mandates Tunnel mode for gateway protection.",
                parameter="mode",
            ))
        else:
            checks.append(ComplianceCheckItem(
                control_id="COMP-MODE-01",
                category="Architecture",
                title="VPN Encapsulation Architecture",
                status="UNKNOWN",
                observed_value="Unknown / Not Detected",
                expected_standard="Tunnel Mode for Gateway Protection",
                references=[],
                rationale="Encapsulation mode could not be verified from outer packet headers.",
                parameter="mode",
            ))

        # -------------------------------------------------------------
        # Control 7: ESP Tunnel Hygiene & Anti-Replay
        # -------------------------------------------------------------
        has_zero_spi = False
        has_replay_anomaly = False
        if findings:
            for f in findings:
                f_id = getattr(f, "id", "") if hasattr(f, "id") else f.get("id", "")
                if f_id == "VPN-005" or "zero_spi" in str(f).lower():
                    has_zero_spi = True
                if f_id == "VPN-006" or "replay" in str(f).lower() or "sequence" in str(f).lower():
                    has_replay_anomaly = True

        esp_pkts = config.get("esp_packets") or config.get("esp_packet_count") or (1 if config.get("esp_present") or config.get("esp_detected") else 0)
        if has_zero_spi:
            r = self.get_rule_by_condition("zero_spi_anomaly")
            checks.append(ComplianceCheckItem(
                control_id="COMP-ESP-01",
                category="Tunnel Integrity",
                title="ESP Security Parameters Index (SPI) Hygiene",
                status="FAIL",
                observed_value="SPI 0x00000000 Detected",
                expected_standard="Non-zero operational SPI (RFC 4303)",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="SPI value 0 is strictly reserved under RFC 4303 Section 2.1 and must not appear on the wire.",
                parameter="esp",
            ))
        elif has_replay_anomaly:
            r = self.get_rule_by_condition("replay_protection_anomaly")
            checks.append(ComplianceCheckItem(
                control_id="COMP-ESP-01",
                category="Tunnel Integrity",
                title="ESP Sequence Number & Replay Protection",
                status="WARNING",
                observed_value="Non-monotonic sequence progression",
                expected_standard="Monotonically increasing sequence counters",
                references=[ref.model_dump() for ref in r.references] if r else [],
                rationale="Potential packet reordering, duplicate delivery, or replay attempt (RFC 4303 Section 3.4.3).",
                parameter="esp",
            ))
        elif esp_pkts and esp_pkts > 0:
            checks.append(ComplianceCheckItem(
                control_id="COMP-ESP-01",
                category="Tunnel Integrity",
                title="ESP Protocol Progression & Header Integrity",
                status="PASS",
                observed_value=f"{esp_pkts} ESP packets with valid SPI progression",
                expected_standard="Valid SPI and active anti-replay progression",
                references=[],
                rationale="Observed ESP packets demonstrate healthy sequence progression and non-zero SPI values.",
                parameter="esp",
            ))
        else:
            checks.append(ComplianceCheckItem(
                control_id="COMP-ESP-01",
                category="Tunnel Integrity",
                title="ESP Protocol Progression & Header Integrity",
                status="UNKNOWN",
                observed_value="No ESP packets detected",
                expected_standard="Valid SPI and active anti-replay progression",
                references=[],
                rationale="Capture contained 0 ESP data packets.",
                parameter="esp",
            ))

        # -------------------------------------------------------------
        # Aggregation
        # -------------------------------------------------------------
        total_checks = len(checks)
        passed = sum(1 for c in checks if c.status == "PASS")
        warnings = sum(1 for c in checks if c.status == "WARNING")
        failed = sum(1 for c in checks if c.status == "FAIL")
        unknown = sum(1 for c in checks if c.status == "UNKNOWN")

        if failed > 0:
            overall = "NON_COMPLIANT"
        elif warnings > 0:
            overall = "COMPLIANT_WITH_WARNINGS"
        elif unknown >= total_checks // 2:
            overall = "INSUFFICIENT_DATA"
        else:
            overall = "COMPLIANT"

        return ComplianceEvaluationResult(
            total_checks=total_checks,
            passed=passed,
            warnings=warnings,
            failed=failed,
            unknown=unknown,
            overall_status=overall,
            checks=checks,
        )
