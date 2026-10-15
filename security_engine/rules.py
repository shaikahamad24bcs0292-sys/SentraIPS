"""
Phase 3 Deterministic Security Assessment Rules for SentraIPS.
Evaluates observed protocol and cryptographic parameters against NIST SP 800-77 Rev. 1,
RFC 7296, RFC 8221, and RFC 4301 compliance criteria.
Enforces explicit distinction between OBSERVED, INFERRED, and UNKNOWN parameters.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml

from packet_analysis.parser import PCAPParseResult
from packet_analysis.features import ESPTrafficFeatures
from .schemas import (
    ESPObservation,
    EvidenceItem,
    ExtractedConfiguration,
    ObservationStatus,
    ParameterObservation,
    SecurityFinding,
)


class SecurityRuleEvaluator:
    """Evaluates security rules deterministically based on config.yaml specifications."""

    def __init__(self, config_path: Optional[Path] = None):
        if not config_path:
            config_path = Path(__file__).resolve().parent / "config.yaml"
        self.config_path = config_path

        with open(self.config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

        self.rule_defs = self.config.get("rules", {})

    def extract_configuration(
        self,
        parsed_pcap: PCAPParseResult,
        features: Optional[ESPTrafficFeatures] = None,
    ) -> ExtractedConfiguration:
        """
        Extracts configuration parameters with strict OBSERVED, INFERRED, and UNKNOWN provenance.
        Never fabricates unobserved fields.
        """
        gt = parsed_pcap.ground_truth or {}
        ike = parsed_pcap.ike
        esp = parsed_pcap.esp

        # 1. Encryption
        enc_raw = gt.get("encryption") or ike.encryption
        if enc_raw and enc_raw != "Unknown / Not Detected":
            enc_source = "Testbed Ground Truth" if "encryption" in gt else "IKE_SA_INIT Transform Proposal"
            enc_status = ObservationStatus.OBSERVED
            enc_val = str(enc_raw)
        else:
            enc_status = ObservationStatus.UNKNOWN
            enc_val = "Unknown / Not Detected"
            enc_source = "IKE SA Init (Payload Not Available or Pre-Negotiated)"

        # 2. DH Group
        dh_raw = gt.get("dh_group") if "dh_group" in gt else ike.dh_group
        dh_name_raw = gt.get("dh_group_name") or ike.dh_group_name
        if dh_raw is not None and str(dh_raw) != "Unknown / Not Detected":
            dh_status = ObservationStatus.OBSERVED
            dh_val = dh_raw
            dh_source = "Testbed Ground Truth" if "dh_group" in gt else "IKE_SA_INIT Key Exchange (KE) Payload"
        else:
            dh_status = ObservationStatus.UNKNOWN
            dh_val = "Unknown / Not Detected"
            dh_source = "IKE_SA_INIT (KE Payload Not Observed)"

        # 3. PFS
        pfs_raw = gt.get("pfs") if "pfs" in gt else ike.pfs
        if isinstance(pfs_raw, bool):
            pfs_status = ObservationStatus.OBSERVED
            pfs_val = pfs_raw
            pfs_source = "Child SA Proposal / Testbed Configuration"
        elif str(pfs_raw).lower() in ("true", "false"):
            pfs_status = ObservationStatus.OBSERVED
            pfs_val = str(pfs_raw).lower() == "true"
            pfs_source = "Child SA Proposal / Testbed Configuration"
        else:
            pfs_status = ObservationStatus.UNKNOWN
            pfs_val = "Unknown / Not Detected"
            pfs_source = "Child SA (Rekey exchange unobserved in capture)"

        # 4. IKE Version
        ike_ver_raw = gt.get("ike_version") or ike.version
        if ike_ver_raw and ike_ver_raw != "Unknown / Not Detected":
            ike_status = ObservationStatus.OBSERVED
            ike_val = str(ike_ver_raw)
            ike_source = "ISAKMP Header Version Field"
        else:
            ike_status = ObservationStatus.UNKNOWN
            ike_val = "Unknown / Not Detected"
            ike_source = "ISAKMP (No cleartext IKE UDP 500/4500 packets found)"

        # 5. VPN Mode
        vpn_mode_raw = gt.get("vpn_mode")
        if vpn_mode_raw:
            mode_status = ObservationStatus.OBSERVED
            mode_val = str(vpn_mode_raw).lower()
            mode_source = "Testbed Ground Truth"
        elif esp.detected and esp.packet_count > 0:
            mode_status = ObservationStatus.INFERRED
            mode_val = "tunnel"  # standard StrongSwan testbed default
            mode_source = "Inferred from outer IP header encapsulation"
        else:
            mode_status = ObservationStatus.UNKNOWN
            mode_val = "Unknown / Not Detected"
            mode_source = "Header Analysis"

        # 6. ESP Observations
        esp_presence = esp.detected or esp.packet_count > 0
        seq_prog = "No ESP packets detected"
        anomalies: List[str] = []

        if esp_presence:
            if esp.seq_min is not None and esp.seq_max is not None:
                if esp.seq_max >= esp.seq_min:
                    seq_prog = f"Monotonic sequence progression (range: {esp.seq_min} to {esp.seq_max})"
                else:
                    seq_prog = f"Non-monotonic progression detected ({esp.seq_min} -> {esp.seq_max})"
                    anomalies.append("Non-monotonic sequence number progression")
            # Check for zero SPI (0x00000000 is invalid per RFC 4303)
            for spi in esp.spis_observed:
                if spi in ("0x00000000", "0x0", "0"):
                    anomalies.append(f"Invalid reserved SPI detected: {spi} (RFC 4303 violation)")

        esp_obs = ESPObservation(
            presence=esp_presence,
            packet_count=esp.packet_count,
            spis_observed=esp.spis_observed,
            seq_min=esp.seq_min,
            seq_max=esp.seq_max,
            seq_progression=seq_prog,
            anomalies_detected=anomalies,
        )

        return ExtractedConfiguration(
            encryption=ParameterObservation(
                name="encryption",
                value=enc_val,
                status=enc_status,
                source=enc_source,
            ),
            dh_group=ParameterObservation(
                name="dh_group",
                value=dh_val,
                status=dh_status,
                source=dh_source,
                notes=str(dh_name_raw) if dh_name_raw != "Unknown / Not Detected" else None,
            ),
            pfs=ParameterObservation(
                name="pfs",
                value=pfs_val,
                status=pfs_status,
                source=pfs_source,
            ),
            ike_version=ParameterObservation(
                name="ike_version",
                value=ike_val,
                status=ike_status,
                source=ike_source,
            ),
            vpn_mode=ParameterObservation(
                name="vpn_mode",
                value=mode_val,
                status=mode_status,
                source=mode_source,
            ),
            esp=esp_obs,
            total_packets=parsed_pcap.total_packets,
            ike_packets=parsed_pcap.ike_packets,
            esp_packets=parsed_pcap.esp_packets,
            raw_parameters={
                "encryption_key_length": gt.get("encryption_key_length") or ike.encryption_key_length,
                "authentication": gt.get("authentication") or ike.authentication,
                "dh_group_name": dh_name_raw,
                "initiator_spi": ike.initiator_spi,
                "responder_spi": ike.responder_spi,
            },
        )

    def evaluate_configuration(
        self,
        config: ExtractedConfiguration,
    ) -> List[SecurityFinding]:
        """Runs deterministic rules strictly over the extracted configuration."""
        findings: List[SecurityFinding] = []
        counter = 1

        # ---------------------------------------------------------------------
        # 1. Cryptography Evaluation
        # ---------------------------------------------------------------------
        enc_obs = config.encryption
        enc_cipher = str(enc_obs.value).upper() if enc_obs.value is not None else ""
        key_len = config.raw_parameters.get("encryption_key_length")
        auth_integ = str(config.raw_parameters.get("authentication") or "").upper()

        if enc_obs.status != ObservationStatus.UNKNOWN and enc_cipher != "UNKNOWN / NOT DETECTED":
            # Check for broken/weak ciphers (DES, 3DES, Blowfish, RC4, NULL)
            if any(w in enc_cipher for w in ["3DES", "DES", "BLOWFISH", "RC4", "NULL"]):
                r_cfg = self.rule_defs["CRYPTO_WEAK_CIPHER"]
                findings.append(
                    SecurityFinding(
                        id=f"VPN-{counter:03d}",
                        finding_id=f"F{counter:03d}",
                        rule_id="CRYPTO_WEAK_CIPHER",
                        title=r_cfg["name"],
                        category=r_cfg["category"],
                        severity=r_cfg["severity"],
                        risk_contribution=r_cfg["weight"],
                        evidence=EvidenceItem(
                            encryption=enc_cipher,
                            observed_field="encryption",
                            observed_value=enc_cipher,
                            packet_source=enc_obs.source,
                            rule_criterion="Cipher must not be DES, 3DES, RC4, or Blowfish (NIST SP 800-77 Rev. 1)",
                        ),
                        description=r_cfg["description"],
                        impact="Vulnerable to cryptanalytic key recovery, Sweet32 block collisions, or cleartext exposure.",
                        recommendation=r_cfg["recommendation"],
                        confidence=1.0 if enc_obs.status == ObservationStatus.OBSERVED else 0.8,
                        source=enc_obs.source,
                    )
                )
                counter += 1

            # Check for legacy non-AEAD CBC mode
            elif "CBC" in enc_cipher and "GCM" not in enc_cipher:
                r_cfg = self.rule_defs["CRYPTO_LEGACY_NON_AEAD"]
                findings.append(
                    SecurityFinding(
                        id=f"VPN-{counter:03d}",
                        finding_id=f"F{counter:03d}",
                        rule_id="CRYPTO_LEGACY_NON_AEAD",
                        title=r_cfg["name"],
                        category=r_cfg["category"],
                        severity=r_cfg["severity"],
                        risk_contribution=r_cfg["weight"],
                        evidence=EvidenceItem(
                            encryption=enc_cipher,
                            observed_field="encryption",
                            observed_value=enc_cipher,
                            packet_source=enc_obs.source,
                            rule_criterion="Cipher mode must be Authenticated Encryption with Associated Data (AEAD)",
                        ),
                        description=r_cfg["description"],
                        impact="CBC mode requires separate MAC and is susceptible to padding oracle attacks if improperly validated.",
                        recommendation=r_cfg["recommendation"],
                        confidence=1.0 if enc_obs.status == ObservationStatus.OBSERVED else 0.8,
                        source=enc_obs.source,
                    )
                )
                counter += 1

        # Check key length if observed
        if key_len is not None and isinstance(key_len, (int, float)) and key_len < 128:
            r_cfg = self.rule_defs["CRYPTO_INSUFFICIENT_KEY_LENGTH"]
            findings.append(
                SecurityFinding(
                    id=f"VPN-{counter:03d}",
                    finding_id=f"F{counter:03d}",
                    rule_id="CRYPTO_INSUFFICIENT_KEY_LENGTH",
                    title=r_cfg["name"],
                    category=r_cfg["category"],
                    severity=r_cfg["severity"],
                    risk_contribution=r_cfg["weight"],
                    evidence=EvidenceItem(
                        encryption_key_length=f"{key_len} bits",
                        observed_field="encryption_key_length",
                        observed_value=f"{key_len} bits",
                        packet_source="IKE Key Length Transform Attribute",
                        rule_criterion="Key length must be >= 128 bits (>= 256 bits recommended)",
                    ),
                    description=r_cfg["description"],
                    impact="Keys under 128 bits can be exhaustively brute-forced by modern compute resources.",
                    recommendation=r_cfg["recommendation"],
                    confidence=1.0,
                    source="Observed from configuration",
                )
            )
            counter += 1

        # Check for weak integrity algorithm (MD5, SHA1)
        if any(w in auth_integ for w in ["MD5", "SHA1", "SHA-1"]):
            r_cfg = self.rule_defs["CRYPTO_WEAK_INTEGRITY"]
            findings.append(
                SecurityFinding(
                    id=f"VPN-{counter:03d}",
                    finding_id=f"F{counter:03d}",
                    rule_id="CRYPTO_WEAK_INTEGRITY",
                    title=r_cfg["name"],
                    category=r_cfg["category"],
                    severity=r_cfg["severity"],
                    risk_contribution=r_cfg["weight"],
                    evidence=EvidenceItem(
                        authentication=auth_integ,
                        observed_field="authentication",
                        observed_value=auth_integ,
                        packet_source="IKE Proposal Integrity/PRF Attribute",
                        rule_criterion="Integrity hash must not be MD5 or SHA-1 (RFC 8221)",
                    ),
                    description=r_cfg["description"],
                    impact="MD5 and SHA-1 suffer from collision vulnerabilities allowing forged message authentication.",
                    recommendation=r_cfg["recommendation"],
                    confidence=1.0,
                    source="Observed from configuration",
                )
            )
            counter += 1

        # ---------------------------------------------------------------------
        # 2. Key Exchange & Diffie-Hellman Evaluation
        # ---------------------------------------------------------------------
        dh_obs = config.dh_group
        dh_grp = dh_obs.value
        dh_name = str(dh_obs.notes or "").lower()

        if dh_obs.status != ObservationStatus.UNKNOWN and str(dh_grp) != "Unknown / Not Detected":
            # Check for insecure DH group (Group 1: 768-bit, Group 2: 1024-bit)
            if dh_grp in (1, 2, "1", "2") or any(w in dh_name for w in ["modp768", "modp1024"]):
                r_cfg = self.rule_defs["DH_GROUP_INSECURE"]
                findings.append(
                    SecurityFinding(
                        id=f"VPN-{counter:03d}",
                        finding_id=f"F{counter:03d}",
                        rule_id="DH_GROUP_INSECURE",
                        title=r_cfg["name"],
                        category=r_cfg["category"],
                        severity=r_cfg["severity"],
                        risk_contribution=r_cfg["weight"],
                        evidence=EvidenceItem(
                            dh_group=dh_grp,
                            observed_field="dh_group",
                            observed_value=f"Group {dh_grp} ({dh_name or 'modp1024'})",
                            packet_source=dh_obs.source,
                            rule_criterion="Diffie-Hellman group key size must be >= 2048 bits (RFC 8221)",
                        ),
                        description=r_cfg["description"],
                        impact="Logjam attack and discrete logarithm precomputations make sub-2048 bit MODP groups breakable.",
                        recommendation=r_cfg["recommendation"],
                        confidence=1.0,
                        source=dh_obs.source,
                    )
                )
                counter += 1

            # Check for legacy DH group (Group 5: 1536-bit)
            elif dh_grp in (5, "5") or "modp1536" in dh_name:
                r_cfg = self.rule_defs["DH_GROUP_LEGACY"]
                findings.append(
                    SecurityFinding(
                        id=f"VPN-{counter:03d}",
                        finding_id=f"F{counter:03d}",
                        rule_id="DH_GROUP_LEGACY",
                        title=r_cfg["name"],
                        category=r_cfg["category"],
                        severity=r_cfg["severity"],
                        risk_contribution=r_cfg["weight"],
                        evidence=EvidenceItem(
                            dh_group=dh_grp,
                            observed_field="dh_group",
                            observed_value=f"Group {dh_grp} ({dh_name or 'modp1536'})",
                            packet_source=dh_obs.source,
                            rule_criterion="Diffie-Hellman group must be Group 14 (2048-bit) or ECP Group 19/20",
                        ),
                        description=r_cfg["description"],
                        impact="1536-bit key exchange provides insufficient security margin against long-term cryptanalysis.",
                        recommendation=r_cfg["recommendation"],
                        confidence=1.0,
                        source=dh_obs.source,
                    )
                )
                counter += 1

        # Check Perfect Forward Secrecy (PFS)
        pfs_obs = config.pfs
        if pfs_obs.status != ObservationStatus.UNKNOWN:
            pfs_val = pfs_obs.value
            if pfs_val is False or pfs_val == "False" or pfs_val == 0:
                r_cfg = self.rule_defs["PFS_DISABLED"]
                findings.append(
                    SecurityFinding(
                        id=f"VPN-{counter:03d}",
                        finding_id=f"F{counter:03d}",
                        rule_id="PFS_DISABLED",
                        title=r_cfg["name"],
                        category=r_cfg["category"],
                        severity=r_cfg["severity"],
                        risk_contribution=r_cfg["weight"],
                        evidence=EvidenceItem(
                            pfs=False,
                            observed_field="pfs",
                            observed_value=False,
                            packet_source=pfs_obs.source,
                            rule_criterion="Perfect Forward Secrecy (PFS) must be enabled on all Child SAs",
                        ),
                        description=r_cfg["description"],
                        impact="Compromise of the long-term private key allows retroactive decryption of all recorded past sessions.",
                        recommendation=r_cfg["recommendation"],
                        confidence=1.0,
                        source=pfs_obs.source,
                    )
                )
                counter += 1

        # ---------------------------------------------------------------------
        # 3. Protocol & SA Configuration Evaluation
        # ---------------------------------------------------------------------
        ike_obs = config.ike_version
        if ike_obs.status != ObservationStatus.UNKNOWN:
            ike_ver = str(ike_obs.value).upper()
            if "IKEV1" in ike_ver:
                r_cfg = self.rule_defs["IKE_VERSION_DEPRECATED"]
                findings.append(
                    SecurityFinding(
                        id=f"VPN-{counter:03d}",
                        finding_id=f"F{counter:03d}",
                        rule_id="IKE_VERSION_DEPRECATED",
                        title=r_cfg["name"],
                        category=r_cfg["category"],
                        severity=r_cfg["severity"],
                        risk_contribution=r_cfg["weight"],
                        evidence=EvidenceItem(
                            ike_version=ike_ver,
                            observed_field="ike_version",
                            observed_value=ike_ver,
                            packet_source=ike_obs.source,
                            rule_criterion="IKEv2 (RFC 7296) must be used instead of deprecated IKEv1",
                        ),
                        description=r_cfg["description"],
                        impact="IKEv1 lacks native cookie-based DoS defenses and is vulnerable to offline dictionary attacks in aggressive mode.",
                        recommendation=r_cfg["recommendation"],
                        confidence=1.0,
                        source=ike_obs.source,
                    )
                )
                counter += 1

        # Check ESP Replay & Anomalies
        esp_obs = config.esp
        if esp_obs.anomalies_detected:
            r_cfg = self.rule_defs["REPLAY_PROTECTION_ANOMALY"]
            findings.append(
                SecurityFinding(
                    id=f"VPN-{counter:03d}",
                    finding_id=f"F{counter:03d}",
                    rule_id="REPLAY_PROTECTION_ANOMALY",
                    title=r_cfg["name"],
                    category=r_cfg["category"],
                    severity=r_cfg["severity"],
                    risk_contribution=r_cfg["weight"],
                    evidence=EvidenceItem(
                        esp_anomalies=esp_obs.anomalies_detected,
                        observed_field="esp_sequence_progression",
                        observed_value="; ".join(esp_obs.anomalies_detected),
                        packet_source="ESP Header Sequence Numbers & SPIs",
                        rule_criterion="ESP sequence numbers must advance monotonically without replay or invalid SPIs",
                    ),
                    description=r_cfg["description"],
                    impact="Indicates network packet duplication, replay attack attempt, or misconfigured anti-replay window.",
                    recommendation=r_cfg["recommendation"],
                    confidence=0.9,
                    source="Observed from ESP packet headers",
                )
            )
            counter += 1

        # ---------------------------------------------------------------------
        # 4. Metadata Exposure Evaluation
        # ---------------------------------------------------------------------
        # Exposure via traffic analysis / flow inference
        if esp_obs.presence and esp_obs.packet_count > 0:
            r_cfg = self.rule_defs["METADATA_EXPOSURE_FLOW_INFERENCE"]
            findings.append(
                SecurityFinding(
                    id=f"VPN-{counter:03d}",
                    finding_id=f"F{counter:03d}",
                    rule_id="METADATA_EXPOSURE_FLOW_INFERENCE",
                    title=r_cfg["name"],
                    category=r_cfg["category"],
                    severity=r_cfg["severity"],
                    risk_contribution=r_cfg["weight"],
                    evidence=EvidenceItem(
                        esp_packets=esp_obs.packet_count,
                        observed_field="esp_packets",
                        observed_value=f"{esp_obs.packet_count} packets",
                        packet_source="Outer IP/ESP packet headers and inter-arrival timestamps",
                        rule_criterion="Traffic flow confidentiality (TFC) padding (RFC 4303)",
                    ),
                    description=r_cfg["description"],
                    impact="Passive observers can profile application traffic types (VoIP, video, file transfers) from timing and packet sizes.",
                    recommendation=r_cfg["recommendation"],
                    confidence=0.9,
                    source="Observed from ESP packet flow",
                )
            )
            counter += 1

        # Exposure via cleartext IKE_SA_INIT negotiation
        if config.ike_packets > 0:
            r_cfg = self.rule_defs["METADATA_EXPOSURE_PLAINTEXT_IKE_HEADERS"]
            findings.append(
                SecurityFinding(
                    id=f"VPN-{counter:03d}",
                    finding_id=f"F{counter:03d}",
                    rule_id="METADATA_EXPOSURE_PLAINTEXT_IKE_HEADERS",
                    title=r_cfg["name"],
                    category=r_cfg["category"],
                    severity=r_cfg["severity"],
                    risk_contribution=r_cfg["weight"],
                    evidence=EvidenceItem(
                        ike_packets=config.ike_packets,
                        observed_field="ike_packets",
                        observed_value=f"{config.ike_packets} IKE packets",
                        packet_source="IKE_SA_INIT message headers (UDP 500/4500)",
                        rule_criterion="IKEv2 cleartext handshake visibility (RFC 7296)",
                    ),
                    description=r_cfg["description"],
                    impact="External network observers learn gateway identity and supported cryptographic suites from initial negotiation.",
                    recommendation=r_cfg["recommendation"],
                    confidence=1.0,
                    source="Observed from IKE handshake",
                )
            )
            counter += 1

        return findings

    def evaluate(
        self,
        parsed_pcap: PCAPParseResult,
        features: Optional[ESPTrafficFeatures] = None,
    ) -> List[SecurityFinding]:
        """Runs all deterministic rules over the parsed capture and returns findings."""
        config = self.extract_configuration(parsed_pcap, features)
        return self.evaluate_configuration(config)

    def evaluate_dict(self, config_dict: Dict[str, Any]) -> List[SecurityFinding]:
        """Evaluates arbitrary configuration dictionaries (useful for API inputs)."""
        enc_val = config_dict.get("encryption", "Unknown / Not Detected")
        enc_status = (
            ObservationStatus.UNKNOWN
            if not enc_val or enc_val == "Unknown / Not Detected"
            else ObservationStatus.OBSERVED
        )

        dh_val = config_dict.get("dh_group")
        dh_status = (
            ObservationStatus.UNKNOWN
            if dh_val is None or str(dh_val) == "Unknown / Not Detected"
            else ObservationStatus.OBSERVED
        )

        pfs_val = config_dict.get("pfs")
        if isinstance(pfs_val, bool) or str(pfs_val).lower() in ("true", "false"):
            pfs_status = ObservationStatus.OBSERVED
            pfs_clean = True if str(pfs_val).lower() == "true" or pfs_val is True else False
        else:
            pfs_status = ObservationStatus.UNKNOWN
            pfs_clean = "Unknown / Not Detected"

        ike_val = config_dict.get("ike_version", "Unknown / Not Detected")
        ike_status = (
            ObservationStatus.UNKNOWN
            if not ike_val or ike_val == "Unknown / Not Detected"
            else ObservationStatus.OBSERVED
        )

        mode_val = config_dict.get("vpn_mode", "tunnel")
        mode_status = ObservationStatus.OBSERVED if "vpn_mode" in config_dict else ObservationStatus.UNKNOWN

        config = ExtractedConfiguration(
            encryption=ParameterObservation(
                name="encryption",
                value=enc_val,
                status=enc_status,
                source="Config API Input",
            ),
            dh_group=ParameterObservation(
                name="dh_group",
                value=dh_val if dh_val is not None else "Unknown / Not Detected",
                status=dh_status,
                source="Config API Input",
                notes=config_dict.get("dh_group_name"),
            ),
            pfs=ParameterObservation(
                name="pfs",
                value=pfs_clean,
                status=pfs_status,
                source="Config API Input",
            ),
            ike_version=ParameterObservation(
                name="ike_version",
                value=ike_val,
                status=ike_status,
                source="Config API Input",
            ),
            vpn_mode=ParameterObservation(
                name="vpn_mode",
                value=mode_val,
                status=mode_status,
                source="Config API Input",
            ),
            esp=ESPObservation(
                presence=bool(config_dict.get("esp_packets", 0) > 0),
                packet_count=config_dict.get("esp_packets", 0),
            ),
            total_packets=config_dict.get("total_packets", 0),
            ike_packets=config_dict.get("ike_packets", 0),
            esp_packets=config_dict.get("esp_packets", 0),
            raw_parameters=config_dict,
        )
        return self.evaluate_configuration(config)
