"""
Phase 3 Prioritized Recommendation Engine for SentraIPS.
Generates actionable remediation recommendations based strictly on observed findings
and identified parameter limitations.
Priority levels:
  CRITICAL
  HIGH
  MEDIUM
  LOW
"""

from typing import List, Optional
from .schemas import (
    ExtractedConfiguration,
    ObservationStatus,
    Recommendation,
    RecommendationPriority,
    SecurityFinding,
)


class RecommendationEngine:
    """Generates and prioritizes recommendations derived from security findings."""

    PRIORITY_RANKS = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
        "INFO": 5,
    }

    def generate(
        self,
        findings: List[SecurityFinding],
        configuration: Optional[ExtractedConfiguration] = None,
    ) -> List[Recommendation]:
        """
        Derives prioritized recommendations from findings and unobserved configuration elements.
        """
        recs: List[Recommendation] = []
        seen_titles = set()

        # 1. Generate recommendations directly from findings
        for f in findings:
            if not f.recommendation:
                continue

            # Map severity to priority
            sev = f.severity.upper()
            if sev == "CRITICAL":
                priority = RecommendationPriority.CRITICAL.value
            elif sev == "HIGH":
                priority = RecommendationPriority.HIGH.value
            elif sev == "MEDIUM":
                priority = RecommendationPriority.MEDIUM.value
            else:
                priority = RecommendationPriority.LOW.value

            title = f"Remediate: {f.title}"
            if title in seen_titles:
                continue
            seen_titles.add(title)

            # Build action advice
            action = self._derive_action(f)

            recs.append(
                Recommendation(
                    priority=priority,
                    title=title,
                    description=f.recommendation,
                    action=action,
                    related_finding_id=f.id,
                    category=f.category,
                )
            )

        # 2. Generate operational guidance for unknown parameters
        if configuration:
            unknown_params = []
            for param_name in ["encryption", "dh_group", "pfs", "ike_version"]:
                param_obs = getattr(configuration, param_name, None)
                if param_obs and param_obs.status == ObservationStatus.UNKNOWN:
                    unknown_params.append(param_obs.name)

            if unknown_params:
                unknown_str = ", ".join(unknown_params)
                rec_title = f"Verify Unobserved Parameters ({unknown_str})"
                if rec_title not in seen_titles:
                    seen_titles.add(rec_title)
                    recs.append(
                        Recommendation(
                            priority=RecommendationPriority.LOW.value,
                            title=rec_title,
                            description=(
                                f"The following security parameters could not be observed from the packet capture: "
                                f"{unknown_str}. This typically occurs when the capture began after IKE SA negotiation, "
                                f"or when Child SA proposals are negotiated inside encrypted IKE_AUTH payloads."
                            ),
                            action=(
                                "Capture initial IKE_SA_INIT UDP 500/4500 exchange packets at tunnel setup, "
                                "or verify IPSec configuration directly on the security gateway / strongSwan configuration."
                            ),
                            related_finding_id=None,
                            category="Operational Visibility",
                        )
                    )

        # Sort recommendations by priority rank
        recs.sort(key=lambda r: self.PRIORITY_RANKS.get(r.priority.upper(), 99))
        return recs

    def _derive_action(self, finding: SecurityFinding) -> str:
        """Provides specific implementation or configuration guidance for a finding."""
        rule_id = getattr(finding, "rule_id", finding.id).upper()

        if "WEAK_CIPHER" in rule_id:
            return "Reconfigure IPsec proposal to use 'esp = aes256gcm16' or 'esp = chacha20poly1305' in swanctl.conf / ipsec.conf."
        elif "NON_AEAD" in rule_id or "CBC" in rule_id:
            return "Upgrade encryption suite from CBC mode to Authenticated Encryption (AEAD): enforce AES-256-GCM or AES-128-GCM."
        elif "DH_GROUP" in rule_id or "LEGACY" in rule_id:
            return "Update key exchange configuration to require Elliptic Curve Diffie-Hellman: DH Group 19 (ecp256) or Group 20 (ecp384)."
        elif "PFS" in rule_id:
            return "Enable Perfect Forward Secrecy by appending DH group to ESP proposal: e.g. 'esp = aes256gcm16-ecp256!'."
        elif "IKE_VERSION" in rule_id:
            return "Set 'keyexchange = ikev2' in IPsec configuration and disable IKEv1 daemon support."
        elif "INTEGRITY" in rule_id:
            return "Enforce SHA-256 or SHA-384 integrity (or eliminate separate hash by using AEAD ciphers)."
        elif "INSUFFICIENT_KEY" in rule_id:
            return "Increase cipher key length to at least 256 bits (AES-256)."
        elif "FLOW_INFERENCE" in rule_id:
            return "Evaluate IPsec Traffic Flow Confidentiality (TFC) padding (RFC 4303) if packet size profiling is a threat."

        return finding.recommendation
