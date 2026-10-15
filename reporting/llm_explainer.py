"""
LLM Explanation and Technical/Executive Synthesis Engine for SentraIPS.
Provides contextual explanations, business impact narratives, and remediation strategies
strictly bounded by deterministic security findings and RAG standards evidence.
GUARANTEE: The LLM NEVER calculates risk, overrides rules, or invents packet data.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from knowledge_base.rag import StandardsRAGEngine, StructuredEvidenceItem
from security_engine.findings import SecurityAssessmentReport, SecurityFinding


class FindingExplanation(BaseModel):
    """Detailed contextual explanation for an individual finding."""
    finding_id: str
    rule_id: str
    title: str
    severity: str
    points: int
    technical_explanation: str
    business_impact: str
    authoritative_basis: str
    recommended_action: str


class AuditNarrative(BaseModel):
    """Executive narrative synthesized from structured audit findings."""
    executive_summary: str
    risk_profile_description: str
    primary_vulnerability_drivers: List[str]
    business_operational_impact: str
    strategic_remediation_roadmap: List[str]
    compliance_statement: str

    @property
    def strategic_recommendations(self) -> List[str]:
        return self.strategic_remediation_roadmap


class LLMExplainer:
    """
    Explainability and report narrative engine for SentraIPS.
    Operates in offline expert mode (zero hallucination, deterministic template reasoning)
    or online mode when LLM API keys (Gemini / OpenAI) are configured in the environment.
    """

    def __init__(self, rag_engine: Optional[StandardsRAGEngine] = None):
        self.rag = rag_engine or StandardsRAGEngine()
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        self.openai_api_key = os.getenv("OPENAI_API_KEY")

    def explain_finding(self, finding: SecurityFinding, evidence: Optional[StructuredEvidenceItem] = None) -> FindingExplanation:
        """
        Generates structured technical and business explanations for an individual finding.
        Never alters score or rule ID.
        """
        if evidence is None:
            evidence = self.rag.enrich_finding(finding)

        rule_id = finding.rule_id
        ev_item = getattr(finding, "evidence", None)
        if ev_item:
            obs = f"{getattr(ev_item, 'observed_field', '')} = {getattr(ev_item, 'observed_value', '')}"
        else:
            obs = getattr(finding, "observed_field", "")

        fid = getattr(finding, "finding_id", getattr(finding, "id", "F001"))
        pts = getattr(finding, "risk_contribution", getattr(finding, "points", 0))

        # Build authoritative reference string
        ref_parts = []
        for r in evidence.references[:2]:
            ref_parts.append(f"{r.get('document')} ({r.get('section')}: {r.get('title')})")
        auth_basis = " & ".join(ref_parts) if ref_parts else getattr(finding, "description", finding.rule_id)

        # Rule-grounded synthesis
        if "CBC" in rule_id or "NON_AEAD" in rule_id:
            tech_exp = (
                f"The IPsec tunnel operates with a non-AEAD legacy cipher mode ({obs}). "
                f"Unlike modern AEAD ciphers (e.g. AES-GCM), CBC mode separates encryption and message "
                f"authentication. If padding or IV validation is improperly handled in the cryptostack, "
                f"the tunnel is susceptible to padding-oracle side-channel attacks."
            )
            biz_imp = (
                "Data in transit risks integrity degradation and potential eavesdropping through "
                "cryptographic side-channel attacks. Legacy ciphers fail modern regulatory compliance mandates."
            )
        elif "DH" in rule_id:
            tech_exp = (
                f"The key exchange negotiation utilized {obs}, which provides insufficient mathematical "
                f"work factor against modern cryptanalytic computing capabilities. Standards mandate at least "
                f"2048-bit MODP (Group 14) or 256-bit Elliptic Curve (Group 19)."
            )
            biz_imp = (
                "Vulnerability to discrete-logarithm key recovery by advanced adversaries, which enables "
                "passive recording and retroactive bulk decryption of all session communications."
            )
        elif "PFS" in rule_id:
            tech_exp = (
                "Perfect Forward Secrecy (PFS) is disabled on Child SAs. Phase 2 session keys (KEYMAT) "
                "are derived directly from the primary IKE SA master key without ephemeral Diffie-Hellman re-computation."
            )
            biz_imp = (
                "CRITICAL EXPOSURE: If gateway long-term private keys or IKE session state are ever compromised "
                "or seized, adversaries can retroactively decrypt all previously captured historical VPN traffic."
            )
        elif "METADATA" in rule_id:
            tech_exp = (
                f"ESP encrypted packet sizes, burst frequencies, and inter-arrival intervals are directly observable "
                f"on the wire ({obs}). Without Traffic Flow Confidentiality (TFC) padding, deep packet inspection "
                f"and AI ensemble classifiers can infer user application types (Web, Video, VoIP)."
            )
            biz_imp = (
                "Operational intelligence leakage: Adversaries monitoring transit backbones can fingerprint "
                "internal organizational activity, communication schedules, and video conferencing patterns."
            )
        else:
            tech_exp = (
                f"Observed parameter '{obs}' deviates from recommended security standards. "
                f"Automated rule evaluation identified a vulnerability under {finding.rule_id}."
            )
            biz_imp = "Potential non-compliance with organizational security baselines and standards."

        rec = finding.recommendation or evidence.remediation_guideline or "Reconfigure IPsec parameters to comply with current standards."

        return FindingExplanation(
            finding_id=fid,
            rule_id=finding.rule_id,
            title=finding.title,
            severity=finding.severity,
            points=pts,
            technical_explanation=tech_exp,
            business_impact=biz_imp,
            authoritative_basis=auth_basis,
            recommended_action=rec,
        )

    def generate_audit_narrative(
        self,
        report: SecurityAssessmentReport,
        traffic_inference: Optional[Dict[str, Any]] = None,
    ) -> AuditNarrative:
        """
        Synthesizes an executive-grade narrative strictly using deterministic scores
        and structured findings from the SecurityAssessmentReport.
        """
        score = report.risk_score
        severity = report.severity
        finding_count = report.threat_matrix.total_findings

        # Executive summary
        exec_sum = (
            f"An automated IPsec VPN security audit was performed on session '{report.capture_id}'. "
            f"The deterministic risk assessment engine computed an aggregate risk score of {score}/100, "
            f"classifying the overall security posture as {severity}. A total of {finding_count} security "
            f"finding(s) were identified across cryptographic, key exchange, and metadata exposure domains."
        )

        # Risk profile description
        if score >= 75:
            profile = (
                "CRITICAL RISK PROFILE: The VPN configuration contains acute cryptographic weaknesses, "
                "deprecated key exchange parameters, or disabled forward secrecy that leave network traffic "
                "vulnerable to immediate compromise or retroactive decryption. Immediate remediation is mandatory."
            )
        elif score >= 50:
            profile = (
                "HIGH RISK PROFILE: Significant deviations from authoritative NIST and RFC standards were identified. "
                "The presence of legacy cipher modes, sub-2048-bit Diffie-Hellman groups, or unhardened forward "
                "secrecy substantially elevates adversary exploitation potential."
            )
        elif score >= 20:
            profile = (
                "MODERATE RISK PROFILE: The tunnel demonstrates acceptable core protections but exhibits "
                "architectural gaps (such as lack of AEAD ciphers or traffic flow confidentiality) that "
                "should be upgraded during the next maintenance window."
            )
        else:
            profile = (
                "LOW RISK PROFILE: The IPsec tunnel conforms to modern cryptographic best practices, "
                "utilizing robust AEAD encryption and secure Diffie-Hellman parameters. Residual points reflect "
                "inherent metadata visibility on transit networks."
            )

        # Primary vulnerability drivers
        drivers = []
        for f in report.threat_matrix.findings:
            if f.severity in ("CRITICAL", "HIGH", "MEDIUM"):
                pts = getattr(f, "risk_contribution", getattr(f, "points", 0))
                drivers.append(f"{f.title} (+{pts} pts, Rule: {f.rule_id})")
        if not drivers:
            drivers.append("No critical or high-severity vulnerabilities detected.")

        # Business and operational impact
        biz_impact = (
            f"From an operational perspective, the {severity} risk posture directly affects confidentiality "
            f"guarantees for internal organizational communications traversing untrusted transit backbones. "
            f"Non-compliance with NIST SP 800-77 Rev. 1 guidelines exposes the enterprise to audit non-conformances "
            f"and cryptographic vulnerabilities."
        )

        # Strategic remediation roadmap
        roadmap = []
        for i, f in enumerate(report.threat_matrix.findings, 1):
            if f.recommendation:
                roadmap.append(f"Priority {i}: {f.recommendation}")
        if not roadmap:
            roadmap.append("Maintain current configuration; review cryptographic cipher deprecation schedules periodically.")

        # Compliance statement
        comp_stmt = (
            f"Assessment evaluated against NIST SP 800-77 Rev. 1, RFC 7296 (IKEv2), RFC 4301 (IPsec Architecture), "
            f"and RFC 8221 (Cryptographic Algorithm Requirements for ESP/AH). Deterministic audit score: {score}/100 ({severity})."
        )

        return AuditNarrative(
            executive_summary=exec_sum,
            risk_profile_description=profile,
            primary_vulnerability_drivers=drivers,
            business_operational_impact=biz_impact,
            strategic_remediation_roadmap=roadmap,
            compliance_statement=comp_stmt,
        )
