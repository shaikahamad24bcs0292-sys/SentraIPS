"""
Phase 3 Deterministic Risk Scoring Engine for SentraIPS.
Implements a transparent 0-100 risk scoring formula strictly derived from observed findings.
Score bands:
  0-24   : LOW / SECURE
  25-49  : LOW-MEDIUM
  50-74  : MEDIUM
  75-89  : HIGH
  90-100 : CRITICAL
"""

from typing import Any, Dict, List, Tuple
from .schemas import (
    ScoreBreakdownItem,
    SecurityFinding,
    SubScores,
)


class RiskScoringEngine:
    """Transparent and explainable risk calculation engine."""

    # Explicit Phase 3 scoring thresholds
    SCORE_BANDS = [
        (0, 24, "LOW"),
        (25, 49, "LOW-MEDIUM"),
        (50, 74, "MEDIUM"),
        (75, 89, "HIGH"),
        (90, 100, "CRITICAL"),
    ]

    def __init__(self, min_score: int = 0, max_score: int = 100):
        self.min_score = min_score
        self.max_score = max_score

    def map_severity(self, score: int) -> str:
        """Maps numeric risk score to qualitative severity band."""
        for low, high, label in self.SCORE_BANDS:
            if low <= score <= high:
                return label
        if score < 0:
            return "LOW"
        return "CRITICAL"

    def calculate(
        self,
        findings: List[SecurityFinding],
    ) -> Dict[str, Any]:
        """
        Calculates explainable risk score, sub-scores, and itemized breakdown from findings.
        Returns:
            {
                "risk_score": int,
                "severity": str,
                "score_breakdown": List[ScoreBreakdownItem],
                "sub_scores": SubScores,
                "findings": List[SecurityFinding],
            }
        """
        score_breakdown: List[ScoreBreakdownItem] = []
        sub_crypto = 0
        sub_ke = 0
        sub_cfg = 0
        sub_meta = 0

        for f in findings:
            pts = getattr(f, "risk_contribution", 0)
            cat = (getattr(f, "category", "") or "").upper()
            rule_id = getattr(f, "rule_id", f.id)

            if pts > 0:
                score_breakdown.append(
                    ScoreBreakdownItem(
                        finding_id=f.id,
                        rule_id=rule_id,
                        title=f.title,
                        severity=f.severity,
                        points=pts,
                        category=f.category,
                        reason=f.description,
                    )
                )

            # Accumulate domain sub-scores
            if "CRYPTO" in cat:
                sub_crypto += pts
            elif "KEY" in cat or "DH" in cat:
                sub_ke += pts
            elif "PROTOCOL" in cat or "SA" in cat or "CONFIG" in cat:
                sub_cfg += pts
            elif "METADATA" in cat or "TRAFFIC" in cat:
                sub_meta += pts
            else:
                sub_cfg += pts

        raw_score = sum(item.points for item in score_breakdown)
        normalized_score = max(self.min_score, min(self.max_score, raw_score))
        severity = self.map_severity(normalized_score)

        sub_scores = SubScores(
            crypto_risk=sub_crypto,
            key_exchange_risk=sub_ke,
            configuration_risk=sub_cfg,
            metadata_exposure_risk=sub_meta,
        )

        return {
            "risk_score": normalized_score,
            "severity": severity,
            "score_breakdown": score_breakdown,
            "sub_scores": sub_scores,
            "findings": findings,
        }
