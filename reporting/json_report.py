"""
JSON Report Serialization Engine for SentraIPS (Phase 5).
Produces clean, validated machine-readable assessment records conforming to Phase 5 schema.
"""

import json
from pathlib import Path
from typing import Any, Dict, Union
from reporting.report_schema import SecurityAssessmentReportUnified


class JSONReportGenerator:
    """
    Serializes SecurityAssessmentReportUnified to structured dictionary and JSON file.
    """

    @staticmethod
    def generate(report: SecurityAssessmentReportUnified) -> Dict[str, Any]:
        """Converts report object to validated JSON-serializable dictionary."""
        return report.model_dump()

    @staticmethod
    def to_json(report: SecurityAssessmentReportUnified, indent: int = 2) -> str:
        """Serializes report object to formatted JSON string."""
        return json.dumps(report.model_dump(), indent=indent, default=str)

    @staticmethod
    def save(
        report: SecurityAssessmentReportUnified,
        output_path: Union[str, Path],
        indent: int = 2,
    ) -> Path:
        """Writes JSON report to target path on disk."""
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        content = JSONReportGenerator.to_json(report, indent=indent)
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)
        return target

    @classmethod
    def save_to_file(
        cls,
        report: SecurityAssessmentReportUnified,
        output_path: Union[str, Path],
        indent: int = 2,
    ) -> str:
        """Writes JSON report to disk and returns serialized string."""
        p = cls.save(report, output_path, indent=indent)
        with open(p, "r", encoding="utf-8") as f:
            return f.read()

