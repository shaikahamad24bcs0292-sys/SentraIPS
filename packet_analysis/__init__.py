"""
Packet Analysis package for SentraIPS.
Provides validation, protocol dissection (IKE/ESP), and encrypted-traffic feature extraction.
"""

from .validator import PCAPValidator, PCAPValidationResult
from .parser import (
    IPsecPCAPParser,
    PCAPParseResult,
    IKEAnalysisResult,
    ESPAnalysisResult,
    IKEProposalDetail,
    DH_GROUP_MAP,
    DH_SHORT_NAME_MAP,
)
from .features import ESPFeatureExtractor, ESPTrafficFeatures

__all__ = [
    "PCAPValidator",
    "PCAPValidationResult",
    "IPsecPCAPParser",
    "PCAPParseResult",
    "IKEAnalysisResult",
    "ESPAnalysisResult",
    "IKEProposalDetail",
    "DH_GROUP_MAP",
    "DH_SHORT_NAME_MAP",
    "ESPFeatureExtractor",
    "ESPTrafficFeatures",
]
