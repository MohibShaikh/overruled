"""Check registry."""

from .consistency import ConsistencyCheck
from .evidence import FabricatedEvidenceCheck, MissedEvidenceCheck
from .verdict import VerdictCheck

ALL_CHECKS = [
    VerdictCheck(),
    FabricatedEvidenceCheck(),
    MissedEvidenceCheck(),
    ConsistencyCheck(),
]
