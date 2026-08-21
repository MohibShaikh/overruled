"""Check registry."""

from .consistency import ConsistencyCheck
from .evidence import FabricatedEvidenceCheck, MissedEvidenceCheck
from .parroting import AlertParrotingCheck
from .verdict import VerdictCheck

ALL_CHECKS = [
    VerdictCheck(),
    FabricatedEvidenceCheck(),
    MissedEvidenceCheck(),
    ConsistencyCheck(),
    AlertParrotingCheck(),
]
