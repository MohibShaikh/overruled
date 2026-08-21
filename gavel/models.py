"""Core data model: cases, ground truth, agent artifacts, scorecards."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ExpectedVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    ESCALATE = "escalate"


class Severity(StrEnum):
    INFO = "info"
    MINOR = "minor"
    MAJOR = "major"
    CRITICAL = "critical"


class EvidenceItem(BaseModel):
    """A fact planted in the case that a correct agent should surface."""

    ioc: str
    kind: str = "indicator"
    description: str = ""
    must_surface: bool = True


class Case(BaseModel):
    """A security scenario with known ground truth.

    `event` is what gets fed to the subject agent. `evidence` lists the
    facts a competent investigation should find. `expected_verdict` is
    the ruling gavel grades against.
    """

    id: str
    name: str
    event: dict[str, Any]
    expected_verdict: ExpectedVerdict
    evidence: list[EvidenceItem] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    notes: str = ""


class AgentArtifact(BaseModel):
    """What the subject agent returned for one case run.

    Normalized across agents so checks never see vendor shapes.
    """

    verdict: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    cited_iocs: list[str] = Field(default_factory=list)
    enriched_iocs: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    escalated_for_human: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)
    run_index: int = 0
    duration_ms: int = 0


class CheckResult(BaseModel):
    rule_id: str
    check: str
    passed: bool
    severity: Severity = Severity.MINOR
    detail: str = ""


class CaseScore(BaseModel):
    case_id: str
    case_name: str
    runs: int
    results: list[CheckResult]
    passed: bool

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]


class Scorecard(BaseModel):
    subject: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    cases: list[CaseScore] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed for c in self.cases)

    @property
    def total_failures(self) -> int:
        return sum(len(c.failures) for c in self.cases)
