"""Core data model: cases, ground truth, agent artifacts, scorecards."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ExpectedVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    ESCALATE = "escalate"


#: Artifact marker for a run that never produced a ruling: transport
#: failure, 5xx, unreadable body, timeout. Excluded from every estimate
#: because infrastructure noise must not look like the agent's fault.
ERROR_VERDICT = "error"


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
    the ruling overruled grades against.
    """

    id: str
    name: str
    event: dict[str, Any]
    expected_verdict: ExpectedVerdict
    evidence: list[EvidenceItem] = Field(default_factory=list)
    discoverable: list[EvidenceItem] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    metamorphic: list[str] = Field(default_factory=list)
    notes: str = ""


class AgentArtifact(BaseModel):
    """What the subject agent returned for one case run.

    Normalized across agents so checks never see vendor shapes.
    """

    verdict: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    confidence: float | None = None
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
    verdict_correct_runs: int = 0
    expected_verdict: str = ""
    rulings: list[str] = Field(default_factory=list)
    confidences: list[float | None] = Field(default_factory=list)
    error_runs: int = 0

    @property
    def failures(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]

    @property
    def incomplete(self) -> bool:
        """Majority of runs hit infrastructure errors, not the agent."""
        return self.error_runs * 2 > self.runs


class ExcludedCase(BaseModel):
    """A case the subject never claimed to be able to answer.

    Excluded, never coerced into the nearest label, and always reported:
    a score is only honest alongside what it declined to grade.
    """

    case_id: str
    case_name: str
    event_type: str = ""
    reason: str = "outside the subject's declared taxonomy"


class Scorecard(BaseModel):
    subject: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tool_version: str = ""
    pack_fingerprint: str = ""
    cases: list[CaseScore] = Field(default_factory=list)
    excluded: list[ExcludedCase] = Field(default_factory=list)
    mapped_case_ids: list[str] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        """A subject passes by being graded and surviving, not by dodging.

        An empty scorecard is vacuously all-passing, which would let a
        subject clear the gate by declaring a taxonomy that covers none
        of the pack. Nothing graded is not a pass.
        """
        return bool(self.cases) and all(c.passed for c in self.cases)

    @property
    def total_failures(self) -> int:
        return sum(len(c.failures) for c in self.cases)

    @property
    def total_errors(self) -> int:
        return sum(c.error_runs for c in self.cases)

    @property
    def accuracy(self) -> tuple[int, int]:
        """Verdict-correct runs over gradable runs; error runs excluded.

        A transport failure says nothing about the agent, so it counts
        toward neither side.
        """
        correct = sum(c.verdict_correct_runs for c in self.cases)
        total = sum(c.runs - c.error_runs for c in self.cases)
        return (correct, total)

    @property
    def ruling_pairs(self) -> list[tuple[str, str]]:
        """(expected, actual) per gradable run, for kappa and loss math."""
        pairs = []
        for c in self.cases:
            pairs.extend(
                (c.expected_verdict, r) for r in c.rulings if r != ERROR_VERDICT
            )
        return pairs

    @property
    def security_errors(self) -> tuple[int, int]:
        """(false_negatives, false_positives) across all runs.

        FN: malicious ground truth ruled benign. FP: benign ground truth
        ruled malicious. Escalate-expected runs are excluded; they are
        ambiguous by design, not errors either way.
        """
        fn = fp = 0
        for expected, ruling in self.ruling_pairs:
            if expected == "true_positive" and ruling == "false_positive":
                fn += 1
            elif expected == "false_positive" and ruling == "true_positive":
                fp += 1
        return (fn, fp)
