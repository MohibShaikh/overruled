"""Orchestrator: run cases against a subject, apply checks, emit a scorecard."""

from .checks import ALL_CHECKS
from .models import AgentArtifact, Case, CaseScore, Scorecard
from .subject import SubjectAdapter


class Auditor:
    def __init__(self, subject: SubjectAdapter, runs_per_case: int = 3):
        self.subject = subject
        self.runs = max(1, runs_per_case)

    async def run(self, cases: list[Case]) -> Scorecard:
        card = Scorecard(subject=self.subject.name)
        for case in cases:
            artifacts = await self._investigate(case)
            card.cases.append(self._score(case, artifacts))
        return card

    async def _investigate(self, case: Case) -> list[AgentArtifact]:
        return [await self.subject.investigate(case.event, i) for i in range(self.runs)]

    def _score(self, case: Case, artifacts: list[AgentArtifact]) -> CaseScore:
        results = [check.run(case, artifacts) for check in ALL_CHECKS]
        return CaseScore(
            case_id=case.id,
            case_name=case.name,
            runs=len(artifacts),
            results=results,
            passed=all(r.passed for r in results),
        )
