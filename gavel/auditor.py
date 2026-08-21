"""Orchestrator: run cases against a subject, apply checks, emit a scorecard."""

from .checks import ALL_CHECKS
from .checks.metamorphic import MetamorphicCheck, build_variant_event
from .models import AgentArtifact, Case, CaseScore, Scorecard
from .subject import SubjectAdapter


class Auditor:
    def __init__(self, subject: SubjectAdapter, runs_per_case: int = 3):
        self.subject = subject
        self.runs = max(1, runs_per_case)

    async def run(self, cases: list[Case]) -> Scorecard:
        card = Scorecard(subject=self.subject.name)
        for case in cases:
            artifacts = await self._investigate(case.event)
            variant_artifacts: list[AgentArtifact] = []
            if case.metamorphic:
                variant_event = build_variant_event(case)
                variant_artifacts = await self._investigate(variant_event, offset=self.runs)
            card.cases.append(self._score(case, artifacts, variant_artifacts))
        return card

    async def _investigate(self, event: dict, offset: int = 0) -> list[AgentArtifact]:
        return [
            await self.subject.investigate(event, i + offset)
            for i in range(self.runs)
        ]

    def _score(
        self,
        case: Case,
        artifacts: list[AgentArtifact],
        variant_artifacts: list[AgentArtifact],
    ) -> CaseScore:
        results = [check.run(case, artifacts) for check in ALL_CHECKS]
        metamorphic = MetamorphicCheck().run(case, artifacts, variant_artifacts)
        if metamorphic is not None:
            results.append(metamorphic)
        expected = case.expected_verdict.value
        correct = sum(1 for a in artifacts if a.verdict == expected)
        return CaseScore(
            case_id=case.id,
            case_name=case.name,
            runs=len(artifacts),
            results=results,
            passed=all(r.passed for r in results),
            verdict_correct_runs=correct,
        )
