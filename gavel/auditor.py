"""Orchestrator: run cases against a subject, apply checks, emit a scorecard."""

from .checks import ALL_CHECKS
from .checks.metamorphic import MetamorphicCheck, build_variant_event
from .models import AgentArtifact, Case, CaseScore, Scorecard
from .stats import sprt_decide
from .subject import SubjectAdapter


class Auditor:
    def __init__(
        self,
        subject: SubjectAdapter,
        runs_per_case: int = 3,
        adaptive: bool = False,
    ):
        self.subject = subject
        self.runs = max(1, runs_per_case)
        self.adaptive = adaptive

    async def run(self, cases: list[Case]) -> Scorecard:
        card = Scorecard(subject=self.subject.name)
        for case in cases:
            expected = case.expected_verdict.value
            artifacts = await self._investigate(case.event, expected=expected)
            variant_artifacts: list[AgentArtifact] = []
            if case.metamorphic:
                variant_event = build_variant_event(case)
                variant_artifacts = await self._investigate(
                    variant_event, expected=expected, offset=len(artifacts)
                )
            card.cases.append(self._score(case, artifacts, variant_artifacts))
        return card

    async def _investigate(
        self,
        event: dict,
        expected: str = "",
        offset: int = 0,
    ) -> list[AgentArtifact]:
        """Run the case N times, or until SPRT decides when adaptive.

        SPRT (Wald 1945) stops early once the run record statistically
        supports reliable or unreliable, saving subject API calls.
        """
        artifacts: list[AgentArtifact] = []
        for i in range(self.runs):
            artifacts.append(await self.subject.investigate(event, i + offset))
            if self.adaptive and i + 1 < self.runs:
                correct = sum(1 for a in artifacts if a.verdict == expected)
                decision = sprt_decide(correct, len(artifacts))
                if decision is not None:
                    break
        return artifacts

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
            expected_verdict=expected,
            rulings=[a.verdict or "none" for a in artifacts],
            confidences=[a.confidence for a in artifacts],
        )
