"""Orchestrator: run cases against a subject, apply checks, emit a scorecard."""

import httpx

from .checks import ALL_CHECKS
from .checks.metamorphic import MetamorphicCheck, build_variant_event
from .models import (
    ERROR_VERDICT,
    AgentArtifact,
    Case,
    CaseScore,
    ExcludedCase,
    Scorecard,
    Severity,
)
from .stats import sprt_decide
from .subject import Scope, SubjectAdapter


class Auditor:
    def __init__(
        self,
        subject: SubjectAdapter,
        runs_per_case: int = 3,
        adaptive: bool = False,
        map_taxonomy: bool = False,
        tool_version: str = "",
        pack_fingerprint: str = "",
        strict: bool = False,
    ):
        self.subject = subject
        self.runs = max(1, runs_per_case)
        self.adaptive = adaptive
        self.map_taxonomy = map_taxonomy
        self.tool_version = tool_version
        self.pack_fingerprint = pack_fingerprint
        self.strict = strict

    async def run(self, cases: list[Case]) -> Scorecard:
        card = Scorecard(
            subject=self.subject.name,
            tool_version=self.tool_version,
            pack_fingerprint=self.pack_fingerprint,
        )
        for case in cases:
            expected = case.expected_verdict.value
            event = case.event
            if self.map_taxonomy:
                scope, event = self.subject.scope(case.event)
                if scope is Scope.OUT_OF_SCOPE:
                    card.excluded.append(ExcludedCase(
                        case_id=case.id, case_name=case.name,
                        event_type=str(case.event.get("event_type", "")),
                    ))
                    continue
                if scope is Scope.MAPPED:
                    card.mapped_case_ids.append(case.id)
            artifacts = await self._investigate(event, expected=expected)
            variant_artifacts: list[AgentArtifact] = []
            if case.metamorphic:
                variant_event = build_variant_event(case)
                if self.map_taxonomy:
                    _, variant_event = self.subject.scope(variant_event)
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
            try:
                artifact = await self.subject.investigate(event, i + offset)
            except (httpx.HTTPError, TimeoutError):
                artifact = AgentArtifact(verdict=ERROR_VERDICT, run_index=i + offset)
            artifacts.append(artifact)
            if self.adaptive and i + 1 < self.runs:
                gradable = [a for a in artifacts if a.verdict != ERROR_VERDICT]
                if gradable:
                    correct = sum(1 for a in gradable if a.verdict == expected)
                    decision = sprt_decide(correct, len(gradable))
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
        error_runs = sum(1 for a in artifacts if a.verdict == ERROR_VERDICT)
        # MINOR findings are warnings by default; --strict fails the
        # gate on them. Every finding stays visible either way.
        blocking = [
            r for r in results
            if not r.passed and (self.strict or r.severity != Severity.MINOR)
        ]
        return CaseScore(
            case_id=case.id,
            case_name=case.name,
            runs=len(artifacts),
            results=results,
            passed=not blocking,
            verdict_correct_runs=correct,
            expected_verdict=expected,
            rulings=[a.verdict or "none" for a in artifacts],
            confidences=[a.confidence for a in artifacts],
            error_runs=error_runs,
        )
