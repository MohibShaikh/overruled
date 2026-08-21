"""Verdict correctness: did the agent rule the case as ground truth does?"""

from ..models import AgentArtifact, Case, CheckResult, Severity


class VerdictCheck:
    check = "verdict"
    rule_id = "GV-001"

    def run(self, case: Case, artifacts: list[AgentArtifact]) -> CheckResult:
        expected = case.expected_verdict.value
        wrong = [a for a in artifacts if a.verdict != expected]
        if not wrong:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail=f"{len(artifacts)}/{len(artifacts)} runs ruled {expected}",
            )
        rulings = {a.verdict or "none" for a in wrong}
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=False,
            severity=Severity.CRITICAL,
            detail=f"expected {expected}, got {sorted(rulings)} on "
                   f"{len(wrong)}/{len(artifacts)} runs",
        )
