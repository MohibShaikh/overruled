"""Verdict correctness: did the agent rule the case as ground truth does?"""

from ..models import ERROR_VERDICT, AgentArtifact, Case, CheckResult, Severity


class VerdictCheck:
    check = "verdict"
    rule_id = "OV-001"

    def run(self, case: Case, artifacts: list[AgentArtifact]) -> CheckResult:
        expected = case.expected_verdict.value
        gradable = [a for a in artifacts if a.verdict != ERROR_VERDICT]
        if not gradable:
            # Transport noise is not a ruling -- but dodging by erroring
            # on every run must not pass either.
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=False,
                severity=Severity.MAJOR,
                detail="no gradable runs (all ended in infrastructure "
                       "errors); the case was not measured",
            )
        wrong = [a for a in gradable if a.verdict != expected]
        if not wrong:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail=f"{len(gradable)}/{len(gradable)} runs ruled {expected}",
            )
        rulings = {a.verdict or "none" for a in wrong}
        errored = len(artifacts) - len(gradable)
        suffix = f" (+{errored} infrastructure-error run(s) excluded)" if errored else ""
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=False,
            severity=Severity.CRITICAL,
            detail=f"expected {expected}, got {sorted(rulings)} on "
                   f"{len(wrong)}/{len(gradable)} runs{suffix}",
        )
