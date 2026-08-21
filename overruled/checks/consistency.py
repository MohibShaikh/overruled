"""Consistency: same case, N runs, one ruling.

An agent that flips verdicts between runs of an identical event is not
making decisions; it is sampling. Variance is reported as a failure.
"""

from ..models import AgentArtifact, Case, CheckResult, Severity


class ConsistencyCheck:
    check = "consistency"
    rule_id = "OV-004"

    def run(self, case: Case, artifacts: list[AgentArtifact]) -> CheckResult:
        if len(artifacts) < 2:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail="single run, consistency not applicable",
            )
        rulings = {a.verdict or "none" for a in artifacts}
        if len(rulings) == 1:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail=f"identical ruling across {len(artifacts)} runs",
            )
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=False,
            severity=Severity.MAJOR,
            detail=f"{len(rulings)} distinct rulings across "
                   f"{len(artifacts)} identical runs: {sorted(rulings)}",
        )
