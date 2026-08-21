"""GV-005: metamorphic invariance.

A verdict that flips under a relation-preserving transform of the
event is anchored to surface features. Declared per case because only
the case author knows which transforms preserve ground truth.
"""

from ..metamorphic import apply_transforms
from ..models import AgentArtifact, Case, CheckResult, Severity


class MetamorphicCheck:
    check = "metamorphic_invariance"
    rule_id = "GV-005"

    def run(
        self,
        case: Case,
        artifacts: list[AgentArtifact],
        transformed_artifacts: list[AgentArtifact] | None = None,
    ) -> CheckResult | None:
        if not case.metamorphic:
            return None
        if not artifacts or not transformed_artifacts:
            return None
        base_rulings = {a.verdict or "none" for a in artifacts}
        variant_rulings = {a.verdict or "none" for a in transformed_artifacts}
        stable = base_rulings & variant_rulings
        if stable and base_rulings <= variant_rulings and variant_rulings <= base_rulings:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail=f"ruling invariant under {case.metamorphic}",
            )
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=False,
            severity=Severity.MAJOR,
            detail=f"verdict flipped under {case.metamorphic}: "
                   f"base {sorted(base_rulings)} vs transformed "
                   f"{sorted(variant_rulings)}",
        )


def build_variant_event(case: Case) -> dict:
    return apply_transforms(case.event, case.metamorphic)
