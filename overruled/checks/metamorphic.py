"""OV-005: metamorphic invariance.

A verdict that flips under a relation-preserving transform of the
event is anchored to surface features. Declared per case because only
the case author knows which transforms preserve ground truth.
"""

import json

from ..metamorphic import apply_transforms
from ..models import ERROR_VERDICT, AgentArtifact, Case, CheckResult, Severity


class MetamorphicCheck:
    check = "metamorphic_invariance"
    rule_id = "OV-005"

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
        base_rulings = {a.verdict for a in artifacts if a.verdict != ERROR_VERDICT}
        variant_rulings = {a.verdict for a in transformed_artifacts
                           if a.verdict != ERROR_VERDICT}
        # Infrastructure noise on both sides tests nothing about the
        # agent; asymmetric errors (base errors, variant succeeds) are
        # also infra, not a flip-flop.
        if not base_rulings or not variant_rulings:
            return None
        stable = base_rulings & variant_rulings
        if not (stable and base_rulings <= variant_rulings
                and variant_rulings <= base_rulings):
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=False,
                severity=Severity.MAJOR,
                detail=f"verdict flipped under {case.metamorphic}: "
                       f"base {sorted(base_rulings)} vs transformed "
                       f"{sorted(variant_rulings)}",
            )
        # Compared as serialized JSON, not dicts: reorder_payload works
        # precisely by changing what the agent sees on the wire, which
        # dict equality cannot see. Fully deterministic off the case.
        def changes_anything(transform: str) -> bool:
            variant = apply_transforms(case.event, [transform])
            return json.dumps(variant) != json.dumps(case.event)

        no_ops = [t for t in case.metamorphic if not changes_anything(t)]
        if no_ops:
            # An invariance that changed nothing was never tested. The
            # author declared a transform their own event ignores.
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=False,
                severity=Severity.MINOR,
                detail=f"ruling invariant under {case.metamorphic}, but "
                       f"{no_ops} change nothing in this event; declare "
                       f"transforms that touch ground-truth-bearing fields",
            )
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=True,
            detail=f"ruling invariant under {case.metamorphic}",
        )


def build_variant_event(case: Case) -> dict:
    return apply_transforms(case.event, case.metamorphic)
