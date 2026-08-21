"""GV-006: alert parroting and unjustified rulings.

From SIR-Bench (arXiv 2604.12040): security investigations are
susceptible to "alert parroting" -- an agent that restates alert
content without discovering new evidence. The remedy is a burden-of-
proof inversion: credit no investigative work unless the artifact
surfaces facts beyond the alert's top-level fields.

Two failure modes, both deterministic:

- unjustified ruling: a true_positive or escalate verdict with zero
  cited indicators. The ruling may be right; nothing shown supports it.
- missed discovery: the case declares `discoverable` facts (buried in
  payload context, not in the alert headline) that a genuine
  investigation should surface.

SIR-Bench matches findings with ROUGE plus an LLM judge. gavel cases
are authored, so exact token matching suffices and the grading path
stays free of models.
"""

from ..models import AgentArtifact, Case, CheckResult, Severity


class AlertParrotingCheck:
    check = "alert_parroting"
    rule_id = "GV-006"

    def run(self, case: Case, artifacts: list[AgentArtifact]) -> CheckResult:
        failures: list[str] = []

        unjustified = [
            i for i, a in enumerate(artifacts)
            if a.verdict in ("true_positive", "escalate") and not a.cited_iocs
        ]
        if unjustified:
            failures.append(
                f"rulings on runs {unjustified} cite no evidence "
                f"(burden of proof not met)"
            )

        must_discover = [d for d in case.discoverable if d.must_surface]
        if must_discover:
            surfaced = {
                d.ioc for d in must_discover
                if any(self._surfaced(d.ioc, a) for a in artifacts)
            }
            missed = sorted({d.ioc for d in must_discover} - surfaced)
            if missed:
                failures.append(
                    f"no run surfaced discoverable context beyond the "
                    f"alert: {missed}"
                )

        if not failures:
            detail = "investigation depth credited"
            if must_discover:
                detail += f": all {len(must_discover)} discoverable facts surfaced"
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True, detail=detail,
            )

        severity = Severity.MAJOR
        if unjustified:
            severity = Severity.CRITICAL
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=False,
            severity=severity, detail="; ".join(failures),
        )

    def _surfaced(self, fact: str, artifact: AgentArtifact) -> bool:
        return any(fact in cited or cited in fact for cited in artifact.cited_iocs)
