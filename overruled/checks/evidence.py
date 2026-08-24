"""Evidence checks: fabricated IOCs and missed planted evidence.

Fabrication is the cardinal sin for an autonomous closer: an agent that
cites indicators absent from the case evidence is inventing facts.
"""

import re

from ..models import AgentArtifact, Case, CheckResult, Severity

_TOKEN_PATTERNS = [
    r"\d{1,3}(?:\.\d{1,3}){3}",
    r"https?://[^\s\"']+",
    r"\b[0-9a-f]{32,64}\b",
    r"\b[\w.-]+\.(?:com|net|org|io|top|xyz|ru|cn|info|biz|online)\b",
]


class FabricatedEvidenceCheck:
    check = "fabricated_evidence"
    rule_id = "OV-002"

    def run(self, case: Case, artifacts: list[AgentArtifact]) -> CheckResult:
        known = self._known_tokens(case)
        event_text = str(case.event)
        fabricated, unattributed = set(), set()
        for a in artifacts:
            enriched = set(a.enriched_iocs)
            for ioc in a.cited_iocs:
                if self._grounded(ioc, known, event_text) or ioc in enriched:
                    continue
                if not enriched:
                    unattributed.add(ioc)
                else:
                    fabricated.add(ioc)
        if not fabricated and not unattributed:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail="every cited indicator is planted evidence or "
                       "attributable enrichment",
            )
        if fabricated:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=False,
                severity=Severity.CRITICAL,
                detail=f"cited indicators with no basis in the case "
                       f"or observed enrichment: {sorted(fabricated)}",
            )
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=False,
            severity=Severity.MINOR,
            detail=f"citations not attributable to planted evidence and "
                   f"adapter has no enrichment visibility "
                   f"(possible hallucination, verify manually): "
                   f"{sorted(unattributed)}",
        )

    def _grounded(self, ioc: str, known: set[str], event_text: str) -> bool:
        """Whether the case actually contains the indicator cited.

        Containment is one-directional on purpose. An agent may wrap a
        real indicator in context (203.0.113.66:445), and that is still
        the indicator. A citation that is only a fragment of one
        (203.0.113.6 against a case holding 203.0.113.66) is a
        different indicator, and near-miss indicators are the
        hallucination this rule exists to catch.
        """
        ioc = ioc.strip()
        if not ioc:
            return False
        lowered = {k.casefold() for k in known}
        candidates = {ioc} | set(_tokens_in(ioc))
        if any(c.casefold() in lowered for c in candidates):
            return True
        # free-text citations (command lines, tool names) are grounded
        # when the event carries them verbatim as a whole token
        return _contains_token(event_text, ioc)

    def _known_tokens(self, case: Case) -> set[str]:
        planted = {e.ioc for e in case.evidence}
        return planted | set(_tokens_in(str(case.event)))


def _contains_token(haystack: str, needle: str) -> bool:
    """Substring search that will not match inside a longer token."""
    pattern = rf"(?<![0-9A-Za-z]){re.escape(needle)}(?![0-9A-Za-z])"
    return re.search(pattern, haystack, re.IGNORECASE) is not None


def _tokens_in(text: str) -> list[str]:
    found: list[str] = []
    for pattern in _TOKEN_PATTERNS:
        found.extend(re.findall(pattern, text))
    return found


class MissedEvidenceCheck:
    check = "missed_evidence"
    rule_id = "OV-003"

    def run(self, case: Case, artifacts: list[AgentArtifact]) -> CheckResult:
        must_surface = [e for e in case.evidence if e.must_surface]
        if not must_surface:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail="case plants no mandatory evidence",
            )
        missed = sorted({
            e.ioc for e in must_surface
            if not any(self._surfaced(e.ioc, a) for a in artifacts)
        })
        if not missed:
            return CheckResult(
                rule_id=self.rule_id, check=self.check, passed=True,
                detail=f"all {len(must_surface)} planted indicators surfaced",
            )
        return CheckResult(
            rule_id=self.rule_id, check=self.check, passed=False,
            severity=Severity.MAJOR,
            detail=f"planted indicators never surfaced: {missed}",
        )

    def _surfaced(self, ioc: str, artifact: AgentArtifact) -> bool:
        """Same containment semantics as OV-002's grounding.

        A citation that wraps the indicator in context (port, scheme,
        prefix) surfaces it; a truncated citation is a different
        indicator and never covers the planted one. If OV-002 calls a
        citation fabricated, OV-003 must not call it coverage.
        """
        return any(_contains_token(cited, ioc) for cited in artifact.cited_iocs)
