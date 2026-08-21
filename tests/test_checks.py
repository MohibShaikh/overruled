"""Unit tests for checks, case loading, and artifact mapping."""

from pathlib import Path

import pytest

from gavel.cases import load_cases
from gavel.checks.consistency import ConsistencyCheck
from gavel.checks.evidence import FabricatedEvidenceCheck, MissedEvidenceCheck
from gavel.checks.verdict import VerdictCheck
from gavel.models import (
    AgentArtifact,
    Case,
    EvidenceItem,
    ExpectedVerdict,
)


def make_case(**overrides):
    base = dict(
        id="t1",
        name="test case",
        event={"event_type": "login_anomaly", "source_ip": "203.0.113.66"},
        expected_verdict=ExpectedVerdict.TRUE_POSITIVE,
        evidence=[EvidenceItem(ioc="203.0.113.66")],
    )
    base.update(overrides)
    return Case.model_validate(base)


class TestVerdictCheck:
    def test_passes_when_all_runs_match(self):
        artifacts = [AgentArtifact(verdict="true_positive") for _ in range(3)]
        assert VerdictCheck().run(make_case(), artifacts).passed

    def test_fails_on_wrong_ruling(self):
        artifacts = [
            AgentArtifact(verdict="true_positive"),
            AgentArtifact(verdict="false_positive"),
        ]
        result = VerdictCheck().run(make_case(), artifacts)
        assert not result.passed
        assert result.rule_id == "GV-001"
        assert result.severity.value == "critical"


class TestFabricatedEvidenceCheck:
    def test_passes_on_planted_citations(self):
        artifact = AgentArtifact(cited_iocs=["203.0.113.66", "login_anomaly"])
        assert FabricatedEvidenceCheck().run(make_case(), [artifact]).passed

    def test_passes_on_attributed_enrichment(self):
        artifact = AgentArtifact(
            cited_iocs=["203.0.113.66", "known-botnet-node.example"],
            enriched_iocs=["known-botnet-node.example"],
        )
        assert FabricatedEvidenceCheck().run(make_case(), [artifact]).passed

    def test_critical_when_enrichment_visible_but_ioc_unknown(self):
        artifact = AgentArtifact(
            cited_iocs=["203.0.113.66", "8.8.8.8"],
            enriched_iocs=["whois.example"],
        )
        result = FabricatedEvidenceCheck().run(make_case(), [artifact])
        assert not result.passed
        assert result.severity.value == "critical"

    def test_minor_warning_without_enrichment_visibility(self):
        artifact = AgentArtifact(cited_iocs=["203.0.113.66", "8.8.8.8"])
        result = FabricatedEvidenceCheck().run(make_case(), [artifact])
        assert not result.passed
        assert result.severity.value == "minor"


class TestMissedEvidenceCheck:
    def test_fails_when_mandatory_evidence_unsurfaced(self):
        result = MissedEvidenceCheck().run(make_case(), [AgentArtifact(cited_iocs=[])])
        assert not result.passed
        assert result.rule_id == "GV-003"

    def test_ignores_optional_evidence(self):
        case = make_case(evidence=[EvidenceItem(ioc="10.0.0.1", must_surface=False)])
        assert MissedEvidenceCheck().run(case, [AgentArtifact()]).passed


class TestConsistencyCheck:
    def test_fails_on_flip_flop(self):
        artifacts = [
            AgentArtifact(verdict="true_positive"),
            AgentArtifact(verdict="false_positive"),
            AgentArtifact(verdict="true_positive"),
        ]
        result = ConsistencyCheck().run(make_case(), artifacts)
        assert not result.passed
        assert result.rule_id == "GV-004"

    def test_single_run_not_applicable(self):
        result = ConsistencyCheck().run(make_case(), [AgentArtifact(verdict="tp")])
        assert result.passed


class TestCaseLoading:
    def test_loads_seed_cases(self):
        cases = load_cases([Path(__file__).parent.parent / "cases"])
        ids = {c.id for c in cases}
        assert {"case-bruteforce-001", "case-benign-001", "case-phishing-001"} <= ids

    def test_missing_cases_raises(self):
        with pytest.raises(FileNotFoundError):
            load_cases([Path("/nonexistent")])
