"""Unit tests for checks, case loading, and artifact mapping."""

from pathlib import Path

import pytest

from overruled.cases import bundled_cases, load_cases
from overruled.checks.consistency import ConsistencyCheck
from overruled.checks.evidence import FabricatedEvidenceCheck, MissedEvidenceCheck
from overruled.checks.verdict import VerdictCheck
from overruled.models import (
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
        assert result.rule_id == "OV-001"
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

    @pytest.mark.parametrize("cited", [
        "203.0.113.6",    # one octet short of the planted address
        "203.0.113.660",  # planted address with a digit appended
        "3.0.113.6",      # fragment starting mid-octet
    ])
    def test_near_miss_indicator_is_not_grounded(self, cited):
        """A wrong-digit IP is the classic threat-intel hallucination.
        Substring matching used to wave these through."""
        artifact = AgentArtifact(cited_iocs=[cited], enriched_iocs=["whois.example"])
        result = FabricatedEvidenceCheck().run(make_case(), [artifact])
        assert not result.passed
        assert cited in result.detail

    def test_real_indicator_wrapped_in_context_still_grounded(self):
        """Adding a port to a planted address is annotation, not invention."""
        artifact = AgentArtifact(cited_iocs=["203.0.113.66:445"])
        assert FabricatedEvidenceCheck().run(make_case(), [artifact]).passed

    def test_free_text_citation_grounded_by_whole_token_in_event(self):
        case = make_case(event={"event_type": "process", "payload":
                                {"cmd": "vssadmin delete shadows"}})
        artifact = AgentArtifact(cited_iocs=["vssadmin delete shadows"])
        assert FabricatedEvidenceCheck().run(case, [artifact]).passed


class TestMissedEvidenceCheck:
    def test_fails_when_mandatory_evidence_unsurfaced(self):
        result = MissedEvidenceCheck().run(make_case(), [AgentArtifact(cited_iocs=[])])
        assert not result.passed
        assert result.rule_id == "OV-003"

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
        assert result.rule_id == "OV-004"

    def test_single_run_not_applicable(self):
        result = ConsistencyCheck().run(make_case(), [AgentArtifact(verdict="tp")])
        assert result.passed


class TestCaseLoading:
    def test_loads_seed_cases(self):
        cases = bundled_cases()
        ids = {c.id for c in cases}
        assert {"case-bruteforce-001", "case-benign-001", "case-phishing-001"} <= ids

    def test_missing_cases_raises(self):
        with pytest.raises(FileNotFoundError):
            load_cases([Path("/nonexistent")])


class TestScopeClassification:
    """The mapping is a lever on the subject's score, so out-of-scope has
    to be a real outcome rather than a nudge toward the nearest label."""

    def test_no_declared_taxonomy_means_everything_is_native(self):
        from overruled.subject import JSONAdapter, Scope

        adapter = JSONAdapter("http://x")
        scope, event = adapter.scope({"event_type": "anything_at_all"})
        assert scope is Scope.NATIVE
        assert event == {"event_type": "anything_at_all"}

    def test_declared_type_passes_through_untouched(self):
        from overruled.subject import Scope, ThreatSentinelAdapter

        adapter = ThreatSentinelAdapter("http://x", "t")
        scope, event = adapter.scope({"event_type": "login_anomaly", "payload": {"a": 1}})
        assert scope is Scope.NATIVE
        assert event["event_type"] == "login_anomaly"

    def test_mapped_type_is_translated_without_mutating_the_case(self):
        from overruled.subject import Scope, ThreatSentinelAdapter

        adapter = ThreatSentinelAdapter("http://x", "t")
        original = {"event_type": "network_anomaly", "source_ip": "203.0.113.66"}
        scope, event = adapter.scope(original)
        assert scope is Scope.MAPPED
        assert event["event_type"] == "suspicious_ip"
        assert event["source_ip"] == "203.0.113.66"
        assert original["event_type"] == "network_anomaly"

    def test_uncovered_type_is_excluded_not_coerced(self):
        from overruled.subject import Scope, ThreatSentinelAdapter

        adapter = ThreatSentinelAdapter("http://x", "t")
        for event_type in ("endpoint_anomaly", "cloud_api", "data_exfiltration", "web_attack"):
            scope, event = adapter.scope({"event_type": event_type})
            assert scope is Scope.OUT_OF_SCOPE, event_type
            assert event["event_type"] == event_type
