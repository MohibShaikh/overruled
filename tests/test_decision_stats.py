"""Tests for kappa, Brier, expected loss, and SPRT."""

import pytest

from overruled.checks.parroting import AlertParrotingCheck
from overruled.metamorphic import TRANSFORMS, reformat_numbers, reorder_payload
from overruled.models import AgentArtifact, Case, EvidenceItem, Severity
from overruled.stats import brier_score, cohens_kappa, expected_loss, sprt_decide


class TestKappa:
    def test_perfect_agreement(self):
        pairs = [("tp", "tp")] * 5 + [("fp", "fp")] * 5
        assert cohens_kappa(pairs) == pytest.approx(1.0)

    def test_majority_class_bias_scores_low(self):
        # Agent always says tp on a 90% tp pack: high accuracy, low kappa.
        pairs = [("tp", "tp")] * 9 + [("fp", "tp")]
        kappa = cohens_kappa(pairs)
        assert 0.0 <= kappa < 0.3

    def test_chance_agreement_is_zero(self):
        pairs = [("a", "a"), ("a", "b"), ("b", "a"), ("b", "b")]
        assert cohens_kappa(pairs) == pytest.approx(0.0)

    def test_empty_is_none(self):
        assert cohens_kappa([]) is None


class TestBrier:
    def test_perfectly_calibrated(self):
        pairs = [(1.0, True), (0.0, False)]
        assert brier_score(pairs) == pytest.approx(0.0)

    def test_worst_possible(self):
        pairs = [(1.0, False), (0.0, True)]
        assert brier_score(pairs) == pytest.approx(1.0)

    def test_overconfident_wrong_hurts(self):
        pairs = [(1.0, False), (0.6, True)]
        score = brier_score(pairs)
        assert score > 0.25

    def test_no_confidences_is_none(self):
        assert brier_score([]) is None


class TestExpectedLoss:
    def test_asymmetric_weights(self):
        loss = expected_loss(false_negatives=2, false_positives=10,
                             fn_weight=20, fp_weight=1, total_runs=100)
        assert loss == pytest.approx(50.0)

    def test_scales_to_per_alerts(self):
        loss = expected_loss(1, 0, total_runs=50)
        assert loss == pytest.approx(40.0)

    def test_zero_runs(self):
        assert expected_loss(0, 0, total_runs=0) == 0.0


class TestSPRT:
    def test_all_correct_accepts_reliable(self):
        # Ten clean runs at alpha=beta=0.05 clears log(19) ~ 2.94.
        assert sprt_decide(successes=10, trials=10) == "accept_h1"

    def test_three_clean_runs_not_enough(self):
        assert sprt_decide(successes=3, trials=3) is None

    def test_all_wrong_accepts_unreliable(self):
        assert sprt_decide(successes=0, trials=3) == "accept_h0"

    def test_undecided_keeps_running(self):
        assert sprt_decide(successes=1, trials=2) is None

    def test_negative_trials_raises(self):
        with pytest.raises(ValueError):
            sprt_decide(0, -1)


class TestAlertParroting:
    def _case(self, discoverable=None):
        return Case(
            id="t", name="t", event={"source_ip": "1.2.3.4"},
            expected_verdict="true_positive",
            evidence=[EvidenceItem(ioc="1.2.3.4", kind="ip")],
            discoverable=discoverable or [],
        )

    def _artifact(self, verdict="true_positive", cited=("1.2.3.4",)):
        return AgentArtifact(
            verdict=verdict, cited_iocs=list(cited),
        )

    def test_unjustified_tp_is_critical(self):
        result = AlertParrotingCheck().run(self._case(), [self._artifact(cited=())])
        assert not result.passed
        assert result.severity == Severity.CRITICAL

    def test_cited_tp_passes(self):
        result = AlertParrotingCheck().run(self._case(), [self._artifact()])
        assert result.passed

    def test_fp_verdict_needs_no_evidence(self):
        case = self._case()
        case.expected_verdict = "false_positive"
        artifact = AgentArtifact(verdict="false_positive", cited_iocs=[])
        result = AlertParrotingCheck().run(case, [artifact])
        assert result.passed

    def test_missed_discovery_is_major(self):
        disc = EvidenceItem(ioc="svc-backup-admin", kind="account")
        result = AlertParrotingCheck().run(
            self._case(discoverable=[disc]), [self._artifact()],
        )
        assert not result.passed
        assert result.severity == Severity.MAJOR

    def test_discovery_surfaced_passes(self):
        disc = EvidenceItem(ioc="svc-backup-admin", kind="account")
        artifact = AgentArtifact(
            verdict="true_positive",
            cited_iocs=["1.2.3.4", "svc-backup-admin"],
        )
        result = AlertParrotingCheck().run(
            self._case(discoverable=[disc]), [artifact],
        )
        assert result.passed

    def test_no_discoverable_declared_passes_clean(self):
        result = AlertParrotingCheck().run(self._case(), [self._artifact()])
        assert "investigation depth credited" in result.detail


class TestFormatTransforms:
    def test_reorder_payload_reverses_keys(self):
        event = {"payload": {"a": 1, "b": 2, "c": 3}}
        out = reorder_payload(event)
        assert list(out["payload"]) == ["c", "b", "a"]
        assert out["payload"]["a"] == 1
        assert list(event["payload"]) == ["a", "b", "c"]

    def test_reformat_numbers_adds_separators(self):
        event = {"payload": {"count": 5000, "small": 42, "flag": True}}
        out = reformat_numbers(event)
        assert out["payload"]["count"] == "5,000"
        assert out["payload"]["small"] == 42
        assert out["payload"]["flag"] is True

    def test_transforms_registered(self):
        for name in ("reorder_payload", "reformat_numbers"):
            assert name in TRANSFORMS


class TestDiscoverableValidation:
    def _write(self, tmp_path, event, disc="svc-x"):
        case = f"""
id: t1
name: t
expected_verdict: true_positive
discoverable:
- ioc: {disc}
  kind: account
event: {event}
"""
        p = tmp_path / "t.yaml"
        p.write_text(case)
        return p

    def test_headline_discoverable_rejected(self, tmp_path):
        from overruled.cases import load_case
        p = self._write(tmp_path, {"user": "svc-x", "payload": {"n": 1}})
        with pytest.raises(ValueError, match="headline"):
            load_case(p)

    def test_nested_discoverable_accepted(self, tmp_path):
        from overruled.cases import load_case
        p = self._write(tmp_path, {"source_ip": "1.2.3.4", "payload": {"user": "svc-x"}})
        assert load_case(p).discoverable[0].ioc == "svc-x"

    def test_ungrounded_discoverable_rejected(self, tmp_path):
        from overruled.cases import load_case
        p = self._write(tmp_path, {"source_ip": "1.2.3.4", "payload": {"n": 1}})
        with pytest.raises(ValueError, match="not grounded"):
            load_case(p)
