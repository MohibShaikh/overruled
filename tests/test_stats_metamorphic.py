"""Tests for stats estimators and metamorphic transforms."""

import pytest

from overruled.metamorphic import apply_transforms, rebrand_domain, rename_user, swap_source_ip
from overruled.stats import mcnemar_exact, pass_k, verdict_flip_probability, wilson_interval


class TestWilson:
    def test_full_success_small_sample_is_wide(self):
        low, high = wilson_interval(3, 3)
        assert low < 0.7
        assert high > 0.6

    def test_half_and_half(self):
        low, high = wilson_interval(5, 10)
        assert low < 0.5 < high

    def test_zero_trials_spans_everything(self):
        assert wilson_interval(0, 0) == (0.0, 1.0)

    def test_never_exceeds_bounds(self):
        for k in range(0, 11):
            low, high = wilson_interval(k, 10)
            assert 0.0 <= low <= high <= 1.0


class TestPassK:
    def test_ninety_percent_three_runs(self):
        assert pass_k(3, 0.9) == pytest.approx(0.729)

    def test_rejects_zero(self):
        with pytest.raises(ValueError):
            pass_k(0, 0.9)


class TestMcNemar:
    def test_all_discordant_one_direction(self):
        assert mcnemar_exact(5, 0) == pytest.approx(0.0625)

    def test_balanced_discordance_is_not_significant(self):
        assert mcnemar_exact(4, 4) == pytest.approx(1.0)

    def test_no_discordance(self):
        assert mcnemar_exact(0, 0) == 1.0

    def test_large_imbalance_is_significant(self):
        assert mcnemar_exact(12, 1) < 0.01


class TestFlipProbability:
    def test_bounds_bracket_point(self):
        low, high = verdict_flip_probability(3, 3)
        assert pass_k(3, low) <= pass_k(3, 1.0)
        assert low <= high


class TestTransforms:
    BASE = {
        "event_type": "login_anomaly",
        "source_ip": "203.0.113.66",
        "target_user": "svc-backup-admin",
        "url": "https://secure-login.example-phish.top/verify",
        "payload": {"nested_ip": "198.51.100.23", "count": 47},
    }

    def test_swap_source_ip_changes_ips_only(self):
        out = swap_source_ip(self.BASE)
        assert out["source_ip"] != self.BASE["source_ip"]
        assert out["payload"]["nested_ip"] != "198.51.100.23"
        assert out["target_user"] == self.BASE["target_user"]
        assert out["payload"]["count"] == 47

    def test_rename_user_preserves_structure(self):
        out = rename_user(self.BASE)
        assert out["target_user"] != "svc-backup-admin"
        assert out["source_ip"] == self.BASE["source_ip"]

    def test_rename_user_reaches_nested_identity_keys(self):
        base = {**self.BASE,
                "payload": {"context": {"account_name": "b.kowalski",
                                        "count": 47}}}
        out = rename_user(base)
        assert out["payload"]["context"]["account_name"] != "b.kowalski"
        assert out["payload"]["context"]["count"] == 47

    def test_rename_user_leaves_non_identity_keys_alone(self):
        base = {"event_type": "login_anomaly", "user_agent": "curl/8.0"}
        out = rename_user(base)
        assert out["user_agent"] == "curl/8.0"

    def test_rebrand_domain_swaps_domains(self):
        out = rebrand_domain(self.BASE)
        assert out["url"] != self.BASE["url"]
        assert ".example.com" in out["url"]

    def test_deterministic(self):
        assert swap_source_ip(self.BASE) == swap_source_ip(self.BASE)

    def test_unknown_transform_raises(self):
        with pytest.raises(ValueError):
            apply_transforms(self.BASE, ["does_not_exist"])


class TestNoOpDetection:
    """A transform that changes nothing tests nothing; the author gets a
    warning instead of false confidence."""

    CASE = {
        "id": "case-noop-001",
        "name": "noop probe",
        "expected_verdict": "true_positive",
        "event": {"event_type": "login_anomaly",
                  "source_ip": "203.0.113.66",
                  "payload": {"count": 3, "window": "3m"}},
        "metamorphic": ["reorder_payload"],
    }
    ARTIFACTS = [{"verdict": "true_positive"}]

    def _run(self, case_overrides):
        from overruled.checks.metamorphic import MetamorphicCheck
        from overruled.models import AgentArtifact, Case

        case = Case.model_validate({**self.CASE, **case_overrides})
        artifacts = [AgentArtifact(verdict="true_positive")]
        return MetamorphicCheck().run(
            case, artifacts, [AgentArtifact(verdict="true_positive")],
        )

    def test_noop_transform_warns_minor(self):
        # reorder_payload touches only payload; this event has none.
        result = self._run({"event": {"event_type": "login_anomaly",
                                      "source_ip": "203.0.113.66"}})
        assert not result.passed
        assert result.severity.value == "minor"

    def test_effective_transform_stays_clean_when_invariant(self):
        result = self._run({})
        assert result is None or result.passed

    def test_flipped_verdict_is_still_major(self):
        from overruled.checks.metamorphic import MetamorphicCheck
        from overruled.models import AgentArtifact, Case

        case = Case.model_validate(self.CASE)
        result = MetamorphicCheck().run(
            case, [AgentArtifact(verdict="true_positive")],
            [AgentArtifact(verdict="false_positive")],
        )
        assert not result.passed
        assert result.severity.value == "major"
