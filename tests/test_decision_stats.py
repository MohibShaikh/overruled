"""Tests for kappa, Brier, expected loss, and SPRT."""

import pytest

from gavel.stats import brier_score, cohens_kappa, expected_loss, sprt_decide


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
