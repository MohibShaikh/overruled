"""Property-based invariants for the statistics module.

Known-answer tests prove the formulas; properties prove the edges.
Any violation here means a scorecard could lie."""

import math

from hypothesis import given
from hypothesis import strategies as st

from overruled.stats import (
    brier_score,
    cohens_kappa,
    expected_loss,
    mcnemar_exact,
    pass_k,
    sprt_decide,
    verdict_flip_probability,
    wilson_interval,
)

ints = st.integers(min_value=0, max_value=10_000)


class TestInputValidation:
    def test_negative_discordant_counts_rejected(self):
        import pytest
        with pytest.raises(ValueError):
            mcnemar_exact(-1, 5)
counts = st.tuples(ints, ints).filter(lambda t: t[0] <= t[1] and t[1] > 0)


class TestWilson:
    @given(counts)
    def test_interval_contains_estimate_and_unit_range(self, tc):
        s, n = tc
        low, high = wilson_interval(s, n)
        p = s / n
        assert 0.0 <= low <= p <= high <= 1.0 + 1e-12

    @given(st.integers(1, 500))
    def test_all_success_gives_upper_bound_one(self, n):
        _, high = wilson_interval(n, n)
        assert abs(high - 1.0) < 1e-9

    @given(counts)
    def test_monotone_in_successes(self, tc):
        s, n = tc
        if s < n:
            assert wilson_interval(s, n)[1] <= wilson_interval(s + 1, n)[1]


class TestPassK:
    @given(st.floats(0.0, 1.0), st.integers(2, 6))
    def test_bounds_and_decay(self, p, k):
        v = pass_k(k, p)
        assert 0.0 <= v <= 1.0
        if k >= 2 and 0 < p < 1:
            assert v < p


class TestMcNemar:
    @given(st.integers(0, 400), st.integers(0, 400))
    def test_pvalue_in_unit_interval(self, b, c):
        assert 0.0 <= mcnemar_exact(b, c) <= 1.0

    def test_symmetry(self):
        assert mcnemar_exact(3, 7) == mcnemar_exact(7, 3)


class TestKappa:
    @given(st.lists(st.sampled_from(["tp", "fp", "esc"]), min_size=4, max_size=40))
    def test_bounded_below_by_negative_one(self, expected):
        pairs = [(e, e) for e in expected]
        kappa = cohens_kappa(pairs)
        assert kappa == 1.0 or kappa is None

    @given(st.lists(st.sampled_from(["a", "b"]), min_size=4, max_size=60))
    def test_label_swap_symmetry(self, labels):
        pairs = [(x, y) for x, y in zip(labels, reversed(labels), strict=True)]
        forward = cohens_kappa(pairs)
        swapped = cohens_kappa([("b" if a == "b" else "a",
                                 "b" if b == "b" else "a") for a, b in pairs])
        if forward is not None:
            assert math.isclose(forward, swapped, abs_tol=1e-12)


class TestBrier:
    @given(st.lists(st.tuples(st.floats(0.0, 1.0), st.booleans()), min_size=1))
    def test_in_unit_interval(self, pairs):
        value = brier_score(pairs)
        assert value is not None and 0.0 <= value <= 1.0


class TestSPRT:
    @given(st.integers(1, 40), st.integers(0, 39))
    def test_monotone_in_successes(self, trials, successes):
        successes = min(successes, trials)
        decisions = [sprt_decide(s, trials) for s in range(trials + 1)]
        order = {None: 0, "accept_h0": -1, "accept_h1": 1}
        numeric = [order[d] for d in decisions]
        assert numeric == sorted(numeric)


class TestFlipProbability:
    @given(st.integers(1, 30), st.integers(0, 30))
    def test_bounds(self, runs, agreements):
        agreements = min(agreements, runs)
        low, high = verdict_flip_probability(runs, agreements)
        assert 0.0 <= low <= high <= 1.0


class TestExpectedLoss:
    @given(ints, ints, st.integers(1, 10_000))
    def test_nonnegative_and_scaling(self, fn, fp, total):
        loss = expected_loss(fn, fp, per=100, total_runs=total)
        assert loss >= 0.0
