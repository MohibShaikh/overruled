"""Statistical machinery for small-sample verdict auditing.

Every function here is deterministic and dependency-free. These are
established estimators, not heuristics:

- Wilson score interval (Wilson 1927) for binomial proportion CIs
- pass^k reliability (tau-bench, Yao et al. 2024) for agent consistency
- exact McNemar test (McNemar 1947) for paired subject comparison
- Cohen's kappa (1960) for chance-corrected agreement
- Brier score (1950) for confidence calibration
- Wald's SPRT (1945) for adaptive early stopping
"""

import math
from itertools import product

Z_95 = 1.959963984540054


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float]:
    """95% CI on a binomial proportion. Returns (low, high)."""
    if trials <= 0:
        return (0.0, 1.0)
    p = successes / trials
    denom = 1 + z * z / trials
    center = (p + z * z / (2 * trials)) / denom
    spread = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return (max(0.0, center - spread), min(1.0, center + spread))


def pass_k(k: int, per_run_success_prob: float) -> float:
    """Probability that all k independent runs succeed.

    The agent-consistency metric from tau-bench: an agent that passes
    90% of single runs still fails a k=3 gate about a quarter of the
    time. 0.9^3 = 0.729.
    """
    if k <= 0:
        raise ValueError("k must be positive")
    return per_run_success_prob ** k


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value for paired binary outcomes.

    b = cases only subject A passed, c = cases only subject B passed.
    Under the null the signs are fair coin flips: p = 2 * P(X <= min(b,c))
    for X ~ Binomial(b+c, 0.5), capped at 1.
    """
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(0, min(b, c) + 1))
    return min(1.0, 2 * tail / 2 ** n)


def cohens_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Chance-corrected agreement between expected and actual rulings.

    kappa = (p_o - p_e) / (1 - p_e). Plain accuracy overstates agents on
    imbalanced packs: always answering the majority class looks good by
    luck. Returns None when undefined (no pairs or perfect disagreement
    with p_e = 1).
    """
    if not pairs:
        return None
    n = len(pairs)
    p_o = sum(1 for e, a in pairs if e == a) / n
    expected_counts: dict[str, int] = {}
    actual_counts: dict[str, int] = {}
    for e, a in pairs:
        expected_counts[e] = expected_counts.get(e, 0) + 1
        actual_counts[a] = actual_counts.get(a, 0) + 1
    p_e = sum(
        (expected_counts.get(k, 0) / n) * (actual_counts.get(k, 0) / n)
        for k in set(expected_counts) | set(actual_counts)
    )
    if p_e >= 1.0:
        return None
    return (p_o - p_e) / (1 - p_e)


def brier_score(confidence_correct: list[tuple[float, bool]]) -> float | None:
    """Mean squared error of stated confidence against correctness.

    confidence_correct holds (stated_confidence_in_verdict, was_correct).
    A perfectly calibrated agent scores 0.0; always guessing 1.0 scores
    1 - accuracy. Returns None when no confidences were reported.
    """
    if not confidence_correct:
        return None
    return sum((c - o) ** 2 for c, o in confidence_correct) / len(confidence_correct)


def sprt_decide(
    successes: int,
    trials: int,
    p0: float = 0.7,
    p1: float = 0.95,
    alpha: float = 0.05,
    beta: float = 0.05,
) -> str | None:
    """Wald's sequential probability ratio test.

    Returns 'accept_h1' once the evidence supports reliable (>= p1),
    'accept_h0' once it supports unreliable (<= p0), or None to keep
    running. H1 accepted when LLR >= log((1-beta)/alpha); H0 when
    LLR <= log(beta/(1-alpha)).
    """
    if trials < 0:
        raise ValueError("trials must be non-negative")
    llr = successes * math.log(p1 / p0) + (trials - successes) * math.log(
        (1 - p1) / (1 - p0)
    )
    upper = math.log((1 - beta) / alpha)
    lower = math.log(beta / (1 - alpha))
    if llr >= upper:
        return "accept_h1"
    if llr <= lower:
        return "accept_h0"
    return None


def expected_loss(
    false_negatives: int,
    false_positives: int,
    fn_weight: float = 20.0,
    fp_weight: float = 1.0,
    per: int = 100,
    total_runs: int = 100,
) -> float:
    """Loss-weighted score in cost units per `per` alerts.

    Security errors are asymmetric: a missed threat (agent ruled benign
    on malicious ground truth) costs multiples of a false alarm. Default
    20:1 reflects the common practitioner ratio; make it explicit in
    reports so readers can argue the weights instead of the math.
    """
    if total_runs <= 0:
        return 0.0
    scale = per / total_runs
    return (fn_weight * false_negatives + fp_weight * false_positives) * scale


def verdict_flip_probability(runs: int, observed_agreements: int) -> tuple[float, float]:
    """Estimate per-run agreement rate with a Wilson interval from runs."""
    low, high = wilson_interval(observed_agreements, runs)
    return (pass_k(runs, low), pass_k(runs, high))


def all_ruling_combinations(verdicts: set[str], runs: int) -> list[tuple[str, ...]]:
    """Enumerate possible ruling sequences, for exhaustive consistency math."""
    return list(product(sorted(verdicts), repeat=runs))
