"""Statistical machinery for small-sample verdict auditing.

Every function here is deterministic and dependency-free. These are
established estimators, not heuristics:

- Wilson score interval (Wilson 1927) for binomial proportion CIs
- pass^k reliability (tau-bench, Yao et al. 2024) for agent consistency
- exact McNemar test (McNemar 1947) for paired subject comparison
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


def verdict_flip_probability(runs: int, observed_agreements: int) -> tuple[float, float]:
    """Estimate per-run agreement rate with a Wilson interval from runs."""
    low, high = wilson_interval(observed_agreements, runs)
    return (pass_k(runs, low), pass_k(runs, high))


def all_ruling_combinations(verdicts: set[str], runs: int) -> list[tuple[str, ...]]:
    """Enumerate possible ruling sequences, for exhaustive consistency math."""
    return list(product(sorted(verdicts), repeat=runs))
