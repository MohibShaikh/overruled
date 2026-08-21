# gavel

The verdict auditor for AI SOC agents.

AI agents now close security alerts autonomously. When one closes an alert,
two questions go unanswered: was the close correct, and is the agent inventing
its reasoning. Vendors grade themselves. gavel grades them for you.

It replays cases with known ground truth against any agent that speaks HTTP,
then checks the agent's verdicts for correctness, evidence fabrication, missed
evidence, and consistency across runs. Exit code 1 on failure, so it gates
deployments like any other CI step.

## Why

Top LLMs score 61-67% on autonomous triage benchmarks. A third of verdicts
wrong, and nobody measures which third until after the breach. Gartner: 70%
of SOCs will pilot AI agents, 15% will see results. The gap between piloting
and trusting is unmeasured verdict quality. gavel is the measurement.

## Install

```
pip install gavel-audit
```

The distribution is `gavel-audit`; the command is `gavel`. For development:

```
pip install -e ".[dev]"
```

## Use

Audit a subject agent:

```
gavel run cases/ --url https://agent.example.com --token "$TOKEN" --runs 3
```

Gate a pipeline (JUnit for CI dashboards):

```
gavel run cases/ --url "$AGENT_URL" --format junit --out gavel.xml
```

Findings into existing dashboards (SARIF):

```
gavel run cases/ --url "$AGENT_URL" --format sarif --out gavel.sarif
```

Compare two vendors on the same case pack before you sign either contract:

```
gavel compare cases/ \
  --subject incumbent=https://a.example.com \
  --subject candidate=https://b.example.com
```

## Checks

| Rule | Check | Severity | Question |
|---|---|---|---|
| GV-001 | verdict | critical | Did the agent rule what ground truth says is correct? |
| GV-002 | fabricated_evidence | critical | Are cited indicators real facts from the case or observed enrichment? |
| GV-003 | missed_evidence | major | Did it surface the planted indicators a competent investigator would find? |
| GV-004 | consistency | major | Same case, N runs, same ruling? |
| GV-005 | metamorphic_invariance | major | Does the ruling survive a cosmetic change that preserves ground truth? |
| GV-006 | alert_parroting | critical/major | Did a TP ruling cite any evidence at all? Did the agent surface facts buried in payload context, or only restate the alert headline? |

## Methods

The statistics are established estimators, not invented heuristics:

- **Wilson score intervals** (Wilson 1927) on verdict accuracy. A subject
  that passes 27 of 30 runs is reported as a range, never a bare percentage.
- **pass^k reliability** (tau-bench, Yao et al. 2024) bounds per-case
  reliability across repeated runs. An agent that is right 90% of single
  runs still fails a three-run gate about a quarter of the time.
- **Exact McNemar test** (McNemar 1947) in `gavel compare`. When one vendor
  beats another, gavel reports whether the difference is significant at
  0.05 or procurement noise.
- **Cohen's kappa** (1960): chance-corrected agreement. An agent that
  always answers the majority class looks accurate by luck; kappa does not
  let it. Below 0.6 gavel labels agreement poor.
- **Brier score** (1950) on stated confidence: mean squared error between
  how sure the agent sounded and whether it was right. Overconfident wrong
  verdicts are the expensive ones.
- **Expected loss** (Neyman-Pearson decision theory): security errors are
  asymmetric, so scorecards report loss-weighted cost per 100 alerts at an
  explicit 20:1 missed-threat-to-false-alarm weight. Argue the weights,
  not the math.
- **SPRT adaptive stopping** (Wald 1945): `--adaptive` stops re-running a
  case once the record statistically supports reliable or unreliable,
  instead of burning fixed N subject calls.
- **Metamorphic testing** (Chen et al.): cases declare which cosmetic
  transforms preserve their ground truth (`metamorphic: [rename_user]`).
  A flipped verdict means the agent pattern-matched surface features.
- **Alert parroting detection** (SIR-Bench, arXiv 2604.12040): burden of
  proof inverted. A true-positive ruling with zero cited evidence is
  flagged no matter how right it looks, and cases can declare facts that
  sit nested in payload context; an agent that never surfaces them is
  restating the alert headline, not investigating. Where SIR-Bench needs
  ROUGE plus an LLM judge, gavel cases are authored so exact matching
  keeps the grading path model-free.

No LLM participates in any check. Same inputs, same findings, every run.

## Trust properties

Stated plainly, because an auditor that asks for trust has already failed.

- **No LLM in the grading path.** All checks are deterministic set and string
  logic over normalized artifacts. Same inputs, same findings, every time.
- **Local-first.** Cases and evidence stay in your environment. gavel calls
  your agent; nothing calls home. No telemetry.
- **Reproducible.** Cases are versioned YAML in git. Scorecards are plain
  JSON/markdown/SARIF/JUnit you can archive and diff.
- **Honest epistemics.** If the adapter cannot see an agent's enrichment
  calls, unverifiable citations are reported as warnings (possible
  hallucination, verify manually), not as proven fabrication. GV-002 only
  goes critical when enrichment was visible and the citation still has no
  basis.
- **Documented limitations.** See below.

## Limitations

- Verdict mapping assumes the common escalate/true-positive/false-positive
  vocabulary. Agents with exotic taxonomies need adapter work.
- Fabrication detection is only as good as adapter visibility. An agent that
  hides its tool calls can only be warned about, not convicted.
- Case quality bounds audit quality. Ground truth in `cases/` reflects the
  judgment of whoever wrote them; contest it in a pull request, not in a
  breach postmortem.
- Consistency checking sends each case N times. Budget for that load.

## Writing cases

A case is three things: the event to feed the agent, the evidence planted in
it, and the ruling a correct agent should produce.

```yaml
id: case-bruteforce-001
name: Brute force against privileged account
expected_verdict: true_positive
mitre_attack: [T1110]
event:
  event_type: login_anomaly
  source_ip: 203.0.113.66
  payload:
    failed_login_attempts: 47
evidence:
  - ioc: 203.0.113.66
    kind: ip
    must_surface: true
```

The case library is the product. Contribute scenarios from your own redacted
alerts; contested ground truth belongs in pull requests.

## License

MIT
