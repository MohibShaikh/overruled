# overruled

Verdicts are claims. We overrule the wrong ones.

AI agents now close security alerts autonomously. When one closes an alert,
two questions go unanswered: was the close correct, and is the agent inventing
its reasoning. Vendors grade themselves. overruled grades them for you, then
returns its own ruling: SUBJECT PASSES or SUBJECT OVERRULED.

It replays cases with known ground truth against any agent that speaks HTTP,
then checks the agent's verdicts for correctness, evidence fabrication, missed
evidence, and consistency across runs. Exit code 1 on failure, so it gates
deployments like any other CI step.

## Why

Top LLMs score 61-67% on autonomous triage benchmarks. A third of verdicts
wrong, and nobody measures which third until after the breach. Gartner: 70%
of SOCs will pilot AI agents, 15% will see results. The gap between piloting
and trusting is unmeasured verdict quality. overruled is the measurement.

## Install

```
pip install overruled
```
 For development:

```
pip install -e ".[dev]"
```

## Try it without an agent

Two mock subjects ship with the repo, so you can read a scorecard before
wiring up anything real. The broken one closes every alert as benign,
which is the failure mode nobody catches in production:

```
python -m mocks --agent broken --port 9102
overruled run cases/ --adapter json --url http://127.0.0.1:9102 --runs 1
```

```
SUBJECT FAILS (62 finding(s))
Verdict accuracy 21/50 (42%, 95% CI 29%-56%), kappa 0.00 (poor),
expected loss 880.0 units/100 alerts (FN weight 20:1, 22 missed threats,
0 false alarms)
```

42% from an agent that investigates nothing. A pack with this much benign
traffic hands that out for free, which is why accuracy alone proves
nothing. Kappa 0.00 is the tell: agreement no better than chance.

The reference mock is rule-based and cites the indicators it finds. It
passes the cases it was written against:

```
python -m mocks --agent reference --port 9101
overruled run cases/brute_force.yaml cases/case-pth-lateral.yaml \
  cases/case-fp-cert-window.yaml cases/case-esc-exit-delete.yaml \
  --adapter json --url http://127.0.0.1:9101 --runs 2
```

Both mocks back the differential self-test in CI: overruled must pass the
reference and convict the broken one on the same cases, or overruled
itself is not measuring anything.

## Use

Audit a subject agent:

```
overruled run cases/ --url https://agent.example.com --token "$TOKEN" --runs 3
```

`--adapter` picks the subject contract. The default `threatsentinel`
speaks that REST shape; `--adapter json` POSTs `{"event_data": event}`
and reads back `{"verdict", "cited_iocs", "confidence"}`. Anything else
needs a `SubjectAdapter` subclass, which is about thirty lines.

Gate a pipeline (JUnit for CI dashboards):

```
overruled run cases/ --url "$AGENT_URL" --format junit --out overruled.xml
```

Findings into existing dashboards (SARIF):

```
overruled run cases/ --url "$AGENT_URL" --format sarif --out overruled.sarif
```

Compare two vendors on the same case pack before you sign either contract:

```
overruled compare cases/ \
  --subject incumbent=https://a.example.com \
  --subject candidate=https://b.example.com
```

Per-case PASS/FAIL for each subject, plus an exact McNemar test on the
discordant cases so a two-point lead does not get mistaken for a better
agent.

## Checks

| Rule | Check | Severity | Question |
|---|---|---|---|
| OV-001 | verdict | critical | Did the agent rule what ground truth says is correct? |
| OV-002 | fabricated_evidence | critical | Are cited indicators real facts from the case or observed enrichment? |
| OV-003 | missed_evidence | major | Did it surface the planted indicators a competent investigator would find? |
| OV-004 | consistency | major | Same case, N runs, same ruling? |
| OV-005 | metamorphic_invariance | major | Does the ruling survive a cosmetic change that preserves ground truth? |
| OV-006 | alert_parroting | critical/major | Did a TP ruling cite any evidence at all? Did the agent surface facts buried in payload context, or only restate the alert headline? |

## Methods

The statistics are established estimators, not invented heuristics:

- **Wilson score intervals** (Wilson 1927) on verdict accuracy. A subject
  that passes 27 of 30 runs is reported as a range, never a bare percentage.
- **pass^k reliability** (tau-bench, Yao et al. 2024) bounds per-case
  reliability across repeated runs. An agent that is right 90% of single
  runs still fails a three-run gate about a quarter of the time.
- **Exact McNemar test** (McNemar 1947) on paired case outcomes. When one
  agent beats another, overruled reports whether the difference is
  significant at 0.05 or procurement noise.
- **Cohen's kappa** (1960): chance-corrected agreement. An agent that
  always answers the majority class looks accurate by luck; kappa does not
  let it. Below 0.6 overruled labels agreement poor.
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
  ROUGE plus an LLM judge, overruled cases are authored so exact matching
  keeps the grading path model-free.

No LLM participates in any check. Same inputs, same findings, every run.

## Trust properties

Stated plainly, because an auditor that asks for trust has already failed.

- **No LLM in the grading path.** All checks are deterministic set and string
  logic over normalized artifacts. Same inputs, same findings, every time.
- **Local-first.** Cases and evidence stay in your environment. overruled calls
  your agent; nothing calls home. No telemetry.
- **Reproducible.** Cases are versioned YAML in git. Scorecards are plain
  JSON/markdown/SARIF/JUnit you can archive and diff.
- **Honest epistemics.** If the adapter cannot see an agent's enrichment
  calls, unverifiable citations are reported as warnings (possible
  hallucination, verify manually), not as proven fabrication. OV-002 only
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
