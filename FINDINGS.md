# Findings: auditor correctness issues and the fix plan

Consolidated review of overruled's own machinery, gathered 2026-08-24.
Sources: an external agent's review written while wiring ThreatSentinel up
to the harness, plus two passes over the source in this repo. This file is
written for a fresh session that has never seen the discussion. Everything
needed to implement or fix is inline.

Severity tiers mean:

- **Tier 1**: can produce a wrong conviction (good agent failed) or wrong
  acquittal (bad agent passed). An auditor's only product is never doing
  this. Fix first.
- **Tier 2**: scores or gates mislead even when no individual ruling is
  wrong.
- **Tier 3**: coverage, authority, and sharp edges.

## Context a fresh session needs

overruled replays security cases with known ground truth against an HTTP
agent and grades its rulings with six deterministic rules, OV-001 through
OV-006. Exit 1 gates CI. Read `AGENTS.md` and `README.md` before editing;
the constraints below come from there and bind every fix in this file:

- **No LLM anywhere in the grading path.** Checks are set and string logic.
  Do not fix a detection gap by adding fuzzy or model-based matching.
- **Rule IDs are frozen**, OV-001..006, one check module per rule in
  `overruled/checks/`, registry in `checks/__init__.ALL_CHECKS`.
- **Case IOCs only from documentation ranges** (203.0.113.x, 198.51.100.x,
  192.0.2.x, example.com/example.top).
- **Minimal edits, match the existing voice.** No defensive sprawl, no
  filler comments.
- Tests are fast and offline (~5s). The differential self-test
  (`tests/test_differential.py`) is the contract that matters most: the
  reference mock must pass, the broken mock must convict. Re-run it after
  every fix here.

Relevant files: `overruled/models.py`, `cases.py`, `subject.py`,
`auditor.py`, `stats.py`, `metamorphic.py`, `report.py`, `cli.py`,
`checks/*.py`, `tests/*`.

Verify with:

```
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
# broken mock must fail:
python -m overruled.mocks --agent broken --port 9102 &
.venv/bin/overruled run --adapter json --url http://127.0.0.1:9102 --runs 1
# reference mock must pass:
python -m overruled.mocks --agent reference --port 9101 &
.venv/bin/overruled run overruled/cases/brute_force.yaml \
  overruled/cases/case-pth-lateral.yaml \
  overruled/cases/case-fp-cert-window.yaml \
  overruled/cases/case-esc-exit-delete.yaml \
  --adapter json --url http://127.0.0.1:9101 --runs 2
```

---

## Tier 1: wrong convictions and acquittals

### F1. The ThreatSentinel adapter launders evidence citations

**Evidence.** `_extract_iocs` appends the event's own `source_ip`,
`target_ip`, `url`, `file_hash` to `cited_iocs` unconditionally
(`subject.py:209-212`). The module header says "adapters must not
special-case checks; they only translate" (`subject.py:5`), and this does
exactly that.

**Why it matters.** An agent that did nothing but receive the alert now
appears to have cited its headline fields. That hands free passes on OV-003
missed_evidence whenever planted evidence sits in those columns, and
weakens OV-006 alert_parroting for the flagship adapter, the exact check
the README leads with.

**Fix sketch.** Delete the event-field loop in `_extract_iocs`. Cited IOCs
come only from indicators the subject itself produced (the
`intelligence_data` walk). If ThreatSentinel's result body carries an
explicit citation list somewhere else, map that instead; do not infer
citations from inputs.

**Tests.** Extend `tests/test_differential.py`: a mock that echoes back the
event's headline IP without investigating must still fail missed_evidence
on a case whose `must_surface` evidence lives in those fields. Add a direct
unit test on `_extract_iocs` with a body containing `intelligence_data`
and an `event_data` echo; assert the echoed fields are absent.

### F2. Transport errors count as wrong rulings

**Evidence.** Non-200 and unparseable bodies become `verdict="error"`
(`subject.py:78`, `subject.py:82`); investigation failure becomes
`verdict="error"` (`subject.py:144-148`). Every consumer treats "error"
as a ruling that is not the expected one: accuracy
(`auditor.py:82`), kappa and loss via `ruling_pairs`
(`models.py:130-135`), SPRT correctness counts (`auditor.py:65`). There
are no retries anywhere.

**Why it matters.** One vendor API blip looks identical to the agent
botching the case. Accuracy drops, kappa drops, expected loss rises, and
OV-001 goes critical. Infrastructure noise convicts the agent.

**Fix sketch.**

1. Retry transient failures before giving up: catch
   `httpx.TransportError` and 5xx responses, retry twice with short
   backoff, then record an error artifact.
2. Account for errors separately end to end. `AgentArtifact` already has
   `verdict="error"` as the marker; give `CaseScore` an `error_runs`
   count, exclude error artifacts from `accuracy`, `ruling_pairs`,
   Brier pairs, and SPRT counts, and print infrastructure errors as their
   own line in every format.
3. A case where the majority of runs errored is **incomplete**, not
   failed: report it as such and let the gate treat it explicitly (see
   F6 for how this interacts with exit codes).

**Tests.** Property test in `tests/test_stats_properties.py`: scorecard
math is invariant to injecting error artifacts (counts change, estimates
do not). Adapter test: a mock HTTP server that 503s twice then succeeds
produces a normal artifact, not an error.

### F3. One flake aborts the entire audit

**Evidence.** Nothing catches exceptions around `subject.investigate`
(`auditor.py:62-69`). `_wait_for` raises `TimeoutError` after 90s
(`subject.py:169`) and `raise_for_status()` propagates on create and
result calls (`subject.py:140`, `subject.py:151`). One slow response
kills the run, discards all completed cases, and exits with a traceback.

**Fix sketch.** Wrap the per-run call in `_investigate` with a narrow
except (`httpx.HTTPError`, `TimeoutError`) producing an error artifact,
which F2 already knows how to account for. In the ThreatSentinel adapter,
replace `raise_for_status()` with explicit status handling returning
error artifacts. The audit always completes with whatever it measured.

**Tests.** Unit test: an adapter whose investigate raises yields a
completed scorecard with the case marked incomplete, not a raised
exception.

### F4. OV-002 and OV-003 contradict each other on near-miss citations

**Evidence.** Fabrication grounding rejects substring matches inside
longer tokens, so citing `203.0.113.6` against a case holding
`203.0.113.66` is flagged as fabricated (`evidence.py:58-77`,
`_contains_token` at `evidence.py:84-87`). Missed-evidence surfacing uses
bidirectional containment, `ioc in cited or cited in ioc`
(`evidence.py:123-124`), so that same near-miss citation satisfies
surfacing. One rule calls the citation a hallucination, the other accepts
it as coverage of the planted indicator.

**Why it matters.** Internal contradiction between two rules on the same
artifact destroys the credibility of both. It also means a fabricating
agent can buy back its OV-002 failure with OV-003 credit.

**Fix sketch.** Rewrite `_surfaced` so a planted indicator counts as
surfaced only when it appears whole-token inside some citation:
`_contains_token(cited, ioc)` for each cited string. Drop the `cited in
ioc` direction entirely. This matches OV-002's stated semantics: wrapping
an indicator in context is fine, truncating it is not.

**Tests.** Unit tests covering four cells: citation equals planted IOC
(surfaced), citation wraps it with port or prefix (surfaced), citation
truncates it (not surfaced, and OV-002 flags it), citation unrelated
(not surfaced). Confirm the broken mock's findings count shifts
predictably and update the differential expectations.

---

## Tier 2: misleading scores and gates

### F5. Scorecards are not bound to the pack that produced them

**Evidence.** `Scorecard` records subject name and timestamp only
(`models.py:107-112`). No overruled version, no hash of the case files.
Cases ship inside the wheel (`pyproject.toml` package-data), so a v0.2
release silently changes the benchmark and archived scorecards stop being
comparable. The README sells reproducible, diffable scorecards; today
they do not survive a version bump.

**Fix sketch.** Compute a pack fingerprint in `load_cases`: sha256 over
sorted (path, file-bytes). Thread it into `Auditor` onto `Scorecard`
alongside `tool_version` from `importlib.metadata.version("overruled")`.
Render both in rich and markdown headers, SARIF `properties`, JUnit
`<properties>`. `tests/test_report_formats.py` asserts structural
contracts; extend them.

**Tests.** Report format tests assert the version and pack hash appear
in all four outputs. Loader test: mutating a case YAML changes the hash.

### F6. The gate conflates critical hallucination with minor warnings

**Evidence.** `CaseScore.passed` requires every check green
(`auditor.py:88`), including MINOR findings like the unverifiable-citation
warning (`evidence.py:49-56`), and `Scorecard.passed` requires every case
green (`models.py:114-116`). Any real agent over 50 cases accumulates a
MINOR eventually, so SUBJECT OVERRULED fires almost always and exit 1
stops distinguishing a fabricated-evidence conviction from cosmetic
noise.

**Fix sketch.** Base the pass decision on severity: CRITICAL and MAJOR
fail the gate, MINOR warnings do not unless `--strict` is passed. Keep
every finding visible in all formats; this changes only the rollup and
exit code. Update `cli.py:_run` to accept the flag. Say plainly in the
README that the default gate ignores MINOR findings.

**Tests.** `test_report_formats.py`: a card with only MINOR failures
reports passing by default and failing under strict. JUnit failure counts
follow the same policy.

### F7. Serial, fixed-order execution pollutes consistency

**Evidence.** `Auditor.run` iterates cases in sorted order with awaits
one at a time (`auditor.py:23-48`), roughly 150+ calls for a full audit
at runs=3 with variants. Against a hosted LLM-backed vendor that
stretches past an hour, providers change behavior within a day, and any
server-side cache sees identical request order every audit. OV-004 can
flag provider drift or benefit from caches.

**Fix sketch.** Two small levers. Shuffle case order once per invocation
with a recorded seed (`--seed`, stored on the scorecard for
reproducibility). Add optional bounded concurrency (`--concurrency N`,
default 1) fanning out independent cases behind an asyncio semaphore.
Keep output ordering deterministic by sorting results afterward.

**Tests.** Determinism test: same seed produces same order; results list
is order-independent.

### F8. pass^k assumes independent runs

**Evidence.** `pass_k` multiplies marginals (`stats.py:36-45`) and the
docstring says so. LLM agents fail correlately: same prompt, same latent
failure. Positive correlation makes joint success higher than p^k when p
is high, so the quoted bound is optimistic exactly where people will
quote it.

**Fix sketch.** Report the empirical joint reliability from observed runs
next to the p^k bound (a helper already exists in spirit:
`verdict_flip_probability`, `stats.py:152`). One added line in the
markdown and rich summaries stating both numbers. No math changes.

**Tests.** Stats property test: empirical joint estimate lies within
known bounds for constructed correlated sequences.

---

## Tier 3: coverage and authority

### F9. Metamorphic transforms can silently change nothing

**Evidence.** `rename_user` touches only four top-level keys
(`metamorphic.py:43`); `reorder_payload` and `reformat_numbers` touch
only `event["payload"]` (`metamorphic.py:86-106`). Ground truth in this
pack deliberately nests facts deep in payload context, so a case whose
ruling hinges on a username buried in `payload.context` gets
`metamorphic: [rename_user]` declared, the transform changes nothing
relevant, the verdict survives, and OV-005 reports invariance that was
never tested.

**Fix sketch.** Two parts.

1. No-op detection, cheap and honest: `MetamorphicCheck` compares the
   built variant event to the base event (`checks/metamorphic.py`);
   equality emits a MINOR finding naming the transform as a no-op for
   this case. Under F6 semantics this warns by default, fails under
   `--strict`, and tells case authors their declaration was toothless.
2. Widen `rename_user` to recurse: rename values under any key matching
   `(^|_)(user|account|actor)s?$` at any depth. Document remaining scope
   honestly in the module docstring rather than pretending full coverage.

**Tests.** Loader/check test: a case with a nested username and
`metamorphic: [rename_user]` produces a changed variant after the
recursion widening; a transform that changes nothing emits the no-op
finding.

### F10. Verdict inference for ThreatSentinel is knife-edge

**Evidence.** ThreatSentinel exposes no explicit verdict field, so the
adapter infers: escalate if flagged for human review, true_positive if
risk_level is critical or high, else false_positive
(`subject.py:171-183`). An agent scoring ransomware at the boundary
lands one label away from expectation and fails OV-001 despite reacting
more urgently than a passing peer. The external reviewer hit this from
the other side while tuning ThreatSentinel.

**Fix sketch.** Make the mapping configurable instead of hardcoded
(`--tp-levels critical,high` fed into the adapter constructor), and
record the effective mapping in the scorecard subject string so
scorecards state their own lens. Prefer an explicit verdict field on the
body when present, falling back to inference. Longer term this is also a
ThreatSentinel-side fix: emit an explicit verdict and let the adapter
prefer it.

**Tests.** Adapter unit test: same body maps differently under different
level sets; explicit verdict field wins over level inference.

### F11. The public pack is also the training set

**Evidence.** Cases ship readable inside the wheel
(`cases.py:BUNDLED_CASES`, package-data globs). Anyone tuning an agent
can fit all 50 files exactly. The external reviewer said it plainly: a
pass on the bundled pack proves works-on-the-training-set. The TTPs are
generic enough that matching them approximates real detection, but the
score is a floor, not proof.

**Fix sketch.** Mostly convention and docs, little code: the CLI already
accepts arbitrary paths, so a held-out pack is just a private directory
kept out of the wheel. What overruled should add is the documented
workflow and the reporting hook: a `run --pack public --pack private`
pattern or simply docs showing a two-command ritual, plus a line in the
rich/markdown summary distinguishing bundled-pack scores from
brought-your-own-pack scores. Highest-leverage move available for trust;
also the natural home for contested ground truth before it goes public.

**Tests.** None strictly required; a loader test that private dirs
outside the package load identically.

### F12. Thin coverage per category

**Evidence.** 22 TP / 21 FP / 7 escalate across 50 files, with several
event types appearing once or twice, so single odd cases swing results.
The external reviewer flagged this independently.

**Fix sketch.** Extend the existing case-pack integrity check in CI
(currently a floor of 50) with minimum counts per expected_verdict and
per event_type, printed on violation. Then authoring: grow sparse
categories, keeping distribution roughly proportional per `AGENTS.md`.

### F13. Smaller notes, batch them opportunistically

- `JSONAdapter.investigate` POSTs a fixed `/` path (`subject.py:76`);
  take an optional endpoint.
- `_validate_discoverable` checks headline collisions against first-level
  scalar values only (`cases.py:38-40`); a discoverable fact duplicated
  verbatim inside a top-level list slips the check. Cheap to tighten.
- `_TOKEN_PATTERNS` misses IPv6 and several TLDs (`evidence.py:11-16`);
  the verbatim fallback in `_grounded` usually saves this, but planted
  IPv6 evidence would never enter `known_tokens`.
- Default token `dev-secret-key` baked into the CLI (`cli.py:37`): fine
  for local dev, worth a README caution against pointing defaults at
  production URLs.
- `compare` builds a fresh `Auditor` per case per subject serially
  (`cli.py:97-104`); benefits for free from F7's concurrency work.

---

## Strategic context (not code)

Recorded here because a fresh session evaluating effort should know the
landscape. overruled has roughly 200 PyPI downloads, v0.1.1, publish job
blocked on the manual trusted-publisher step described in `AGENTS.md`.
The moat is the case library; the competition for mindshare is SIR-Bench
with published baselines and academic weight. Ground truth is currently
one author's judgment adjudicated by PRs to the same repo; a public plus
private pack split (F11) is the single highest-trust move available, and
vendor adoption of the adapter contract is the adoption bottleneck. None
of that changes the code priorities above; F1 through F4 stand on their
own because they are about never convicting wrongly.

## Suggested work order

1. **F3** abort safety: smallest change, makes live audits trustworthy.
2. **F2** error accounting and retries: rides on F3's except path.
3. **F1** stop laundering citations, guarded by the differential test.
4. **F4** align containment between OV-002 and OV-003.
5. **F5** bind scorecards to pack and version.
6. **F6** severity-aware gate with `--strict`.
7. **F9** no-op transform detection, quick win.
8. **F7, F8, F10** determinism, reliability honesty, threshold config.
9. Authoring track: **F11** held-out workflow docs, **F12** coverage
   floors, then grow the library.

After each tier, re-run ruff, pytest, and both mock invocations from the
top of this file. The broken mock's finding count will shift with F1 and
F4; update the differential expectations deliberately, not silently.
