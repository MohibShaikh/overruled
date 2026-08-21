"""Differential self-test: the auditor must pass a good agent and
convict a broken one on identical cases. A measurement tool that cannot
detect a deliberately wrong subject is measuring nothing."""

import pytest

from mocks import BrokenAgent, ReferenceAgent, serve
from overruled.auditor import Auditor
from overruled.cases import load_cases
from overruled.subject import JSONAdapter

SELF_TEST_CASES = [
    "case-bruteforce-001",   # TP with planted IP evidence
    "case-pth-lateral-001",  # TP with planted hash suffix
    "case-fp-cert-window-001",  # FP trap, benign context in payload
    "case-esc-exit-delete-001",  # escalate, legal hold + discoverable actor
]


@pytest.fixture(scope="module")
def reference_url():
    server = serve(ReferenceAgent, 0)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def broken_url():
    server = serve(BrokenAgent, 0)
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _cases():
    all_cases = load_cases([__import__("pathlib").Path("cases")])
    by_id = {c.id: c for c in all_cases}
    return [by_id[cid] for cid in SELF_TEST_CASES]


async def test_reference_agent_passes(reference_url):
    card = await Auditor(JSONAdapter(reference_url, name="reference"), runs_per_case=2).run(_cases())
    assert card.passed, [
        (s.case_id, [f.detail for f in s.results if not f.passed])
        for s in card.cases if not s.passed
    ]
    correct, total = card.accuracy
    assert correct == total


async def test_broken_agent_fails_with_verdict_findings(broken_url):
    card = await Auditor(JSONAdapter(broken_url, name="broken"), runs_per_case=2).run(_cases())
    assert not card.passed
    fired = {r.rule_id for s in card.cases for r in s.results if not r.passed}
    assert "OV-001" in fired
    correct, _ = card.accuracy
    # The broken closer only survives on the benign case (2 runs);
    # every threat gets closed as noise.
    assert correct == 2
