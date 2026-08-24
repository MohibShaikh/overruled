"""Differential self-test: the auditor must pass a good agent and
convict a broken one on identical cases. A measurement tool that cannot
detect a deliberately wrong subject is measuring nothing."""

from http.server import BaseHTTPRequestHandler

import pytest

from overruled.auditor import Auditor
from overruled.cases import bundled_cases
from overruled.mocks import BrokenAgent, ReferenceAgent, serve
from overruled.subject import JSONAdapter, ThreatSentinelAdapter

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
    by_id = {c.id: c for c in bundled_cases()}
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


class ParrotingSentinel(BaseHTTPRequestHandler):
    """A ThreatSentinel-shaped subject that investigates nothing.

    It answers high risk for every alert but never produces intel data.
    The event's own headline fields are inputs it was handed, not
    evidence it cited, so OV-003 must still fire."""

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("content-length", 0)))
        self._reply({"investigation_id": "inv-parrot-1"})

    def do_GET(self):  # noqa: N802
        if self.path.endswith("/result"):
            self._reply({
                "investigation_id": "inv-parrot-1",
                "status": "completed",
                "risk_assessment": {"risk_level": "high", "risk_score": 88,
                                    "confidence": 0.9},
            })
        else:
            self._reply({"investigation_id": "inv-parrot-1",
                         "status": "completed"})

    def _reply(self, obj):
        import json

        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


async def test_parroting_sentinel_cannot_bank_headline_fields_as_evidence():
    server = serve(ParrotingSentinel, 0)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        by_id = {c.id: c for c in bundled_cases()}
        case = by_id["case-bruteforce-001"]
        adapter = ThreatSentinelAdapter(url, "dev-secret-key")
        card = await Auditor(adapter, runs_per_case=1).run([case])
    finally:
        server.shutdown()
    score = card.cases[0]
    assert not score.passed
    fired = {r.rule_id for r in score.results if not r.passed}
    assert "OV-003" in fired
