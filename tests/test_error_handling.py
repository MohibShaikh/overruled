"""Infrastructure failures must not impersonate agent failures.

A 5xx, a refused connection, or a hung agent says nothing about the
subject's judgment, so every one of these ends in an error artifact the
scorecard accounts for separately."""

import asyncio

import httpx
import pytest

from overruled.auditor import Auditor
from overruled.models import Case
from overruled.subject import JSONAdapter, SubjectAdapter, ThreatSentinelAdapter

CASE = Case(
    id="case-transport-001",
    name="transport probe",
    event={"event_type": "login_anomaly"},
    expected_verdict="true_positive",
)


@pytest.fixture(autouse=True)
def fast_sleep(monkeypatch):
    monkeypatch.setattr(asyncio, "sleep", _instant)


async def _instant(_delay):
    pass


def _adapter(handler) -> JSONAdapter:
    adapter = JSONAdapter("http://mock", name="mock")
    adapter.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://mock",
    )
    return adapter


class FlakyAgent(SubjectAdapter):
    """The whole stack is on fire; investigate never returns an artifact."""

    name = "flaky"

    async def investigate(self, event: dict, run_index: int = 0):
        raise TimeoutError("agent hung")


async def test_transient_5xx_retries_then_succeeds():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"verdict": "true_positive", "confidence": 0.9})

    artifact = await _adapter(handler).investigate(CASE.event)
    assert len(calls) == 3
    assert artifact.verdict == "true_positive"


async def test_persistent_5xx_becomes_an_error_artifact():
    def handler(request):
        return httpx.Response(503)

    artifact = await _adapter(handler).investigate(CASE.event)
    assert artifact.verdict == "error"


async def test_transport_failure_becomes_an_error_artifact():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    artifact = await _adapter(handler).investigate(CASE.event)
    assert artifact.verdict == "error"


async def test_raising_adapter_still_produces_a_scorecard():
    card = await Auditor(FlakyAgent(), runs_per_case=2).run([CASE])
    score = card.cases[0]
    assert score.runs == 2
    assert score.error_runs == 2
    assert score.incomplete
    assert card.total_errors == 2
    correct, total = card.accuracy
    assert (correct, total) == (0, 0)


def test_extract_iocs_ignores_the_event_it_was_handed():
    body = {
        "intelligence_data": {
            "virustotal": {"indicators": ["198.51.100.7", "evil.example.top"]},
        },
        "event_data": {
            "source_ip": "203.0.113.66",
            "target_ip": "203.0.113.1",
            "url": "https://phish.example.com/login",
            "file_hash": "deadbeef",
        },
    }
    iocs = ThreatSentinelAdapter("http://mock", "dev-secret-key")._extract_iocs(body)
    assert iocs == ["198.51.100.7", "evil.example.top"]
