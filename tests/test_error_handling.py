"""Infrastructure failures must not impersonate agent failures.

A 5xx, a refused connection, or a hung agent says nothing about the
subject's judgment, so every one of these ends in an error artifact the
scorecard accounts for separately."""

import asyncio

import httpx
import pytest

from overruled.auditor import Auditor
from overruled.models import AgentArtifact, Case
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


async def test_post_5xx_does_not_retry():
    """A POST 5xx means the server received and choked; retrying risks
    creating a duplicate investigation at a stateful endpoint."""
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"verdict": "true_positive", "confidence": 0.9})

    artifact = await _adapter(handler).investigate(CASE.event)
    assert len(calls) == 1
    assert artifact.verdict == "error"


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
    # Infrastructure noise must not convict: no CRITICAL from OV-001,
    # but the case is not measured, so it cannot pass either.
    assert not score.passed
    ov001 = next(r for r in score.results if r.rule_id == "OV-001")
    assert ov001.severity.value == "major"
    assert "no gradable runs" in ov001.detail


async def test_malformed_body_becomes_an_error_artifact_not_a_crash():
    def handler(request):
        return httpx.Response(200, json={"verdict": {}, "confidence": "high"})

    artifact = await _adapter(handler).investigate(CASE.event)
    assert artifact.verdict == "error"


async def test_nan_confidence_is_rejected_at_the_boundary():
    def handler(request):
        return httpx.Response(200, json={"verdict": "true_positive",
                                         "confidence": float("nan")})

    artifact = await _adapter(handler).investigate(CASE.event)
    assert artifact.verdict == "error"


async def test_partial_errors_do_not_break_consistency():
    """One dropped run among real ones is noise, not a flip-flop."""
    calls = []

    class HalfBroken(SubjectAdapter):
        name = "half-broken"

        async def investigate(self, event: dict, run_index: int = 0):
            calls.append(run_index)
            if run_index == 0:
                raise httpx.ConnectError("refused")
            return AgentArtifact(verdict="true_positive", run_index=run_index)

    card = await Auditor(HalfBroken(), runs_per_case=3).run([CASE])
    score = card.cases[0]
    assert score.error_runs == 1
    ov004 = next(r for r in score.results if r.rule_id == "OV-004")
    assert ov004.passed


async def test_per_case_timeout_aborts_a_hanging_agent():
    import threading

    block = threading.Event()

    class SlowAgent(SubjectAdapter):
        name = "slow"
        async def investigate(self, event, run_index=0):
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, block.wait)
            return AgentArtifact(verdict="true_positive")

    card = await Auditor(SlowAgent(), runs_per_case=3,
                         per_case_timeout=0.1).run([CASE])
    score = card.cases[0]
    assert score.error_runs > 0
    assert not score.passed
    block.set()


async def test_timeout_preserves_partial_results():
    """When the first run succeeds but the second hangs, the scorecard
    reflects the partial results — not a total failure."""
    import threading

    block = threading.Event()

    class HangsOnSecond(SubjectAdapter):
        name = "partial"
        async def investigate(self, event, run_index=0):
            if run_index == 1:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, block.wait)
            return AgentArtifact(verdict="true_positive", run_index=run_index)

    card = await Auditor(HangsOnSecond(), runs_per_case=3,
                         per_case_timeout=0.1).run([CASE])
    score = card.cases[0]
    assert score.runs == 3
    assert score.error_runs == 1
    # First and third runs succeeded; the case is measured, not total failure
    assert score.verdict_correct_runs == 2
    block.set()


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


class TestVerdictMapping:
    BODY = {
        "status": "completed",
        "risk_assessment": {"risk_level": "medium", "risk_score": 55,
                            "confidence": 0.8},
    }

    def test_default_levels_map_medium_to_false_positive(self):
        adapter = ThreatSentinelAdapter("http://mock", "t")
        artifact = adapter._to_artifact(self.BODY, "inv-1", 0, 10)
        assert artifact.verdict == "false_positive"

    def test_custom_levels_change_the_lens_and_the_name_states_it(self):
        adapter = ThreatSentinelAdapter("http://mock", "t",
                                        tp_levels=("medium",))
        artifact = adapter._to_artifact(self.BODY, "inv-1", 0, 10)
        assert artifact.verdict == "true_positive"
        assert "tp=medium" in adapter.name

    def test_explicit_verdict_field_wins_over_inference(self):
        body = {**self.BODY, "verdict": "escalate"}
        adapter = ThreatSentinelAdapter("http://mock", "t")
        artifact = adapter._to_artifact(body, "inv-1", 0, 10)
        assert artifact.verdict == "escalate"
