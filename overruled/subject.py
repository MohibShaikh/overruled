"""Subject adapters: how overruled feeds a case to an agent and reads the artifact.

An adapter receives the case event, drives the subject agent through its
normal interface, and returns a normalized AgentArtifact. Adapters must
not special-case checks; they only translate.
"""

from abc import ABC, abstractmethod
from enum import StrEnum

import httpx

from .models import ERROR_VERDICT, AgentArtifact


async def _retry(client: httpx.AsyncClient, method: str, url: str,
                 **kwargs) -> httpx.Response:
    """Send a request, retrying transport errors and 5xxs twice.

    A vendor API blip must not look like the agent botching the case.
    Exhausted retries return the last response (or re-raise) so the
    caller records an error artifact on its own terms.
    """
    import asyncio

    for _ in range(2):
        try:
            response = await client.request(method, url, **kwargs)
        except httpx.TransportError:
            pass
        else:
            if response.status_code < 500:
                return response
        await asyncio.sleep(0.5)
    return await client.request(method, url, **kwargs)


class Scope(StrEnum):
    """Whether a case is answerable in the subject's own vocabulary."""

    NATIVE = "native"          # the case already speaks the subject's taxonomy
    MAPPED = "mapped"          # translated faithfully into it
    OUT_OF_SCOPE = "out_of_scope"  # no faithful translation exists


class SubjectAdapter(ABC):
    name: str = "subject"

    @abstractmethod
    async def investigate(self, event: dict, run_index: int = 0) -> AgentArtifact: ...

    #: Event types the subject declares it handles. Empty means the subject
    #: makes no such claim, so every case is answerable and nothing is
    #: excluded. Declaring a taxonomy is what enables out-of-scope reporting.
    NATIVE_EVENT_TYPES: frozenset[str] = frozenset()

    #: Pack event type -> subject event type, for cases the subject's own
    #: documented vocabulary genuinely covers. Anything absent is out of
    #: scope; it is not coerced into the nearest label.
    TAXONOMY: dict[str, str] = {}

    def scope(self, event: dict) -> tuple[Scope, dict]:
        """Classify a case against the subject's declared vocabulary.

        Translating a case the subject never claimed to handle would
        measure the mapping rather than the agent, so the third outcome
        exists: say so and exclude it.
        """
        if not self.NATIVE_EVENT_TYPES:
            return (Scope.NATIVE, event)
        event_type = event.get("event_type")
        if event_type in self.NATIVE_EVENT_TYPES:
            return (Scope.NATIVE, event)
        mapped = self.TAXONOMY.get(event_type)
        if mapped is None:
            return (Scope.OUT_OF_SCOPE, event)
        return (Scope.MAPPED, {**event, "event_type": mapped})


class JSONAdapter(SubjectAdapter):
    """Drives a minimal-contract agent over HTTP.

    POSTs `{"event_data": event}` and expects back a flat verdict:
    `{"verdict": "true_positive"|"false_positive"|"escalate",
      "cited_iocs": [...], "confidence": 0.0-1.0}`. Missing fields are
    tolerated; an unreadable body becomes verdict=error.
    """

    def __init__(self, base_url: str, token: str = "", name: str = ""):
        self.name = name or f"agent@{base_url}"
        self.client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"} if token else {},
            timeout=60.0,
        )

    async def investigate(self, event: dict, run_index: int = 0) -> AgentArtifact:
        try:
            response = await _retry(self.client, "POST", "/", json={"event_data": event})
            if response.status_code != 200:
                return AgentArtifact(verdict=ERROR_VERDICT, run_index=run_index)
            body = response.json()
            return AgentArtifact(
                verdict=body.get("verdict") or None,
                confidence=body.get("confidence"),
                cited_iocs=[str(i) for i in (body.get("cited_iocs") or [])],
                raw=body,
                run_index=run_index,
            )
        except (httpx.HTTPError, ValueError):
            # ValueError covers ValidationError and json parse errors:
            # a malformed body says nothing about the agent's judgment.
            return AgentArtifact(verdict=ERROR_VERDICT, run_index=run_index)


class ThreatSentinelAdapter(SubjectAdapter):
    """Drives a ThreatSentinel instance over its REST API.

    Reads the investigation result and maps it onto the artifact shape:
    verdict from risk level plus escalation state, IOCs from cited
    indicators in the reasoning and intel data.
    """

    #: Default mapping lives on the constructor; see tp_levels there.

    #: ThreatSentinel README, "Supported event types".
    NATIVE_EVENT_TYPES = frozenset({
        "suspicious_ip", "suspicious_url", "malware_detection",
        "login_anomaly", "ddos_signs", "phishing_attempt",
    })

    #: Written against those six published descriptions, before any rerun,
    #: and deliberately sparse. "IPs showing malicious behavior" covers
    #: beaconing and tunnelling; "social engineering, credential theft by
    #: email" covers mail lures; "file-based threats, trojans, ransomware"
    #: covers a detected malicious file.
    #:
    #: Everything else in the pack is left out of scope on purpose. LSASS
    #: dumping is not a file reputation question, cloud key abuse is not an
    #: IP reputation question, and SQL injection against your own login page
    #: is not a "potentially malicious website". Filing them under the
    #: nearest label would hand them to machinery that cannot evaluate them
    #: and would score the mapping, not the agent.
    TAXONOMY = {
        "network_anomaly": "suspicious_ip",
        "email_anomaly": "phishing_attempt",
        "file_event": "malware_detection",
    }

    def __init__(self, base_url: str, token: str,
                 tp_levels: tuple[str, ...] = ("critical", "high")):
        self.tp_levels = {level.lower() for level in tp_levels}
        # The scorecard states its lens: which risk levels count as a
        # true positive is a scoring decision, not a fact.
        self.name = (f"threatsentinel@{base_url.rstrip('/')}"
                     f" [tp={'+'.join(sorted(self.tp_levels))}]")
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=120.0,
        )

    async def investigate(self, event: dict, run_index: int = 0) -> AgentArtifact:
        import time

        started = time.perf_counter()
        try:
            created = await _retry(
                self.client, "POST", "/api/v1/investigations/",
                json={"event_data": event},
            )
            if created.is_error:
                return AgentArtifact(
                    verdict="error", run_index=run_index,
                    raw={"status_code": created.status_code},
                )
            inv_id = created.json()["investigation_id"]
            status = await self._wait_for(inv_id)
            if status.get("status") == "failed":
                return AgentArtifact(
                    verdict="error", run_index=run_index,
                    raw={"investigation_id": inv_id, "status": "failed"},
                )
            result = await _retry(
                self.client, "GET", f"/api/v1/investigations/{inv_id}/result",
            )
            if result.is_error:
                return AgentArtifact(
                    verdict="error", run_index=run_index,
                    raw={"investigation_id": inv_id, "status_code": result.status_code},
                )
            body = result.json()
            return self._to_artifact(body, inv_id, run_index,
                                     int((time.perf_counter() - started) * 1000))
        except (httpx.HTTPError, TimeoutError, ValueError, KeyError):
            return AgentArtifact(verdict=ERROR_VERDICT, run_index=run_index)

    async def _wait_for(self, inv_id: str, timeout_s: float = 90.0) -> dict:
        import asyncio
        import time

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            response = await _retry(self.client, "GET", f"/api/v1/investigations/{inv_id}")
            if response.is_error:
                raise httpx.HTTPStatusError(
                    f"{response.status_code} polling investigation {inv_id}",
                    request=response.request, response=response,
                )
            body = response.json()
            if body.get("status") in ("completed", "failed", "pending_human_review"):
                return body
            await asyncio.sleep(0.5)
        raise TimeoutError(f"investigation {inv_id} did not settle")

    def _to_artifact(self, body: dict, inv_id: str, run_index: int,
                     duration_ms: int) -> AgentArtifact:
        risk = body.get("risk_assessment") or {}
        level = (risk.get("risk_level") or "").lower()
        escalated = bool(body.get("requires_human_review")) or \
            body.get("status") == "pending_human_review"

        explicit = body.get("verdict")
        if explicit in ("true_positive", "false_positive", "escalate"):
            verdict = explicit
        elif escalated:
            verdict = "escalate"
        elif level in self.tp_levels:
            verdict = "true_positive"
        else:
            verdict = "false_positive"

        return AgentArtifact(
            verdict=verdict,
            risk_score=risk.get("risk_score"),
            risk_level=level or None,
            confidence=risk.get("confidence"),
            cited_iocs=self._extract_iocs(body),
            recommended_actions=[
                a.get("description", "") for a in (body.get("recommended_actions") or [])
                if isinstance(a, dict)
            ],
            escalated_for_human=escalated,
            raw={"investigation_id": inv_id},
            run_index=run_index,
            duration_ms=duration_ms,
        )

    def _extract_iocs(self, body: dict) -> list[str]:
        """Citations come only from indicators the subject produced.

        The event's own headline fields are inputs the subject was
        handed; counting them as cited evidence would credit parroting
        as investigation.
        """
        iocs: list[str] = []
        intel = body.get("intelligence_data") or {}
        for source_result in intel.values() if isinstance(intel, dict) else []:
            indicators = source_result.get("indicators", []) if isinstance(source_result, dict) else []
            for ind in indicators:
                if isinstance(ind, str):
                    iocs.append(ind)
        seen: set[str] = set()
        return [i for i in iocs if not (i in seen or seen.add(i))]
