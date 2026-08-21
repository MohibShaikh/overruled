"""Subject adapters: how gavel feeds a case to an agent and reads the artifact.

An adapter receives the case event, drives the subject agent through its
normal interface, and returns a normalized AgentArtifact. Adapters must
not special-case checks; they only translate.
"""

from abc import ABC, abstractmethod

import httpx

from .models import AgentArtifact


class SubjectAdapter(ABC):
    name: str = "subject"

    @abstractmethod
    async def investigate(self, event: dict, run_index: int = 0) -> AgentArtifact: ...


class ThreatSentinelAdapter(SubjectAdapter):
    """Drives a ThreatSentinel instance over its REST API.

    Reads the investigation result and maps it onto the artifact shape:
    verdict from risk level plus escalation state, IOCs from cited
    indicators in the reasoning and intel data.
    """

    CRITICAL_HIGH = {"critical", "high"}

    def __init__(self, base_url: str, token: str):
        self.name = f"threatsentinel@{base_url}"
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=120.0,
        )

    async def investigate(self, event: dict, run_index: int = 0) -> AgentArtifact:
        import time

        started = time.perf_counter()
        created = await self.client.post("/api/v1/investigations/", json={"event_data": event})
        created.raise_for_status()
        inv_id = created.json()["investigation_id"]

        status = await self._wait_for(inv_id)
        if status.get("status") == "failed":
            return AgentArtifact(
                verdict="error", run_index=run_index,
                raw={"investigation_id": inv_id, "status": "failed"},
            )

        result = await self.client.get(f"/api/v1/investigations/{inv_id}/result")
        result.raise_for_status()
        body = result.json()

        return self._to_artifact(body, inv_id, run_index,
                                 int((time.perf_counter() - started) * 1000))

    async def _wait_for(self, inv_id: str, timeout_s: float = 90.0) -> dict:
        import asyncio
        import time

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            response = await self.client.get(f"/api/v1/investigations/{inv_id}")
            response.raise_for_status()
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

        if escalated:
            verdict = "escalate"
        elif level in self.CRITICAL_HIGH:
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
        iocs: list[str] = []
        intel = body.get("intelligence_data") or {}
        for source_result in intel.values() if isinstance(intel, dict) else []:
            indicators = source_result.get("indicators", []) if isinstance(source_result, dict) else []
            for ind in indicators:
                if isinstance(ind, str):
                    iocs.append(ind)
        event = body.get("event_data") or {}
        for key in ("source_ip", "target_ip", "url", "file_hash"):
            if event.get(key):
                iocs.append(str(event[key]))
        seen: set[str] = set()
        return [i for i in iocs if not (i in seen or seen.add(i))]
