"""Mock subject agents for differential self-testing and demos.

reference_agent: rule-based, cites evidence it was given. Must PASS.
broken_agent: closes everything as benign, cites nothing. Must FAIL.

Run standalone:  python -m mocks --agent reference --port 9101
"""

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

_CITE_KEYS = (
    "source_ip", "dest_domain", "hash_suffix", "key_id", "bucket",
    "folder", "dest_ip", "actor", "user",
)

_LIST_CITE_KEYS = ("accessed_endpoints",)

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b[\w.-]+\.example\.(?:com|top)\b")

_FP_CONTEXT_KEYS = {
    "change_ticket", "maintenance_incident", "test_plan",
    "vendor_platform", "engagement_ticket", "job_name",
    "scheduled_run", "supervised_session", "course", "project",
    "deployment_manifest_match", "travel_notice_active",
    "known_issue_published", "replay_backlog", "vendor_approved_destination",
}


def _leaves(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v
            yield from _leaves(v)
    elif isinstance(node, list):
        for item in node:
            yield from _leaves(item)


def classify(event: dict) -> tuple[str, list[str]]:
    payload = event.get("payload") or {}
    text = json.dumps(event)
    cited = _IP_RE.findall(text) + _DOMAIN_RE.findall(text)
    for key, val in _leaves(event):
        if isinstance(val, (str, int)) and (
            key in _CITE_KEYS or key in ("legal_hold_flag", "hash_suffix")
        ):
            cited.append(str(val))

    if payload.get("legal_hold_flag") is True:
        return "escalate", sorted(set(cited))
    if any(payload.get(k) for k in _FP_CONTEXT_KEYS):
        return "false_positive", sorted(set(cited))
    for key, val in _leaves(event):
        if key in _LIST_CITE_KEYS and isinstance(val, list):
            cited += [str(v) for v in val]
    attempts = payload.get("failed_attempts") or payload.get(
        "failed_login_attempts", 0)
    if attempts >= 20 or str(payload.get("auth_type", "")).startswith("ntlm"):
        return "true_positive", sorted(set(cited))
    return "escalate", sorted(set(cited))


class ReferenceAgent(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = max(0, min(int(self.headers.get("content-length", 0)), 1_000_000))
        body = json.loads(self.rfile.read(length) or b"{}")
        verdict, cited = classify(body.get("event_data") or {})
        self._reply({"verdict": verdict, "cited_iocs": sorted(set(cited)),
                     "confidence": 0.95})

    def _reply(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class BrokenAgent(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = max(0, min(int(self.headers.get("content-length", 0)), 1_000_000))
        self.rfile.read(length)
        data = json.dumps(
            {"verdict": "false_positive", "cited_iocs": [], "confidence": 0.99}
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def serve(handler, port: int) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), handler)
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server
