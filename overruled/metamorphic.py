"""Metamorphic transforms: surface changes that must not move the verdict.

From metamorphic testing (Chen et al.): feed a relation-preserving
variant of the input; a correct system keeps its answer. A SOC agent
that flips its ruling because the source IP changed is pattern
matching on cosmetics, not reasoning on behavior.

Transforms are declared per case in YAML (`metamorphic: [swap_source_ip]`)
because only the case author knows which fields carry ground truth.
Swapping the IP on a case whose benign ruling depends on CMDB asset
identity would be a bad transform, so nothing runs unless declared.
"""

import re

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_DOC_RANGES = ["203.0.113.", "198.51.100.", "192.0.2."]

_SUBSTITUTION_USERS = ["audit-reader", "svc-inventory", "temp-reviewer"]

_SUBSTITUTION_DOMAINS = [
    "alt-mirror.example.com",
    "secondary-node.example.com",
    "replica-edge.example.com",
]


def _hash_index(value: str, modulo: int) -> int:
    return sum(value.encode()) % modulo


def swap_source_ip(event: dict) -> dict:
    """Replace every IP value with another address in the doc ranges."""
    out = _deep_copy(event)
    _replace_matching(out, _IP_RE, lambda v: _doc_ip(v))
    return out


_USER_KEY_RE = re.compile(r"(?:^|_)(user|account|actor)(?:_name)?s?$",
                          re.IGNORECASE)


def rename_user(event: dict) -> dict:
    """Swap user/account identifiers for neutral ones.

    Recurses through the whole event for keys ending in user, account,
    or actor (plural allowed). Free text is left alone, so a username
    buried inside a prose field survives the transform; scope is
    documented here rather than claimed complete.
    """
    out = _deep_copy(event)

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, val in node.items():
                if isinstance(val, str) and _USER_KEY_RE.search(key):
                    node[key] = _SUBSTITUTION_USERS[
                        _hash_index(val, len(_SUBSTITUTION_USERS))
                    ]
                else:
                    walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(out)
    return out


def rebrand_domain(event: dict) -> dict:
    """Swap domains for structurally identical example.com hosts."""
    out = _deep_copy(event)
    _replace_matching(
        out,
        re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE),
        lambda v: _SUBSTITUTION_DOMAINS[_hash_index(v, len(_SUBSTITUTION_DOMAINS))],
    )
    _replace_url_hosts(out)
    return out


_URL_RE = re.compile(r"^(https?)://([^/]+)(/.*)?$")


def _swap_url_host(url: str) -> str:
    match = _URL_RE.match(url)
    if not match:
        return url
    scheme, host, path = match.groups()
    new_host = _SUBSTITUTION_DOMAINS[_hash_index(host, len(_SUBSTITUTION_DOMAINS))]
    return f"{scheme}://{new_host}{path or ''}"


def _replace_url_hosts(node) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(val, str) and val.startswith(("http://", "https://")):
                node[key] = _swap_url_host(val)
            else:
                _replace_url_hosts(val)
    elif isinstance(node, list):
        for item in node:
            _replace_url_hosts(item)


def reorder_payload(event: dict) -> dict:
    """Reverse payload key order; semantics identical, surface differs.

    From Safetility (Litvak 2026): deployability requires verdicts that
    survive benign formatting changes.
    """
    out = _deep_copy(event)
    if isinstance(out.get("payload"), dict):
        out["payload"] = dict(reversed(list(out["payload"].items())))
    return out


def reformat_numbers(event: dict) -> dict:
    """Render integer counts with thousands separators as strings."""
    out = _deep_copy(event)
    payload = out.get("payload")
    if isinstance(payload, dict):
        for key, val in list(payload.items()):
            if isinstance(val, int) and not isinstance(val, bool) and val >= 1000:
                payload[key] = f"{val:,}"
    return out


TRANSFORMS = {
    "swap_source_ip": swap_source_ip,
    "rename_user": rename_user,
    "rebrand_domain": rebrand_domain,
    "reorder_payload": reorder_payload,
    "reformat_numbers": reformat_numbers,
}


def apply_transforms(event: dict, names: list[str]) -> dict:
    out = event
    for name in names:
        try:
            out = TRANSFORMS[name](out)
        except KeyError:
            raise ValueError(f"unknown metamorphic transform: {name}") from None
    return out


def _doc_ip(value: str) -> str:
    prefix = _DOC_RANGES[_hash_index(value, len(_DOC_RANGES))]
    host = (_hash_index(value, 250) + 1)
    return f"{prefix}{host}"


def _deep_copy(value):
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value


def _replace_matching(node, pattern, substitute) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(val, str) and pattern.match(val):
                node[key] = substitute(val)
            else:
                _replace_matching(val, pattern, substitute)
    elif isinstance(node, list):
        for item in node:
            _replace_matching(item, pattern, substitute)
