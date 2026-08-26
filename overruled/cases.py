"""Case loading from YAML files."""

import hashlib
import json
from pathlib import Path

import yaml

from .models import Case

BUNDLED_CASES = Path(__file__).parent / "cases"


def bundled_cases() -> list[Case]:
    """The case pack that ships with the package.

    Installing overruled has to give you something to audit against, or
    every command in the docs needs a git clone first.
    """
    return load_cases([BUNDLED_CASES])


def load_case(path: Path) -> Case:
    with open(path) as f:
        data = yaml.safe_load(f)
    case = Case.model_validate(data)
    _validate_discoverable(case)
    _validate_evidence(case)
    return case


def _validate_discoverable(case: Case) -> None:
    """Discoverable facts must be nested, never alert headline values.

    A discoverable IOC that sits at the top level of the event proves
    nothing about investigation depth; citing it is parroting. SIR-Bench
    credits only findings beyond the alert's headline fields.
    """
    event_str = json.dumps(case.event)
    top_level = {
        str(v) for v in case.event.values() if not isinstance(v, (dict, list))
    }
    for item in case.discoverable:
        if item.ioc not in event_str:
            raise ValueError(
                f"{case.id}: discoverable {item.ioc!r} not grounded in event"
            )
        if item.ioc in top_level:
            raise ValueError(
                f"{case.id}: discoverable {item.ioc!r} is a headline field, "
                f"move it into payload context"
            )


def _validate_evidence(case: Case) -> None:
    """Planted evidence has to be recoverable from what the agent sees.

    YAML reads 0x0900c3 as the integer 590019, so an unquoted scalar in
    the event leaves the graded IOC unsurfaceable by any honest agent:
    a guaranteed wrong conviction hiding inside an otherwise valid
    case. Reject at load time, not in a breach postmortem.
    """
    event_str = json.dumps(case.event)
    for item in case.evidence:
        if item.ioc not in event_str:
            raise ValueError(
                f"{case.id}: planted evidence {item.ioc!r} never appears "
                f"in the event (an unquoted scalar like 0x0900c3 parses "
                f"as an integer; quote it)"
            )


def _case_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(p.glob("*.y*ml")))
        elif p.is_file() and p.suffix in (".yaml", ".yml"):
            files.append(p)
    return files


def pack_fingerprint(paths: list[Path]) -> str:
    """sha256 over the case file names and bytes, sorted.

    Scorecards claim to be reproducible and diffable; without this they
    stop being comparable the moment the pack changes. Hashed by file
    name, not full path, so the same pack hashes identically from a
    wheel, a checkout, or a held-out directory -- and identically
    however the paths were ordered on the command line.
    """
    digest = hashlib.sha256()
    for f in sorted(_case_files(paths)):
        digest.update(f.name.encode())
        digest.update(f.read_bytes())
    return digest.hexdigest()


def load_cases(paths: list[Path]) -> list[Case]:
    cases = [load_case(f) for f in sorted(_case_files(paths))]
    if not cases:
        raise FileNotFoundError(f"no case files found in {paths}")
    counts: dict[str, int] = {}
    for c in cases:
        counts[c.id] = counts.get(c.id, 0) + 1
    duplicates = sorted(cid for cid, n in counts.items() if n > 1)
    if duplicates:
        raise ValueError(f"duplicate case ids across the pack: {duplicates}")
    return cases
