"""Case loading from YAML files."""

import json
from pathlib import Path

import yaml

from .models import Case


def load_case(path: Path) -> Case:
    with open(path) as f:
        data = yaml.safe_load(f)
    case = Case.model_validate(data)
    _validate_discoverable(case)
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


def load_cases(paths: list[Path]) -> list[Case]:
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(p.glob("*.y*ml")))
        elif p.is_file() and p.suffix in (".yaml", ".yml"):
            files.append(p)
    cases = [load_case(f) for f in sorted(files)]
    if not cases:
        raise FileNotFoundError(f"no case files found in {paths}")
    return cases
