"""Case loading from YAML files."""

from pathlib import Path

import yaml

from .models import Case


def load_case(path: Path) -> Case:
    with open(path) as f:
        data = yaml.safe_load(f)
    return Case.model_validate(data)


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
