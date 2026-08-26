"""CLI entrypoint for overruled."""

import argparse
import asyncio
import sys
from pathlib import Path

from .auditor import Auditor
from .cases import BUNDLED_CASES, load_cases, pack_fingerprint
from .report import print_card, to_junit, to_markdown, to_sarif
from .subject import JSONAdapter, ThreatSentinelAdapter

_FORMATS = ("rich", "markdown", "sarif", "junit")


_ADAPTERS = {"threatsentinel": ThreatSentinelAdapter, "json": JSONAdapter}


def _subject(spec: str) -> tuple[str, str]:
    name, sep, url = spec.partition("=")
    if not sep:
        raise argparse.ArgumentTypeError(f"expected name=url, got {spec!r}")
    return name, url


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="overruled",
        description="The verdict auditor for AI SOC agents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="audit one subject agent against cases")
    run_p.add_argument("cases", nargs="*", type=Path,
                       help="case files or directories (default: the bundled pack)")
    run_p.add_argument("--url", default="http://localhost:8000", help="subject agent base URL")
    run_p.add_argument("--token", default="dev-secret-key", help="bearer token for the subject")
    run_p.add_argument("--adapter", choices=tuple(_ADAPTERS), default="threatsentinel",
                       help="subject contract: ThreatSentinel REST or minimal JSON")
    run_p.add_argument("--tp-levels", default="critical,high",
                       help="ThreatSentinel risk levels mapped to true_positive "
                            "(recorded on the scorecard subject string)")
    run_p.add_argument("--runs", type=int, default=3, help="runs per case")
    run_p.add_argument("--map-taxonomy", action="store_true",
                       help="translate cases into the subject's declared event "
                            "vocabulary, excluding those it does not cover")
    run_p.add_argument("--adaptive", action="store_true",
                       help="stop each case early once SPRT decides (Wald 1945)")
    run_p.add_argument("--strict", action="store_true",
                       help="fail the gate on MINOR findings too (the default "
                            "gate fails only CRITICAL and MAJOR)")
    run_p.add_argument("--format", choices=_FORMATS, default="rich")
    run_p.add_argument("--out", type=Path, help="write report to file instead of stdout")
    run_p.add_argument("--per-case-timeout", type=float, default=300.0,
                       help="wall-clock seconds before a single case is aborted "
                            "(default: 300)")

    cmp_p = sub.add_parser("compare", help="audit several subjects on the same cases")
    cmp_p.add_argument("cases", nargs="*", type=Path)
    cmp_p.add_argument("--subject", dest="subjects", action="append", type=_subject,
                       required=True, metavar="NAME=URL")
    cmp_p.add_argument("--token", default="dev-secret-key")
    cmp_p.add_argument("--adapter", choices=tuple(_ADAPTERS), default="threatsentinel",
                       help="subject contract: ThreatSentinel REST or minimal JSON")
    cmp_p.add_argument("--map-taxonomy", action="store_true")
    cmp_p.add_argument("--runs", type=int, default=3)
    cmp_p.add_argument("--per-case-timeout", type=float, default=300.0)

    args = parser.parse_args(argv)

    if args.command == "run":
        return asyncio.run(_run(args))
    if args.command == "compare":
        return asyncio.run(_compare(args))
    return 2


def _case_paths(args) -> list[Path]:
    return list(args.cases) or [BUNDLED_CASES]


def _tool_version() -> str:
    from importlib.metadata import version

    return version("overruled")


def _subject_adapter(args):
    kwargs = {}
    if args.adapter == "threatsentinel":
        kwargs["tp_levels"] = tuple(args.tp_levels.split(","))
    return _ADAPTERS[args.adapter](args.url, args.token, **kwargs)


async def _run(args) -> int:
    paths = _case_paths(args)
    cases = load_cases(paths)
    subject = _subject_adapter(args)
    card = await Auditor(subject, runs_per_case=args.runs, adaptive=args.adaptive,
                         map_taxonomy=args.map_taxonomy,
                         tool_version=_tool_version(),
                         pack_fingerprint=pack_fingerprint(paths),
                         strict=args.strict,
                         per_case_timeout=args.per_case_timeout).run(cases)
    _emit(card, args.format, args.out)
    return 0 if card.passed else 1


async def _compare(args) -> int:
    from rich.console import Console
    from rich.table import Table

    from .stats import mcnemar_exact

    cases = load_cases(_case_paths(args))
    subjects = [(name, _ADAPTERS[args.adapter](url, args.token))
                for name, url in args.subjects]
    console = Console()
    table = Table(title=f"overruled comparison: {len(cases)} cases, {args.runs} runs each")
    table.add_column("Case")
    for name, _ in subjects:
        table.add_column(name, justify="center")

    # None marks a case the subject declined as out of scope: a scope
    # difference is not a skill difference, so skips stay out of McNemar.
    results: dict[str, dict[str, bool | None]] = {name: {} for name, _ in subjects}
    for case in cases:
        row = [f"{case.name}\n[dim]{case.id}[/dim]"]
        for name, adapter in subjects:
            card = await Auditor(adapter, runs_per_case=args.runs,
                                 map_taxonomy=args.map_taxonomy,
                                 per_case_timeout=args.per_case_timeout).run([case])
            if card.excluded and not card.cases:
                results[name][case.id] = None
                row.append("[yellow]SKIP[/yellow]")
            else:
                results[name][case.id] = card.passed
                row.append("[green]PASS[/green]" if card.passed else "[red]FAIL[/red]")
        table.add_row(*row)

    console.print(table)
    summary = "  ".join(
        f"{name}: {sum(1 for v in r.values() if v)}/"
        f"{sum(1 for v in r.values() if v is not None)}"
        for name, r in results.items()
    )
    console.print(summary)

    names = [name for name, _ in subjects]
    if len(names) == 2:
        a, b = results[names[0]], results[names[1]]
        graded = [cid for cid in a if a[cid] is not None and b[cid] is not None]
        only_a = sum(1 for cid in graded if a[cid] and not b[cid])
        only_b = sum(1 for cid in graded if b[cid] and not a[cid])
        p = mcnemar_exact(only_a, only_b)
        call = "significant at 0.05" if p < 0.05 else "not significant"
        console.print(
            f"McNemar exact: {only_a} wins {names[0]}, {only_b} wins "
            f"{names[1]}, p={p:.3f} ({call}). Differences within noise "
            f"should not drive procurement."
        )
    return 0


def _emit(card, fmt: str, out: Path | None) -> None:
    if fmt == "rich":
        print_card(card)
        return
    text = {
        "markdown": to_markdown,
        "sarif": to_sarif,
        "junit": to_junit,
    }[fmt](card)
    if out:
        out.write_text(text)
        print(f"report written to {out}")
    else:
        print(text)


if __name__ == "__main__":
    sys.exit(main())
