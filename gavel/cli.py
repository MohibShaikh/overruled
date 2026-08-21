"""CLI entrypoint for gavel."""

import argparse
import asyncio
import sys
from pathlib import Path

from .auditor import Auditor
from .cases import load_cases
from .report import print_card, to_junit, to_markdown, to_sarif
from .subject import SubjectAdapter, ThreatSentinelAdapter

_FORMATS = ("rich", "markdown", "sarif", "junit")


def _subject(spec: str) -> tuple[str, SubjectAdapter]:
    name, sep, url = spec.partition("=")
    if not sep:
        raise argparse.ArgumentTypeError(f"expected name=url, got {spec!r}")
    return name, ThreatSentinelAdapter(url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gavel",
        description="The verdict auditor for AI SOC agents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="audit one subject agent against cases")
    run_p.add_argument("cases", nargs="+", type=Path, help="case files or directories")
    run_p.add_argument("--url", default="http://localhost:8000", help="subject agent base URL")
    run_p.add_argument("--token", default="dev-secret-key", help="bearer token for the subject")
    run_p.add_argument("--runs", type=int, default=3, help="runs per case")
    run_p.add_argument("--format", choices=_FORMATS, default="rich")
    run_p.add_argument("--out", type=Path, help="write report to file instead of stdout")

    cmp_p = sub.add_parser("compare", help="audit several subjects on the same cases")
    cmp_p.add_argument("cases", nargs="+", type=Path)
    cmp_p.add_argument("--subject", dest="subjects", action="append", type=_subject,
                       required=True, metavar="NAME=URL")
    cmp_p.add_argument("--token", default="dev-secret-key")
    cmp_p.add_argument("--runs", type=int, default=3)

    args = parser.parse_args(argv)

    if args.command == "run":
        return asyncio.run(_run(args))
    if args.command == "compare":
        return asyncio.run(_compare(args))
    return 2


async def _run(args) -> int:
    cases = load_cases(list(args.cases))
    subject = ThreatSentinelAdapter(args.url, args.token)
    card = await Auditor(subject, runs_per_case=args.runs).run(cases)
    _emit(card, args.format, args.out)
    return 0 if card.passed else 1


async def _compare(args) -> int:
    from rich.console import Console
    from rich.table import Table

    cases = load_cases(list(args.cases))
    console = Console()
    table = Table(title=f"Gavel comparison: {len(cases)} cases, {args.runs} runs each")
    table.add_column("Case")
    for name, _ in args.subjects:
        table.add_column(name, justify="center")

    cards: dict[str, dict[str, bool]] = {name: {} for name, _ in args.subjects}
    for case in cases:
        row = [f"{case.name}\n[dim]{case.id}[/dim]"]
        for name, adapter in args.subjects:
            card = await Auditor(adapter, runs_per_case=args.runs).run([case])
            cards[name][case.id] = card.passed
            row.append("[green]PASS[/green]" if card.passed else "[red]FAIL[/red]")
        table.add_row(*row)

    console.print(table)
    summary = "  ".join(
        f"{name}: {sum(v.values())}/{len(cases)}" for name, v in cards.items()
    )
    console.print(summary)
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
