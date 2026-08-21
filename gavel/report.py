"""Scorecard rendering: rich terminal, markdown, SARIF, JUnit XML.

All formats are deterministic functions of the scorecard. No LLM
touches the grading or the reporting path.
"""

import json
from xml.etree.ElementTree import Element, SubElement, tostring

from .models import Scorecard, Severity

_SEVERITY_MARK = {
    Severity.CRITICAL: "!!",
    Severity.MAJOR: "! ",
    Severity.MINOR: ". ",
    Severity.INFO: "  ",
}

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.MAJOR: "error",
    Severity.MINOR: "warning",
    Severity.INFO: "note",
}


def to_markdown(card: Scorecard) -> str:
    lines = [
        f"# Gavel scorecard: {card.subject}",
        "",
        f"Ran {len(card.cases)} cases. "
        f"{'ALL PASSED' if card.passed else f'{card.total_failures} finding(s)'}",
        "",
    ]
    for case in card.cases:
        mark = "PASS" if case.passed else "FAIL"
        lines.append(f"## [{mark}] {case.case_name} (`{case.case_id}`, {case.runs} runs)")
        if not case.failures:
            for r in case.results:
                lines.append(f"- {r.check}: {r.detail}")
        else:
            for r in case.failures:
                lines.append(f"- **{r.rule_id} ({r.severity.value})** {r.check}: {r.detail}")
        lines.append("")
    return "\n".join(lines)


def to_sarif(card: Scorecard) -> str:
    """SARIF 2.1.0 so findings land in existing dashboards and CI gates."""
    rules = {
        r.rule_id: {"id": r.rule_id, "name": r.check}
        for c in card.cases for r in c.results
    }
    results = []
    for c in card.cases:
        for r in c.failures:
            results.append({
                "ruleId": r.rule_id,
                "level": _SARIF_LEVEL[r.severity],
                "message": {"text": f"{c.case_name}: {r.detail}"},
                "properties": {"caseId": c.case_id, "runs": c.runs},
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "gavel",
                "informationUri": "https://github.com/gavel-audit/gavel",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_junit(card: Scorecard) -> str:
    """JUnit XML so any CI system can gate on gavel natively."""
    suite = Element("testsuite", {
        "name": f"gavel:{card.subject}",
        "tests": str(len(card.cases)),
        "failures": str(sum(1 for c in card.cases if not c.passed)),
    })
    for c in card.cases:
        tc = SubElement(suite, "testcase", {
            "classname": card.subject,
            "name": f"{c.case_id} ({c.runs} runs)",
        })
        if not c.passed:
            failure = SubElement(tc, "failure", {
                "message": "; ".join(f"{f.rule_id}: {f.detail}" for f in c.failures),
            })
            failure.text = "\n".join(f"{f.rule_id} [{f.severity.value}] {f.detail}"
                                     for f in c.failures)
    return tostring(suite, encoding="unicode")


def print_card(card: Scorecard) -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title=f"Gavel: {card.subject}", show_lines=True)
    table.add_column("Case")
    table.add_column("Runs", justify="right")
    table.add_column("Result")
    table.add_column("Findings")

    for case in card.cases:
        if case.passed:
            findings = "[green]clean[/green]"
        else:
            parts = []
            for f in case.failures:
                color = "red" if f.severity == Severity.CRITICAL else "yellow"
                parts.append(f"[{color}]{f.rule_id}[/{color}] {f.check}: {f.detail}")
            findings = "\n".join(parts)
        table.add_row(
            f"{case.case_name}\n[dim]{case.case_id}[/dim]",
            str(case.runs),
            "[green]PASS[/green]" if case.passed else "[red]FAIL[/red]",
            findings,
        )

    console.print(table)
    verdict = "[green]SUBJECT PASSES[/green]" if card.passed else \
        f"[red]SUBJECT FAILS[/red] ({card.total_failures} finding(s))"
    console.print(verdict)
