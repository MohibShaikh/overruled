"""Scorecard rendering: rich terminal, markdown, SARIF, JUnit XML.

All formats are deterministic functions of the scorecard. No LLM
touches the grading or the reporting path. Accuracy is reported with
Wilson score intervals and per-case reliability as pass^k bounds
(tau-bench), because small samples deserve honest uncertainty.
"""

import json
from xml.etree.ElementTree import Element, SubElement, tostring

from .models import Scorecard, Severity
from .stats import (
    brier_score,
    cohens_kappa,
    expected_loss,
    verdict_flip_probability,
    wilson_interval,
)

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


def _accuracy_line(card: Scorecard) -> str:
    correct, total = card.accuracy
    if total == 0:
        return "No runs recorded."
    low, high = wilson_interval(correct, total)
    parts = [
        f"Verdict accuracy {correct}/{total} "
        f"({correct / total:.0%}, 95% CI {low:.0%}-{high:.0%})"
    ]
    kappa = cohens_kappa(card.ruling_pairs)
    if kappa is not None:
        band = "good" if kappa >= 0.8 else "fair" if kappa >= 0.6 else "poor"
        parts.append(f"kappa {kappa:.2f} ({band})")
    fn, fp = card.security_errors
    if fn or fp:
        loss = expected_loss(fn, fp, total_runs=card.accuracy[1])
        parts.append(
            f"expected loss {loss:.1f} units/100 alerts "
            f"(FN weight 20:1, {fn} missed threats, {fp} false alarms)"
        )
    return ", ".join(parts)


def _calibration_line(card: Scorecard) -> str | None:
    pairs = []
    for c in card.cases:
        for conf, ruling in zip(c.confidences, c.rulings, strict=True):
            if conf is None:
                continue
            pairs.append((conf, ruling == c.expected_verdict))
    score = brier_score(pairs)
    if score is None:
        return None
    return f"Confidence calibration (Brier): {score:.3f} over {len(pairs)} scored runs"


def _reliability_line(case) -> str:
    if case.runs < 2:
        return ""
    low, high = verdict_flip_probability(case.runs, case.verdict_correct_runs)
    return f"pass^{case.runs} in [{low:.2f}, {high:.2f}]"


def to_markdown(card: Scorecard) -> str:
    lines = [
        f"# overruled scorecard: {card.subject}",
        "",
        f"Ran {len(card.cases)} cases. "
        f"{'ALL PASSED' if card.passed else f'{card.total_failures} finding(s)'}. "
        f"{_accuracy_line(card)}",
        "",
    ]
    for case in card.cases:
        mark = "PASS" if case.passed else "FAIL"
        reliability = _reliability_line(case)
        suffix = f", {reliability}" if reliability else ""
        lines.append(
            f"## [{mark}] {case.case_name} (`{case.case_id}`, {case.runs} runs{suffix})"
        )
        if not case.failures:
            for r in case.results:
                lines.append(f"- {r.check}: {r.detail}")
        else:
            for r in case.failures:
                lines.append(f"- **{r.rule_id} ({r.severity.value})** {r.check}: {r.detail}")
        lines.append("")
    calibration = _calibration_line(card)
    if calibration:
        lines.append("## Calibration")
        lines.append(f"- {calibration}")
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
                "name": "overruled",
                "informationUri": "https://github.com/MohibShaikh/overruled",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_junit(card: Scorecard) -> str:
    """JUnit XML so any CI system can gate on overruled natively."""
    suite = Element("testsuite", {
        "name": f"overruled:{card.subject}",
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
    table = Table(title=f"overruled: {card.subject}", show_lines=True)
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
    console.print(_accuracy_line(card))
    calibration = _calibration_line(card)
    if calibration:
        console.print(calibration)
