"""Scorecard rendering: rich terminal, markdown, SARIF, JUnit XML.

All formats are deterministic functions of the scorecard. No LLM
touches the grading or the reporting path. Accuracy is reported with
Wilson score intervals and per-case reliability as pass^k bounds
(tau-bench), because small samples deserve honest uncertainty.
"""

import json
import re
from xml.etree.ElementTree import Element, SubElement, tostring

from .models import ERROR_VERDICT, Scorecard, Severity
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


def _scope_line(card: Scorecard) -> str | None:
    """Coverage, stated whenever anything was mapped or excluded.

    A percentage with cases silently dropped is a worse number than a
    lower percentage with the drops named.
    """
    if not card.excluded and not card.mapped_case_ids:
        return None
    graded = len(card.cases)
    parts = [f"Graded {graded} of {graded + len(card.excluded)} cases"]
    if card.mapped_case_ids:
        parts.append(f"{len(card.mapped_case_ids)} mapped into the subject's taxonomy")
    if card.excluded:
        types = sorted({e.event_type for e in card.excluded if e.event_type})
        parts.append(
            f"{len(card.excluded)} excluded as outside it"
            + (f" ({', '.join(types)})" if types else "")
        )
    return ", ".join(parts) + "."


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
            if conf is None or ruling == ERROR_VERDICT:
                continue
            pairs.append((conf, ruling == c.expected_verdict))
    score = brier_score(pairs)
    if score is None:
        return None
    return f"Confidence calibration (Brier): {score:.3f} over {len(pairs)} scored runs"


def _errors_line(card: Scorecard) -> str | None:
    """Infrastructure errors, counted separately from the agent's record."""
    if not card.total_errors:
        return None
    incomplete = sum(1 for c in card.cases if c.incomplete)
    parts = [
        f"{card.total_errors} run(s) ended in infrastructure errors, "
        "excluded from accuracy and calibration"
    ]
    if incomplete:
        parts.append(f"{incomplete} case(s) incomplete (majority of runs errored)")
    return ", ".join(parts)


def _case_mark(case) -> str:
    if case.incomplete:
        return "INCOMPLETE"
    return "PASS" if case.passed else "FAIL"


def _reliability_line(case) -> str:
    gradable = case.runs - case.error_runs
    observed = f"observed {case.verdict_correct_runs}/{gradable} correct"
    if case.runs < 2 or gradable == 0:
        return observed
    low, high = verdict_flip_probability(gradable, case.verdict_correct_runs)
    return f"pass^{gradable} in [{low:.2f}, {high:.2f}] assuming independence, {observed}"


def _provenance_line(card: Scorecard) -> str | None:
    """Which tool and which pack produced this, so archived scorecards
    stay comparable across releases."""
    if not card.tool_version and not card.pack_fingerprint:
        return None
    parts = []
    if card.tool_version:
        parts.append(f"overruled {card.tool_version}")
    if card.pack_fingerprint:
        parts.append(f"pack {card.pack_fingerprint[:12]}")
    return ", ".join(parts)


def to_markdown(card: Scorecard) -> str:
    if not card.passed:
        outcome = f"{card.total_failures} finding(s)"
    elif card.total_failures:
        outcome = f"PASSED ({card.total_failures} minor)"
    else:
        outcome = "ALL PASSED"
    lines = [
        f"# overruled scorecard: {card.subject}",
        "",
        f"Ran {len(card.cases)} cases. {outcome}. {_accuracy_line(card)}",
        "",
    ]
    provenance = _provenance_line(card)
    if provenance:
        lines.extend([provenance, ""])
    scope = _scope_line(card)
    if scope:
        lines.extend([scope, ""])
    errors = _errors_line(card)
    if errors:
        lines.extend([errors, ""])
    for case in card.cases:
        mark = _case_mark(case)
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
                # backticked so agent-controlled text cannot inject
                # markdown links into published scorecards
                lines.append(
                    f"- **{r.rule_id} ({r.severity.value})** {r.check}: "
                    f"`{r.detail}`"
                )
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
                "properties": {
                    "caseId": c.case_id,
                    "runs": c.runs,
                    "errorRuns": c.error_runs,
                },
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "overruled",
                "informationUri": "https://github.com/MohibShaikh/overruled",
                "version": card.tool_version,
                "rules": list(rules.values()),
            }},
            "properties": {
                "errorRuns": card.total_errors,
                "packFingerprint": card.pack_fingerprint,
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_junit(card: Scorecard) -> str:
    """JUnit XML so any CI system can gate on overruled natively."""
    def xml_safe(text: str) -> str:
        # XML 1.0 forbids these code points outright; leaving them in
        # produces a report strict parsers must reject
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)

    suite = Element("testsuite", {
        "name": xml_safe(f"overruled:{card.subject}"),
        "tests": str(len(card.cases) + len(card.excluded)),
        "failures": str(sum(1 for c in card.cases if not c.passed)),
        "skipped": str(len(card.excluded)),
    })
    props = SubElement(suite, "properties")
    for name, value in (
        ("toolVersion", card.tool_version),
        ("packFingerprint", card.pack_fingerprint),
        ("errorRuns", str(card.total_errors)),
    ):
        if value:
            SubElement(props, "property", {"name": name, "value": value})
    for c in card.cases:
        tc = SubElement(suite, "testcase", {
            "classname": xml_safe(card.subject),
            "name": xml_safe(f"{c.case_id} ({c.runs} runs)"),
        })
        if not c.passed:
            failure = SubElement(tc, "failure", {
                "message": xml_safe("; ".join(
                    f"{f.rule_id}: {f.detail}" for f in c.failures)),
            })
            failure.text = xml_safe(
                "\n".join(f"{f.rule_id} [{f.severity.value}] {f.detail}"
                          for f in c.failures)
            )
    for e in card.excluded:
        tc = SubElement(suite, "testcase", {
            "classname": card.subject, "name": xml_safe(f"{e.case_id} (not graded)"),
        })
        SubElement(tc, "skipped", {"message": xml_safe(f"{e.reason}: {e.event_type}")})
    return tostring(suite, encoding="unicode")


def print_card(card: Scorecard) -> None:
    from rich.console import Console
    from rich.markup import escape
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
                # details carry agent-controlled text; escaped so a
                # citation like "[/] cannot forge or break the report
                parts.append(
                    f"[{color}]{f.rule_id}[/{color}] {escape(f.check)}: {escape(f.detail)}"
                )
            findings = "\n".join(parts)
        mark = _case_mark(case)
        color = "green" if mark == "PASS" else "yellow" if mark == "INCOMPLETE" else "red"
        table.add_row(
            f"{escape(case.case_name)}\n[dim]{escape(case.case_id)}[/dim]",
            str(case.runs),
            f"[{color}]{mark}[/{color}]",
            findings,
        )

    console.print(table)
    if not card.cases:
        verdict = "[yellow]NOT GRADED[/yellow] (no case survived scoping; nothing was measured)"
    elif card.passed:
        if card.total_failures:
            verdict = (f"[green]SUBJECT PASSES[/green] "
                       f"({card.total_failures} minor finding(s), "
                       f"--strict fails on these)")
        else:
            verdict = "[green]SUBJECT PASSES[/green]"
    else:
        verdict = f"[red]SUBJECT FAILS[/red] ({card.total_failures} finding(s))"
    console.print(verdict)
    console.print(_accuracy_line(card))
    provenance = _provenance_line(card)
    if provenance:
        console.print(f"[dim]{provenance}[/dim]")
    errors = _errors_line(card)
    if errors:
        console.print(errors)
    scope = _scope_line(card)
    if scope:
        console.print(scope)
    calibration = _calibration_line(card)
    if calibration:
        console.print(calibration)
