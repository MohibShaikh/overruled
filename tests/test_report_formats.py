"""Output contract tests: SARIF and JUnit are consumed by other tools,
so a malformed document breaks a dashboard silently instead of loudly.
These assert the structure downstream parsers require, and that hostile
detail text survives escaping intact."""

import json
from xml.etree import ElementTree

from overruled.models import CaseScore, CheckResult, Scorecard, Severity
from overruled.report import to_junit, to_markdown, to_sarif

_HOSTILE = 'detail with <tag> & "quotes" and \'apostrophes\''


def _card() -> Scorecard:
    return Scorecard(
        subject="agent@<test>",
        cases=[
            CaseScore(
                case_id="case-ok-001",
                case_name="clean case",
                runs=3,
                passed=True,
                verdict_correct_runs=3,
                expected_verdict="false_positive",
                rulings=["false_positive"] * 3,
                confidences=[0.8, 0.8, 0.9],
                results=[
                    CheckResult(rule_id="OV-001", check="verdict", passed=True,
                                severity=Severity.CRITICAL, detail="ruled as expected"),
                ],
            ),
            CaseScore(
                case_id="case-bad-001",
                case_name="failing case",
                runs=3,
                passed=False,
                verdict_correct_runs=0,
                expected_verdict="true_positive",
                rulings=["false_positive"] * 3,
                confidences=[0.99, 0.99, None],
                results=[
                    CheckResult(rule_id="OV-001", check="verdict", passed=False,
                                severity=Severity.CRITICAL, detail=_HOSTILE),
                    CheckResult(rule_id="OV-003", check="missed_evidence", passed=False,
                                severity=Severity.MAJOR, detail="missed 203.0.113.66"),
                    CheckResult(rule_id="OV-004", check="consistency", passed=True,
                                severity=Severity.MAJOR, detail="stable"),
                ],
            ),
        ],
    )


class TestSarif:
    """SARIF 2.1.0 required shape (spec sections 3.13-3.27). This is a
    structural conformance check, not full JSON-schema validation."""

    def setup_method(self):
        self.doc = json.loads(to_sarif(_card()))

    def test_parses_and_declares_version(self):
        assert self.doc["version"] == "2.1.0"
        assert self.doc["$schema"].endswith("sarif-2.1.0.json")

    def test_run_carries_a_tool_driver(self):
        driver = self.doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "overruled"
        assert driver["informationUri"].startswith("https://")

    def test_only_failures_become_results(self):
        results = self.doc["runs"][0]["results"]
        assert len(results) == 2
        assert {r["ruleId"] for r in results} == {"OV-001", "OV-003"}

    def test_every_result_is_well_formed(self):
        for result in self.doc["runs"][0]["results"]:
            assert result["level"] in ("error", "warning", "note", "none")
            assert result["message"]["text"]
            assert result["properties"]["caseId"]
            assert isinstance(result["properties"]["runs"], int)

    def test_result_rule_ids_resolve_to_declared_rules(self):
        declared = {r["id"] for r in self.doc["runs"][0]["tool"]["driver"]["rules"]}
        for result in self.doc["runs"][0]["results"]:
            assert result["ruleId"] in declared

    def test_rules_are_declared_once_each(self):
        ids = [r["id"] for r in self.doc["runs"][0]["tool"]["driver"]["rules"]]
        assert len(ids) == len(set(ids))

    def test_hostile_detail_survives_json_encoding(self):
        texts = [r["message"]["text"] for r in self.doc["runs"][0]["results"]]
        assert any(_HOSTILE in t for t in texts)


class TestJunit:
    def setup_method(self):
        self.suite = ElementTree.fromstring(to_junit(_card()))

    def test_parses_as_a_testsuite(self):
        assert self.suite.tag == "testsuite"
        assert self.suite.get("name").startswith("overruled:")

    def test_counts_match_the_cases(self):
        cases = self.suite.findall("testcase")
        assert self.suite.get("tests") == str(len(cases)) == "2"
        assert self.suite.get("failures") == "1"

    def test_passing_case_has_no_failure_child(self):
        passing = [tc for tc in self.suite.findall("testcase")
                   if tc.get("name").startswith("case-ok-001")]
        assert passing and passing[0].find("failure") is None

    def test_failing_case_reports_only_its_failures(self):
        failing = next(tc for tc in self.suite.findall("testcase")
                       if tc.get("name").startswith("case-bad-001"))
        failure = failing.find("failure")
        assert "OV-001" in failure.get("message")
        assert "OV-003" in failure.get("message")
        assert "OV-004" not in failure.get("message")

    def test_hostile_detail_round_trips_through_escaping(self):
        failing = next(tc for tc in self.suite.findall("testcase")
                       if tc.get("name").startswith("case-bad-001"))
        assert _HOSTILE in failing.find("failure").get("message")
        assert _HOSTILE in failing.find("failure").text


def test_markdown_names_the_tool_and_every_case():
    text = to_markdown(_card())
    assert text.startswith("# overruled scorecard:")
    assert "case-ok-001" in text and "case-bad-001" in text
    assert "Brier" in text


def test_nothing_graded_is_not_a_pass():
    """A subject could otherwise clear the gate by declaring a taxonomy
    that covers none of the pack: zero cases, vacuously all-passing."""
    from overruled.models import ExcludedCase

    card = Scorecard(subject="narrow", cases=[], excluded=[
        ExcludedCase(case_id="case-x", case_name="x", event_type="endpoint_anomaly"),
    ])
    assert not card.passed


def test_junit_counts_excluded_cases_as_skipped():
    from overruled.models import ExcludedCase

    card = _card()
    card.excluded.append(ExcludedCase(case_id="case-skip-001", case_name="skipped",
                                      event_type="cloud_api"))
    suite = ElementTree.fromstring(to_junit(card))
    assert suite.get("tests") == "3"
    assert suite.get("skipped") == "1"
    skipped = [tc for tc in suite.findall("testcase") if tc.find("skipped") is not None]
    assert len(skipped) == 1
    assert "cloud_api" in skipped[0].find("skipped").get("message")
