import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from scanners import Finding  # noqa: E402
import prompts  # noqa: E402


def test_dependency_cve_prompt_with_a_fix_version_instructs_upgrade():
    finding = Finding(
        fingerprint="pysec-2026-2151:flask", source="pip-audit", finding_class="dependency-cve",
        severity="low", summary="Flask CVE", package="flask", current_version="2.3.3",
        fixed_version="3.1.3", cve_id="CVE-2026-27205",
    )
    text = prompts.render_prompt(finding, repo="neerajsa/superset", branch="master", run_id="run-1")

    assert "Fixed in: 3.1.3" in text
    assert "upgrade the pin to the minimum version at or above" in text
    assert "flask" in text


def test_dependency_cve_prompt_with_no_fix_instructs_no_guessing():
    finding = Finding(
        fingerprint="pysec-2026-2858:paramiko", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="paramiko CVE", package="paramiko", current_version="3.5.1",
        fixed_version=None, cve_id="CVE-2026-44405",
    )
    text = prompts.render_prompt(finding, repo="neerajsa/superset", branch="master", run_id="run-1")

    assert "Fixed in: none published" in text
    assert "Do not guess a version" in text
    assert "needs_human" in text


def test_reported_issue_prompt_instructs_investigation_not_a_prescribed_fix():
    finding = Finding(
        fingerprint="github-issue-42", source="github-issue", finding_class="reported-issue",
        severity="unrated", summary="Previous calendar quarter is off by one at year boundaries",
    )
    text = prompts.render_prompt(finding, repo="neerajsa/superset", branch="master", run_id="run-1")

    assert "Find the actual root cause" in text
    assert "regression test" in text
    assert "Previous calendar quarter is off by one at year boundaries" in text


def test_render_prompt_raises_for_unknown_finding_class():
    finding = Finding(
        fingerprint="f", source="s", finding_class="not-a-real-class",
        severity="unrated", summary="s",
    )
    with pytest.raises(ValueError, match="not-a-real-class"):
        prompts.render_prompt(finding)


def test_structured_output_schema_has_the_required_fields_and_enum():
    schema = prompts.STRUCTURED_OUTPUT_SCHEMA
    assert set(schema["required"]) == {
        "finding_id", "status", "files_changed", "tests_passed", "summary", "confidence",
    }
    assert schema["properties"]["status"]["enum"] == [
        "remediated", "partially_remediated", "not_applicable", "needs_human",
    ]
    # "summary" is required but was missing from properties in the original spec text -
    # fixed here since we actually ship this schema to a real API now.
    assert schema["properties"]["summary"] == {"type": "string"}
