import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import scanners  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pip_audit_raw():
    return json.loads((FIXTURES / "pip_audit_sample.json").read_text())


def _stub_client(severity_by_ghsa: dict[str, str]) -> httpx.Client:
    """httpx.Client whose transport returns a canned OSV response - no real network call."""
    def handler(request: httpx.Request) -> httpx.Response:
        ghsa_id = request.url.path.rsplit("/", 1)[-1]
        severity = severity_by_ghsa.get(ghsa_id)
        if severity is None:
            return httpx.Response(404)
        return httpx.Response(200, json={"database_specific": {"severity": severity}})

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_parse_pip_audit_dedupes_duplicate_setuptools_row(pip_audit_raw):
    client = _stub_client({})
    findings = scanners.parse_pip_audit(pip_audit_raw, client=client)

    setuptools_findings = [f for f in findings if f.package == "setuptools"]
    assert len(setuptools_findings) == 1
    assert setuptools_findings[0].fingerprint == "pysec-2026-3447:setuptools"


def test_parse_pip_audit_skips_packages_with_no_vulns(pip_audit_raw):
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    packages = {f.package for f in findings}
    assert "bcrypt" not in packages  # 0 vulns in the fixture
    assert packages == {"flask", "paramiko", "setuptools", "pip"}


def test_parse_pip_audit_empty_fix_versions_stays_none_not_guessed(pip_audit_raw):
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    paramiko = next(f for f in findings if f.package == "paramiko")
    assert paramiko.fixed_version is None
    assert paramiko.cve_id == "CVE-2026-44405"


def test_parse_pip_audit_resolves_severity_via_ghsa_alias(pip_audit_raw):
    client = _stub_client({"GHSA-68rp-wp8r-4726": "LOW"})
    findings = scanners.parse_pip_audit(pip_audit_raw, client=client)
    flask = next(f for f in findings if f.package == "flask")
    assert flask.severity == "low"


def test_parse_pip_audit_severity_is_unrated_on_any_failure(pip_audit_raw):
    client = _stub_client({})  # every GHSA lookup 404s
    findings = scanners.parse_pip_audit(pip_audit_raw, client=client)
    assert all(f.severity == "unrated" for f in findings)


# --- Fan-out fix: multiple distinct CVEs at one (package, version) group into
# ONE Finding, not one per CVE (real, observed: pip==25.1.1 has 5 CVEs, mcp==
# 1.24.0 has 3) - dispatching one Devin session per CVE would race several
# sessions against the exact same pin bump.

def test_parse_pip_audit_groups_multiple_cves_for_same_package_into_one_finding(pip_audit_raw):
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    pip_findings = [f for f in findings if f.package == "pip"]
    assert len(pip_findings) == 1


def test_grouped_finding_fingerprint_joins_sorted_vuln_ids(pip_audit_raw):
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    pip_finding = next(f for f in findings if f.package == "pip")
    assert pip_finding.fingerprint == "pysec-2026-1001+pysec-2026-1002:pip"


def test_single_cve_fingerprint_format_is_unchanged_for_backward_compat(pip_audit_raw):
    # Already-issued findings (setuptools, flask, paramiko) embed their
    # fingerprint in a real, live GitHub issue marker - this format must
    # never change for a package with exactly one CVE.
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    setuptools_finding = next(f for f in findings if f.package == "setuptools")
    assert setuptools_finding.fingerprint == "pysec-2026-3447:setuptools"


def test_grouped_finding_fixed_version_is_the_max_across_the_group(pip_audit_raw):
    # pip's two CVEs fix at 25.2.0 and 25.3.0 respectively - the pin must move
    # to at least 25.3.0 to resolve both at once.
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    pip_finding = next(f for f in findings if f.package == "pip")
    assert pip_finding.fixed_version == "25.3.0"


def test_grouped_finding_fixed_version_is_none_if_any_cve_has_no_fix(pip_audit_raw):
    raw = json.loads(json.dumps(pip_audit_raw))
    pip_dep = next(d for d in raw["dependencies"] if d["name"] == "pip")
    pip_dep["vulns"][1]["fix_versions"] = []  # second CVE has no published fix

    findings = scanners.parse_pip_audit(raw, client=_stub_client({}))
    pip_finding = next(f for f in findings if f.package == "pip")
    assert pip_finding.fixed_version is None


def test_grouped_finding_cve_id_lists_every_cve_in_the_group(pip_audit_raw):
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    pip_finding = next(f for f in findings if f.package == "pip")
    assert pip_finding.cve_id == "CVE-2026-10001, CVE-2026-10002"


def test_grouped_finding_severity_is_the_worst_across_the_group(pip_audit_raw):
    client = _stub_client({"GHSA-aaaa-bbbb-cccc": "LOW", "GHSA-dddd-eeee-ffff": "CRITICAL"})
    findings = scanners.parse_pip_audit(pip_audit_raw, client=client)
    pip_finding = next(f for f in findings if f.package == "pip")
    assert pip_finding.severity == "critical"


def test_grouped_finding_summary_mentions_every_vuln_id_in_the_group(pip_audit_raw):
    findings = scanners.parse_pip_audit(pip_audit_raw, client=_stub_client({}))
    pip_finding = next(f for f in findings if f.package == "pip")
    assert "PYSEC-2026-1001" in pip_finding.summary
    assert "PYSEC-2026-1002" in pip_finding.summary
