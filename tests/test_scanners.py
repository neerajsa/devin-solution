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
    assert packages == {"flask", "paramiko", "setuptools"}


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
