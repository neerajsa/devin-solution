"""Normalizes raw scanner output into a common Finding shape."""

from dataclasses import dataclass

import httpx

OSV_API = "https://api.osv.dev/v1/vulns"


@dataclass
class Finding:
    fingerprint: str
    source: str
    finding_class: str
    severity: str
    summary: str
    package: str | None = None
    current_version: str | None = None
    fixed_version: str | None = None
    cve_id: str | None = None
    file_path: str | None = None


def _severity_from_aliases(aliases: list[str], client: httpx.Client) -> str:
    """Resolve severity via a GHSA alias's database_specific.severity. 'unrated' on any failure.

    pip-audit's own JSON never includes a severity field, so this is a
    real network call, not a local parse. Never infer severity from
    summary text - unrated is always the honest fallback.
    """
    ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), None)
    if not ghsa_id:
        return "unrated"
    try:
        resp = client.get(f"{OSV_API}/{ghsa_id}", timeout=10)
        resp.raise_for_status()
        severity = resp.json().get("database_specific", {}).get("severity")
        return severity.lower() if severity else "unrated"
    except (httpx.HTTPError, ValueError):
        return "unrated"


def parse_pip_audit(raw: dict, *, client: httpx.Client | None = None) -> list[Finding]:
    """Normalize `pip-audit --no-deps --format json` output.

    Dedupes on (package, version, vuln_id) - pip-audit really does return
    the same vulnerability twice for some packages (confirmed: setuptools/
    PYSEC-2026-3447). Never guesses a fixed_version when fix_versions is
    empty - that's a real, observed case (paramiko/PYSEC-2026-2858) meaning
    no safe version is published, not missing data to fill in.
    """
    owns_client = client is None
    client = client or httpx.Client()
    try:
        seen: set[tuple[str, str, str]] = set()
        findings = []
        for dep in raw.get("dependencies", []):
            package = dep["name"]
            version = dep["version"]
            for vuln in dep.get("vulns", []):
                key = (package, version, vuln["id"])
                if key in seen:
                    continue
                seen.add(key)

                fixed_versions = vuln.get("fix_versions") or []
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

                findings.append(Finding(
                    fingerprint=f"{vuln['id'].lower()}:{package.lower()}",
                    source="pip-audit",
                    finding_class="dependency-cve",
                    package=package,
                    current_version=version,
                    fixed_version=fixed_versions[0] if fixed_versions else None,
                    cve_id=cve_id,
                    severity=_severity_from_aliases(aliases, client),
                    summary=vuln.get("description", "")[:500],
                ))
        return findings
    finally:
        if owns_client:
            client.close()
