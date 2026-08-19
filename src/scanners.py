"""Normalizes raw scanner output into a common Finding shape."""

import asyncio
import json
import os
import sys
import tempfile
from dataclasses import dataclass

import httpx
from packaging.version import InvalidVersion, Version

OSV_API = "https://api.osv.dev/v1/vulns"

SEVERITY_RANK = {"unrated": 0, "low": 1, "moderate": 2, "medium": 2, "high": 3, "critical": 4}


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

    Packages with multiple distinct CVEs pinned at the same version (real,
    observed: pip==25.1.1 has 5, mcp==1.24.0 has 3, python-multipart==0.0.29
    has 3) are grouped into ONE Finding per (package, version) rather than
    fanned out into one Finding - and one Devin session - per CVE, which
    would otherwise dispatch several sessions racing to bump the exact same
    pin. A package with exactly one CVE keeps the original single-CVE
    fingerprint format unchanged (`{vuln_id}:{package}`) - the formula below
    generalizes to it naturally by joining one sorted id instead of several -
    so already-issued findings (setuptools, flask, paramiko, cryptography)
    keep matching their real GitHub issue fingerprint markers.
    """
    owns_client = client is None
    client = client or httpx.Client()
    try:
        seen: set[tuple[str, str, str]] = set()
        grouped: dict[tuple[str, str], list[dict]] = {}
        for dep in raw.get("dependencies", []):
            package = dep["name"]
            version = dep["version"]
            for vuln in dep.get("vulns", []):
                key = (package, version, vuln["id"])
                if key in seen:
                    continue
                seen.add(key)
                grouped.setdefault((package, version), []).append(vuln)

        return [
            _finding_for_group(package, version, vulns, client)
            for (package, version), vulns in grouped.items()
        ]
    finally:
        if owns_client:
            client.close()


def _finding_for_group(package: str, version: str, vulns: list[dict], client: httpx.Client) -> Finding:
    vuln_ids = sorted(v["id"] for v in vulns)
    fingerprint = f"{'+'.join(id_.lower() for id_ in vuln_ids)}:{package.lower()}"

    all_aliases = [a for v in vulns for a in v.get("aliases", [])]
    cve_ids = sorted({a for a in all_aliases if a.startswith("CVE-")})

    return Finding(
        fingerprint=fingerprint,
        source="pip-audit",
        finding_class="dependency-cve",
        package=package,
        current_version=version,
        fixed_version=_combined_fixed_version(vulns),
        cve_id=", ".join(cve_ids) if cve_ids else None,
        severity=max(
            (_severity_from_aliases(v.get("aliases", []), client) for v in vulns),
            key=lambda s: SEVERITY_RANK.get(s, 0),
        ),
        summary="\n\n".join(f"{v['id']}: {v.get('description', '')[:500]}" for v in vulns),
    )


def _combined_fixed_version(vulns: list[dict]) -> str | None:
    """The lowest version that resolves every vuln in the group - the max across
    each vuln's own minimum fix version. None if any vuln in the group has no
    published fix at all (never guess - see the module docstring), since no
    single version then fixes the whole group.
    """
    firsts = []
    for v in vulns:
        fix_versions = v.get("fix_versions") or []
        if not fix_versions:
            return None
        firsts.append(fix_versions[0])
    try:
        return max(firsts, key=Version)
    except InvalidVersion:
        return max(firsts)


async def fetch_and_scan(repo: str, branch: str, paths: list[str], *,
                          client: httpx.AsyncClient) -> list[Finding]:
    """Fetch each requirements file over HTTP (no clone needed, per IMPLEMENTATION_PLAN.md
    §7.1) and run `pip-audit --no-deps` against it. Must run under Python 3.11 - pip-audit
    hard-fails resolving some pins under 3.14 (see IMPLEMENTATION_PLAN.md §5.6), which is
    exactly what the orchestrator's own python:3.11-slim container provides.

    Strips `-e ./local-path` editable-install lines before writing the tempfile: these
    reference local subprojects (e.g. `-e ./superset-core`) that only resolve inside an
    actual checkout, not a fetched-and-isolated file, and they're our own code anyway -
    not third-party packages with CVE data to audit (confirmed via a real pip-audit
    failure against the fork, 2026-08-17: "./superset-core is not a valid editable
    requirement" when run outside the repo tree).
    """
    findings = []
    sync_client = httpx.Client()
    try:
        for path in paths:
            url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
            resp = await client.get(url, timeout=15)
            resp.raise_for_status()
            text = "\n".join(
                line for line in resp.text.splitlines() if not line.startswith("-e ")
            )

            fd, tmp_path = tempfile.mkstemp(suffix=".txt")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(text)
                # Invoked as `sys.executable -m pip_audit`, not a bare "pip-audit" PATH
                # lookup - the latter can silently resolve to a different interpreter's
                # install (confirmed live: it found a pip-audit bound to a stray Python
                # 3.14, immediately hitting the exact backports-zstd wheel-gap failure
                # this whole 3.11 requirement exists to avoid). sys.executable guarantees
                # the same interpreter this module is already running under.
                proc = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "pip_audit", "--no-deps", "-r", tmp_path,
                    "--format", "json",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _stderr = await proc.communicate()
                # pip-audit exits 1 when it finds vulnerabilities - that's expected,
                # not a failure. Only an unparseable stdout means something's wrong.
                raw = json.loads(stdout)
            finally:
                os.unlink(tmp_path)

            findings.extend(parse_pip_audit(raw, client=sync_client))
        return findings
    finally:
        sync_client.close()
