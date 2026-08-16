"""FastAPI app: webhook intake, HMAC verification, issue-as-pointer dispatch."""

import asyncio
import hashlib
import hmac
import json
import logging
import os

import httpx
from fastapi import FastAPI, HTTPException, Request

import config
import store
from dashboard import router as dashboard_router
from devin import DevinClient
from github_client import GitHubClient, extract_fingerprint
from orchestrator import Orchestrator
from scanners import Finding, fetch_and_scan

SCAN_TARGETS = ["requirements/base.txt", "requirements/development.txt"]

app = FastAPI(title="Devin Remediation Pipeline")
logger = logging.getLogger("main")

_cfg = config.load()

os.makedirs("data", exist_ok=True)
_conn = store.connect("data/pipeline.db")
_devin_client = DevinClient(api_key=_cfg.devin_api_key, org_id=_cfg.devin_org_id)
_github_client = GitHubClient(token=_cfg.github_token, repo=_cfg.github_repo)
_orchestrator = Orchestrator(
    devin_client=_devin_client, github_client=_github_client, conn=_conn, repo=_cfg.github_repo,
)

app.state.conn = _conn
app.include_router(dashboard_router)


def verify_signature(body: bytes, header: str | None, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header or "")


def _finding_from_row(row) -> Finding:
    return Finding(
        fingerprint=row["fingerprint"], source=row["source"], finding_class=row["class"],
        severity=row["severity"], summary=row["summary"], package=row["package"],
        current_version=row["current_version"], fixed_version=row["fixed_version"],
        cve_id=row["cve_id"], file_path=row["file_path"],
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan/run")
async def scan_run(request: Request) -> dict[str, str]:
    # Not a GitHub-signed webhook - this is our own trigger, called by
    # scanner/scan.yml (scheduled or workflow_dispatch) on the fork. Reuses
    # WEBHOOK_SECRET as a bearer token rather than adding a second secret.
    auth = request.headers.get("authorization", "")
    if auth != f"Bearer {_cfg.webhook_secret}":
        raise HTTPException(status_code=401, detail="invalid token")

    run_id = store.start_run(_conn, trigger="scheduled_scan")
    asyncio.create_task(_scan_and_file(run_id))
    return {"status": "accepted", "run_id": run_id}


@app.post("/webhooks/github")
async def github_webhook(request: Request) -> dict[str, str]:
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256")
    if not verify_signature(body, signature, _cfg.webhook_secret):
        raise HTTPException(status_code=401, detail="invalid signature")

    delivery_id = request.headers.get("x-github-delivery")
    if not delivery_id or not store.record_delivery(_conn, delivery_id):
        return {"status": "duplicate_or_missing_delivery_id"}

    event = request.headers.get("x-github-event")
    payload = json.loads(body) if body else {}

    if event == "issues" and payload.get("action") == "labeled":
        # The delivery is already recorded as seen above, so a redelivery of
        # this same event won't be retried by us even if handling fails here
        # (GitHub would just get a 200 either way). Never let a downstream
        # API hiccup turn into a crashed webhook endpoint - log and move on.
        try:
            await _handle_issue_labeled(payload)
        except Exception:
            logger.exception("failed to handle issues.labeled for delivery %s", delivery_id)

    return {"status": "accepted"}


async def _handle_issue_labeled(payload: dict) -> None:
    if payload.get("label", {}).get("name") != "devin-autofix":
        return

    issue = payload["issue"]
    fingerprint = extract_fingerprint(issue.get("body") or "")

    if fingerprint is None:
        # No marker means this wasn't filed by our scanner - treat the issue
        # itself as the finding. The issue number is already a stable, unique
        # identifier, so no marker needs to be written back into the body.
        fingerprint = f"github-issue-{issue['number']}"
        title = issue.get("title") or ""
        body = issue.get("body") or ""
        store.insert_finding(
            _conn, fingerprint=fingerprint, source="github-issue",
            finding_class="reported-issue", severity="unrated",
            summary=f"{title}\n\n{body}".strip(),
        )

    finding_row = store.get_finding_by_fingerprint(_conn, fingerprint)
    if finding_row is None:
        await _github_client.comment(
            issue["number"],
            f"No known finding matches fingerprint `{fingerprint}` yet - nothing to dispatch.",
        )
        return

    store.set_finding_issue(
        _conn, finding_row["id"], issue_number=issue["number"], issue_url=issue["html_url"],
    )
    run_id = store.start_run(_conn, trigger="issue_labeled")
    asyncio.create_task(_dispatch_and_verify(_finding_from_row(finding_row), run_id))


async def _dispatch_and_verify(finding: Finding, run_id: str) -> None:
    # This runs as a fire-and-forget background task (asyncio.create_task) so
    # the webhook response isn't blocked on a multi-minute Devin session. A
    # failure anywhere in here would otherwise only surface via asyncio's
    # default unhandled-task-exception logging and never touch the runs
    # table, so any failure must be caught and persisted explicitly - not
    # swallowed, per the same rule devin.py follows for its own errors.
    sessions_count = 0
    try:
        result = await _orchestrator.dispatch(finding, run_id=run_id)
        sessions_count = 1
        if result["state"] in ("remediated", "partially_remediated") and result["pr_url"]:
            await _orchestrator.verify_ci(
                session_id=result["session_id"],
                devin_session_id=result["devin_session_id"],
                pr_url=result["pr_url"],
            )
    except Exception:
        logger.exception("dispatch/verify failed for run %s", run_id)
    finally:
        store.finish_run(_conn, run_id, findings_count=1, sessions_count=sessions_count)


async def _scan_and_file(run_id: str) -> None:
    # Fire-and-forget background task, same failure-handling shape as
    # _dispatch_and_verify: any error must still leave the run marked
    # finished, never NULL forever.
    findings_count = 0
    try:
        async with httpx.AsyncClient() as client:
            findings = await fetch_and_scan(
                _cfg.github_repo, "master", SCAN_TARGETS, client=client,
            )
        findings_count = len(findings)

        for finding in findings:
            finding_id = store.insert_finding(
                _conn, fingerprint=finding.fingerprint, source=finding.source,
                finding_class=finding.finding_class, severity=finding.severity,
                summary=finding.summary, package=finding.package,
                current_version=finding.current_version, fixed_version=finding.fixed_version,
                cve_id=finding.cve_id, file_path=finding.file_path,
            )
            row = store.get_finding(_conn, finding_id)
            if row["issue_number"] is not None:
                continue  # already filed on an earlier scan - dedup, don't re-file

            issue = await _github_client.file_issue(
                title=f"[security] {finding.package}: {finding.cve_id or finding.fingerprint}",
                body=finding.summary,
                fingerprint=finding.fingerprint,
                labels=[],
            )
            store.set_finding_issue(
                _conn, finding_id, issue_number=issue["number"], issue_url=issue["html_url"],
            )
            # Labeling separately (not at creation) guarantees a distinct
            # issues.labeled webhook event, which is what actually triggers
            # dispatch via the existing _handle_issue_labeled path above -
            # this function only scans, files, and labels; it doesn't dispatch.
            await _github_client.label(issue["number"], ["devin-autofix"])
    except Exception:
        logger.exception("scan run %s failed", run_id)
    finally:
        store.finish_run(_conn, run_id, findings_count=findings_count, sessions_count=0)
