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
from auth import require_token
from dashboard import router as dashboard_router
from devin import DevinClient
from github_client import GitHubClient, extract_fingerprint
from orchestrator import DispatchNotStartedError, Orchestrator
from scanners import Finding, fetch_and_scan

SCAN_TARGETS = ["requirements/base.txt", "requirements/development.txt"]

app = FastAPI(title="Devin Remediation Pipeline")
logger = logging.getLogger("main")

_cfg = config.load()

os.makedirs("data", exist_ok=True)
_conn = store.connect("data/pipeline.db")
_devin_client = DevinClient(api_key=_cfg.devin_api_key, org_id=_cfg.devin_org_id)
_github_client = GitHubClient(token=_cfg.github_token, repo=_cfg.github_repo)
_orchestrator = Orchestrator(devin_client=_devin_client, conn=_conn, repo=_cfg.github_repo)

app.state.conn = _conn
app.state.webhook_secret = _cfg.webhook_secret
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
def healthz(request: Request) -> dict[str, str]:
    # Gated once a public tunnel exists (Task 4.2) - an unauthenticated liveness
    # probe still confirms to anyone with the URL that something real is behind
    # it, which is worth closing off even though the response itself is inert.
    require_token(request, _cfg.webhook_secret)
    return {"status": "ok"}


@app.post("/scan/run")
async def scan_run(request: Request) -> dict[str, str]:
    # Not a GitHub-signed webhook - a manual on-demand trigger for us, e.g. to
    # scan right now during testing instead of waiting for the next interval
    # of the internal scheduler below. Reuses WEBHOOK_SECRET as a bearer token
    # rather than adding a second secret.
    auth = request.headers.get("authorization", "")
    if auth != f"Bearer {_cfg.webhook_secret}":
        raise HTTPException(status_code=401, detail="invalid token")

    run_id = store.start_run(_conn, trigger="manual_scan")
    asyncio.create_task(_scan_and_file(run_id))
    return {"status": "accepted", "run_id": run_id}


@app.on_event("startup")
async def _start_scan_scheduler() -> None:
    asyncio.create_task(_scan_loop())


async def _scan_loop() -> None:
    # The periodic scan trigger lives here, in-process, rather than as a
    # GitHub Actions workflow committed into the fork - nothing about a
    # "scheduled trigger" requires it to live in the target repo's CI, and
    # keeping it here avoids splitting scan orchestration (already entirely
    # in this process: scanning, finding storage, dispatch) across two repos
    # for no real benefit. Sleeps first, then scans, matching how a real cron
    # schedule behaves - use POST /scan/run above to trigger one immediately.
    while True:
        await asyncio.sleep(_cfg.scan_interval_seconds)
        run_id = store.start_run(_conn, trigger="scheduled_scan")
        await _scan_and_file(run_id)


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

    if event == "issues" and _has_devin_autofix_trigger(payload):
        # The delivery is already recorded as seen above, so a redelivery of
        # this same event won't be retried by us even if handling fails here
        # (GitHub would just get a 200 either way). Never let a downstream
        # API hiccup turn into a crashed webhook endpoint - log and move on.
        try:
            await _handle_issue_finding(payload["issue"])
        except Exception:
            logger.exception("failed to handle issues event for delivery %s", delivery_id)

    return {"status": "accepted"}


def _has_devin_autofix_trigger(payload: dict) -> bool:
    """True if this issues-event payload should trigger a dispatch attempt.

    Two cases, not one: the label was just added (action=labeled, the
    payload's own `label` key names it), or the issue was opened already
    carrying the label. GitHub does NOT fire a separate `labeled` event when
    a label is included at issue creation - confirmed empirically against a
    real webhook (Task 4.2) - so a human filing an issue and picking
    devin-autofix from the labels dropdown before submitting (a completely
    normal GitHub UI flow) would otherwise never trigger anything at all.
    """
    action = payload.get("action")
    if action == "labeled":
        return payload.get("label", {}).get("name") == "devin-autofix"
    if action == "opened":
        labels = [label["name"] for label in payload.get("issue", {}).get("labels", [])]
        return "devin-autofix" in labels
    return False


async def _handle_issue_finding(issue: dict) -> None:
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

    if not store.claim_finding_for_dispatch(_conn, finding_row["id"]):
        # Already claimed by another trigger event for the same finding (real,
        # observed case: GitHub sending both issues.opened-with-label and a
        # separate issues.labeled for one issue-creation-with-label call) -
        # skip rather than start a second Devin session for the same work.
        return

    run_id = store.start_run(_conn, trigger="issue_labeled")
    asyncio.create_task(_dispatch(_finding_from_row(finding_row), run_id, issue["number"]))


async def _dispatch(finding: Finding, run_id: str, issue_number: int) -> None:
    # This runs as a fire-and-forget background task (asyncio.create_task) so
    # the webhook response isn't blocked on a multi-minute Devin session. A
    # failure anywhere in here would otherwise only surface via asyncio's
    # default unhandled-task-exception logging and never touch the runs
    # table, so any failure must be caught and persisted explicitly - not
    # swallowed, per the same rule devin.py follows for its own errors.
    #
    # dispatch() itself now runs to a real terminal outcome (a real PR is the
    # completion signal - see orchestrator.py's 2026-08-17 revision) and
    # already terminates the session and triggers a Devin Review before
    # returning, so there's nothing further to do here after it returns.
    sessions_count = 0
    try:
        await _orchestrator.dispatch(finding, run_id=run_id, issue_number=issue_number)
        sessions_count = 1
    except DispatchNotStartedError:
        # No session was ever created - safe to make this retryable (e.g. a
        # human re-labeling the issue) rather than leaving it stuck forever.
        logger.exception("dispatch never started for run %s - reverting for retry", run_id)
        row = store.get_finding_by_fingerprint(_conn, finding.fingerprint)
        if row:
            store.update_finding_status(_conn, row["id"], "new")
    except Exception:
        # A session may already exist - do NOT revert the claim here, that
        # risks a genuine duplicate session (the real 2026-08-17 incident).
        logger.exception("dispatch failed for run %s", run_id)
    finally:
        store.finish_run(_conn, run_id, findings_count=1, sessions_count=sessions_count)


async def _scan_and_file(run_id: str) -> None:
    # Fire-and-forget background task, same failure-handling shape as _dispatch:
    # any error must still leave the run marked finished, never NULL forever.
    findings_count = 0
    sessions_count = 0
    try:
        async with httpx.AsyncClient() as client:
            findings = await fetch_and_scan(
                _cfg.github_repo, "master", SCAN_TARGETS, client=client,
            )
        findings_count = len(findings)

        for finding in findings:
            # Each finding is fault-isolated - one bad finding (a file_issue
            # network blip, a bug in one finding's dispatch) must never abort
            # the rest of the scan's findings.
            try:
                if await _file_and_dispatch(finding, run_id):
                    sessions_count += 1
            except Exception:
                logger.exception("failed to process scanner finding %s", finding.fingerprint)
    except Exception:
        logger.exception("scan run %s failed", run_id)
    finally:
        store.finish_run(_conn, run_id, findings_count=findings_count, sessions_count=sessions_count)


async def _file_and_dispatch(finding: Finding, run_id: str) -> bool:
    """File a GitHub issue for `finding` if it doesn't have one yet, then dispatch
    it directly, in-process - no webhook round-trip for this trigger at all, and no
    dependency on the tunnel being up.

    Deliberately files WITHOUT the devin-autofix label. That label is reserved
    exclusively for the webhook-triggered path (_has_devin_autofix_trigger above).
    Including it here would make issue creation itself ALSO fire a real
    issues.opened-with-label-present webhook event, racing this direct call for
    the exact same finding on every single scan, not just occasionally - the
    label is exactly what the webhook trigger watches for, so it can't be present
    on a scanner-filed issue without creating that race by construction.

    Returns True if a dispatch was actually attempted (used for the run's
    sessions_count bookkeeping).
    """
    finding_id = store.insert_finding(
        _conn, fingerprint=finding.fingerprint, source=finding.source,
        finding_class=finding.finding_class, severity=finding.severity,
        summary=finding.summary, package=finding.package,
        current_version=finding.current_version, fixed_version=finding.fixed_version,
        cve_id=finding.cve_id, file_path=finding.file_path,
    )
    row = store.get_finding(_conn, finding_id)

    if row["issue_number"] is None:
        issue = await _github_client.file_issue(
            title=f"[security] {finding.package}: {finding.cve_id or finding.fingerprint}",
            body=finding.summary, fingerprint=finding.fingerprint, labels=[],
        )
        store.set_finding_issue(
            _conn, finding_id, issue_number=issue["number"], issue_url=issue["html_url"],
        )
        row = store.get_finding(_conn, finding_id)

    if row["status"] != "new":
        return False  # already claimed/dispatching/done on an earlier scan

    if not store.claim_finding_for_dispatch(_conn, finding_id):
        return False  # lost a race to another concurrent scan run

    try:
        await _orchestrator.dispatch(finding, run_id=run_id, issue_number=row["issue_number"])
    except DispatchNotStartedError:
        # No session was ever created - safe to make this retryable on the
        # next scan rather than leaving it stuck forever.
        logger.exception("dispatch never started for %s - reverting for retry", finding.fingerprint)
        store.update_finding_status(_conn, finding_id, "new")
        return False
    except Exception:
        # A session may already exist - do NOT revert the claim here, that
        # risks a genuine duplicate session (the real 2026-08-17 incident).
        # Leave it stuck in 'dispatching' for a human to investigate.
        logger.exception(
            "dispatch failed after possibly starting a session for %s - not auto-retrying",
            finding.fingerprint,
        )
        return False

    return True
