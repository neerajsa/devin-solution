"""FastAPI app: webhook intake, HMAC verification, issue-as-pointer dispatch."""

import asyncio
import hashlib
import hmac
import json
import logging
import os

from fastapi import FastAPI, HTTPException, Request

import config
import store
from devin import DevinClient
from github_client import GitHubClient, extract_fingerprint
from orchestrator import Orchestrator
from scanners import Finding

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
        return

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
