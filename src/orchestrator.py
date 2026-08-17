"""Dispatches findings to Devin, polls for a terminal outcome, and enforces the evidence rule.

Evidence-based, not status-based: a session's own `status` frequently
never reaches a terminal value (confirmed empirically - see
docs/api-surface.md), so `resolve()` treats a real pull_requests[]
entry or a well-formed terminal structured_output claim as the signal,
not `status` alone.

[REVISED 2026-08-17] Completion is judged on a real PR existing, full stop -
CI verification (waiting for the PR's checks to go green, retrying a failure
back into the same session) was built, tested, and then retired the same day
after a real incident: GitHub Actions was never enabled on the target fork,
`wait_for_checks` timed out, and the retry logic sent Devin a "CI failed"
message with no actual evidence behind it - Devin was told to fix something
that was never broken. Waiting on third-party CI to resolve (which turned out
to plausibly need 30-40+ minutes on this specific workflow, not the ~15
originally assumed) also meant sessions could sit open far longer than makes
sense for this MVP. A human reviewing the PR is the actual gate before
anything merges regardless, so verifying CI ourselves isn't load-bearing for
that decision - see IMPLEMENTATION_PLAN.md for the full writeup.
"""

import asyncio
import logging
import time

import prompts
import store
from devin import DevinClient
from scanners import Finding

logger = logging.getLogger("orchestrator")

TERMINAL_SESSION_STATUS = {"exit", "error"}
BLOCKED_DETAILS = {"waiting_for_user", "waiting_for_approval"}
PR_BACKED_CLAIMS = {"remediated", "partially_remediated"}
NO_PR_NEEDED_CLAIMS = {"not_applicable", "needs_human"}


def resolve(session: dict) -> tuple[str, str | None]:
    """Map a raw Devin session to (internal_state, pr_url).

    Never returns remediated/partially_remediated without a real PR
    backing the claim. "working"/"blocked" mean: keep polling.
    """
    status = session.get("status")
    detail = session.get("status_detail")
    out = session.get("structured_output") or {}
    prs = session.get("pull_requests") or []
    pr = prs[0]["pr_url"] if prs else None
    claim = out.get("status")

    if claim in NO_PR_NEEDED_CLAIMS:
        return claim, pr
    if claim in PR_BACKED_CLAIMS and pr:
        return claim, pr

    if status == "suspended":
        return "blocked", pr
    if status == "running" and detail in BLOCKED_DETAILS:
        return "blocked", pr
    if status in TERMINAL_SESSION_STATUS:
        return ("no_pr" if not pr else "remediated"), pr
    return "working", pr


class Orchestrator:
    def __init__(self, *, devin_client: DevinClient, conn, repo: str, branch: str = "master",
                 max_concurrent: int = 4, max_acu_limit: int = 20,
                 poll_interval: float = 15, blocked_nudge_timeout: float = 300):
        self._devin = devin_client
        self._conn = conn
        self._repo = repo
        self._branch = branch
        self._max_acu_limit = max_acu_limit
        self._poll_interval = poll_interval
        self._blocked_nudge_timeout = blocked_nudge_timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def dispatch(self, finding: Finding, *, run_id: str) -> dict:
        """Create/reuse the finding record, dispatch a Devin session, poll to a terminal outcome.

        A real PR is the completion signal - the session terminates as soon as
        one exists, for every outcome. A human approving the PR is the actual
        gate before anything merges, and Devin Review (triggered below,
        fire-and-forget) gives them an automated second opinion to read
        alongside it - we don't block termination on either.
        """
        finding_id = store.insert_finding(
            self._conn, fingerprint=finding.fingerprint, source=finding.source,
            finding_class=finding.finding_class, severity=finding.severity,
            summary=finding.summary, package=finding.package,
            current_version=finding.current_version, fixed_version=finding.fixed_version,
            cve_id=finding.cve_id, file_path=finding.file_path,
        )

        async with self._semaphore:
            prompt = prompts.render_prompt(finding, repo=self._repo, branch=self._branch, run_id=run_id)
            raw = await self._devin.create_session(
                prompt=prompt,
                title=f"{finding.finding_class}: {finding.summary[:60]}",
                tags=[f"finding:{finding.fingerprint}", f"run:{run_id}", "superset"],
                max_acu_limit=self._max_acu_limit,
                structured_output_schema=prompts.STRUCTURED_OUTPUT_SCHEMA,
            )
            devin_session_id = raw["session_id"]
            session_id = store.upsert_session(
                self._conn, session_id=None, finding_id=finding_id,
                devin_session_id=devin_session_id, devin_url=raw["url"], state="working",
            )
            result = await self._poll_to_terminal(session_id, devin_session_id)

            if result.get("pr_url"):
                try:
                    await self._devin.trigger_pr_review(result["pr_url"])
                except Exception:
                    # Never let a review-trigger failure affect the dispatch outcome
                    # that's already been recorded - it's a nice-to-have on top of a
                    # real, already-terminated result, not a gate on anything.
                    logger.exception("failed to trigger PR review for %s", result["pr_url"])

            return result

    async def _poll_to_terminal(self, session_id: str, devin_session_id: str) -> dict:
        nudged_at: float | None = None
        human_messages_sent = 0

        while True:
            raw = await self._devin.get_session(devin_session_id)
            state, pr_url = resolve(raw)

            if state == "working":
                await asyncio.sleep(self._poll_interval)
                continue

            if state == "blocked":
                if nudged_at is None:
                    await self._devin.send_message(
                        devin_session_id,
                        "Still working? Please continue and report back with your structured output.",
                    )
                    nudged_at = time.monotonic()
                    human_messages_sent += 1
                elif time.monotonic() - nudged_at > self._blocked_nudge_timeout:
                    return await self._finish(
                        session_id, devin_session_id, state="needs_human", pr_url=pr_url,
                        structured_output=raw.get("structured_output"),
                        human_messages_sent=human_messages_sent,
                        acu_used=raw.get("acus_consumed") or 0,
                    )
                await asyncio.sleep(self._poll_interval)
                continue

            # Terminal from our perspective, always: not_applicable, needs_human,
            # no_pr, or a PR-backed remediated/partially_remediated claim. A real
            # PR is the completion signal now - the session always terminates here.
            return await self._finish(
                session_id, devin_session_id, state=state, pr_url=pr_url,
                structured_output=raw.get("structured_output"),
                human_messages_sent=human_messages_sent,
                acu_used=raw.get("acus_consumed") or 0,
            )

    async def _finish(self, session_id: str, devin_session_id: str, *, state: str,
                       pr_url: str | None, structured_output: dict | None,
                       human_messages_sent: int, acu_used: float = 0) -> dict:
        store.upsert_session(
            self._conn, session_id=session_id, state=state, pr_url=pr_url,
            human_messages_sent=human_messages_sent, structured_output=structured_output,
            acu_used=acu_used, terminal=True,
        )
        await self._devin.terminate_session(devin_session_id, archive=True)
        return {"session_id": session_id, "devin_session_id": devin_session_id, "state": state, "pr_url": pr_url}
