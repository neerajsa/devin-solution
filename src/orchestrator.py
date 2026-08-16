"""Dispatches findings to Devin, polls for a terminal outcome, and enforces the evidence rule.

Evidence-based, not status-based: a session's own `status` frequently
never reaches a terminal value (confirmed empirically - see
docs/api-surface.md), so `resolve()` treats a real pull_requests[]
entry or a well-formed terminal structured_output claim as the signal,
not `status` alone.
"""

import asyncio
import time

import prompts
import store
from devin import DevinClient
from github_client import GitHubClient
from scanners import Finding

CI_RETRY_MESSAGE_TEMPLATE = (
    "CI failed on your PR. Below is the failing job log. Diagnose the "
    "failure and push a fix to the same branch. Do not open a new PR.\n\n{log}"
)
CI_LOG_TRUNCATE_CHARS = 6000


def pr_number_from_url(pr_url: str) -> int:
    return int(pr_url.rstrip("/").rsplit("/", 1)[-1])

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
    def __init__(self, *, devin_client: DevinClient, github_client: GitHubClient, conn,
                 repo: str, branch: str = "master",
                 max_concurrent: int = 4, max_acu_limit: int = 20,
                 poll_interval: float = 15, blocked_nudge_timeout: float = 300,
                 ci_timeout: float = 900):
        self._devin = devin_client
        self._github = github_client
        self._conn = conn
        self._repo = repo
        self._branch = branch
        self._max_acu_limit = max_acu_limit
        self._poll_interval = poll_interval
        self._blocked_nudge_timeout = blocked_nudge_timeout
        self._ci_timeout = ci_timeout
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def dispatch(self, finding: Finding, *, run_id: str) -> dict:
        """Create/reuse the finding record, dispatch a Devin session, poll to a terminal outcome.

        Terminates the session immediately for outcomes that don't need it
        kept alive (not_applicable, needs_human, no_pr). Leaves it open for
        remediated/partially_remediated with a real PR - the CI verification
        loop needs it for a possible same-session retry.
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
            return await self._poll_to_terminal(session_id, devin_session_id)

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
                    )
                await asyncio.sleep(self._poll_interval)
                continue

            # Terminal from our perspective: not_applicable, needs_human, no_pr,
            # or a PR-backed remediated/partially_remediated claim.
            terminal = state not in PR_BACKED_CLAIMS
            result = await self._finish(
                session_id, devin_session_id, state=state, pr_url=pr_url,
                structured_output=raw.get("structured_output"),
                human_messages_sent=human_messages_sent, terminate_session=terminal,
            )
            return result

    async def verify_ci(self, *, session_id: str, devin_session_id: str, pr_url: str) -> dict:
        """"PR opened" is not success; "PR green" is. One retry, same session, then escalate.

        Same session so Devin keeps its context; one retry only so a broken
        fix can't loop; truncated log to control prompt size; explicit
        "do not open a new PR" because otherwise the natural agent behavior
        is to branch again.
        """
        pr_number = pr_number_from_url(pr_url)
        conclusion = await self._github.wait_for_checks(pr_number, timeout=self._ci_timeout)
        ci_retries = store.get_session(self._conn, session_id)["ci_retries"]

        if conclusion == "success":
            return await self._finish_ci(
                session_id, devin_session_id, state="remediated_ci_green",
                pr_url=pr_url, ci_conclusion=conclusion, ci_retries=ci_retries,
            )

        if ci_retries >= 1:
            return await self._finish_ci(
                session_id, devin_session_id, state="ci_red_needs_human",
                pr_url=pr_url, ci_conclusion=conclusion, ci_retries=ci_retries,
            )

        log = await self._github.failing_job_log(pr_number)
        await self._devin.send_message(
            devin_session_id, CI_RETRY_MESSAGE_TEMPLATE.format(log=log[:CI_LOG_TRUNCATE_CHARS]),
        )
        store.upsert_session(
            self._conn, session_id=session_id, state="ci_retry_dispatched",
            pr_url=pr_url, ci_conclusion=conclusion, ci_retries=ci_retries + 1, terminal=False,
        )
        return {"session_id": session_id, "devin_session_id": devin_session_id, "state": "ci_retry_dispatched", "pr_url": pr_url}

    async def _finish_ci(self, session_id: str, devin_session_id: str, *, state: str,
                          pr_url: str, ci_conclusion: str, ci_retries: int) -> dict:
        store.upsert_session(
            self._conn, session_id=session_id, state=state, pr_url=pr_url,
            ci_conclusion=ci_conclusion, ci_retries=ci_retries, terminal=True,
        )
        await self._devin.terminate_session(devin_session_id, archive=True)
        return {"session_id": session_id, "devin_session_id": devin_session_id, "state": state, "pr_url": pr_url}

    async def _finish(self, session_id: str, devin_session_id: str, *, state: str,
                       pr_url: str | None, structured_output: dict | None,
                       human_messages_sent: int, terminate_session: bool = True) -> dict:
        store.upsert_session(
            self._conn, session_id=session_id, state=state, pr_url=pr_url,
            human_messages_sent=human_messages_sent, structured_output=structured_output,
            terminal=terminate_session,
        )
        if terminate_session:
            await self._devin.terminate_session(devin_session_id, archive=True)
        return {"session_id": session_id, "devin_session_id": devin_session_id, "state": state, "pr_url": pr_url}
