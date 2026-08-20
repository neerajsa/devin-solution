"""HTML dashboard - renders the five metrics plus a session-level findings table.

[REVISED 2026-08-20] The sixth metric, a backlog-burndown chart, was tried
twice (a per-status line chart, then a simplified open-vs-resolved version
with real axes) and removed both times on real feedback: with the actual
number of findings this project has, a time-series chart didn't earn its
place over just reading the findings table below it. Not rebuilding it
speculatively - if it comes back, it should be because a real dataset at a
larger scale actually needs it, not because a six-metric slot is empty."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import metrics
from auth import require_token

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

SUMMARY_TRUNCATE_LEN = 140


def _truncate_summary(text: str, limit: int = SUMMARY_TRUNCATE_LEN) -> str:
    """First ~limit chars, word-boundary-aware, with a trailing ellipsis. Multi-CVE
    findings' summary can run past 1000 chars (one paragraph per CVE after the
    fan-out fix) - this is what's actually shown in the findings table; the full
    text stays available via the title attribute in the template."""
    text = text or ""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    last_space = cut.rfind(" ")
    if last_space > 0:
        cut = cut[:last_space]
    return cut.rstrip() + "…"


def _findings_with_sessions(conn) -> list[dict]:
    """Session-level findings rows: one row per session, LEFT JOIN'd so a finding
    with N sessions (e.g. a dispatch + a re-run) shows N rows, and a finding with
    zero sessions yet (status still 'new') still shows exactly one row with no
    session data. Rows for the same finding are contiguous (ordered by the
    finding's created_at, then the session's created_at) so the template can mute
    the repeated finding-identity columns on the 2nd+ row of a group."""
    rows = conn.execute(
        """
        SELECT f.*,
               s.id AS session_id,
               s.devin_url AS session_devin_url,
               s.state AS session_state,
               s.pr_url AS session_pr_url
        FROM findings f
        LEFT JOIN sessions s ON s.finding_id = f.id
        ORDER BY f.created_at DESC, s.created_at ASC
        """
    ).fetchall()

    result = []
    last_finding_id = None
    for r in rows:
        result.append({
            "finding_id": r["id"],
            "fingerprint": r["fingerprint"],
            "class": r["class"],
            "package": r["package"],
            "severity": r["severity"],
            "status": r["status"],
            "issue_url": r["issue_url"],
            "issue_number": r["issue_number"],
            "seeded": r["seeded"],
            "summary_full": r["summary"],
            "summary_short": _truncate_summary(r["summary"]),
            "is_continuation": r["id"] == last_finding_id,
            "session_id": r["session_id"],
            "session_devin_url": r["session_devin_url"],
            "session_state": r["session_state"],
            "session_pr_url": r["session_pr_url"],
        })
        last_finding_id = r["id"]
    return result


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    require_token(request, request.app.state.webhook_secret)
    conn = request.app.state.conn
    m = metrics.all_metrics(conn)
    findings = _findings_with_sessions(conn)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "m": m,
            "findings": findings,
        },
    )
