"""HTML dashboard - renders the six metrics (five stat cards + one chart) plus a
session-level findings table."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import metrics
from auth import require_token

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

SUMMARY_TRUNCATE_LEN = 140

# Fixed colors for the statuses we know about (findings.status); anything else
# (a future status value) falls back to the rotating palette below rather than
# silently not rendering a line.
_STATUS_COLORS = {
    "new": "#94a3b8",
    "dispatching": "#f59e0b",
    "remediated": "#16a34a",
    "partially_remediated": "#0891b2",
    "not_applicable": "#a3a3a3",
    "blocked": "#dc2626",
}
_FALLBACK_COLORS = ["#6366f1", "#ec4899", "#14b8a6", "#f97316"]


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


def _render_backlog_chart_svg(series: list[dict], width: int = 880, height: int = 220) -> str:
    """Small hand-rolled inline SVG line chart, one polyline per status - the
    project's stated minimalism rules out a charting library. Returns a full
    <figure> markup string (svg + legend); empty state renders a plain message
    instead of an empty plot."""
    if not series:
        return '<p class="muted">No backlog history yet - snapshots are recorded on the next status change.</p>'

    by_status: dict[str, list[tuple[float, int]]] = {}
    for row in series:
        by_status.setdefault(row["status"], []).append((row["taken_at"], row["n"]))

    all_times = [row["taken_at"] for row in series]
    all_ns = [row["n"] for row in series]
    t_min, t_max = min(all_times), max(all_times)
    t_span = (t_max - t_min) or 1.0
    n_max = max(all_ns) if all_ns else 1
    n_max = n_max or 1

    pad_l, pad_r, pad_t, pad_b = 40, 20, 10, 20
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    def x(t: float) -> float:
        return pad_l + (t - t_min) / t_span * plot_w

    def y(n: int) -> float:
        return pad_t + plot_h - (n / n_max) * plot_h

    polylines = []
    legend_items = []
    fallback_i = 0
    for status in sorted(by_status):
        color = _STATUS_COLORS.get(status)
        if not color:
            color = _FALLBACK_COLORS[fallback_i % len(_FALLBACK_COLORS)]
            fallback_i += 1
        points = sorted(by_status[status], key=lambda p: p[0])
        pts_attr = " ".join(f"{x(t):.1f},{y(n):.1f}" for t, n in points)
        polylines.append(
            f'<polyline points="{pts_attr}" fill="none" stroke="{color}" stroke-width="2" />'
        )
        legend_items.append(
            f'<span class="legend-item"><span class="swatch" style="background:{color}"></span>{status}</span>'
        )

    axis = (
        f'<line x1="{pad_l}" y1="{pad_t + plot_h}" x2="{width - pad_r}" y2="{pad_t + plot_h}" '
        f'stroke="#ddd" stroke-width="1" />'
    )
    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="Backlog burndown by status over time">'
        f"{axis}{''.join(polylines)}</svg>"
    )
    legend = f'<div class="chart-legend">{"".join(legend_items)}</div>'
    return svg + legend


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    require_token(request, request.app.state.webhook_secret)
    conn = request.app.state.conn
    m = metrics.all_metrics(conn)
    findings = _findings_with_sessions(conn)
    backlog_chart_svg = _render_backlog_chart_svg(m["backlog_burndown_series"])
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "m": m,
            "findings": findings,
            "backlog_chart_svg": backlog_chart_svg,
        },
    )
