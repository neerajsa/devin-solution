"""HTML dashboard - renders the six metrics (five stat cards + one chart) plus a
session-level findings table."""

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import metrics
from auth import require_token

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

SUMMARY_TRUNCATE_LEN = 140

# A finding sits "open" while it's new or actively dispatching; every other
# status (remediated, not_applicable, needs_human, no_pr, blocked, ...) is a
# real terminal outcome, so it counts as "resolved" regardless of which one.
# Matches the chart's original spec (IMPLEMENTATION_PLAN.md #10): "Open
# findings vs. remediated, over time - the only chart that matters: is the
# debt shrinking?"
_OPEN_STATUSES = {"new", "dispatching"}
_CHART_COLORS = {"open": "#E0A83E", "resolved": "#34C77B"}


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


def _render_backlog_chart_svg(series: list[dict], width: int = 880, height: int = 240) -> str:
    """Small hand-rolled inline SVG line chart: open vs. resolved findings over
    real time - the project's stated minimalism rules out a charting library.
    A per-status breakdown (one line per findings.status value) was tried
    first and found genuinely hard to read with no axis labels and up to
    seven thin, similarly-weighted lines for a handful of findings - real
    user feedback, 2026-08-20. Simplified back to what the chart was actually
    specified to answer (IMPLEMENTATION_PLAN.md #10): "Open findings vs.
    remediated, over time - is the debt shrinking?" Now with real axis labels:
    a count scale on the left, real calendar dates along the bottom."""
    if not series:
        return '<p class="muted">No backlog history yet.</p>'

    by_bucket: dict[str, dict[float, int]] = {"open": {}, "resolved": {}}
    for row in series:
        bucket = "open" if row["status"] in _OPEN_STATUSES else "resolved"
        by_bucket[bucket][row["taken_at"]] = by_bucket[bucket].get(row["taken_at"], 0) + row["n"]

    all_times = sorted({row["taken_at"] for row in series})
    t_min, t_max = all_times[0], all_times[-1]
    t_span = (t_max - t_min) or 1.0
    all_ns = [n for bucket in by_bucket.values() for n in bucket.values()]
    n_max = max(all_ns) if all_ns else 1
    n_max = n_max or 1

    pad_l, pad_r, pad_t, pad_b = 34, 16, 16, 26
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    def x(t: float) -> float:
        return pad_l + (t - t_min) / t_span * plot_w

    def y(n: int) -> float:
        return pad_t + plot_h - (n / n_max) * plot_h

    marks = []
    legend_items = []
    for bucket in ("open", "resolved"):
        color = _CHART_COLORS[bucket]
        points = sorted(by_bucket[bucket].items())
        if len(points) >= 2:
            pts_attr = " ".join(f"{x(t):.1f},{y(n):.1f}" for t, n in points)
            marks.append(
                f'<polyline points="{pts_attr}" fill="none" stroke="{color}" '
                f'stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" />'
            )
            last_t, last_n = points[-1]
            marks.append(f'<circle cx="{x(last_t):.1f}" cy="{y(last_n):.1f}" r="4" fill="{color}" />')
        elif points:
            # A single real data point can't draw a line - a bucket with no
            # history yet still gets a visible marker instead of silently
            # disappearing.
            t, n = points[0]
            marks.append(f'<circle cx="{x(t):.1f}" cy="{y(n):.1f}" r="4" fill="{color}" />')
        legend_items.append(
            f'<span class="legend-item"><span class="swatch" style="background:{color}"></span>{bucket}</span>'
        )

    # Y-axis: count scale, 0 to n_max in quarters, with real numeric labels -
    # not just gridlines with no indication of what they mean.
    y_axis = []
    for i in range(5):
        frac = i / 4
        yy = pad_t + plot_h - frac * plot_h
        val = round(frac * n_max)
        y_axis.append(
            f'<line x1="{pad_l}" y1="{yy:.1f}" x2="{width - pad_r}" y2="{yy:.1f}" '
            f'stroke="#262B36" stroke-width="1" stroke-dasharray="{"0" if i == 0 else "2 4"}" />'
            f'<text x="{pad_l - 6}" y="{yy + 3:.1f}" text-anchor="end" font-size="10" '
            f'font-family="ui-monospace,monospace" fill="#5F6577">{val}</text>'
        )

    # X-axis: real calendar dates at the start and end of the time range this
    # data actually spans, not an unlabeled axis the reader has to guess at.
    start_label = datetime.fromtimestamp(t_min).strftime("%b %-d")
    end_label = datetime.fromtimestamp(t_max).strftime("%b %-d")
    x_axis = (
        f'<text x="{pad_l}" y="{height - 6}" font-size="10" font-family="ui-monospace,monospace" '
        f'fill="#5F6577">{start_label}</text>'
        f'<text x="{width - pad_r}" y="{height - 6}" text-anchor="end" font-size="10" '
        f'font-family="ui-monospace,monospace" fill="#5F6577">{end_label}</text>'
    )

    svg = (
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
        f'role="img" aria-label="Backlog burndown: open vs. resolved findings over time, '
        f'{start_label} to {end_label}">'
        f"{''.join(y_axis)}{''.join(marks)}{x_axis}</svg>"
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
