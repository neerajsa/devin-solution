import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import dashboard  # noqa: E402
import store  # noqa: E402


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


@pytest.fixture
def client(conn):
    app = FastAPI()
    app.state.conn = conn
    app.state.webhook_secret = "test-secret"
    app.include_router(dashboard.router)
    return TestClient(app)


# --- _truncate_summary ---

def test_truncate_summary_leaves_short_text_untouched():
    assert dashboard._truncate_summary("short text") == "short text"


def test_truncate_summary_cuts_at_word_boundary_with_ellipsis():
    # A real multi-CVE summary shape post-fan-out-fix: several ~500-char paragraphs
    # joined with blank lines, easily 1000+ chars.
    text = "PYSEC-2026-3481: " + ("word " * 100) + "\n\nPYSEC-2026-3482: " + ("word " * 100)
    result = dashboard._truncate_summary(text)
    assert len(result) <= dashboard.SUMMARY_TRUNCATE_LEN + 1  # +1 for the trailing ellipsis char
    assert result.endswith("…")
    assert not result[:-1].endswith(" ")  # word-boundary aware, no dangling space before the ellipsis


def test_truncate_summary_handles_none():
    assert dashboard._truncate_summary(None) == ""


# --- _findings_with_sessions ---

def test_findings_with_sessions_zero_sessions_yields_exactly_one_row_with_no_session_data(conn):
    store.insert_finding(
        conn, fingerprint="f-nosession", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="s",
    )
    rows = dashboard._findings_with_sessions(conn)
    assert len(rows) == 1
    assert rows[0]["session_id"] is None
    assert rows[0]["session_devin_url"] is None
    assert rows[0]["session_state"] is None
    assert rows[0]["is_continuation"] is False


def test_findings_with_sessions_multiple_sessions_yield_one_row_each_grouped(conn):
    # Real shape from the live DB: setuptools (pysec-2026-3447:setuptools) was
    # dispatched twice - a first pass, then a re-run after a prompt change.
    fid = store.insert_finding(
        conn, fingerprint="pysec-2026-3447:setuptools", source="pip-audit",
        finding_class="dependency-cve", severity="moderate", summary="setuptools CVE",
    )
    store.upsert_session(
        conn, session_id=None, finding_id=fid, devin_session_id="d1",
        devin_url="https://app.devin.ai/sessions/d1", state="not_applicable", terminal=True,
    )
    store.upsert_session(
        conn, session_id=None, finding_id=fid, devin_session_id="d2",
        devin_url="https://app.devin.ai/sessions/d2", state="not_applicable", terminal=True,
    )

    rows = dashboard._findings_with_sessions(conn)
    assert len(rows) == 2
    assert all(r["finding_id"] == fid for r in rows)
    assert all(r["fingerprint"] == "pysec-2026-3447:setuptools" for r in rows)
    assert rows[0]["is_continuation"] is False
    assert rows[1]["is_continuation"] is True
    session_ids = {r["session_id"] for r in rows}
    assert len(session_ids) == 2  # two distinct sessions, not deduped/dropped


def test_findings_with_sessions_orders_newest_finding_first(conn):
    fid1 = store.insert_finding(
        conn, fingerprint="f-older", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="s",
    )
    conn.execute("UPDATE findings SET created_at = 1 WHERE id = ?", (fid1,))
    fid2 = store.insert_finding(
        conn, fingerprint="f-newer", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="s",
    )
    conn.execute("UPDATE findings SET created_at = 2 WHERE id = ?", (fid2,))
    conn.commit()

    rows = dashboard._findings_with_sessions(conn)
    assert [r["fingerprint"] for r in rows] == ["f-newer", "f-older"]


# --- _render_backlog_chart_svg ---

def test_render_backlog_chart_svg_empty_series_renders_a_message_not_an_empty_chart():
    html = dashboard._render_backlog_chart_svg([])
    assert "<svg" not in html
    assert "No backlog history" in html


def test_render_backlog_chart_svg_renders_one_polyline_per_status():
    series = [
        {"taken_at": 1.0, "status": "new", "n": 3},
        {"taken_at": 2.0, "status": "new", "n": 2},
        {"taken_at": 1.0, "status": "remediated", "n": 0},
        {"taken_at": 2.0, "status": "remediated", "n": 1},
    ]
    html = dashboard._render_backlog_chart_svg(series)
    assert "<svg" in html
    assert html.count("<polyline") == 2
    assert "new" in html and "remediated" in html


# --- full endpoint ---

def test_dashboard_requires_token(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 401


def test_dashboard_renders_session_and_pr_links(conn, client):
    fid = store.insert_finding(
        conn, fingerprint="pysec-2026-1845:pytest", source="pip-audit",
        finding_class="dependency-cve", severity="moderate", summary="pytest CVE",
    )
    store.upsert_session(
        conn, session_id=None, finding_id=fid, devin_session_id="d1",
        devin_url="https://app.devin.ai/sessions/d1", state="remediated",
        pr_url="https://github.com/org/repo/pull/7", terminal=True,
    )

    resp = client.get("/dashboard", params={"token": "test-secret"})
    assert resp.status_code == 200
    assert "https://app.devin.ai/sessions/d1" in resp.text
    assert "https://github.com/org/repo/pull/7" in resp.text
    assert "PR-open rate" in resp.text
    assert "Est. cost per merged fix" in resp.text
    assert "heuristic estimate, not real billing data" in resp.text


def test_dashboard_shows_dash_for_finding_with_no_sessions_yet(conn, client):
    store.insert_finding(
        conn, fingerprint="f-brand-new", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="brand new finding, not dispatched yet",
    )
    resp = client.get("/dashboard", params={"token": "test-secret"})
    assert resp.status_code == 200
    assert "f-brand-new" in resp.text
