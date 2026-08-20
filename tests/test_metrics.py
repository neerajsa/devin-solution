import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import metrics  # noqa: E402
import store  # noqa: E402


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def _add_session(conn, *, state: str, human_messages_sent: int = 0, ci_retries: int = 0):
    fid = store.insert_finding(
        conn, fingerprint=f"f-{state}-{human_messages_sent}-{ci_retries}", source="pip-audit",
        finding_class="dependency-cve", severity="unrated", summary="s",
    )
    store.upsert_session(
        conn, session_id=None, finding_id=fid, devin_session_id="d", devin_url="u",
        state=state, human_messages_sent=human_messages_sent, ci_retries=ci_retries,
    )


def test_autonomy_rate_only_counts_successful_states_with_zero_human_messages(conn):
    _add_session(conn, state="remediated", human_messages_sent=0)
    _add_session(conn, state="remediated", human_messages_sent=1)  # needed a nudge
    _add_session(conn, state="needs_human", human_messages_sent=0)  # not a successful state at all

    assert metrics.autonomy_rate(conn) == 0.5  # 1 of 2 successful states was fully autonomous


def test_autonomy_rate_is_none_with_no_successful_sessions(conn):
    _add_session(conn, state="needs_human")
    assert metrics.autonomy_rate(conn) is None


def test_all_metrics_exposes_the_raw_counts_behind_both_rates(conn):
    # A bare percentage has no sense of sample size ("100%" of 1 session reads
    # very differently than "100%" of 40) - all_metrics surfaces the real
    # (n, total) behind autonomy_rate and pr_open_rate for the dashboard.
    _add_session(conn, state="remediated", human_messages_sent=0)
    _add_session(conn, state="remediated", human_messages_sent=1)

    m = metrics.all_metrics(conn)
    assert m["autonomy_counts"] == {"n": 1, "total": 2}
    assert m["autonomy_rate"] == 0.5


def test_first_pass_ci_rate_always_none_now_ci_verification_is_retired(conn):
    # [REVISED 2026-08-17] CI verification (and the states that fed this metric)
    # was retired the same day it was built - see orchestrator.py's module
    # docstring. Regardless of what's in the sessions table, there's nothing
    # left for this metric to compute - flagged as an open question for a
    # human, not silently deleted.
    _add_session(conn, state="remediated", ci_retries=0)
    assert metrics.first_pass_ci_rate(conn) is None


def test_cost_per_merged_fix_counts_pr_backed_states_only(conn):
    _add_session(conn, state="remediated")
    _add_session(conn, state="partially_remediated")
    _add_session(conn, state="not_applicable")  # no PR - not a "merged fix"
    _add_session(conn, state="needs_human")  # no PR either

    result = metrics.cost_per_merged_fix(conn)
    assert result["merged_fix_count"] == 2


# --- pr_open_rate ---

def _add_session_with_pr(conn, *, state: str, pr_url: str | None, terminal: bool = True):
    fid = store.insert_finding(
        conn, fingerprint=f"f-{state}-{pr_url}-{terminal}", source="pip-audit",
        finding_class="dependency-cve", severity="unrated", summary="s",
    )
    store.upsert_session(
        conn, session_id=None, finding_id=fid, devin_session_id="d", devin_url="u",
        state=state, pr_url=pr_url, terminal=terminal,
    )


def test_pr_open_rate_counts_any_pr_on_terminal_sessions(conn):
    _add_session_with_pr(conn, state="remediated", pr_url="https://github.com/x/y/pull/1")
    _add_session_with_pr(conn, state="not_applicable", pr_url=None)
    _add_session_with_pr(conn, state="needs_human", pr_url=None)

    assert metrics.pr_open_rate(conn) == pytest.approx(1 / 3)


def test_pr_open_rate_ignores_non_terminal_sessions(conn):
    _add_session_with_pr(conn, state="working", pr_url=None, terminal=False)
    assert metrics.pr_open_rate(conn) is None


def test_pr_open_rate_is_none_with_no_terminal_sessions(conn):
    assert metrics.pr_open_rate(conn) is None


# --- estimate_session_cost_usd / estimated_cost_per_merged_fix ---

def _session_row(conn, *, state="remediated", duration_seconds=60.0,
                  human_messages_sent=0, structured_output=None, terminal=True,
                  pr_url="https://github.com/x/y/pull/1"):
    fid = store.insert_finding(
        conn, fingerprint=f"f-{state}-{duration_seconds}-{human_messages_sent}",
        source="pip-audit", finding_class="dependency-cve", severity="unrated", summary="s",
    )
    session_id = store.upsert_session(
        conn, session_id=None, finding_id=fid, devin_session_id="d", devin_url="u",
        state=state, pr_url=pr_url, human_messages_sent=human_messages_sent,
        structured_output=structured_output, terminal=terminal,
    )
    row = store.get_session(conn, session_id)
    if terminal:
        # Force an exact, known duration rather than relying on wall-clock timing -
        # created_at/terminal_at are both set to time.time() by store.upsert_session.
        conn.execute(
            "UPDATE sessions SET created_at = 0, terminal_at = ? WHERE id = ?",
            (duration_seconds, session_id),
        )
        conn.commit()
        row = store.get_session(conn, session_id)
    return row


def test_estimate_session_cost_usd_is_none_for_non_terminal_session(conn):
    row = _session_row(conn, terminal=False)
    assert metrics.estimate_session_cost_usd(row) is None


def test_estimate_session_cost_usd_neutral_case_matches_rate_times_duration(conn):
    # No human messages -> message_factor is exactly 1.0. No structured_output ->
    # files_changed falls back to FALLBACK_FILES_CHANGED (1), which still applies a
    # small (+5%) scope factor, not a bypass of it - this is the proposal doc's own
    # datetime-fix calibration case (86.3 min, ~$6.43 with the fallback's scope
    # factor applied, close to the ~$6.14 real charge it was calibrated against).
    row = _session_row(conn, duration_seconds=86.3 * 60, human_messages_sent=0,
                        structured_output=None)
    estimate = metrics.estimate_session_cost_usd(row)
    expected = metrics.RATE_PER_MINUTE * 86.3 * 1.0 * (1 + metrics.SCOPE_WEIGHT * metrics.FALLBACK_FILES_CHANGED)
    assert estimate == pytest.approx(expected, abs=0.001)


def test_estimate_session_cost_usd_uses_files_changed_from_structured_output(conn):
    row = _session_row(conn, duration_seconds=600, human_messages_sent=0,
                        structured_output={"files_changed": ["a.py", "b.py"]})
    estimate = metrics.estimate_session_cost_usd(row)
    expected = metrics.RATE_PER_MINUTE * 10 * 1.0 * (1 + metrics.SCOPE_WEIGHT * 2)
    assert estimate == pytest.approx(expected)


def test_estimate_session_cost_usd_applies_message_weight(conn):
    row = _session_row(conn, duration_seconds=600, human_messages_sent=2,
                        structured_output=None)
    estimate = metrics.estimate_session_cost_usd(row)
    # files_changed falls back to 1 (neutral) since structured_output is missing.
    expected = metrics.RATE_PER_MINUTE * 10 * (1 + metrics.MESSAGE_WEIGHT * 2) * (1 + metrics.SCOPE_WEIGHT * 1)
    assert estimate == pytest.approx(expected)


def test_estimate_session_cost_usd_caps_files_scope_factor(conn):
    row = _session_row(conn, duration_seconds=600, human_messages_sent=0,
                        structured_output={"files_changed": [f"f{i}.py" for i in range(50)]})
    estimate = metrics.estimate_session_cost_usd(row)
    expected = metrics.RATE_PER_MINUTE * 10 * 1.0 * (1 + metrics.SCOPE_WEIGHT * metrics.FILES_CAP)
    assert estimate == pytest.approx(expected)


def test_estimated_cost_per_merged_fix_only_sums_pr_backed_states(conn):
    _session_row(conn, state="remediated", duration_seconds=600, pr_url="https://github.com/x/y/pull/1")
    _session_row(conn, state="partially_remediated", duration_seconds=300, pr_url="https://github.com/x/y/pull/2")
    _session_row(conn, state="not_applicable", duration_seconds=100, pr_url=None)  # not PR-backed

    result = metrics.estimated_cost_per_merged_fix(conn)
    assert result["merged_fix_count"] == 2
    assert result["is_heuristic"] is True
    assert result["estimated_usd_per_merged_fix"] is not None
    assert result["estimated_total_usd"] > 0


def test_estimated_cost_per_merged_fix_none_when_no_pr_backed_sessions(conn):
    _session_row(conn, state="not_applicable", duration_seconds=100, pr_url=None)
    result = metrics.estimated_cost_per_merged_fix(conn)
    assert result["merged_fix_count"] == 0
    assert result["estimated_usd_per_merged_fix"] is None
    assert result["estimated_total_usd"] == 0


# --- latency_percentiles human-hours-saved enrichment ---

def test_latency_percentiles_computes_human_hours_saved_against_class_baseline(conn):
    # dependency-cve baseline is 45 min; a 15-min session saves 30 min = 0.5h.
    _session_row(conn, state="remediated", duration_seconds=15 * 60)
    result = metrics.latency_percentiles(conn)
    assert result["est_human_hours_saved"] == pytest.approx(0.5)
    assert "ASSUMED" in result["baseline_note"]


def test_latency_percentiles_hours_saved_floors_at_zero_when_slower_than_baseline(conn):
    # A session that took longer than the baseline shouldn't produce negative savings.
    _session_row(conn, state="remediated", duration_seconds=200 * 60)
    result = metrics.latency_percentiles(conn)
    assert result["est_human_hours_saved"] == 0.0


# --- backlog_burndown_series ---
#
# [REVISED 2026-08-20] Reconstructed from real findings/sessions timestamps,
# not read from backlog_snapshots - a pure snapshot-on-write table only
# captured history from the moment that write path was deployed, which left
# the real dashboard's chart showing a single collapsed point (a real,
# reported gap). See metrics.py::backlog_burndown_series's docstring.

def test_backlog_burndown_series_empty_with_no_findings(conn):
    assert metrics.backlog_burndown_series(conn) == []


def test_backlog_burndown_series_reconstructs_from_real_timestamps(conn):
    fid = store.insert_finding(
        conn, fingerprint="f-burndown", source="pip-audit",
        finding_class="dependency-cve", severity="unrated", summary="s",
    )
    # A real session's own created_at/terminal_at are the source of truth for
    # the 'dispatching' and terminal-state events - not a separate snapshot
    # write path, so this reflects real history even predating this feature.
    store.upsert_session(
        conn, session_id=None, finding_id=fid,
        devin_session_id="d1", devin_url="https://app.devin.ai/sessions/d1",
        state="working",
    )
    session_id = conn.execute("SELECT id FROM sessions WHERE finding_id = ?", (fid,)).fetchone()["id"]
    store.upsert_session(conn, session_id=session_id, state="remediated", terminal=True)

    series = metrics.backlog_burndown_series(conn)
    statuses_seen = {row["status"] for row in series}
    assert "new" in statuses_seen        # the finding's own creation
    assert "dispatching" in statuses_seen  # the session's creation
    assert "remediated" in statuses_seen   # the session's real terminal state
    assert all({"taken_at", "status", "n"} <= row.keys() for row in series)
    # Chronological: the series should be able to show the backlog actually
    # moving, not every point stacked at one timestamp.
    assert len({row["taken_at"] for row in series}) > 1
