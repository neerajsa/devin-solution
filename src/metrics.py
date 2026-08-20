"""The six metrics, computed only from structured_output/status/pull_requests[]/acus_consumed/
CI conclusions/our own timestamps - never parsed from prose. See IMPLEMENTATION_PLAN.md #10."""

import json
import statistics

# [REVISED 2026-08-17] A real PR is the completion signal now, not a CI-verified
# green (orchestrator.py no longer produces remediated_ci_green/ci_red_needs_human/
# ci_unverifiable at all - CI verification was built, then retired the same day
# after a real incident). PR_BACKED_STATES replaces what remediated_ci_green meant
# for "merged fix" purposes below.
SUCCESSFUL_STATES = {"remediated", "partially_remediated", "not_applicable"}
PR_BACKED_STATES = {"remediated", "partially_remediated"}
CI_VERIFIED_STATES: set[str] = set()  # kept as a named constant; see first_pass_ci_rate's docstring
FAILURE_STATES = ["blocked", "no_pr", "needs_human"]

# --- Part 1: cost-estimation heuristic (docs/observability-improvement-proposal.md) ---
# HEURISTIC ONLY - not real billing data. acus_consumed is confirmed structurally
# non-functional for this (self-serve, on-demand-credits) account tier - see
# IMPLEMENTATION_PLAN.md #10 and docs/api-surface.md. RATE_PER_MINUTE is calibrated
# against the one known real charge ($6.14 for the datetime-fix session); see the
# proposal doc for the full calibration walkthrough and caveats.
RATE_PER_MINUTE = 0.071
MESSAGE_WEIGHT = 0.15
SCOPE_WEIGHT = 0.05
FILES_CAP = 10
FALLBACK_FILES_CHANGED = 1  # neutral single-file assumption when structured_output
                            # is missing/malformed (a NULL structured_output row does
                            # not mean nothing happened - see the proposal doc)

# --- Part 2 §4: human-hours-saved baseline (ASSUMED, not measured) ---
HUMAN_BASELINE_MINUTES_BY_CLASS = {
    "dependency-cve": 45,   # ASSUMED - triage CVE reachability, bump, verify, open PR
    "reported-issue": 90,   # ASSUMED - diagnose from a bug report, fix, verify, PR
}
DEFAULT_HUMAN_BASELINE_MINUTES = 60
BASELINE_NOTE = "ASSUMED baseline, not measured - see docs/observability-improvement-proposal.md"


def backlog_burndown(conn) -> dict:
    """Current open-vs-resolved snapshot by finding status.

    Not a full time series - that needs periodic snapshots we don't
    capture yet. Honestly labeled as a snapshot, not a historical chart,
    until that's built.
    """
    rows = conn.execute("SELECT status, COUNT(*) as n FROM findings GROUP BY status").fetchall()
    return {row["status"]: row["n"] for row in rows}


def _autonomy_counts(conn) -> tuple[int, int]:
    """[REVISED 2026-08-20] Denominator is every terminal session, not just the
    ones in SUCCESSFUL_STATES - the earlier version excluded needs_human/no_pr/
    blocked from the denominator entirely, so a refusal could never drag the
    rate down and it was structurally biased toward 100% (real bug, caught on
    review: paramiko's genuine needs_human refusal wasn't reflected at all). A
    session only counts as autonomous if it BOTH reached a real successful
    outcome AND needed zero human messages - a needs_human session now
    correctly counts against the rate, since it didn't complete the work
    without a human, even if no message was ever sent to it mid-session."""
    rows = conn.execute("SELECT state, human_messages_sent FROM sessions WHERE terminal_at IS NOT NULL").fetchall()
    autonomous = sum(
        1 for r in rows if r["state"] in SUCCESSFUL_STATES and r["human_messages_sent"] == 0
    )
    return autonomous, len(rows)


def autonomy_rate(conn) -> float | None:
    """% of all terminal sessions that reached a real successful outcome
    (remediated/partially_remediated/not_applicable) with zero human messages
    sent - not just % of the successful ones that were clean. A needs_human
    or no_pr session counts against this rate."""
    autonomous, total = _autonomy_counts(conn)
    if not total:
        return None
    return autonomous / total


def first_pass_ci_rate(conn) -> float | None:
    """[REVISED 2026-08-17] Always returns None - CI verification was retired the same
    day it was built (see orchestrator.py's module docstring for the real incident that
    drove this), so there are no CI-verified states left for this metric to measure.
    Kept as a function (not deleted outright) since first-pass CI rate was named as a
    specific deliverable in IMPLEMENTATION_PLAN.md #1.3 - this is a flagged, open
    question for a human to resolve (relabel the dashboard card, replace it with a
    review-triggered-rate metric, or formally drop it to a five-metric dashboard),
    not a silent removal."""
    return None


def _pr_open_counts(conn) -> tuple[int, int]:
    rows = conn.execute("SELECT pr_url FROM sessions WHERE terminal_at IS NOT NULL").fetchall()
    with_pr = sum(1 for r in rows if r["pr_url"])
    return with_pr, len(rows)


def pr_open_rate(conn) -> float | None:
    """% of terminal sessions that produced a real pr_url. Replaces the permanently-
    None first_pass_ci_rate (CI verification retired, IMPLEMENTATION_PLAN.md #10/#8.4).
    Reuses the already-tracked pr_url column - no new instrumentation. Distinct from
    autonomy_rate: this counts any PR, whether or not a human message was needed."""
    with_pr, total = _pr_open_counts(conn)
    if not total:
        return None
    return with_pr / total


def latency_percentiles(conn) -> dict:
    """Dispatch to final terminal state, in seconds (p50/p95), plus an estimated
    human-hours-saved figure against an explicitly ASSUMED per-class baseline
    (docs/observability-improvement-proposal.md Part 2 #4 - IMPLEMENTATION_PLAN.md
    #10 names the "compare against a stated human baseline" framing but never states
    an actual number, so one is introduced here as a labeled assumption, not fact).

    Uses sessions.created_at -> terminal_at, which is dispatch-to-final-
    outcome, not specifically dispatch-to-PR-opened (we don't persist that
    narrower timestamp). Labeled accordingly rather than overclaiming
    precision the schema doesn't have.
    """
    rows = conn.execute(
        """SELECT s.created_at, s.terminal_at, f.class AS finding_class
           FROM sessions s JOIN findings f ON f.id = s.finding_id
           WHERE s.terminal_at IS NOT NULL"""
    ).fetchall()
    durations = [r["terminal_at"] - r["created_at"] for r in rows]
    hours_saved = 0.0
    for r in rows:
        baseline_minutes = HUMAN_BASELINE_MINUTES_BY_CLASS.get(
            r["finding_class"], DEFAULT_HUMAN_BASELINE_MINUTES
        )
        duration_minutes = (r["terminal_at"] - r["created_at"]) / 60
        hours_saved += max(0, baseline_minutes - duration_minutes) / 60
    if not durations:
        return {
            "p50_seconds": None, "p95_seconds": None, "n": 0,
            "est_human_hours_saved": 0.0, "baseline_note": BASELINE_NOTE,
        }
    durations.sort()
    return {
        "p50_seconds": statistics.median(durations),
        "p95_seconds": durations[min(len(durations) - 1, int(len(durations) * 0.95))],
        "n": len(durations),
        "est_human_hours_saved": hours_saved,
        "baseline_note": BASELINE_NOTE,
    }


def cost_per_merged_fix(conn) -> dict:
    """Total ACUs consumed / count of PR-backed fixes (remediated/partially_remediated -
    the same PR-is-the-completion-signal definition dispatch() now uses, [REVISED
    2026-08-17], replacing what remediated_ci_green meant here before CI verification
    was retired). Reported in ACU units, not dollars: acus_consumed is confirmed
    non-functional for self-serve accounts (always 0 - see IMPLEMENTATION_PLAN.md),
    so this number is honestly near-meaningless right now, not just unconverted -
    flagged as an open problem, not fabricated around."""
    total_acu = conn.execute("SELECT COALESCE(SUM(acu_used), 0) as total FROM sessions").fetchone()["total"]
    merged_count = conn.execute(
        "SELECT COUNT(*) as n FROM sessions WHERE state IN ({})".format(
            ",".join("?" * len(PR_BACKED_STATES))
        ),
        list(PR_BACKED_STATES),
    ).fetchone()["n"]
    return {
        "total_acu": total_acu,
        "merged_fix_count": merged_count,
        "acu_per_merged_fix": (total_acu / merged_count) if merged_count else None,
    }


def estimate_session_cost_usd(session_row) -> float | None:
    """HEURISTIC estimate only - not real billing data. acus_consumed is confirmed
    non-functional for this (self-serve) account, so this is a duration-plus-
    signal heuristic calibrated against one known $6.14 charge, not a measured
    cost. Returns None for non-terminal sessions (nothing to estimate yet)."""
    if session_row["terminal_at"] is None:
        return None
    duration_minutes = (session_row["terminal_at"] - session_row["created_at"]) / 60
    human_messages = session_row["human_messages_sent"] or 0

    files_changed = FALLBACK_FILES_CHANGED
    raw = session_row["structured_output"]
    if raw:
        try:
            parsed = json.loads(raw)
            fc = parsed.get("files_changed")
            if isinstance(fc, list):
                files_changed = len(fc)
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass  # keep fallback

    message_factor = 1 + MESSAGE_WEIGHT * human_messages
    scope_factor = 1 + SCOPE_WEIGHT * min(files_changed, FILES_CAP)
    return RATE_PER_MINUTE * duration_minutes * message_factor * scope_factor


def estimated_cost_per_merged_fix(conn) -> dict:
    """Replaces the ACU-based cost_per_merged_fix. Sums the per-session heuristic
    estimate over PR-backed sessions (remediated/partially_remediated - the same
    PR-is-completion definition dispatch() uses elsewhere) and divides by count.
    Every key is prefixed/labeled to make clear this is estimated, not measured."""
    rows = conn.execute(
        "SELECT * FROM sessions WHERE state IN ({})".format(
            ",".join("?" * len(PR_BACKED_STATES))
        ),
        list(PR_BACKED_STATES),
    ).fetchall()
    estimates = [e for r in rows if (e := estimate_session_cost_usd(r)) is not None]
    total = sum(estimates)
    return {
        "merged_fix_count": len(rows),
        "estimated_total_usd": round(total, 2),
        "estimated_usd_per_merged_fix": round(total / len(estimates), 2) if estimates else None,
        "is_heuristic": True,  # dashboard.html branches on this to force the disclaimer
    }


def failure_taxonomy(conn) -> dict:
    """Counts of each failure-ish outcome. Tracked honestly, not hidden - a system that never
    shows a failure is less credible than one that does."""
    rows = conn.execute(
        "SELECT state, COUNT(*) as n FROM sessions WHERE state IN ({}) GROUP BY state".format(
            ",".join("?" * len(FAILURE_STATES))
        ),
        FAILURE_STATES,
    ).fetchall()
    counts = {state: 0 for state in FAILURE_STATES}
    counts.update({row["state"]: row["n"] for row in rows})
    return counts


def all_metrics(conn) -> dict:
    """Five stat cards (docs/observability-improvement-proposal.md Part 2, minus the
    chart - see dashboard.py's module docstring for why it was removed, twice).
    autonomy_rate/latency/failure_taxonomy are unchanged; pr_open_rate and
    estimated_cost_per_merged_fix replace the two broken metrics (first_pass_ci_rate/
    cost_per_merged_fix - kept as functions for history, no longer surfaced here).

    autonomy_counts/pr_open_counts expose the raw (n, total) behind each rate, so the
    dashboard can show "100% (9/9)" instead of a bare percentage with no sense of
    sample size. [REVISED 2026-08-20] Both rates now share the same denominator -
    every terminal session, regardless of outcome or trigger path - after a real
    bug was caught on review: autonomy_rate used to only count sessions already in
    SUCCESSFUL_STATES, so a needs_human refusal never entered its denominator at
    all and the rate was structurally biased toward 100%. They still answer
    different questions over that same pool: pr_open_rate asks "did it produce a
    PR," autonomy_rate asks "did it produce a real successful outcome with zero
    human messages" - a needs_human or no_pr session now correctly counts against
    autonomy_rate too."""
    autonomy_n, autonomy_total = _autonomy_counts(conn)
    pr_open_n, pr_open_total = _pr_open_counts(conn)
    return {
        "autonomy_rate": (autonomy_n / autonomy_total) if autonomy_total else None,
        "autonomy_counts": {"n": autonomy_n, "total": autonomy_total},
        "pr_open_rate": (pr_open_n / pr_open_total) if pr_open_total else None,
        "pr_open_counts": {"n": pr_open_n, "total": pr_open_total},
        "latency": latency_percentiles(conn),
        "estimated_cost_per_merged_fix": estimated_cost_per_merged_fix(conn),
        "failure_taxonomy": failure_taxonomy(conn),
    }
