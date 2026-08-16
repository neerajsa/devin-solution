"""The six metrics, computed only from structured_output/status/pull_requests[]/acus_consumed/
CI conclusions/our own timestamps - never parsed from prose. See IMPLEMENTATION_PLAN.md #10."""

import statistics

SUCCESSFUL_STATES = {"remediated", "remediated_ci_green", "partially_remediated", "not_applicable"}
CI_VERIFIED_STATES = {"remediated_ci_green", "ci_red_needs_human"}
FAILURE_STATES = ["blocked", "no_pr", "needs_human", "ci_red_needs_human"]


def backlog_burndown(conn) -> dict:
    """Current open-vs-resolved snapshot by finding status.

    Not a full time series - that needs periodic snapshots we don't
    capture yet. Honestly labeled as a snapshot, not a historical chart,
    until that's built.
    """
    rows = conn.execute("SELECT status, COUNT(*) as n FROM findings GROUP BY status").fetchall()
    return {row["status"]: row["n"] for row in rows}


def autonomy_rate(conn) -> float | None:
    """% of sessions reaching a successful terminal state with zero human messages sent."""
    rows = conn.execute(
        "SELECT state, human_messages_sent FROM sessions WHERE state IN ({})".format(
            ",".join("?" * len(SUCCESSFUL_STATES))
        ),
        list(SUCCESSFUL_STATES),
    ).fetchall()
    if not rows:
        return None
    autonomous = sum(1 for r in rows if r["human_messages_sent"] == 0)
    return autonomous / len(rows)


def first_pass_ci_rate(conn) -> float | None:
    """% of Devin PRs green on the first CI run - the quality metric, not just throughput."""
    rows = conn.execute(
        "SELECT state, ci_retries FROM sessions WHERE state IN ({})".format(
            ",".join("?" * len(CI_VERIFIED_STATES))
        ),
        list(CI_VERIFIED_STATES),
    ).fetchall()
    if not rows:
        return None
    first_pass = sum(1 for r in rows if r["state"] == "remediated_ci_green" and r["ci_retries"] == 0)
    return first_pass / len(rows)


def latency_percentiles(conn) -> dict:
    """Dispatch to final terminal state, in seconds (p50/p95).

    Uses sessions.created_at -> terminal_at, which is dispatch-to-final-
    outcome, not specifically dispatch-to-PR-opened (we don't persist that
    narrower timestamp). Labeled accordingly rather than overclaiming
    precision the schema doesn't have.
    """
    rows = conn.execute(
        "SELECT created_at, terminal_at FROM sessions WHERE terminal_at IS NOT NULL"
    ).fetchall()
    durations = [r["terminal_at"] - r["created_at"] for r in rows]
    if not durations:
        return {"p50_seconds": None, "p95_seconds": None, "n": 0}
    durations.sort()
    return {
        "p50_seconds": statistics.median(durations),
        "p95_seconds": durations[min(len(durations) - 1, int(len(durations) * 0.95))],
        "n": len(durations),
    }


def cost_per_merged_fix(conn) -> dict:
    """Total ACUs consumed / count of CI-green merges. Reported in ACU units, not dollars -
    current ACU-to-USD pricing was never authoritatively confirmed (see docs/api-surface.md),
    so this doesn't fabricate a conversion."""
    total_acu = conn.execute("SELECT COALESCE(SUM(acu_used), 0) as total FROM sessions").fetchone()["total"]
    green_count = conn.execute(
        "SELECT COUNT(*) as n FROM sessions WHERE state = 'remediated_ci_green'"
    ).fetchone()["n"]
    return {
        "total_acu": total_acu,
        "remediated_ci_green_count": green_count,
        "acu_per_merged_fix": (total_acu / green_count) if green_count else None,
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
    return {
        "backlog_burndown": backlog_burndown(conn),
        "autonomy_rate": autonomy_rate(conn),
        "first_pass_ci_rate": first_pass_ci_rate(conn),
        "latency": latency_percentiles(conn),
        "cost_per_merged_fix": cost_per_merged_fix(conn),
        "failure_taxonomy": failure_taxonomy(conn),
    }
