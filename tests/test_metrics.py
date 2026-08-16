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
    _add_session(conn, state="remediated_ci_green", human_messages_sent=0)
    _add_session(conn, state="remediated_ci_green", human_messages_sent=1)  # needed a nudge
    _add_session(conn, state="needs_human", human_messages_sent=0)  # not a successful state at all

    assert metrics.autonomy_rate(conn) == 0.5  # 1 of 2 successful states was fully autonomous


def test_autonomy_rate_is_none_with_no_successful_sessions(conn):
    _add_session(conn, state="needs_human")
    assert metrics.autonomy_rate(conn) is None


def test_first_pass_ci_rate_requires_zero_retries_and_green(conn):
    _add_session(conn, state="remediated_ci_green", ci_retries=0)
    _add_session(conn, state="remediated_ci_green", ci_retries=1)  # green, but not on the first try
    _add_session(conn, state="ci_red_needs_human", ci_retries=1)

    assert metrics.first_pass_ci_rate(conn) == pytest.approx(1 / 3)


def test_first_pass_ci_rate_ignores_sessions_never_ci_verified(conn):
    _add_session(conn, state="needs_human")  # never reached CI verification at all
    assert metrics.first_pass_ci_rate(conn) is None
