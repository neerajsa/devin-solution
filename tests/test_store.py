import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import store  # noqa: E402


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def test_insert_and_get_finding_by_fingerprint(conn):
    finding_id = store.insert_finding(
        conn, fingerprint="pysec-2026-2151:flask", source="pip-audit",
        finding_class="dependency-cve", severity="unrated",
        summary="flask CVE", package="flask", current_version="2.3.3",
        fixed_version="3.1.3", cve_id="CVE-2026-27205",
    )
    row = store.get_finding_by_fingerprint(conn, "pysec-2026-2151:flask")
    assert row["id"] == finding_id
    assert row["package"] == "flask"
    assert row["status"] == "new"
    assert row["seeded"] == 0


def test_insert_finding_is_idempotent_on_fingerprint(conn):
    first_id = store.insert_finding(
        conn, fingerprint="pysec-2026-3447:setuptools", source="pip-audit",
        finding_class="dependency-cve", severity="unrated", summary="setuptools CVE",
    )
    second_id = store.insert_finding(
        conn, fingerprint="pysec-2026-3447:setuptools", source="pip-audit",
        finding_class="dependency-cve", severity="unrated", summary="setuptools CVE (rescanned)",
    )
    assert first_id == second_id
    rows = conn.execute("SELECT * FROM findings").fetchall()
    assert len(rows) == 1


def test_finding_with_no_cve_fields_works_for_code_quality_class(conn):
    finding_id = store.insert_finding(
        conn, fingerprint="dtz005:superset/utils/date_parser.py", source="ruff",
        finding_class="code-quality-datetime", severity="unrated",
        summary="naive datetime.now() calls without tzinfo",
        file_path="superset/utils/date_parser.py",
    )
    row = store.get_finding(conn, finding_id)
    assert row["package"] is None
    assert row["cve_id"] is None
    assert row["file_path"] == "superset/utils/date_parser.py"


def test_upsert_session_create_requires_finding_devin_id_and_url(conn):
    with pytest.raises(ValueError, match="required to create"):
        store.upsert_session(conn, session_id=None, state="working")


def test_upsert_session_update_does_not_require_create_only_fields(conn):
    finding_id = store.insert_finding(
        conn, fingerprint="f-update-only", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="s",
    )
    session_id = store.upsert_session(
        conn, session_id=None, finding_id=finding_id,
        devin_session_id="d1", devin_url="https://app.devin.ai/sessions/d1", state="working",
    )

    # No finding_id/devin_session_id/devin_url passed here - must not raise.
    store.upsert_session(conn, session_id=session_id, state="needs_human", terminal=True)

    row = store.get_session(conn, session_id)
    assert row["state"] == "needs_human"


def test_upsert_session_create_then_update(conn):
    finding_id = store.insert_finding(
        conn, fingerprint="f1", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="s",
    )
    session_id = store.upsert_session(
        conn, session_id=None, finding_id=finding_id,
        devin_session_id="devin-1", devin_url="https://app.devin.ai/sessions/devin-1",
        state="working",
    )
    row = store.get_session(conn, session_id)
    assert row["state"] == "working"
    assert row["terminal_at"] is None

    store.upsert_session(
        conn, session_id=session_id, finding_id=finding_id,
        devin_session_id="devin-1", devin_url="https://app.devin.ai/sessions/devin-1",
        state="remediated", pr_url="https://github.com/org/repo/pull/1",
        structured_output={"status": "remediated"}, terminal=True,
    )
    row = store.get_session(conn, session_id)
    assert row["state"] == "remediated"
    assert row["pr_url"] == "https://github.com/org/repo/pull/1"
    assert row["terminal_at"] is not None
    assert '"status": "remediated"' in row["structured_output"]


def test_record_delivery_dedupes(conn):
    assert store.record_delivery(conn, "delivery-1") is True
    assert store.record_delivery(conn, "delivery-1") is False
    assert store.record_delivery(conn, "delivery-2") is True


def test_claim_finding_for_dispatch_is_exclusive(conn):
    finding_id = store.insert_finding(
        conn, fingerprint="pysec-2026-3447:setuptools", source="pip-audit",
        finding_class="dependency-cve", severity="unrated", summary="setuptools CVE",
    )
    assert store.claim_finding_for_dispatch(conn, finding_id) is True
    assert store.claim_finding_for_dispatch(conn, finding_id) is False

    row = store.get_finding(conn, finding_id)
    assert row["status"] == "dispatching"



def test_start_and_finish_run(conn):
    run_id = store.start_run(conn, "scheduled")
    row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    assert row["trigger"] == "scheduled"
    assert row["finished_at"] is None

    store.finish_run(conn, run_id, findings_count=3, sessions_count=3)
    row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    assert row["finished_at"] is not None
    assert row["findings_count"] == 3
