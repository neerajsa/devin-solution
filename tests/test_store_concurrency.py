import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import store  # noqa: E402


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "pipeline.db")


def _insert(conn, fingerprint):
    return store.insert_finding(
        conn, fingerprint=fingerprint, source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary=fingerprint,
    )


def _run_threads(target, count):
    errors: list[BaseException] = []
    barrier = threading.Barrier(count)

    def wrapped(i):
        try:
            barrier.wait()
            target(i)
        except BaseException as e:  # noqa: BLE001 - surfaced to the test below
            errors.append(e)

    threads = [threading.Thread(target=wrapped, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    return errors


def test_connect_enables_wal_and_busy_timeout(db_path):
    conn = store.connect(db_path)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == store.BUSY_TIMEOUT_MS
    finally:
        conn.close()


def test_write_commits_while_another_connection_holds_a_read_transaction(db_path):
    reader = store.connect(db_path)
    writer = store.connect(db_path)
    try:
        _insert(writer, "fp-before")
        reader.execute("BEGIN")
        assert reader.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1

        started = time.monotonic()
        _insert(writer, "fp-during-read")
        assert time.monotonic() - started < 1

        assert reader.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        reader.rollback()
        assert reader.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
    finally:
        reader.close()
        writer.close()


def _write_workload(conn, i, per_thread, fingerprints, ids_by_fingerprint, ids_lock):
    for n in range(per_thread):
        fp = fingerprints[(i + n) % len(fingerprints)]
        finding_id = _insert(conn, fp)
        with ids_lock:
            ids_by_fingerprint[fp].add(finding_id)
        store.update_finding_status(conn, finding_id, "new")
        store.claim_finding_for_dispatch(conn, finding_id)
        store.record_delivery(conn, f"delivery-{i}-{n}")
        run_id = store.start_run(conn, trigger="concurrency-test")
        store.finish_run(conn, run_id, findings_count=1, sessions_count=0)


@pytest.mark.parametrize("shared_connection", [True, False], ids=["shared-connection", "connection-per-thread"])
def test_concurrent_writes_do_not_raise(db_path, shared_connection):
    """shared-connection mirrors main.py, where one connection is used by both
    the event loop and FastAPI's threadpool; connection-per-thread mirrors
    independent writers (e.g. a second process) contending for the file lock."""
    shared = store.connect(db_path)
    thread_count = 16
    per_thread = 25
    fingerprints = [f"fp-{n}" for n in range(10)]
    ids_by_fingerprint: dict[str, set[str]] = {fp: set() for fp in fingerprints}
    ids_lock = threading.Lock()

    def worker(i):
        conn = shared if shared_connection else store.connect(db_path)
        try:
            _write_workload(conn, i, per_thread, fingerprints, ids_by_fingerprint, ids_lock)
        finally:
            if conn is not shared:
                conn.close()

    try:
        errors = _run_threads(worker, thread_count)
        assert errors == []

        assert all(len(ids) == 1 for ids in ids_by_fingerprint.values())
        count = lambda table: shared.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: E731
        assert count("findings") == len(fingerprints)
        assert count("deliveries") == thread_count * per_thread
        assert count("runs") == thread_count * per_thread
        assert shared.execute("SELECT COUNT(*) FROM runs WHERE finished_at IS NULL").fetchone()[0] == 0
    finally:
        shared.close()


def test_concurrent_insert_of_same_fingerprint_yields_one_row(db_path):
    thread_count = 12
    results: list[str] = []
    results_lock = threading.Lock()

    def worker(_):
        conn = store.connect(db_path)
        try:
            finding_id = _insert(conn, "fp-contended")
            with results_lock:
                results.append(finding_id)
        finally:
            conn.close()

    errors = _run_threads(worker, thread_count)
    assert errors == []
    assert len(results) == thread_count
    assert len(set(results)) == 1
