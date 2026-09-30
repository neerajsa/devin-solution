import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import config  # noqa: E402

# main.py runs config.load() and store.connect() at import time, so tests
# need real-looking env vars set before importing it - matching the pattern
# other modules avoid needing by not doing import-time I/O, which main.py
# does deliberately (fail fast on missing config).

os.environ.setdefault("WEBHOOK_SECRET", "test-secret")
os.environ.setdefault("DEVIN_API_KEY", "test-key")
os.environ.setdefault("DEVIN_ORG_ID", "test-org")
os.environ.setdefault("GITHUB_TOKEN", "test-token")
os.environ.setdefault("GITHUB_REPO", "neerajsa/superset")

import main  # noqa: E402
import store  # noqa: E402
from devin import DevinAPIError  # noqa: E402
from orchestrator import DispatchNotStartedError, Orchestrator  # noqa: E402
from scanners import Finding  # noqa: E402


def test_labeled_action_triggers_only_for_devin_autofix_label():
    assert main._has_devin_autofix_trigger({
        "action": "labeled", "label": {"name": "devin-autofix"}, "issue": {},
    })
    assert not main._has_devin_autofix_trigger({
        "action": "labeled", "label": {"name": "bug"}, "issue": {},
    })


def test_opened_action_triggers_when_label_already_present():
    # The case that motivated this fix: GitHub does not fire a separate
    # "labeled" event when a label is included at issue creation, so an
    # "opened" event must be checked against the issue's own labels[] instead.
    assert main._has_devin_autofix_trigger({
        "action": "opened",
        "issue": {"labels": [{"name": "bug"}, {"name": "devin-autofix"}]},
    })


def test_opened_action_does_not_trigger_without_the_label():
    assert not main._has_devin_autofix_trigger({
        "action": "opened", "issue": {"labels": [{"name": "bug"}]},
    })


def test_other_actions_never_trigger():
    for action in ("closed", "reopened", "unlabeled", "edited"):
        assert not main._has_devin_autofix_trigger({
            "action": action,
            "label": {"name": "devin-autofix"},
            "issue": {"labels": [{"name": "devin-autofix"}]},
        })


# --- main._file_and_dispatch - direct scanner dispatch, no webhook round-trip ---
#
# Real design decision (2026-08-17): the scanner dispatches findings directly,
# in-process, rather than relying on the label->webhook path used by human-reported
# issues. Filed issues deliberately never carry the devin-autofix label (that's
# reserved for the webhook trigger above - including it here would race this direct
# call against itself on every scan, not occasionally). These tests pin down the
# file/skip/claim/retry decision tree that makes that safe.

@pytest.fixture
def fresh_conn(monkeypatch):
    conn = store.connect(":memory:")
    monkeypatch.setattr(main, "_conn", conn)
    yield conn
    conn.close()


class FakeOrchestratorForScan:
    def __init__(self, *, fail_with: Exception | None = None):
        self.dispatched: list[tuple[str, str, int]] = []
        self._fail_with = fail_with

    async def dispatch(self, finding, *, run_id, issue_number):
        self.dispatched.append((finding.fingerprint, run_id, issue_number))
        if self._fail_with:
            raise self._fail_with
        return {"state": "not_applicable", "pr_url": None}


class FakeGitHubClientForScan:
    def __init__(self):
        self.filed: list[dict] = []

    async def file_issue(self, *, title, body, fingerprint, labels):
        self.filed.append({"title": title, "body": body, "fingerprint": fingerprint, "labels": labels})
        n = len(self.filed)
        return {"number": 100 + n, "html_url": f"https://github.com/x/y/issues/{100 + n}"}


def _dependency_finding(**overrides):
    defaults = dict(
        fingerprint="pysec-2026-3447:setuptools", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="setuptools CVE", package="setuptools",
        current_version="80.9.0", fixed_version="83.0.0", cve_id="CVE-2026-59890",
    )
    return Finding(**{**defaults, **overrides})


@pytest.mark.asyncio
async def test_file_and_dispatch_never_files_with_the_devin_autofix_label(monkeypatch, fresh_conn):
    fake_orch = FakeOrchestratorForScan()
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    finding = _dependency_finding()
    result = await main._file_and_dispatch(finding, "run-1")

    assert result is True
    assert len(fake_github.filed) == 1
    assert fake_github.filed[0]["labels"] == []
    assert fake_orch.dispatched == [(finding.fingerprint, "run-1", 101)]


@pytest.mark.asyncio
async def test_file_and_dispatch_skips_refiling_but_retries_dispatch_if_still_new(monkeypatch, fresh_conn):
    finding = _dependency_finding()
    finding_id = store.insert_finding(
        fresh_conn, fingerprint=finding.fingerprint, source=finding.source,
        finding_class=finding.finding_class, severity=finding.severity, summary=finding.summary,
    )
    store.set_finding_issue(fresh_conn, finding_id, issue_number=2, issue_url="https://github.com/x/y/issues/2")

    fake_orch = FakeOrchestratorForScan()
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    result = await main._file_and_dispatch(finding, "run-1")

    assert result is True
    assert fake_github.filed == []  # already had an issue from an earlier scan - not re-filed
    assert fake_orch.dispatched == [(finding.fingerprint, "run-1", 2)]


@pytest.mark.asyncio
async def test_file_and_dispatch_skips_a_finding_already_claimed(monkeypatch, fresh_conn):
    finding = _dependency_finding()
    finding_id = store.insert_finding(
        fresh_conn, fingerprint=finding.fingerprint, source=finding.source,
        finding_class=finding.finding_class, severity=finding.severity, summary=finding.summary,
    )
    store.set_finding_issue(fresh_conn, finding_id, issue_number=2, issue_url="https://github.com/x/y/issues/2")
    store.claim_finding_for_dispatch(fresh_conn, finding_id)  # simulate an earlier scan already claimed it

    fake_orch = FakeOrchestratorForScan()
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    result = await main._file_and_dispatch(finding, "run-1")

    assert result is False
    assert fake_orch.dispatched == []


@pytest.mark.asyncio
async def test_file_and_dispatch_reverts_status_when_dispatch_never_started(monkeypatch, fresh_conn):
    fake_orch = FakeOrchestratorForScan(fail_with=DispatchNotStartedError("network blip"))
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    finding = _dependency_finding()
    result = await main._file_and_dispatch(finding, "run-1")

    assert result is False
    row = store.get_finding_by_fingerprint(fresh_conn, finding.fingerprint)
    assert row["status"] == "new"  # no session was ever created - safe to retry next scan


@pytest.mark.asyncio
async def test_file_and_dispatch_does_not_revert_status_on_other_errors(monkeypatch, fresh_conn):
    # A session may already exist for this failure - reverting to 'new' here
    # would risk a genuine duplicate session on the next scan (the real
    # 2026-08-17 incident). It must stay stuck for a human to investigate.
    fake_orch = FakeOrchestratorForScan(fail_with=RuntimeError("mid-poll network blip"))
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    finding = _dependency_finding()
    result = await main._file_and_dispatch(finding, "run-1")

    assert result is False
    row = store.get_finding_by_fingerprint(fresh_conn, finding.fingerprint)
    assert row["status"] == "dispatching"


# --- main._scan_and_file_demo - the fast, low-cost, single-CVE demo path ---
#
# Real design decision (2026-08-19, revised): a full production scan can surface
# several CVEs at once (real example: base.txt alone has 4), which is fine for
# production but not for a live demo that needs to be fast and cheap. Originally
# pinned to a named package (setuptools), but a fresh fork of current, real
# apache/superset is a moving target - a hardcoded package name could already be
# patched upstream by the time someone runs this. Revised to dispatch whichever
# finding is first and still actually dispatchable, with a development.txt
# fallback if base.txt is fully clean that day. This is a completely separate
# function from _scan_and_file, sharing no state with it - these tests also pin
# down that production scanning is unaffected by this function's existence.

@pytest.mark.asyncio
async def test_scan_and_file_demo_dispatches_the_first_finding_only(monkeypatch, fresh_conn):
    findings = [
        _dependency_finding(package="flask", fingerprint="pysec-x:flask"),
        _dependency_finding(package="setuptools", fingerprint="pysec-x:setuptools"),
        _dependency_finding(package="paramiko", fingerprint="pysec-x:paramiko"),
    ]

    async def fake_fetch_and_scan(repo, branch, paths, *, client):
        assert paths == main.DEMO_SCAN_TARGET  # never the production SCAN_TARGETS
        return findings

    fake_orch = FakeOrchestratorForScan()
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "fetch_and_scan", fake_fetch_and_scan)
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    run_id = store.start_run(fresh_conn, trigger="manual_scan_demo")
    await main._scan_and_file_demo(run_id)

    # First in list order, not a named package - and stops there, never
    # tries setuptools/paramiko even though they're also real findings.
    assert [f for f, _, _ in fake_orch.dispatched] == ["pysec-x:flask"]
    run = fresh_conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    assert run["findings_count"] == 3
    assert run["sessions_count"] == 1


@pytest.mark.asyncio
async def test_scan_and_file_demo_skips_already_claimed_and_tries_the_next(monkeypatch, fresh_conn):
    already_claimed = _dependency_finding(package="flask", fingerprint="pysec-x:flask")
    finding_id = store.insert_finding(
        fresh_conn, fingerprint=already_claimed.fingerprint, source=already_claimed.source,
        finding_class=already_claimed.finding_class, severity=already_claimed.severity,
        summary=already_claimed.summary,
    )
    store.claim_finding_for_dispatch(fresh_conn, finding_id)  # simulate an earlier demo run

    findings = [already_claimed, _dependency_finding(package="setuptools", fingerprint="pysec-x:setuptools")]

    async def fake_fetch_and_scan(repo, branch, paths, *, client):
        return findings

    fake_orch = FakeOrchestratorForScan()
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "fetch_and_scan", fake_fetch_and_scan)
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    run_id = store.start_run(fresh_conn, trigger="manual_scan_demo")
    await main._scan_and_file_demo(run_id)

    # Repeated demo runs progress through the list rather than getting stuck.
    assert [f for f, _, _ in fake_orch.dispatched] == ["pysec-x:setuptools"]


@pytest.mark.asyncio
async def test_scan_and_file_demo_falls_back_to_development_txt_when_base_is_empty(monkeypatch, fresh_conn):
    calls = []

    async def fake_fetch_and_scan(repo, branch, paths, *, client):
        calls.append(paths)
        if paths == main.DEMO_SCAN_TARGET:
            return []  # base.txt fully patched today
        return [_dependency_finding(package="pytest", fingerprint="pysec-x:pytest")]

    fake_orch = FakeOrchestratorForScan()
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "fetch_and_scan", fake_fetch_and_scan)
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    run_id = store.start_run(fresh_conn, trigger="manual_scan_demo")
    await main._scan_and_file_demo(run_id)

    assert calls == [main.DEMO_SCAN_TARGET, main.DEMO_SCAN_TARGET_FALLBACK]
    assert [f for f, _, _ in fake_orch.dispatched] == ["pysec-x:pytest"]


@pytest.mark.asyncio
async def test_scan_and_file_demo_handles_nothing_dispatchable_without_raising(monkeypatch, fresh_conn):
    already_claimed = _dependency_finding(package="flask", fingerprint="pysec-x:flask")
    finding_id = store.insert_finding(
        fresh_conn, fingerprint=already_claimed.fingerprint, source=already_claimed.source,
        finding_class=already_claimed.finding_class, severity=already_claimed.severity,
        summary=already_claimed.summary,
    )
    store.claim_finding_for_dispatch(fresh_conn, finding_id)

    async def fake_fetch_and_scan(repo, branch, paths, *, client):
        return [already_claimed]  # only finding, and it's already claimed

    fake_orch = FakeOrchestratorForScan()
    fake_github = FakeGitHubClientForScan()
    monkeypatch.setattr(main, "fetch_and_scan", fake_fetch_and_scan)
    monkeypatch.setattr(main, "_orchestrator", fake_orch)
    monkeypatch.setattr(main, "_github_client", fake_github)

    run_id = store.start_run(fresh_conn, trigger="manual_scan_demo")
    await main._scan_and_file_demo(run_id)  # must not raise

    assert fake_orch.dispatched == []
    run = fresh_conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    assert run["sessions_count"] == 0
    assert run["findings_count"] == 1


def test_scan_and_file_demo_does_not_affect_production_scan_targets():
    # Regression guard: the two scan paths must never share a target list.
    assert main.DEMO_SCAN_TARGET != main.SCAN_TARGETS
    assert main.DEMO_SCAN_TARGET == ["requirements/base.txt"]
    assert main.DEMO_SCAN_TARGET_FALLBACK == ["requirements/development.txt"]


# --- main._recover_in_flight - startup crash recovery ---
#
# A process restart used to leave findings stuck in 'dispatching' and session
# rows stuck in 'working' forever, while the real Devin sessions kept running
# (and billing) with nobody polling them.

class FakeDevinClientForRecovery:
    def __init__(self, sessions: dict[str, dict | Exception | list[dict | Exception]]):
        self._sessions = sessions
        self.terminated: list[str] = []

    async def get_session(self, devin_session_id):
        result = self._sessions[devin_session_id]
        if isinstance(result, list):
            result = result.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    async def send_message(self, devin_session_id, message):
        pass

    async def terminate_session(self, devin_session_id, *, archive=True):
        self.terminated.append(devin_session_id)


def _insert_dispatching_finding(conn, fingerprint):
    finding_id = store.insert_finding(
        conn, fingerprint=fingerprint, source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary=f"{fingerprint} CVE",
    )
    assert store.claim_finding_for_dispatch(conn, finding_id)
    return finding_id


@pytest.mark.asyncio
async def test_recover_in_flight_resumes_orphaned_sessions_and_flags_unrecorded_findings(
        monkeypatch, fresh_conn):
    no_session_id = _insert_dispatching_finding(fresh_conn, "fp-no-session")
    alive_id = _insert_dispatching_finding(fresh_conn, "fp-alive")
    gone_id = _insert_dispatching_finding(fresh_conn, "fp-gone")
    alive_session = store.upsert_session(
        fresh_conn, session_id=None, finding_id=alive_id, devin_session_id="devin-alive",
        devin_url="https://app.devin.ai/sessions/devin-alive", state="working",
    )
    gone_session = store.upsert_session(
        fresh_conn, session_id=None, finding_id=gone_id, devin_session_id="devin-gone",
        devin_url="https://app.devin.ai/sessions/devin-gone", state="working",
    )

    fake_devin = FakeDevinClientForRecovery({
        "devin-alive": {
            "status": "running", "status_detail": "working",
            "structured_output": {"status": "remediated"},
            "pull_requests": [{"pr_url": "https://github.com/x/y/pull/9"}],
        },
        "devin-gone": DevinAPIError(404, "not found"),
    })
    monkeypatch.setattr(main, "_orchestrator", Orchestrator(
        devin_client=fake_devin, conn=fresh_conn, repo="x/y", poll_interval=0,
    ))

    tasks = main._recover_in_flight()
    await asyncio.gather(*tasks)

    # No session recorded, but one may exist on Devin - never auto-redispatched.
    assert store.get_finding(fresh_conn, no_session_id)["status"] == "needs_human"

    # Still-alive session was polled to its real terminal outcome and terminated.
    alive_row = store.get_session(fresh_conn, alive_session)
    assert alive_row["state"] == "remediated"
    assert alive_row["pr_url"] == "https://github.com/x/y/pull/9"
    assert alive_row["terminal_at"] is not None
    assert store.get_finding(fresh_conn, alive_id)["status"] == "remediated"
    assert fake_devin.terminated == ["devin-alive"]

    # Devin session is gone (404) - marked needs_human, never re-dispatched.
    gone_row = store.get_session(fresh_conn, gone_session)
    assert gone_row["state"] == "needs_human"
    assert gone_row["terminal_at"] is not None
    assert store.get_finding(fresh_conn, gone_id)["status"] == "needs_human"

    assert store.list_non_terminal_sessions(fresh_conn) == []


@pytest.mark.asyncio
async def test_startup_handler_runs_crash_recovery(monkeypatch, fresh_conn):
    finding_id = _insert_dispatching_finding(fresh_conn, "fp-startup")

    async def _no_scan_loop():
        return None

    monkeypatch.setattr(main, "_scan_loop", _no_scan_loop)

    await main._start_scan_scheduler()

    assert store.get_finding(fresh_conn, finding_id)["status"] == "needs_human"


def _insert_working_session(conn, fingerprint, devin_session_id):
    finding_id = _insert_dispatching_finding(conn, fingerprint)
    session_id = store.upsert_session(
        conn, session_id=None, finding_id=finding_id, devin_session_id=devin_session_id,
        devin_url=f"https://app.devin.ai/sessions/{devin_session_id}", state="working",
    )
    return finding_id, session_id


@pytest.mark.asyncio
async def test_resume_session_retries_retriable_api_errors_until_terminal(monkeypatch, fresh_conn):
    finding_id, session_id = _insert_working_session(fresh_conn, "fp-flaky", "devin-flaky")
    fake_devin = FakeDevinClientForRecovery({
        "devin-flaky": [
            DevinAPIError(500, "boom"),
            DevinAPIError(429, "slow down"),
            {"status": "running", "status_detail": "working",
             "structured_output": {"status": "not_applicable"}, "pull_requests": []},
        ],
    })
    monkeypatch.setattr(main, "_orchestrator", Orchestrator(
        devin_client=fake_devin, conn=fresh_conn, repo="x/y", poll_interval=0,
    ))
    monkeypatch.setattr(main, "RESUME_RETRY_INITIAL_SECONDS", 0)

    await asyncio.gather(*main._recover_in_flight())

    assert store.get_session(fresh_conn, session_id)["state"] == "not_applicable"
    assert store.get_finding(fresh_conn, finding_id)["status"] == "not_applicable"
    assert fake_devin.terminated == ["devin-flaky"]


@pytest.mark.asyncio
async def test_resume_session_marks_needs_human_on_non_retriable_api_error(monkeypatch, fresh_conn):
    finding_id, session_id = _insert_working_session(fresh_conn, "fp-unauth", "devin-unauth")
    fake_devin = FakeDevinClientForRecovery({"devin-unauth": DevinAPIError(401, "unauthorized")})
    monkeypatch.setattr(main, "_orchestrator", Orchestrator(
        devin_client=fake_devin, conn=fresh_conn, repo="x/y", poll_interval=0,
    ))

    await asyncio.gather(*main._recover_in_flight())

    row = store.get_session(fresh_conn, session_id)
    assert row["state"] == "needs_human"
    assert row["terminal_at"] is not None
    assert store.get_finding(fresh_conn, finding_id)["status"] == "needs_human"
    assert store.list_non_terminal_sessions(fresh_conn) == []
