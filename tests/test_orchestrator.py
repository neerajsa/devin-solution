import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import orchestrator  # noqa: E402
import store  # noqa: E402
from scanners import Finding  # noqa: E402

resolve = orchestrator.resolve


# --- resolve() - pure function, every branch ---

def test_resolve_active_running_working_is_working():
    assert resolve({"status": "running", "status_detail": "working"}) == ("working", None)


def test_resolve_placeholder_claim_without_pr_is_ignored():
    session = {
        "status": "running", "status_detail": "working",
        "structured_output": {"status": "remediated"}, "pull_requests": [],
    }
    assert resolve(session) == ("working", None)


def test_resolve_remediated_claim_with_real_pr_is_trusted():
    session = {
        "status": "running", "status_detail": "working",
        "structured_output": {"status": "remediated"},
        "pull_requests": [{"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}],
    }
    assert resolve(session) == ("remediated", "https://github.com/x/y/pull/1")


def test_resolve_needs_human_claim_needs_no_pr():
    session = {"status": "running", "status_detail": "working",
               "structured_output": {"status": "needs_human"}, "pull_requests": []}
    assert resolve(session) == ("needs_human", None)


def test_resolve_not_applicable_claim_needs_no_pr():
    session = {"status": "running", "status_detail": "working",
               "structured_output": {"status": "not_applicable"}, "pull_requests": []}
    assert resolve(session) == ("not_applicable", None)


def test_resolve_waiting_for_user_is_blocked():
    assert resolve({"status": "running", "status_detail": "waiting_for_user"}) == ("blocked", None)


def test_resolve_suspended_is_blocked():
    assert resolve({"status": "suspended", "status_detail": "out_of_credits"}) == ("blocked", None)


def test_resolve_terminal_status_with_no_pr_is_no_pr():
    assert resolve({"status": "exit", "structured_output": None, "pull_requests": []}) == ("no_pr", None)


def test_resolve_unknown_status_defaults_to_working_never_raises():
    assert resolve({"status": "some-new-status-we-have-never-seen"}) == ("working", None)


# --- Orchestrator.dispatch / poll loop ---

class FakeDevinClient:
    """Scripted fake, not an HTTP stub - devin.py's own HTTP behavior is tested separately."""

    def __init__(self, get_session_sequence: list[dict]):
        self._sequence = list(get_session_sequence)
        self.created = None
        self.messages_sent: list[str] = []
        self.terminated: list[tuple[str, bool]] = []

    async def create_session(self, **kwargs):
        self.created = kwargs
        return {"session_id": "devin-1", "url": "https://app.devin.ai/sessions/devin-1"}

    async def get_session(self, session_id):
        return self._sequence.pop(0) if len(self._sequence) > 1 else self._sequence[0]

    async def send_message(self, session_id, message):
        self.messages_sent.append(message)

    async def terminate_session(self, session_id, *, archive=True):
        self.terminated.append((session_id, archive))


class FakeGitHubClient:
    """Scripted fake - github_client.py's own HTTP behavior is tested separately."""

    def __init__(self, *, checks_conclusion: str = "success", failing_log: str = "AssertionError"):
        self.checks_conclusion = checks_conclusion
        self.failing_log = failing_log
        self.wait_for_checks_calls: list[int] = []

    async def wait_for_checks(self, pr_number, *, timeout=900):
        self.wait_for_checks_calls.append(pr_number)
        return self.checks_conclusion

    async def failing_job_log(self, pr_number):
        return self.failing_log


@pytest.fixture
def conn():
    c = store.connect(":memory:")
    yield c
    c.close()


def _cve_finding(**overrides):
    defaults = dict(
        fingerprint="pysec-2026-3447:setuptools", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="setuptools CVE", package="setuptools",
        current_version="80.9.0", fixed_version="83.0.0", cve_id="CVE-2026-59890",
    )
    return Finding(**{**defaults, **overrides})


@pytest.mark.asyncio
async def test_dispatch_working_then_remediated_leaves_session_open_for_ci_loop(conn):
    fake = FakeDevinClient([
        {"status": "running", "status_detail": "working"},
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "remediated"},
         "pull_requests": [{"pr_url": "https://github.com/x/y/pull/1"}]},
    ])
    orch = orchestrator.Orchestrator(
        devin_client=fake, github_client=FakeGitHubClient(), conn=conn, repo="x/y", poll_interval=0,
    )

    result = await orch.dispatch(_cve_finding(), run_id="run-1")

    assert result["state"] == "remediated"
    assert result["pr_url"] == "https://github.com/x/y/pull/1"
    assert fake.terminated == []  # not terminated - CI loop still needs it

    row = store.get_session(conn, result["session_id"])
    assert row["state"] == "remediated"
    assert row["terminal_at"] is None


@pytest.mark.asyncio
async def test_dispatch_needs_human_terminates_session_immediately(conn):
    fake = FakeDevinClient([
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "needs_human"}, "pull_requests": []},
    ])
    orch = orchestrator.Orchestrator(
        devin_client=fake, github_client=FakeGitHubClient(), conn=conn, repo="x/y", poll_interval=0,
    )

    result = await orch.dispatch(_cve_finding(), run_id="run-1")

    assert result["state"] == "needs_human"
    assert fake.terminated == [("devin-1", True)]

    row = store.get_session(conn, result["session_id"])
    assert row["terminal_at"] is not None


@pytest.mark.asyncio
async def test_dispatch_blocked_nudges_once_then_times_out_to_needs_human(conn):
    fake = FakeDevinClient([{"status": "running", "status_detail": "waiting_for_user"}])
    orch = orchestrator.Orchestrator(
        devin_client=fake, github_client=FakeGitHubClient(), conn=conn, repo="x/y",
        poll_interval=0, blocked_nudge_timeout=0,
    )

    result = await orch.dispatch(_cve_finding(), run_id="run-1")

    assert result["state"] == "needs_human"
    assert len(fake.messages_sent) == 1  # nudged exactly once, not repeatedly
    assert fake.terminated == [("devin-1", True)]


@pytest.mark.asyncio
async def test_dispatch_records_finding_and_records_evidence_based_history(conn):
    fake = FakeDevinClient([
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "not_applicable"}, "pull_requests": []},
    ])
    orch = orchestrator.Orchestrator(
        devin_client=fake, github_client=FakeGitHubClient(), conn=conn, repo="x/y", poll_interval=0,
    )

    finding = _cve_finding()
    await orch.dispatch(finding, run_id="run-1")

    row = store.get_finding_by_fingerprint(conn, finding.fingerprint)
    assert row is not None
    assert row["package"] == "setuptools"
    assert fake.created["tags"] == [f"finding:{finding.fingerprint}", "run:run-1", "superset"]


# --- Orchestrator.verify_ci ---

def _open_session(conn, *, pr_url="https://github.com/x/y/pull/7"):
    """Set up a session already in the remediated-with-PR state, as dispatch() would leave it."""
    finding_id = store.insert_finding(
        conn, fingerprint="f-ci", source="pip-audit", finding_class="dependency-cve",
        severity="unrated", summary="s",
    )
    session_id = store.upsert_session(
        conn, session_id=None, finding_id=finding_id,
        devin_session_id="devin-1", devin_url="https://app.devin.ai/sessions/devin-1",
        state="remediated", pr_url=pr_url,
    )
    return session_id, pr_url


@pytest.mark.asyncio
async def test_verify_ci_green_terminates_session(conn):
    session_id, pr_url = _open_session(conn)
    fake_devin = FakeDevinClient([{}])
    fake_github = FakeGitHubClient(checks_conclusion="success")
    orch = orchestrator.Orchestrator(devin_client=fake_devin, github_client=fake_github, conn=conn, repo="x/y")

    result = await orch.verify_ci(session_id=session_id, devin_session_id="devin-1", pr_url=pr_url)

    assert result["state"] == "remediated_ci_green"
    assert fake_devin.terminated == [("devin-1", True)]
    assert fake_github.wait_for_checks_calls == [7]

    row = store.get_session(conn, session_id)
    assert row["ci_conclusion"] == "success"
    assert row["terminal_at"] is not None


@pytest.mark.asyncio
async def test_verify_ci_red_first_time_sends_log_and_stays_open(conn):
    session_id, pr_url = _open_session(conn)
    fake_devin = FakeDevinClient([{}])
    fake_github = FakeGitHubClient(checks_conclusion="failure", failing_log="boom: test_x failed")
    orch = orchestrator.Orchestrator(devin_client=fake_devin, github_client=fake_github, conn=conn, repo="x/y")

    result = await orch.verify_ci(session_id=session_id, devin_session_id="devin-1", pr_url=pr_url)

    assert result["state"] == "ci_retry_dispatched"
    assert fake_devin.terminated == []  # not terminated - still has a retry available
    assert len(fake_devin.messages_sent) == 1
    assert "boom: test_x failed" in fake_devin.messages_sent[0]
    assert "do not open a new pr" in fake_devin.messages_sent[0].lower()

    row = store.get_session(conn, session_id)
    assert row["ci_retries"] == 1


@pytest.mark.asyncio
async def test_verify_ci_red_second_time_escalates_and_terminates(conn):
    session_id, pr_url = _open_session(conn)
    # Simulate this session already having used its one retry.
    store.upsert_session(conn, session_id=session_id, state="remediated", pr_url=pr_url, ci_retries=1)

    fake_devin = FakeDevinClient([{}])
    fake_github = FakeGitHubClient(checks_conclusion="failure")
    orch = orchestrator.Orchestrator(devin_client=fake_devin, github_client=fake_github, conn=conn, repo="x/y")

    result = await orch.verify_ci(session_id=session_id, devin_session_id="devin-1", pr_url=pr_url)

    assert result["state"] == "ci_red_needs_human"
    assert fake_devin.terminated == [("devin-1", True)]
    assert fake_devin.messages_sent == []  # no more retries - straight to escalation, no new message


@pytest.mark.asyncio
async def test_verify_ci_timeout_counts_as_failure_not_success(conn):
    session_id, pr_url = _open_session(conn)
    fake_devin = FakeDevinClient([{}])
    fake_github = FakeGitHubClient(checks_conclusion="timeout")
    orch = orchestrator.Orchestrator(devin_client=fake_devin, github_client=fake_github, conn=conn, repo="x/y")

    result = await orch.verify_ci(session_id=session_id, devin_session_id="devin-1", pr_url=pr_url)

    assert result["state"] == "ci_retry_dispatched"  # treated like a failure, gets the one retry


def test_pr_number_from_url_parses_trailing_digits():
    assert orchestrator.pr_number_from_url("https://github.com/neerajsa/superset/pull/42") == 42
