import sys
from pathlib import Path

import httpx
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
        self.reviews_triggered: list[str] = []

    async def create_session(self, **kwargs):
        self.created = kwargs
        return {"session_id": "devin-1", "url": "https://app.devin.ai/sessions/devin-1"}

    async def get_session(self, session_id):
        return self._sequence.pop(0) if len(self._sequence) > 1 else self._sequence[0]

    async def send_message(self, session_id, message):
        self.messages_sent.append(message)

    async def terminate_session(self, session_id, *, archive=True):
        self.terminated.append((session_id, archive))

    async def trigger_pr_review(self, pr_url):
        self.reviews_triggered.append(pr_url)


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
async def test_dispatch_remediated_with_pr_terminates_and_triggers_review(conn):
    # [REVISED 2026-08-17] A real PR is the completion signal, full stop - no more
    # waiting on CI. The session terminates as soon as the PR exists, and Devin
    # Review is triggered on it (fire-and-forget, not awaited to completion).
    fake = FakeDevinClient([
        {"status": "running", "status_detail": "working"},
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "remediated"},
         "pull_requests": [{"pr_url": "https://github.com/x/y/pull/1"}]},
    ])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    result = await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    assert result["state"] == "remediated"
    assert result["pr_url"] == "https://github.com/x/y/pull/1"
    assert fake.terminated == [("devin-1", True)]
    assert fake.reviews_triggered == ["https://github.com/x/y/pull/1"]

    row = store.get_session(conn, result["session_id"])
    assert row["state"] == "remediated"
    assert row["terminal_at"] is not None

    # The finding's own status must mirror the real outcome, not stay stuck at
    # 'dispatching' forever - real gap, found dispatching setuptools twice
    # under this exact code path (2026-08-19).
    finding_row = store.get_finding_by_fingerprint(conn, _cve_finding().fingerprint)
    assert finding_row["status"] == "remediated"


@pytest.mark.asyncio
async def test_dispatch_needs_human_terminates_session_and_skips_review(conn):
    fake = FakeDevinClient([
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "needs_human"}, "pull_requests": []},
    ])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    result = await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    assert result["state"] == "needs_human"
    assert fake.terminated == [("devin-1", True)]
    assert fake.reviews_triggered == []  # no PR, nothing to review

    row = store.get_session(conn, result["session_id"])
    assert row["terminal_at"] is not None


@pytest.mark.asyncio
async def test_dispatch_blocked_nudges_once_then_times_out_to_needs_human(conn):
    fake = FakeDevinClient([{"status": "running", "status_detail": "waiting_for_user"}])
    orch = orchestrator.Orchestrator(
        devin_client=fake, conn=conn, repo="x/y", poll_interval=0, blocked_nudge_timeout=0,
    )

    result = await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    assert result["state"] == "needs_human"
    assert len(fake.messages_sent) == 1  # nudged exactly once, not repeatedly
    assert fake.terminated == [("devin-1", True)]


@pytest.mark.asyncio
async def test_dispatch_records_finding_and_records_evidence_based_history(conn):
    fake = FakeDevinClient([
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "not_applicable"}, "pull_requests": []},
    ])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    finding = _cve_finding()
    await orch.dispatch(finding, run_id="run-1", issue_number=7)

    row = store.get_finding_by_fingerprint(conn, finding.fingerprint)
    assert row is not None
    assert row["package"] == "setuptools"
    assert row["status"] == "not_applicable"
    assert fake.created["tags"] == [f"finding:{finding.fingerprint}", "run:run-1", "superset"]


@pytest.mark.asyncio
async def test_dispatch_review_trigger_failure_does_not_affect_result(conn):
    # A broken review-trigger call must never take down an already-correct,
    # already-recorded dispatch outcome - it's a nice-to-have, not a gate.
    class FailingReviewDevinClient(FakeDevinClient):
        async def trigger_pr_review(self, pr_url):
            raise RuntimeError("boom")

    fake = FailingReviewDevinClient([
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "remediated"},
         "pull_requests": [{"pr_url": "https://github.com/x/y/pull/1"}]},
    ])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    result = await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    assert result["state"] == "remediated"
    assert fake.terminated == [("devin-1", True)]


# --- Orchestrator.dispatch - the DispatchNotStartedError safety boundary ---
#
# Real incident (2026-08-17): a caller needs to know whether it's safe to retry a
# failed dispatch. It's only safe if no real Devin session was ever created -
# retrying after one was would risk a genuine duplicate session. These tests pin
# down the exact boundary: failures at/before create_session raise
# DispatchNotStartedError; anything after it does not.

@pytest.mark.asyncio
async def test_dispatch_failure_before_session_created_raises_not_started_error(conn):
    class FailsToCreateDevinClient(FakeDevinClient):
        async def create_session(self, **kwargs):
            raise RuntimeError("network blip talking to Devin")

    fake = FailsToCreateDevinClient([{}])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    with pytest.raises(orchestrator.DispatchNotStartedError):
        await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    # No session row should exist - nothing was ever created to record.
    assert fake.terminated == []


@pytest.mark.asyncio
async def test_dispatch_failure_after_session_created_does_not_raise_not_started_error(conn):
    class FailsMidPollDevinClient(FakeDevinClient):
        async def get_session(self, session_id):
            raise RuntimeError("network blip mid-poll")

    fake = FailsMidPollDevinClient([{}])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    with pytest.raises(RuntimeError) as exc_info:
        await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    # A real session was already created before the failure - must NOT be
    # classified as safe-to-retry, and the original error must propagate as-is
    # so a caller can't mistake this for the pre-session case above.
    assert not isinstance(exc_info.value, orchestrator.DispatchNotStartedError)
    assert fake.created is not None  # create_session did succeed before the failure


# --- Transient poll-failure resilience (real incident, 2026-08-19: an
# httpx.ReadTimeout mid-poll orphaned a healthy, already-running flask
# session - the loop gave up on a real session for a one-off network blip) ---

@pytest.mark.asyncio
async def test_poll_retries_a_transient_network_error_then_succeeds(conn):
    class FlakyThenFineDevinClient(FakeDevinClient):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._get_calls = 0

        async def get_session(self, session_id):
            self._get_calls += 1
            if self._get_calls == 1:
                raise httpx.ReadTimeout("simulated blip")
            return {"status": "running", "status_detail": "working",
                    "structured_output": {"status": "not_applicable"}, "pull_requests": []}

    fake = FlakyThenFineDevinClient([{}])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    result = await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    assert result["state"] == "not_applicable"
    assert fake.terminated == [("devin-1", True)]


@pytest.mark.asyncio
async def test_poll_retries_transient_failures_with_no_cap(conn):
    # Deliberately uncapped: a transient network error carries no information
    # about the session's real state, exactly like "still working" - there is
    # no principled attempt count at which retrying stops being correct. Many
    # consecutive failures must still recover, not just one.
    class VeryFlakyThenFineDevinClient(FakeDevinClient):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._get_calls = 0

        async def get_session(self, session_id):
            self._get_calls += 1
            if self._get_calls <= 20:
                raise httpx.ReadTimeout("simulated extended blip")
            return {"status": "running", "status_detail": "working",
                    "structured_output": {"status": "not_applicable"}, "pull_requests": []}

    fake = VeryFlakyThenFineDevinClient([{}])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    result = await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    assert result["state"] == "not_applicable"
    assert fake.terminated == [("devin-1", True)]


@pytest.mark.asyncio
async def test_poll_still_propagates_a_real_non_transient_api_error(conn):
    # A genuine DevinAPIError (401/404/500 - not httpx.TransportError) is
    # informative and must still fail fast, unlike a network blip.
    from devin import DevinAPIError

    class BrokenSessionDevinClient(FakeDevinClient):
        async def get_session(self, session_id):
            raise DevinAPIError(404, "session not found")

    fake = BrokenSessionDevinClient([{}])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    with pytest.raises(DevinAPIError):
        await orch.dispatch(_cve_finding(), run_id="run-1", issue_number=7)

    assert fake.terminated == []


@pytest.mark.asyncio
async def test_terminate_failure_does_not_block_recording_the_outcome(conn):
    class FailsToTerminateDevinClient(FakeDevinClient):
        async def terminate_session(self, session_id, *, archive=True):
            raise RuntimeError("boom")

    fake = FailsToTerminateDevinClient([
        {"status": "running", "status_detail": "working",
         "structured_output": {"status": "not_applicable"}, "pull_requests": []},
    ])
    orch = orchestrator.Orchestrator(devin_client=fake, conn=conn, repo="x/y", poll_interval=0)

    finding = _cve_finding()
    result = await orch.dispatch(finding, run_id="run-1", issue_number=7)

    # The real outcome is still fully recorded, on both the session and the
    # finding, even though the non-essential termination call failed.
    assert result["state"] == "not_applicable"
    row = store.get_session(conn, result["session_id"])
    assert row["state"] == "not_applicable"
    assert row["terminal_at"] is not None
    finding_row = store.get_finding_by_fingerprint(conn, finding.fingerprint)
    assert finding_row["status"] == "not_applicable"
