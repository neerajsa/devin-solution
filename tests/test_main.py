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
from orchestrator import DispatchNotStartedError  # noqa: E402
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
        self.dispatched: list[tuple[str, str]] = []
        self._fail_with = fail_with

    async def dispatch(self, finding, *, run_id):
        self.dispatched.append((finding.fingerprint, run_id))
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
    assert fake_orch.dispatched == [(finding.fingerprint, "run-1")]


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
    assert fake_orch.dispatched == [(finding.fingerprint, "run-1")]


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
