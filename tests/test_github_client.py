import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import github_client  # noqa: E402

REPO = "neerajsa/superset"


def _client(handler) -> github_client.GitHubClient:
    return github_client.GitHubClient(
        token="ghp_test", repo=REPO, transport=httpx.MockTransport(handler),
    )


def test_extract_fingerprint_finds_the_marker():
    body = "Some issue text.\n\n<!-- devin-autofix:fingerprint=pysec-2026-2151:flask -->"
    assert github_client.extract_fingerprint(body) == "pysec-2026-2151:flask"


def test_extract_fingerprint_returns_none_without_a_marker():
    assert github_client.extract_fingerprint("Just a regular issue, no marker here.") is None


def test_extract_fingerprint_does_not_regex_other_data_out_of_the_body():
    # A body that *mentions* a package/CVE in prose must not be misread as the fingerprint.
    body = "This relates to flask CVE-2026-27205 somehow, but no marker is present."
    assert github_client.extract_fingerprint(body) is None


@pytest.mark.asyncio
async def test_file_issue_embeds_fingerprint_marker_in_body():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["json"] = request.read()
        return httpx.Response(201, json={"number": 42, "html_url": "https://github.com/x/y/issues/42"})

    client = _client(handler)
    result = await client.file_issue(
        title="Naive datetime handling", body="Investigate please.",
        fingerprint="dtz:superset/utils/date_parser.py", labels=["devin-autofix"],
    )

    assert captured["path"] == f"/repos/{REPO}/issues"
    assert b"devin-autofix:fingerprint=dtz:superset/utils/date_parser.py" in captured["json"]
    assert result["number"] == 42


@pytest.mark.asyncio
async def test_wait_for_checks_returns_success_when_all_runs_pass():
    pr_call = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if "/pulls/" in request.url.path:
            return httpx.Response(200, json={"head": {"sha": "abc123"}})
        return httpx.Response(200, json={"check_runs": [
            {"status": "completed", "conclusion": "success"},
            {"status": "completed", "conclusion": "success"},
        ]})

    client = _client(handler)
    result = await client.wait_for_checks(1, timeout=5, poll_interval=1)

    assert result == "success"


@pytest.mark.asyncio
async def test_wait_for_checks_returns_failure_when_any_run_fails():
    def handler(request: httpx.Request) -> httpx.Response:
        if "/pulls/" in request.url.path:
            return httpx.Response(200, json={"head": {"sha": "abc123"}})
        return httpx.Response(200, json={"check_runs": [
            {"status": "completed", "conclusion": "success"},
            {"status": "completed", "conclusion": "failure"},
        ]})

    client = _client(handler)
    result = await client.wait_for_checks(1, timeout=5, poll_interval=1)

    assert result == "failure"


@pytest.mark.asyncio
async def test_wait_for_checks_times_out_if_never_completes():
    def handler(request: httpx.Request) -> httpx.Response:
        if "/pulls/" in request.url.path:
            return httpx.Response(200, json={"head": {"sha": "abc123"}})
        return httpx.Response(200, json={"check_runs": [{"status": "in_progress", "conclusion": None}]})

    client = _client(handler)
    result = await client.wait_for_checks(1, timeout=2, poll_interval=1)

    assert result == "timeout"


@pytest.mark.asyncio
async def test_wait_for_checks_no_checks_configured_is_timeout_not_success():
    def handler(request: httpx.Request) -> httpx.Response:
        if "/pulls/" in request.url.path:
            return httpx.Response(200, json={"head": {"sha": "abc123"}})
        return httpx.Response(200, json={"check_runs": []})

    client = _client(handler)
    result = await client.wait_for_checks(1, timeout=2, poll_interval=1)

    assert result == "timeout"


@pytest.mark.asyncio
async def test_failing_job_log_fetches_log_for_the_failed_run():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/pulls/" in path:
            return httpx.Response(200, json={"head": {"sha": "abc123"}})
        if "/check-runs" in path:
            return httpx.Response(200, json={"check_runs": [
                {"id": 999, "status": "completed", "conclusion": "failure"},
                {"id": 998, "status": "completed", "conclusion": "success"},
            ]})
        if "/actions/jobs/999/logs" in path:
            return httpx.Response(200, text="FAILED: test_something\nAssertionError")
        return httpx.Response(404)

    client = _client(handler)
    log = await client.failing_job_log(1)

    assert "AssertionError" in log


@pytest.mark.asyncio
async def test_non_2xx_raises_github_api_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="rate limited")

    client = _client(handler)

    with pytest.raises(github_client.GitHubAPIError) as exc_info:
        await client.comment(1, "hi")

    assert exc_info.value.status_code == 403
