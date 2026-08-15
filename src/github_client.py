"""Thin async client for the GitHub REST API - issues, comments, labels, and CI checks."""

import asyncio
import re

import httpx

BASE_URL = "https://api.github.com"
FINGERPRINT_RE = re.compile(r"<!--\s*devin-autofix:fingerprint=(\S+?)\s*-->")


class GitHubAPIError(Exception):
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        super().__init__(f"GitHub API error {status_code}: {body}")


def fingerprint_marker(fingerprint: str) -> str:
    return f"<!-- devin-autofix:fingerprint={fingerprint} -->"


def extract_fingerprint(issue_body: str) -> str | None:
    """Extract the fingerprint marker from an issue body. Never regex the finding data itself -
    this only ever returns the opaque fingerprint token, looked up in our own findings table."""
    match = FINGERPRINT_RE.search(issue_body or "")
    return match.group(1) if match else None


class GitHubClient:
    def __init__(self, *, token: str, repo: str, transport: httpx.AsyncBaseTransport | None = None):
        self._repo = repo
        self._client = httpx.AsyncClient(
            base_url=BASE_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            transport=transport,
        )

    async def file_issue(self, *, title: str, body: str, fingerprint: str, labels: list[str]) -> dict:
        full_body = f"{body}\n\n{fingerprint_marker(fingerprint)}"
        return await self._request("POST", f"/repos/{self._repo}/issues", json={
            "title": title, "body": full_body, "labels": labels,
        })

    async def comment(self, issue_number: int, body: str) -> dict:
        return await self._request(
            "POST", f"/repos/{self._repo}/issues/{issue_number}/comments", json={"body": body},
        )

    async def label(self, issue_number: int, labels: list[str]) -> dict:
        return await self._request(
            "POST", f"/repos/{self._repo}/issues/{issue_number}/labels", json={"labels": labels},
        )

    async def close_issue(self, issue_number: int) -> dict:
        return await self._request(
            "PATCH", f"/repos/{self._repo}/issues/{issue_number}", json={"state": "closed"},
        )

    async def wait_for_checks(self, pr_number: int, *, timeout: int = 900, poll_interval: int = 15) -> str:
        """Poll check-runs on the PR's head commit until all complete, or timeout.

        Returns "success", "failure", or "timeout". No checks configured at
        all also returns "timeout" - we never treat silence as success.
        """
        pr = await self._request("GET", f"/repos/{self._repo}/pulls/{pr_number}")
        sha = pr["head"]["sha"]

        elapsed = 0
        while elapsed < timeout:
            runs = (await self._request("GET", f"/repos/{self._repo}/commits/{sha}/check-runs"))["check_runs"]
            if runs and all(r["status"] == "completed" for r in runs):
                return "success" if all(r["conclusion"] == "success" for r in runs) else "failure"
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        return "timeout"

    async def failing_job_log(self, pr_number: int) -> str:
        """Fetch the log text of the first failed check run on the PR's head commit.

        NOTE: uses the check run's own id as the Actions job id to hit
        /actions/jobs/{id}/logs - true for GitHub Actions-sourced check runs
        (job id and check run id are the same in that case), but not
        independently confirmed against a real CI-red PR yet. Re-verify
        this against a real failure in Phase 4.
        """
        pr = await self._request("GET", f"/repos/{self._repo}/pulls/{pr_number}")
        sha = pr["head"]["sha"]
        runs = (await self._request("GET", f"/repos/{self._repo}/commits/{sha}/check-runs"))["check_runs"]
        failed = next((r for r in runs if r["conclusion"] not in ("success", "neutral", "skipped")), None)
        if failed is None:
            return ""

        resp = await self._client.get(
            f"/repos/{self._repo}/actions/jobs/{failed['id']}/logs", follow_redirects=True,
        )
        if resp.status_code >= 400:
            raise GitHubAPIError(resp.status_code, resp.text)
        return resp.text

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            raise GitHubAPIError(resp.status_code, resp.text)
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()
