"""Thin async client for the Devin v3 API. No business logic - only what docs/api-surface.md confirms exists."""

import httpx

BASE_URL = "https://api.devin.ai"


class DevinAPIError(Exception):
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        super().__init__(f"Devin API error {status_code}: {body}")


class DevinClient:
    def __init__(self, *, api_key: str, org_id: str,
                 transport: httpx.AsyncBaseTransport | None = None):
        self._org_id = org_id
        self._client = httpx.AsyncClient(
            base_url=BASE_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            transport=transport,
        )

    async def create_session(self, *, prompt: str, title: str, tags: list[str],
                              max_acu_limit: int, structured_output_schema: dict) -> dict:
        return await self._request("POST", f"/v3/organizations/{self._org_id}/sessions", json={
            "prompt": prompt,
            "title": title,
            "tags": tags,
            "max_acu_limit": max_acu_limit,
            "structured_output_schema": structured_output_schema,
        })

    async def get_session(self, session_id: str) -> dict:
        return await self._request("GET", f"/v3/organizations/{self._org_id}/sessions/{session_id}")

    async def send_message(self, session_id: str, message: str) -> dict:
        return await self._request(
            "POST", f"/v3/organizations/{self._org_id}/sessions/{session_id}/messages",
            json={"message": message},
        )

    async def trigger_pr_review(self, pr_url: str) -> dict:
        """POST .../pr-reviews - a separate, standalone action against a PR URL, not tied
        to any coding session_id. Fire-and-forget from the orchestrator's perspective:
        callers don't poll this to completion, so a reviewer just reads the findings
        Devin Review posts directly to the PR on GitHub."""
        return await self._request(
            "POST", f"/v3/organizations/{self._org_id}/pr-reviews", json={"pr_url": pr_url},
        )

    async def terminate_session(self, session_id: str, *, archive: bool = True) -> dict:
        """DELETE ...?archive=true both stops the session and preserves it for our audit trail.

        Confirmed empirically: sessions don't self-terminate, and idle ones
        keep accruing small charges - call this on every terminal outcome
        that doesn't need the session kept alive.
        """
        return await self._request(
            "DELETE", f"/v3/organizations/{self._org_id}/sessions/{session_id}",
            params={"archive": str(archive).lower()},
        )

    async def _request(self, method: str, path: str, **kwargs) -> dict:
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            raise DevinAPIError(resp.status_code, resp.text)
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()
