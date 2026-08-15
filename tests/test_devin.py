import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import devin  # noqa: E402

ORG_ID = "org-test"


def _client(handler) -> devin.DevinClient:
    return devin.DevinClient(
        api_key="cog_test", org_id=ORG_ID, transport=httpx.MockTransport(handler),
    )


@pytest.mark.asyncio
async def test_create_session_posts_to_org_scoped_path_with_bearer_auth():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = request.content
        return httpx.Response(200, json={"session_id": "s1", "url": "https://app.devin.ai/sessions/s1"})

    client = _client(handler)
    result = await client.create_session(
        prompt="fix the thing", title="t", tags=["tag1"],
        max_acu_limit=20, structured_output_schema={"type": "object"},
    )

    assert captured["method"] == "POST"
    assert captured["path"] == f"/v3/organizations/{ORG_ID}/sessions"
    assert captured["auth"] == "Bearer cog_test"
    assert result["session_id"] == "s1"


@pytest.mark.asyncio
async def test_get_session_returns_parsed_json():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"session_id": "s1", "status": "running"})

    client = _client(handler)
    result = await client.get_session("s1")

    assert result["status"] == "running"


@pytest.mark.asyncio
async def test_send_message_posts_to_messages_path():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        return httpx.Response(200, json={"session_id": "s1"})

    client = _client(handler)
    await client.send_message("s1", "please retry")

    assert captured["path"] == f"/v3/organizations/{ORG_ID}/sessions/s1/messages"


@pytest.mark.asyncio
async def test_terminate_session_sends_archive_query_param():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["query"] = request.url.query.decode()
        return httpx.Response(200, json={"session_id": "s1", "is_archived": True})

    client = _client(handler)
    await client.terminate_session("s1", archive=True)

    assert captured["method"] == "DELETE"
    assert "archive=true" in captured["query"]


@pytest.mark.asyncio
async def test_non_2xx_raises_devin_api_error_and_does_not_swallow():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    client = _client(handler)

    with pytest.raises(devin.DevinAPIError) as exc_info:
        await client.get_session("s1")

    assert exc_info.value.status_code == 500
    assert "internal error" in exc_info.value.body
