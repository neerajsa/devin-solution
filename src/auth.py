"""Shared token check for routes exposed through the tunnel that aren't already
GitHub-HMAC-verified (webhooks) or bearer-token-checked with their own logic (/scan/run).
Used to gate /healthz and /dashboard once a public tunnel URL exists."""

from fastapi import HTTPException, Request


def require_token(request: Request, secret: str) -> None:
    # Accepts either a query param (?token=...) for browser use (the dashboard)
    # or an Authorization: Bearer header for programmatic use (curl, Docker's
    # own internal healthcheck) - same shared secret either way.
    token = request.query_params.get("token") or request.headers.get("authorization", "").removeprefix("Bearer ")
    if token != secret:
        raise HTTPException(status_code=401, detail="invalid token")
