"""HTML dashboard - renders the six metrics plus a findings table."""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

import metrics
from auth import require_token

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    require_token(request, request.app.state.webhook_secret)
    conn = request.app.state.conn
    findings = conn.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "m": metrics.all_metrics(conn), "findings": findings},
    )
