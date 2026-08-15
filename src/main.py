from fastapi import FastAPI

app = FastAPI(title="Devin Remediation Pipeline")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
