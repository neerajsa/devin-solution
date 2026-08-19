FROM python:3.11-slim

# pkg-config + default-libmysqlclient-dev: requirements/development.txt pins
# mysqlclient, and pip-audit's own internal `pip install --dry-run` still
# resolves build requirements for every listed package (--no-deps only skips
# resolving *transitive* deps, not top-level ones) - without these, resolving
# mysqlclient's build metadata fails outright and the scan never produces any
# findings at all. Found live (2026-08-19) dispatching pytest for real - every
# earlier verification of requirements/development.txt ran on the host (which
# had these installed via Homebrew), never through this actual container.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates pkg-config default-libmysqlclient-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ ./src/

RUN useradd -m app && chown -R app /app
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import os,urllib.request;req=urllib.request.Request('http://localhost:8000/healthz',headers={'Authorization':'Bearer '+os.environ['WEBHOOK_SECRET']});urllib.request.urlopen(req)"
CMD ["uvicorn", "main:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8000"]
