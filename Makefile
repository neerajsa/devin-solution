.PHONY: up test verify-clean tunnel scan dashboard register-webhook demo-issue demo-scan

up:           ; docker compose up --build
test:         ; python -m pytest tests/
tunnel:       ; cloudflared tunnel --url http://localhost:8000

# Prints the dashboard URL (with token) and opens it in a browser if possible.
dashboard:
	@URL="http://localhost:8000/dashboard?token=$$(grep '^WEBHOOK_SECRET=' .env | cut -d'=' -f2)"; \
	echo "$$URL"; \
	(command -v open >/dev/null && open "$$URL") || (command -v xdg-open >/dev/null && xdg-open "$$URL") || true

# Registers a real GitHub webhook pointed at a running `make tunnel`, so the
# human-reported-bug trigger path works against your fork. The tunnel URL is
# assigned fresh each time cloudflared starts, so it can't be hardcoded here -
# run `make tunnel` first, copy the URL it prints, then:
#   make register-webhook URL=https://xxxx.trycloudflare.com
# Everything else (repo, secret, event type) is pulled from .env automatically.
register-webhook:
	@if [ -z "$(URL)" ]; then \
	  echo "Usage: make register-webhook URL=<tunnel-url>  (get <tunnel-url> from a running make tunnel)"; \
	  exit 1; \
	fi
	gh api "repos/$$(grep '^GITHUB_REPO=' .env | cut -d'=' -f2)/hooks" \
	  -f name=web -f active=true \
	  -F "config[url]=$(URL)/webhooks/github" \
	  -F "config[content_type]=json" \
	  -F "config[secret]=$$(grep '^WEBHOOK_SECRET=' .env | cut -d'=' -f2)" \
	  -f "events[]=issues"

# Production scan: all of requirements/base.txt + requirements/development.txt.
scan:
	curl -f -X POST http://localhost:8000/scan/run \
	  -H "Authorization: Bearer $$(grep '^WEBHOOK_SECRET=' .env | cut -d'=' -f2)"

# Demo entry points - fast, cheap, deterministic. Target whatever instance is
# currently up per its own .env, same as every other target here. Requires
# the devin-autofix label to already exist on the target repo (same
# prerequisite as the production webhook path - see README quickstart).
demo-issue:
	gh issue create --repo "$$(grep '^GITHUB_REPO=' .env | cut -d'=' -f2)" \
	  --title "\"previous calendar quarter\" date filter looks wrong at year boundaries" \
	  --body-file scripts/demo_issue_body.md \
	  --label devin-autofix

demo-scan:
	curl -f -X POST http://localhost:8000/scan/run-demo \
	  -H "Authorization: Bearer $$(grep '^WEBHOOK_SECRET=' .env | cut -d'=' -f2)"
verify-clean:
	rm -rf /tmp/devin-solution-verify-clean
	git clone . /tmp/devin-solution-verify-clean
	cp .env /tmp/devin-solution-verify-clean/.env
	cd /tmp/devin-solution-verify-clean && \
	  docker compose build --no-cache && \
	  PORT=8001 docker compose up -d && \
	  sleep 10 && \
	  (curl -f -H "Authorization: Bearer $$(grep '^WEBHOOK_SECRET=' .env | cut -d'=' -f2)" http://localhost:8001/healthz; \
	   status=$$?; PORT=8001 docker compose down; exit $$status)
