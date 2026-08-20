.PHONY: up test verify-clean tunnel scan demo-issue demo-scan

up:           ; docker compose up --build
test:         ; python -m pytest tests/
tunnel:       ; cloudflared tunnel --url http://localhost:8000

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
