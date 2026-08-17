.PHONY: up test seed verify-clean tunnel

up:           ; docker compose up --build
test:         ; python -m pytest tests/
seed:         ; ./scripts/seed_defects.sh
tunnel:       ; cloudflared tunnel --url http://localhost:8000
verify-clean:
	rm -rf /tmp/devin-solution-verify-clean
	git clone . /tmp/devin-solution-verify-clean
	cp .env /tmp/devin-solution-verify-clean/.env
	cd /tmp/devin-solution-verify-clean && \
	  docker compose build --no-cache && \
	  docker compose up -d && \
	  sleep 10 && \
	  curl -f -H "Authorization: Bearer $$(grep '^WEBHOOK_SECRET=' .env | cut -d'=' -f2)" http://localhost:8000/healthz
