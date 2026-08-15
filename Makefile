.PHONY: dev up reset seed verify-clean tunnel

dev:          ; docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
up:           ; docker compose up --build
reset:        ; ./scripts/reset_for_demo.sh
seed:         ; ./scripts/seed_defects.sh
tunnel:       ; cloudflared tunnel --url http://localhost:8000
verify-clean:
	rm -rf /tmp/devin-solution-verify-clean
	git clone . /tmp/devin-solution-verify-clean
	cd /tmp/devin-solution-verify-clean && cp .env.example .env && \
	  docker compose build --no-cache && \
	  docker compose up -d && \
	  sleep 10 && curl -f http://localhost:8000/healthz
