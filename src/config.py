"""Environment config. Loaded once at startup - fails fast if anything required is missing."""

import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    webhook_secret: str
    devin_api_key: str
    devin_org_id: str
    github_token: str
    github_repo: str
    scan_interval_seconds: int
    session_timeout_seconds: int


REQUIRED = ["WEBHOOK_SECRET", "DEVIN_API_KEY", "DEVIN_ORG_ID", "GITHUB_TOKEN", "GITHUB_REPO"]

# Not a credential, so not in REQUIRED - an operational tuning knob with a sane
# default (daily) that's fine to run without ever setting explicitly.
DEFAULT_SCAN_INTERVAL_SECONDS = 86400

# Upper bound on how long a single Devin session is polled before it's given up
# on as 'timed_out' and terminated.
DEFAULT_SESSION_TIMEOUT_SECONDS = 7200


def load() -> Config:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        raise ConfigError(f"missing required environment variable(s): {', '.join(missing)}")

    session_timeout_seconds = int(
        os.environ.get("SESSION_TIMEOUT_SECONDS") or DEFAULT_SESSION_TIMEOUT_SECONDS
    )
    if session_timeout_seconds <= 0:
        raise ConfigError("SESSION_TIMEOUT_SECONDS must be a positive number of seconds")

    return Config(
        webhook_secret=os.environ["WEBHOOK_SECRET"],
        devin_api_key=os.environ["DEVIN_API_KEY"],
        devin_org_id=os.environ["DEVIN_ORG_ID"],
        github_token=os.environ["GITHUB_TOKEN"],
        github_repo=os.environ["GITHUB_REPO"],
        scan_interval_seconds=int(os.environ.get("SCAN_INTERVAL_SECONDS") or DEFAULT_SCAN_INTERVAL_SECONDS),
        session_timeout_seconds=session_timeout_seconds,
    )
