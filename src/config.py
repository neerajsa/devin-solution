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


REQUIRED = ["WEBHOOK_SECRET", "DEVIN_API_KEY", "DEVIN_ORG_ID", "GITHUB_TOKEN", "GITHUB_REPO"]


def load() -> Config:
    missing = [name for name in REQUIRED if not os.environ.get(name)]
    if missing:
        raise ConfigError(f"missing required environment variable(s): {', '.join(missing)}")

    return Config(
        webhook_secret=os.environ["WEBHOOK_SECRET"],
        devin_api_key=os.environ["DEVIN_API_KEY"],
        devin_org_id=os.environ["DEVIN_ORG_ID"],
        github_token=os.environ["GITHUB_TOKEN"],
        github_repo=os.environ["GITHUB_REPO"],
    )
