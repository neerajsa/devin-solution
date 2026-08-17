import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import config  # noqa: E402

ALL_REQUIRED = {
    "WEBHOOK_SECRET": "test-secret",
    "DEVIN_API_KEY": "cog_test",
    "DEVIN_ORG_ID": "org-test",
    "GITHUB_TOKEN": "ghp_test",
    "GITHUB_REPO": "neerajsa/superset",
}


def _set_all(monkeypatch, **overrides):
    values = {**ALL_REQUIRED, **overrides}
    for name, value in values.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def test_loads_with_everything_set(monkeypatch):
    _set_all(monkeypatch)

    cfg = config.load()

    assert cfg.webhook_secret == "test-secret"
    assert cfg.devin_api_key == "cog_test"
    assert cfg.github_repo == "neerajsa/superset"


@pytest.mark.parametrize("missing", list(ALL_REQUIRED))
def test_fails_when_any_required_var_is_missing(monkeypatch, missing):
    _set_all(monkeypatch, **{missing: None})

    with pytest.raises(config.ConfigError, match=missing):
        config.load()


def test_empty_string_counts_as_missing(monkeypatch):
    _set_all(monkeypatch, WEBHOOK_SECRET="")

    with pytest.raises(config.ConfigError, match="WEBHOOK_SECRET"):
        config.load()


def test_scan_interval_defaults_when_unset(monkeypatch):
    _set_all(monkeypatch)
    monkeypatch.delenv("SCAN_INTERVAL_SECONDS", raising=False)

    assert config.load().scan_interval_seconds == config.DEFAULT_SCAN_INTERVAL_SECONDS


def test_scan_interval_is_overridable(monkeypatch):
    _set_all(monkeypatch)
    monkeypatch.setenv("SCAN_INTERVAL_SECONDS", "300")

    assert config.load().scan_interval_seconds == 300
