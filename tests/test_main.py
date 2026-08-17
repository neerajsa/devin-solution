import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import config  # noqa: E402

# main.py runs config.load() and store.connect() at import time, so tests
# need real-looking env vars set before importing it - matching the pattern
# other modules avoid needing by not doing import-time I/O, which main.py
# does deliberately (fail fast on missing config). Only _has_devin_autofix_trigger
# is under test here - pure, synchronous, no I/O - so a dummy env is fine.
import os

os.environ.setdefault("WEBHOOK_SECRET", "test-secret")
os.environ.setdefault("DEVIN_API_KEY", "test-key")
os.environ.setdefault("DEVIN_ORG_ID", "test-org")
os.environ.setdefault("GITHUB_TOKEN", "test-token")
os.environ.setdefault("GITHUB_REPO", "neerajsa/superset")

import main  # noqa: E402


def test_labeled_action_triggers_only_for_devin_autofix_label():
    assert main._has_devin_autofix_trigger({
        "action": "labeled", "label": {"name": "devin-autofix"}, "issue": {},
    })
    assert not main._has_devin_autofix_trigger({
        "action": "labeled", "label": {"name": "bug"}, "issue": {},
    })


def test_opened_action_triggers_when_label_already_present():
    # The case that motivated this fix: GitHub does not fire a separate
    # "labeled" event when a label is included at issue creation, so an
    # "opened" event must be checked against the issue's own labels[] instead.
    assert main._has_devin_autofix_trigger({
        "action": "opened",
        "issue": {"labels": [{"name": "bug"}, {"name": "devin-autofix"}]},
    })


def test_opened_action_does_not_trigger_without_the_label():
    assert not main._has_devin_autofix_trigger({
        "action": "opened", "issue": {"labels": [{"name": "bug"}]},
    })


def test_other_actions_never_trigger():
    for action in ("closed", "reopened", "unlabeled", "edited"):
        assert not main._has_devin_autofix_trigger({
            "action": action,
            "label": {"name": "devin-autofix"},
            "issue": {"labels": [{"name": "devin-autofix"}]},
        })
