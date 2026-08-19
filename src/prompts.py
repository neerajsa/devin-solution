"""Prompt templates and the structured_output_schema contract, by finding_class."""

from scanners import Finding

STRUCTURED_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["finding_id", "status", "files_changed", "tests_passed", "summary", "confidence"],
    "properties": {
        "finding_id": {"type": "string"},
        "status": {"enum": ["remediated", "partially_remediated", "not_applicable", "needs_human"]},
        "summary": {"type": "string"},
        "root_cause": {"type": "string"},
        "pr_url": {"type": ["string", "null"]},
        "files_changed": {"type": "array", "items": {"type": "string"}},
        "breaking_changes_handled": {"type": "array", "items": {"type": "string"}},
        "tests_run": {"type": "string"},
        "tests_passed": {"type": "boolean"},
        "residual_risk": {"type": "string"},
        "confidence": {"type": "number"},
    },
}

# Shared verbatim across every finding class, so a change here applies to every
# prompt at once instead of needing separate, driftable edits per class - the
# exact problem that motivated pulling these out (2026-08-18).

AUTONOMY_INSTRUCTION = """\
You are operating fully autonomously - no human is monitoring this session or
available to answer questions. Do not pause to ask a clarifying question or
wait for approval on a judgment call. Make the best-supported decision
yourself and note any uncertainty in your final summary; if you genuinely
cannot proceed without a human decision, stop immediately and return status
"needs_human" explaining why, rather than waiting."""


def communicate_result_block(issue_number: int) -> str:
    return f"""COMMUNICATE YOUR RESULT
  Whatever the outcome - a PR opened, or a decision that no PR is needed -
  post ONE comment on issue #{issue_number} in this repo explaining what you
  found and what you did (or, if you didn't act, why not). This is the
  primary way a human learns the outcome, so write it standalone: don't
  assume they've read the PR, this session, or anything else.

  Return your result against the provided structured output schema."""


def render_dependency_cve_prompt(finding: Finding, *, repo: str, branch: str,
                                  run_id: str, issue_number: int) -> str:
    # An issue for this finding already exists by the time this prompt is
    # rendered - main.py's scanner path (_file_and_dispatch) files a plain
    # tracking issue itself, deterministically, before ever calling dispatch().
    # Devin is never asked to create it: we need the issue number back
    # synchronously, before dispatch, for our own fingerprint-marker dedup
    # system - if Devin created it instead we'd only learn the number after
    # the session finished, adding parsing/coupling on our side for something
    # that's pure mechanical record-keeping, not a judgment call. Revisit this
    # split if the tracking-issue format ever needs to be richer than a raw
    # scan summary - at that point having Devin author it directly might be
    # worth the coupling cost.
    fixed_in = finding.fixed_version or "none published"
    return f"""You are remediating security finding {finding.fingerprint} in {repo} on branch {branch}.
This finding is tracked in issue #{issue_number} of this repo.

{AUTONOMY_INSTRUCTION}

FINDING
  Package:  {finding.package}, pinned at {finding.current_version}
  CVE:      {finding.cve_id}
  Fixed in: {fixed_in}
  Severity: {finding.severity}
  Source:   {finding.source}, scan run {run_id}
  Summary:  {finding.summary}

TASK
  1. Confirm the finding applies. If {finding.package} is not actually reachable in
     Superset's usage, or the pin is already patched, return
     status "not_applicable" with your evidence and STOP. Do not open a PR.
  2. If "Fixed in" above is "none published", no non-vulnerable version has been
     published upstream. Do not guess a version or upgrade to the latest
     release hoping it's patched. Investigate whether a mitigation short of
     an upgrade exists (config change, usage restriction). If none does,
     return status "needs_human" explaining that no fix is currently
     published, and STOP. Do not open a PR.
     Otherwise, upgrade the pin to the minimum version at or above "Fixed in".
  3. Read the upstream changelog between the current and target version and
     identify breaking changes. Search the codebase for call sites of
     {finding.package} and adapt every affected one. Update affected tests.
  4. Verify: run ONLY `pytest tests/unit_tests/<paths you touched>`.
     DO NOT run tests/integration_tests/ - they require Postgres and Redis
     and will exhaust the session budget.
  5. Follow this repository's own agent instructions in AGENTS.md at the repo
     root before pushing - in particular, run
     `pre-commit run --files <changed files>`.
  6. Open a PR against {branch} of {repo}, titled
     `fix({finding.package}): bump to <version> for {finding.cve_id}`.
     The body must include: the CVE summary, the breaking changes you handled
     (or "none"), every file you modified, the exact test command with its
     output, and a reference to issue #{issue_number} (e.g. "Fixes #{issue_number}")
     so it closes automatically on merge.

CONSTRAINTS
  - One finding per PR. Do not bump unrelated dependencies.
  - Do not run formatters or linters across the whole repository.
  - If the correct fix requires a product decision rather than an engineering
    one, return status "needs_human" with an explanation. Do not guess.
  - Stay within the session ACU cap. If you are approaching it without a clear
    path, stop and return "needs_human" describing what blocked you.

{communicate_result_block(issue_number)}"""


def render_reported_issue_prompt(finding: Finding, *, repo: str, branch: str,
                                  run_id: str, issue_number: int) -> str:
    return f"""You are investigating a human-reported issue in {repo} on branch {branch}.
This report is issue #{issue_number} of this repo.

{AUTONOMY_INSTRUCTION}

REPORT
  Source:  {finding.source}, run {run_id}
  Report:  {finding.summary}

  This report is a precursory human observation, not a full investigation.
  It may be imprecise, incomplete, or describe only a symptom rather than
  the root cause. Do not assume it is fully accurate.

TASK
  1. Reproduce the problem described above. If you cannot reproduce it, or
     find the described behavior is actually correct/intended, return status
     "not_applicable" with your evidence and STOP. Do not open a PR.
  2. Find the actual root cause - do not patch around a symptom.
  3. Implement a fix, and add a regression test that fails without your fix
     and passes with it.
  4. Verify: run ONLY `pytest tests/unit_tests/<paths you touched>`.
     DO NOT run tests/integration_tests/ - they require Postgres and Redis
     and will exhaust the session budget.
  5. Follow this repository's own agent instructions in AGENTS.md at the repo
     root before pushing - in particular, run
     `pre-commit run --files <changed files>`.
  6. Open a PR against {branch} of {repo}. The body must include: the root
     cause you found, the regression test you added, every file you
     modified, the exact test command with its output, and a reference to
     issue #{issue_number} (e.g. "Fixes #{issue_number}") so it closes
     automatically on merge.

CONSTRAINTS
  - One issue per PR. Do not fix unrelated bugs you happen to notice.
  - Do not run formatters or linters across the whole repository.
  - If the correct fix requires a product decision rather than an engineering
    one, return status "needs_human" with an explanation. Do not guess.
  - Stay within the session ACU cap. If you are approaching it without a clear
    path, stop and return "needs_human" describing what blocked you.

{communicate_result_block(issue_number)}"""


RENDERERS = {
    "dependency-cve": render_dependency_cve_prompt,
    "reported-issue": render_reported_issue_prompt,
}


def render_prompt(finding: Finding, **context) -> str:
    renderer = RENDERERS.get(finding.finding_class)
    if renderer is None:
        raise ValueError(f"no prompt template for finding_class {finding.finding_class!r}")
    return renderer(finding, **context)
