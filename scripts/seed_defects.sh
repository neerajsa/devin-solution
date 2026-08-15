#!/usr/bin/env bash
#
# Applies Seed B (the Jinja2 vulnerable-range finding) to the sibling
# superset checkout. Rationale, fingerprint, and detector expectations
# live in devin-solution/docs/seeded-defects.md — read that first.
#
# This script only edits requirements/base.in. Regenerating base.txt
# (./scripts/uv-pip-compile.sh) and committing are separate, reviewed
# steps (see Task 2.2) — not automated here, since both need a human
# to look at the diff before it lands on the fork's master.
#
set -euo pipefail

SUPERSET_DIR="${SUPERSET_DIR:-../superset}"

if [ ! -d "$SUPERSET_DIR" ]; then
  echo "error: superset checkout not found at $SUPERSET_DIR" >&2
  echo "set SUPERSET_DIR to override the default sibling-directory path" >&2
  exit 1
fi

BASE_IN="$SUPERSET_DIR/requirements/base.in"

if grep -q "jinja2>=3.1.2,<3.1.4" "$BASE_IN"; then
  echo "Seed B already present in $BASE_IN — nothing to do."
  exit 0
fi

cat <<'EOF' >> "$BASE_IN"

# Security: seed — vulnerable Jinja2 range for scanner demo
jinja2>=3.1.2,<3.1.4
EOF

echo "Seed B applied to $BASE_IN."
echo "Next: cd $SUPERSET_DIR && ./scripts/uv-pip-compile.sh, then review the diff before committing."
