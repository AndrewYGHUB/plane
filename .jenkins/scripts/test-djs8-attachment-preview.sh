#!/usr/bin/env bash
# DJS-8 controlled development suite for the three images released together.
set -euo pipefail

die() { printf 'DJS-8 required test suite: %s\n' "$*" >&2; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"

for tool in node pnpm python3; do
  command -v "$tool" >/dev/null || die "$tool is required"
done

# These Django contracts exercise transaction and row-lock behavior. Refuse
# accidental SQLite or an implicit local default; credentials remain in env.
python3 - <<'PY'
import os
from urllib.parse import urlsplit

url = os.environ.get("DATABASE_URL", "")
if url:
    if urlsplit(url).scheme not in {"postgres", "postgresql"}:
        raise SystemExit("DJS-8 backend contracts require PostgreSQL DATABASE_URL")
else:
    required = ("POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")
    if any(not os.environ.get(key) for key in required):
        raise SystemExit("DJS-8 backend contracts require explicit PostgreSQL environment")
PY

(
  cd apps/api
  python3 -m pytest -q \
    plane/tests/contract/utils/test_attachment_preview_mapping.py \
    plane/tests/contract/app/test_issue_attachment_preview_app.py \
    plane/tests/contract/api/test_issue_attachment_preview_api.py
)

node --test apps/web/core/components/issues/attachment/attachment-preview.test.mjs
pnpm --dir apps/live exec vitest run tests/lib/auth.test.ts
