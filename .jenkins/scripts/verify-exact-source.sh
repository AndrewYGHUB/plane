#!/usr/bin/env bash
# Verify the exact public fork source and its reviewed upstream ancestry.
# --self-test replaces git with a local argv-capturing stub; it never fetches.
set -euo pipefail

die() { printf 'Plane exact source: %s\n' "$*" >&2; exit 2; }

origin_url='https://github.com/AndrewYGHUB/plane.git'
upstream_url='https://github.com/makeplane/plane.git'
upstream_commit='5662b761062b0b2f9d42a6578b55481b5b069792'
upstream_refspec='+refs/tags/v1.4.1:refs/tags/djs8-upstream-v1.4.1'
upstream_local_ref='refs/tags/djs8-upstream-v1.4.1^{commit}'

validate_fetch_contract() {
  [ "$#" -eq 5 ] || { printf 'fetch argv count differs from the reviewed contract\n' >&2; return 2; }
  [ "$1" = '--force' ] || { printf 'fetch must use --force\n' >&2; return 2; }
  [ "$2" = '--no-tags' ] || { printf 'fetch must use --no-tags\n' >&2; return 2; }
  [ "$3" = "$upstream_url" ] || { printf 'fetch upstream URL differs from the reviewed contract\n' >&2; return 2; }
  [ "$4" = "$upstream_refspec" ] || { printf 'fetch tag/refspec differs from the reviewed contract\n' >&2; return 2; }
  [ "$5" = "$upstream_commit" ] || { printf 'fetch base commit differs from the reviewed contract\n' >&2; return 2; }
}

verify_source() {
  sha="${SOURCE_SHA:-}"
  case "$sha" in ''|*[!0-9a-f]*) die 'SOURCE_SHA must be 40 lowercase hex characters' ;; esac
  [ "${#sha}" -eq 40 ] || die 'SOURCE_SHA must be 40 lowercase hex characters'
  command -v git >/dev/null || die 'git is required'

  [ "$(git rev-parse HEAD)" = "$sha" ] || die 'HEAD differs from SOURCE_SHA'
  [ "$(git remote get-url origin)" = "$origin_url" ] || die 'origin URL differs from the public fork'
  git merge-base --is-ancestor "$sha" origin/main ||
    die 'SOURCE_SHA is not reachable from origin/main'

  fetch_args=(--force --no-tags "$upstream_url" "$upstream_refspec")
  validate_fetch_contract "${fetch_args[@]}" "$upstream_commit"
  git fetch "${fetch_args[@]}"

  [ "$(git rev-parse "$upstream_local_ref")" = "$upstream_commit" ] ||
    die 'upstream v1.4.1 tag does not resolve to the reviewed commit'
  git cat-file -e "${upstream_commit}^{commit}" ||
    die 'reviewed upstream commit object is unavailable'
  git merge-base --is-ancestor "$upstream_commit" "$sha" ||
    die 'SOURCE_SHA is not a descendant of reviewed upstream v1.4.1'
  printf 'Exact public Plane source verified: %.12s\n' "$sha"
}

self_test() {
  tmp="$(mktemp -d)"
  trap 'find "$tmp" -type f -exec chmod u+rw {} + 2>/dev/null || true; rm -rf -- "$tmp"' EXIT
  cat >"$tmp/git" <<'SH'
#!/usr/bin/env bash
set -eu
python3 - "$DJS8_GIT_ARGV_LOG" "$@" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
text = path.read_text() if path.exists() else ""
rows = json.loads(text) if text.strip() else []
rows.append(sys.argv[2:])
path.write_text(json.dumps(rows) + "\n")
PY
case "$1:$2:${3:-}" in
  rev-parse:HEAD:) printf '%s\n' "$SOURCE_SHA" ;;
  remote:get-url:origin) printf '%s\n' 'https://github.com/AndrewYGHUB/plane.git' ;;
  merge-base:--is-ancestor:*) exit 0 ;;
  fetch:--force:--no-tags) exit 0 ;;
  rev-parse:refs/tags/djs8-upstream-v1.4.1\^\{commit\}:)
    printf '%s\n' '5662b761062b0b2f9d42a6578b55481b5b069792'
    ;;
  cat-file:-e:*) exit 0 ;;
  *) exit 19 ;;
esac
SH
  chmod +x "$tmp/git"
  : >"$tmp/argv.json"
  PATH="$tmp:$PATH" DJS8_GIT_ARGV_LOG="$tmp/argv.json" \
    SOURCE_SHA='1111111111111111111111111111111111111111' verify_source >/dev/null
  python3 - "$tmp/argv.json" <<'PY'
import json, pathlib, sys
calls = json.loads(pathlib.Path(sys.argv[1]).read_text())
fetches = [row for row in calls if row and row[0] == "fetch"]
want = [[
    "fetch", "--force", "--no-tags",
    "https://github.com/makeplane/plane.git",
    "+refs/tags/v1.4.1:refs/tags/djs8-upstream-v1.4.1",
]]
if fetches != want:
    raise SystemExit("stub-captured fetch argv differs from reviewed contract")
PY

  validate_fetch_contract --force --no-tags "$upstream_url" "$upstream_refspec" "$upstream_commit"
  if validate_fetch_contract --force --no-tags "$upstream_url" + "$upstream_refspec" "$upstream_commit" >/dev/null 2>&1; then
    die 'extra-plus negative control unexpectedly passed'
  fi
  if validate_fetch_contract --force --no-tags "$upstream_url" \
    '+refs/tags/v1.4.2:refs/tags/djs8-upstream-v1.4.1' "$upstream_commit" >/dev/null 2>&1; then
    die 'changed-tag negative control unexpectedly passed'
  fi
  if validate_fetch_contract --force --no-tags "$upstream_url" \
    '+refs/tags/v1.4.1:refs/tags/djs8-upstream-other' "$upstream_commit" >/dev/null 2>&1; then
    die 'changed-refspec negative control unexpectedly passed'
  fi
  printf 'Plane exact-source fetch contract: PASS (stub argv + 3 negative controls)\n'
}

case "${1:-}" in
  '') verify_source ;;
  --self-test) self_test ;;
  --check-fetch-argv)
    shift
    validate_fetch_contract "$@"
    ;;
  *) die 'usage: verify-exact-source.sh [--self-test]' ;;
esac
