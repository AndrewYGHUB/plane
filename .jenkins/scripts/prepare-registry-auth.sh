#!/usr/bin/env bash
# Prepare a Docker client config which names a credential helper only.
# Secret values stay in mounted files and flow directly to requesting clients.
set -euo pipefail

die() { printf 'plane registry auth: %s\n' "$*" >&2; exit 2; }

case "${1:-}" in
  --self-test)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    printf 'test-user\n' >"$tmp/user"
    printf 'test-password\n' >"$tmp/pass"
    HARBOR_USERNAME_FILE="$tmp/user" HARBOR_PASSWORD_FILE="$tmp/pass" \
      PATH="$(cd "$(dirname "$0")/../bin" && pwd):$PATH" \
      sh -c 'printf %s harbor.yunxilu.com | docker-credential-harbor-ci get' \
      >"$tmp/result.json"
    python3 - "$tmp/result.json" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert payload == {
    "ServerURL": "harbor.yunxilu.com",
    "Username": "test-user",
    "Secret": "test-password",
}
PY
    if PATH="$(cd "$(dirname "$0")/../bin" && pwd):$PATH" \
      sh -c 'printf %s registry.invalid | docker-credential-harbor-ci get' \
      >"$tmp/negative.out" 2>"$tmp/negative.err"; then
      die 'unapproved registry negative control unexpectedly passed'
    fi
    printf 'registry credential-helper contract: PASS\n'
    exit 0
    ;;
  '') ;;
  *) die 'usage: prepare-registry-auth.sh [--self-test]' ;;
esac

[ -n "${DOCKER_CONFIG:-}" ] || die 'DOCKER_CONFIG is required'
helper="$(cd "$(dirname "$0")/../bin" && pwd)/docker-credential-harbor-ci"
[ -x "$helper" ] || die 'credential helper is not executable'

umask 077
mkdir -p "$DOCKER_CONFIG"
chmod 0700 "$DOCKER_CONFIG"
python3 - "$DOCKER_CONFIG/config.json" <<'PY'
import json, os, pathlib, sys
path = pathlib.Path(sys.argv[1])
payload = {"credHelpers": {"harbor.yunxilu.com": "harbor-ci"}}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, separators=(",", ":"))
    stream.write("\n")
PY
chmod 0600 "$DOCKER_CONFIG/config.json"
grep -Fq '"credHelpers"' "$DOCKER_CONFIG/config.json" || die 'credential helper config missing'
if grep -Fq '"auths"' "$DOCKER_CONFIG/config.json"; then
  die 'credential value config is forbidden'
fi
printf 'Harbor credential-helper config ready (no credential value stored)\n'
