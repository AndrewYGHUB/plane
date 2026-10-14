#!/usr/bin/env bash
# Resolve the three public bases once, copy their exact amd64 manifests into
# Harbor, and emit only Harbor@digest references for the actual Plane build.
set -euo pipefail

die() { printf 'plane base mirror: %s\n' "$*" >&2; exit 2; }

[ -n "${DOCKER_CONFIG:-}" ] || die 'DOCKER_CONFIG is required'
command -v crane >/dev/null || die 'crane is required'
command -v python3 >/dev/null || die 'python3 is required'
command -v timeout >/dev/null || die 'GNU timeout is required'
readonly RETRY_ATTEMPTS=3
readonly RETRY_TOTAL_SECONDS=300
readonly RETRY_BACKOFF_SECONDS=10
readonly RETRY_KILL_AFTER_SECONDS=10
readonly RETRY_ATTEMPT_SECONDS=90

output_dir="${1:-.plane-release}"
mkdir -p "$output_dir"
tsv="$output_dir/base-images.tsv"
: >"$tsv"
retained_tsv="$output_dir/retained-images.tsv"
: >"$retained_tsv"

retry_read() {
  local label="$1"; shift
  local attempt rc=0 deadline remaining attempt_budget sleep_budget
  # One budget covers all retries. GNU timeout owns a separate process group by
  # default; TERM followed by a short KILL bounds descendants that ignore TERM.
  deadline=$((SECONDS + RETRY_TOTAL_SECONDS))
  for ((attempt = 1; attempt <= RETRY_ATTEMPTS; attempt++)); do
    remaining=$((deadline - SECONDS))
    [ "$remaining" -gt "$RETRY_KILL_AFTER_SECONDS" ] ||
      die "$label exhausted its ${RETRY_TOTAL_SECONDS}s total budget"
    attempt_budget=$((remaining - RETRY_KILL_AFTER_SECONDS))
    [ "$attempt_budget" -le "$RETRY_ATTEMPT_SECONDS" ] || attempt_budget="$RETRY_ATTEMPT_SECONDS"
    if timeout --signal=TERM --kill-after="${RETRY_KILL_AFTER_SECONDS}s" "${attempt_budget}s" "$@"; then
      return 0
    else
      rc=$?
    fi
    [ "$attempt" -eq "$RETRY_ATTEMPTS" ] && break
    remaining=$((deadline - SECONDS))
    [ "$remaining" -gt 0 ] || die "$label exhausted its ${RETRY_TOTAL_SECONDS}s total budget (rc=$rc)"
    sleep_budget="$RETRY_BACKOFF_SECONDS"
    [ "$sleep_budget" -le "$remaining" ] || sleep_budget="$remaining"
    sleep "$sleep_budget"
  done
  die "$label failed after ${RETRY_ATTEMPTS} attempts within one ${RETRY_TOTAL_SECONDS}s budget (rc=$rc)"
}

read_target_digest() {
  local target="$1" err value
  err="$(mktemp "$output_dir/target-digest-error.XXXXXX")"
  trap 'rm -f "$err"' RETURN
  if value="$(timeout --signal=TERM --kill-after="${RETRY_KILL_AFTER_SECONDS}s" 45s crane digest "$target" 2>"$err")"; then
    printf '%s\n' "$value"
    return 0
  fi
  if grep -qiE 'MANIFEST_UNKNOWN|NAME_UNKNOWN|404[[:space:]]+Not[[:space:]]+Found|NOT_FOUND: artifact .* not found' "$err"; then
    return 4
  fi
  return 2
}

mirror_one() {
  local key="$1" source="$2" source_digest="$3" target_repo="$4"
  local target_digest target_tag pinned_source pinned_target target_rc origin_digest
  case "${source_digest#sha256:}" in ''|*[!0-9a-f]*) die "$key reviewed digest is invalid" ;; esac
  [ "${source_digest#sha256:}" != "$source_digest" ] || die "$key reviewed digest algorithm is invalid"
  [ "${#source_digest}" -eq 71 ] || die "$key reviewed digest length is invalid"
  target_tag="${target_repo}:${source_digest#sha256:}"
  pinned_source="${source}@${source_digest}"

  # Harbor is the first read. A warm reviewed digest never touches the public
  # origin; only an explicit registry-level missing response authorizes fetch.
  set +e
  target_digest="$(read_target_digest "$target_tag")"
  target_rc=$?
  set -e
  if [ "$target_rc" -eq 0 ]; then
    [ "$target_digest" = "$source_digest" ] \
      || die "$key Harbor tag exists with a different digest"
  elif [ "$target_rc" -eq 4 ]; then
    origin_digest="$(retry_read "verify reviewed origin $key" crane digest --platform linux/amd64 "$pinned_source")"
    [ "$origin_digest" = "$source_digest" ] \
      || die "$key public origin differs from its reviewed digest"
    retry_read "copy $key into Harbor" crane copy "$pinned_source" "$target_tag"
    target_digest="$(retry_read "read back $key from Harbor" crane digest "$target_tag")"
    [ "$target_digest" = "$source_digest" ] \
      || die "$key Harbor digest differs after copy"
  else
    die "$key Harbor tag could not be read safely before copy"
  fi

  pinned_target="${target_repo}@${target_digest}"
  printf '%s\t%s\t%s\t%s\n' "$key" "$source" "$pinned_source" "$pinned_target" >>"$tsv"
}

mirror_retained() {
  local component="$1" source="$2" expected_digest="$3" target_repo="$4"
  local actual_digest target_digest target_tag pinned_source pinned_target target_rc
  target_tag="${target_repo}:${expected_digest#sha256:}"
  pinned_source="${source}@${expected_digest}"
  set +e
  target_digest="$(read_target_digest "$target_tag")"
  target_rc=$?
  set -e
  if [ "$target_rc" -eq 0 ]; then
    [ "$target_digest" = "$expected_digest" ] \
      || die "retained $component Harbor tag exists with a different digest"
  elif [ "$target_rc" -eq 4 ]; then
    actual_digest="$(retry_read "verify retained origin $component" crane digest --platform linux/amd64 "$pinned_source")"
    [ "$actual_digest" = "$expected_digest" ] \
      || die "retained $component upstream digest differs from the reviewed v1.4.1 baseline"
    retry_read "copy retained $component into Harbor" crane copy "$pinned_source" "$target_tag"
    target_digest="$(retry_read "read back retained $component from Harbor" crane digest "$target_tag")"
    [ "$target_digest" = "$expected_digest" ] \
      || die "retained $component Harbor digest differs after copy"
  else
    die "retained $component Harbor tag could not be read safely before copy"
  fi
  pinned_target="${target_repo}@${target_digest}"
  printf '%s\t%s\t%s\t%s\n' "$component" "$source" "$pinned_source" "$pinned_target" >>"$retained_tsv"
}

mirror_one API_BASE_IMAGE docker.io/library/python:3.12.10-alpine \
  sha256:af87513194f00b2e6f037eb9a65e339ebbb6f7c6430c456049a7f3169412948f \
  harbor.yunxilu.com/cloudhandstack/mirror/plane-python
mirror_one WEB_NODE_BASE_IMAGE docker.io/library/node:22-alpine \
  sha256:2c752226d477b4a886378baa95b9af252be59301b725fdb0b7e15208131505a8 \
  harbor.yunxilu.com/cloudhandstack/mirror/plane-node
mirror_one WEB_NGINX_BASE_IMAGE docker.io/library/nginx:1.31-alpine \
  sha256:0530961ff0592b58c10f767535cc0abdfccf9e389ff7cc90f87320c1bc7e8506 \
  harbor.yunxilu.com/cloudhandstack/mirror/plane-nginx

# These components are unmodified v1.4.1 binaries. They are mirrored exactly;
# they are not represented as fork-built artifacts.
mirror_retained admin artifacts.plane.so/makeplane/plane-admin:v1.4.1 \
  sha256:db0df60977fb58a5401356925aa48dc05caf4b8814a3c9019e8112b8a4a53916 \
  harbor.yunxilu.com/cloudhandstack/mirror/plane-admin
mirror_retained space artifacts.plane.so/makeplane/plane-space:v1.4.1 \
  sha256:5853edec5897708cb86b16755758faf1aafae568c8fcd2576f9a1d0674ce42fc \
  harbor.yunxilu.com/cloudhandstack/mirror/plane-space
python3 - "$tsv" "$retained_tsv" "$output_dir/base-images.env" "$output_dir/base-images.json" <<'PY'
import json
import pathlib
import re
import sys

tsv_path, retained_path, env_path, json_path = map(pathlib.Path, sys.argv[1:])
rows = []
for line in tsv_path.read_text().splitlines():
    key, source, pinned_source, pinned_harbor = line.split("\t")
    if not re.fullmatch(r"[A-Z_]+", key):
        raise SystemExit("invalid base key")
    if not re.fullmatch(r"harbor[.]yunxilu[.]com/[^ @]+@sha256:[0-9a-f]{64}", pinned_harbor):
        raise SystemExit("base is not a Harbor digest reference")
    rows.append(
        {
            "build_arg": key,
            "origin": source,
            "origin_pinned": pinned_source,
            "harbor_pinned": pinned_harbor,
        }
    )
if len(rows) != 3:
    raise SystemExit("expected exactly three base images")
retained = []
for line in retained_path.read_text().splitlines():
    component, origin, origin_pinned, harbor_pinned = line.split("\t")
    if component not in {"admin", "space"}:
        raise SystemExit("invalid retained component")
    if not re.fullmatch(r"harbor[.]yunxilu[.]com/[^ @]+@sha256:[0-9a-f]{64}", harbor_pinned):
        raise SystemExit("retained image is not an immutable Harbor reference")
    retained.append(
        {
            "component": component,
            "origin": origin,
            "origin_pinned": origin_pinned,
            "harbor_pinned": harbor_pinned,
        }
    )
if {row["component"] for row in retained} != {"admin", "space"}:
    raise SystemExit("retained component set is incomplete")
env_values = {row["build_arg"]: row["harbor_pinned"] for row in rows}
env_values["LIVE_NODE_BASE_IMAGE"] = env_values["WEB_NODE_BASE_IMAGE"]
env_path.write_text("".join(f"PLANE_{key}={env_values[key]}\n" for key in sorted(env_values)))
json_path.write_text(json.dumps({"schema": 1, "base_images": rows, "retained_components": retained}, indent=2) + "\n")
PY

printf 'Plane Harbor pre-store ready: 3 unique bases + 2 retained upstream components\n'
