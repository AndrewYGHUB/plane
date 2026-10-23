#!/usr/bin/env bash
# Prepare daemonless Docker archives for the three DJS-8 images. This script
# deliberately does not push: sign-and-sbom.sh scans all archives first.
set -euo pipefail

die() { printf 'plane image build: %s\n' "$*" >&2; exit 2; }
command -v python3 >/dev/null || die 'python3 is required'
. "$(dirname "$0")/lib-harbor-exact-not-found.sh"

validate_evidence_status() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, pathlib, sys, runpy
strict_json = runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")["strict_json"]
path = pathlib.Path(sys.argv[1])
evidence = sys.argv[2]
source_sha = sys.argv[3]
try:
    payload = strict_json(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit("Plane evidence status file is unreadable") from exc
expected = {
    "evidence_id": evidence,
    "item": "DJS-8",
    "stage": "dev",
    "status": "plane-readback-verified",
    "verified_source_sha": source_sha,
    "verified_worktree_clean": True,
    "verified_test_result": "passed",
    "verified_exit_code": 0,
    "verified_test_suite": "djs8-plane-release-contracts-v2",
    "verified_test_command_sha256": "c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b",
    "verified_test_entrypoint_sha256": "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0",
}

if payload.get("apk_revision_receipt"):
    import runpy
    controls = runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")
    receipt = payload["apk_revision_receipt"]
    assert receipt["schema"] == controls["APK_REVISION_SCHEMA"] and not any(payload.get(key) for key in controls["RECEIPT_KEYS"].values() if key != "apk_revision_receipt")
    controls["verify"](receipt, source_sha)
    expected["verified_source_sha"] = receipt["tested_source_sha"]
    expected["apk_revision_receipt"] = receipt
elif payload.get("apk_amendment_receipt"):
    import runpy
    controls = runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")
    receipt = payload["apk_amendment_receipt"]
    assert receipt["schema"] == controls["APK_SCHEMA"] and not any(payload.get(key) for key in controls["RECEIPT_KEYS"].values() if key != "apk_amendment_receipt")
    controls["verify"](receipt, source_sha)
    expected["verified_source_sha"] = receipt["tested_source_sha"]
    expected["apk_amendment_receipt"] = receipt
elif payload.get("frontend_amendment_receipt"):
    import runpy
    controls = runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")
    receipt = payload["frontend_amendment_receipt"]
    assert receipt["schema"] == controls["FRONTEND_SCHEMA"] and not any(payload.get(key) for key in ("rootfs_amendment_receipt", "signing_amendment_receipt", "live_amendment_receipt", "ci_tree_equivalence"))
    controls["verify"](receipt, source_sha)
    expected["verified_source_sha"] = receipt["tested_source_sha"]
    expected["frontend_amendment_receipt"] = receipt
elif payload.get("rootfs_amendment_receipt"):
    import runpy
    controls = runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")
    receipt = payload["rootfs_amendment_receipt"]
    assert receipt["schema"] == controls["ROOTFS_SCHEMA"] and not any(payload.get(key) for key in ("signing_amendment_receipt", "live_amendment_receipt", "ci_tree_equivalence"))
    controls["verify"](receipt, source_sha)
    expected["verified_source_sha"] = receipt["tested_source_sha"]
    expected["rootfs_amendment_receipt"] = receipt
elif payload.get("signing_amendment_receipt"):
    import runpy
    controls = runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")
    receipt = payload["signing_amendment_receipt"]
    assert receipt["schema"] == controls["SIGNING_SCHEMA"] and not payload.get("live_amendment_receipt") and not payload.get("ci_tree_equivalence")
    controls["verify"](receipt, source_sha)
    expected["verified_source_sha"] = receipt["tested_source_sha"]
    expected["signing_amendment_receipt"] = receipt
elif payload.get("live_amendment_receipt"):
    import runpy
    receipt = payload["live_amendment_receipt"]
    assert receipt["schema"] == "djs8-scoped-live-amendment-v1" and not payload.get("ci_tree_equivalence")
    runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")["verify"](receipt, source_sha)
    expected["verified_source_sha"] = receipt["tested_source_sha"]
    expected["live_amendment_receipt"] = receipt
elif payload.get("ci_tree_equivalence"):
    import runpy
    receipt = payload["ci_tree_equivalence"]
    assert receipt["schema"] == "djs8-ci-tree-equivalence-v1"
    runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")["verify"](receipt, source_sha)
    expected["verified_source_sha"] = receipt["tested_source_sha"]
    expected["ci_tree_equivalence"] = receipt
if payload != expected:
    raise SystemExit("Plane evidence status file does not match this clean DJS-8 build")
print(payload["status"] + "\t" + payload["verified_source_sha"] + "\tclean")
PY
}

if [ "${1:-}" = "--self-test-evidence" ]; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf -- "$tmpdir"' EXIT
  evidence='ev-0123456789ab'
  current_sha='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
  old_sha='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
  write_status() {
    python3 - "$tmpdir/status.json" "$evidence" "$1" "$2" "$3" "$4" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "evidence_id": sys.argv[2], "item": "DJS-8", "stage": "dev",
    "status": "plane-readback-verified", "verified_source_sha": sys.argv[3],
    "verified_worktree_clean": sys.argv[4] == "clean",
    "verified_test_result": sys.argv[5],
    "verified_exit_code": 0 if sys.argv[5] == "passed" else 1,
    "verified_test_suite": ("djs8-plane-release-contracts-v2"
        if sys.argv[6] == "target" else "non-target-suite"),
    "verified_test_command_sha256": ("c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b"
        if sys.argv[6] == "target" else "b5bea41b6c623f7c09f1bf24dcae58eb90d0769795f21a7be7d9b8bc1932a506"),
    "verified_test_entrypoint_sha256": ("b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0"
        if sys.argv[6] == "target" else "15e70b731d9598386f876229fe2013a58b7d0e386e52ce999f13a6b66ce3c673"),
}) + "\n")
PY
  }
  write_status "$current_sha" clean passed target
  validate_evidence_status "$tmpdir/status.json" "$evidence" "$current_sha" >/dev/null
  write_status "$old_sha" clean passed target
  if validate_evidence_status "$tmpdir/status.json" "$evidence" "$current_sha" >/dev/null 2>&1; then
    die 'old-evidence/new-source negative control unexpectedly passed'
  fi
  write_status "$current_sha" dirty passed target
  if validate_evidence_status "$tmpdir/status.json" "$evidence" "$current_sha" >/dev/null 2>&1; then
    die 'dirty-worktree evidence negative control unexpectedly passed'
  fi
  write_status "$current_sha" clean failed target
  if validate_evidence_status "$tmpdir/status.json" "$evidence" "$current_sha" >/dev/null 2>&1; then
    die 'failed-test evidence negative control unexpectedly passed'
  fi
  write_status "$current_sha" clean passed non-target
  if validate_evidence_status "$tmpdir/status.json" "$evidence" "$current_sha" >/dev/null 2>&1; then
    die 'non-target evidence negative control unexpectedly passed'
  fi
  printf 'Plane evidence/source binding self-test: 1 positive + stale-source/dirty-tree/failed-test/non-target negatives passed\n'
  exit 0
fi

dev_test_evidence="${DEV_TEST_EVIDENCE:-}"
[[ "$dev_test_evidence" =~ ^ev-[0-9a-f]{12}$ ]] ||
  die 'DEV_TEST_EVIDENCE must be one Plane evidence ID (ev- plus 12 lowercase hex characters)'
for tool in buildctl cosign-v2 crane shasum; do command -v "$tool" >/dev/null || die "$tool is required"; done

sha="${SOURCE_SHA:-}"
case "$sha" in ''|*[!0-9a-f]*) die 'SOURCE_SHA must be lowercase hexadecimal' ;; esac
[ "${#sha}" -eq 40 ] || die 'SOURCE_SHA must contain 40 characters'
[ "$(git rev-parse HEAD)" = "$sha" ] || die 'working tree does not match SOURCE_SHA'
output_dir="${1:-.plane-release}"
evidence_status_file="${PLANE_EVIDENCE_STATUS_FILE:-$output_dir/development-evidence-status.json}"
evidence_status='caller-format-validated/unverified'
evidence_item='DJS-8'
evidence_stage='dev'
evidence_verified_source_sha=''
evidence_verified_worktree_clean='false'
evidence_verified_test_result='unverified'
evidence_verified_exit_code=''
evidence_verified_test_suite='unverified'
evidence_verified_test_command_sha256=''
evidence_verified_test_entrypoint_sha256=''
if [ -f "$evidence_status_file" ]; then
  evidence_fields="$(validate_evidence_status "$evidence_status_file" "$dev_test_evidence" "$sha")" ||
    die 'Plane evidence status validation failed'
  IFS=$'\t' read -r evidence_status evidence_verified_source_sha evidence_clean_marker <<<"$evidence_fields"
  [ "$evidence_clean_marker" = clean ] || die 'Plane evidence clean-tree marker is invalid'
  evidence_verified_worktree_clean='true'
  evidence_verified_test_result='passed'
  evidence_verified_exit_code='0'
  evidence_verified_test_suite='djs8-plane-release-contracts-v2'
  evidence_verified_test_command_sha256='c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b'
  evidence_verified_test_entrypoint_sha256='b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0'
elif [ -n "${PLANE_API_TOKEN:-}" ] || [ -n "${PLANE_EVIDENCE_STATUS_FILE:-}" ]; then
  die 'Plane credential/status was supplied but verified evidence status is unavailable'
fi
upstream_base='5662b761062b0b2f9d42a6578b55481b5b069792'
git cat-file -e "${upstream_base}^{commit}" 2>/dev/null || die 'reviewed upstream base object is unavailable'
git merge-base --is-ancestor "$upstream_base" "$sha" || die 'SOURCE_SHA is not a descendant of reviewed upstream v1.4.1'

mkdir -p "$output_dir"
trusted='.jenkins/trust/czs10-controller-cosign-v1.pub'
trusted_sha='df0c4d475fb1f8d7a270a6909b0f42403d58bdf24840f8c715cda60d9272e43d'
[ -s "$trusted" ] || die 'fixed trusted public key is missing'
[ "$(shasum -a 256 "$trusted" | awk '{print $1}')" = "$trusted_sha" ] ||
  die 'fixed trusted public key SHA-256 mismatch'
env_file="$output_dir/base-images.env"
[ -s "$env_file" ] || die 'Harbor base-image environment is missing'
python3 - "$env_file" <<'PY'
import pathlib, re, sys
rows = pathlib.Path(sys.argv[1]).read_text().splitlines()
allowed = {"PLANE_API_BASE_IMAGE", "PLANE_WEB_NODE_BASE_IMAGE", "PLANE_WEB_NGINX_BASE_IMAGE", "PLANE_LIVE_NODE_BASE_IMAGE"}
seen = set()
for row in rows:
    key, sep, value = row.partition("=")
    if not sep or key not in allowed or key in seen:
        raise SystemExit("unsafe base-image environment")
    if not re.fullmatch(r"harbor[.]yunxilu[.]com/[^ @]+@sha256:[0-9a-f]{64}", value):
        raise SystemExit("base-image value is not an immutable Harbor reference")
    seen.add(key)
if seen != allowed:
    raise SystemExit("base-image environment is incomplete")
PY
# shellcheck disable=SC1090
. "$env_file"

epoch="$(git show -s --format=%ct "$sha")"
case "$epoch" in ''|*[!0-9]*) die 'source commit timestamp is invalid' ;; esac

read_tag_digest() {
  tag="$1"; err="$(mktemp "$output_dir/digest-error.XXXXXX")"
  trap 'rm -f "$err"' RETURN
  if value="$(crane digest "$tag" 2>"$err")"; then
    printf '%s\n' "$value"
    return 0
  fi
  if harbor_digest_error_is_exact_not_found "$err" "$tag" 40; then
    return 4
  fi
  return 2
}

verify_archive_labels() {
  python3 - "$1" "$sha" <<'PY'
import json, sys, tarfile
archive, sha = sys.argv[1:]
with tarfile.open(archive) as tf:
    manifest = json.load(tf.extractfile("manifest.json"))
    if len(manifest) != 1:
        raise SystemExit("archive must contain exactly one image")
    cfg = json.load(tf.extractfile(manifest[0]["Config"]))
labels = (cfg.get("config") or {}).get("Labels") or {}
want = {
    "org.opencontainers.image.source": "https://github.com/AndrewYGHUB/plane",
    "org.opencontainers.image.revision": sha,
}
for key, value in want.items():
    if labels.get(key) != value:
        raise SystemExit("archive OCI label mismatch: " + key)
bad = []
for item in (cfg.get("config") or {}).get("Env") or []:
    key, _, value = item.partition("=")
    if any(mark in key.upper() for mark in ("PASSWORD", "SECRET", "TOKEN", "PRIVATE_KEY", "API_KEY")) and value:
        bad.append(key)
if bad:
    print("credential-shaped non-empty image ENV keys: " + ",".join(sorted(bad)), file=sys.stderr)
    raise SystemExit(1)
PY
}

verify_reusable_signature() {
  tag="$1"; digest="$2"; proof="$3"
  immutable="${tag}@${digest}"
  if ! cosign-v2 verify --key "$trusted" --insecure-ignore-tlog=true "$immutable" >"$proof"; then
    rm -f "$proof"
    return 1
  fi
  if ! python3 - "$proof" "${tag%:*}" "$digest" <<'PY'
import json, pathlib, sys
proof, repository, digest = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    signatures = json.loads(proof.read_text())
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit("existing signature proof is invalid JSON") from exc
if not isinstance(signatures, list) or not signatures:
    raise SystemExit("existing signature proof is empty")
for signature in signatures:
    critical = signature.get("critical") or {}
    identity = critical.get("identity") or {}
    image = critical.get("image") or {}
    if critical.get("type") != "cosign container image signature":
        raise SystemExit("existing signature proof has an unexpected type")
    if identity.get("docker-reference") != repository:
        raise SystemExit("existing signature proof repository mismatch")
    if image.get("docker-manifest-digest") != digest:
        raise SystemExit("existing signature proof digest mismatch")
PY
  then
    rm -f "$proof"
    return 1
  fi
}

build_component_archive() {
  component="$1"; archive="$2"; metadata="$3"; origin="$4"
  case "$component" in
      backend)
        buildctl build --frontend dockerfile.v0 \
          --local context=apps/api --local dockerfile=apps/api \
          --opt filename=Dockerfile.api --opt platform=linux/amd64 \
          --opt "build-arg:API_BASE_IMAGE=$PLANE_API_BASE_IMAGE" \
          --opt "build-arg:SOURCE_SHA=$sha" --opt "build-arg:SOURCE_DATE_EPOCH=$epoch" \
          --output "type=docker,dest=$archive,rewrite-timestamp=true" --metadata-file "$metadata"
        ;;
      frontend)
        buildctl build --frontend dockerfile.v0 \
          --local context=. --local dockerfile=. \
          --opt filename=apps/web/Dockerfile.web --opt platform=linux/amd64 \
          --opt "build-arg:WEB_NODE_BASE_IMAGE=$PLANE_WEB_NODE_BASE_IMAGE" \
          --opt "build-arg:WEB_NGINX_BASE_IMAGE=$PLANE_WEB_NGINX_BASE_IMAGE" \
          --opt "build-arg:SOURCE_SHA=$sha" --opt "build-arg:SOURCE_DATE_EPOCH=$epoch" \
          --output "type=docker,dest=$archive,rewrite-timestamp=true" --metadata-file "$metadata"
        ;;
      live)
        buildctl build --frontend dockerfile.v0 \
          --local context=. --local dockerfile=. \
          --opt filename=apps/live/Dockerfile.live --opt platform=linux/amd64 \
          --opt "build-arg:LIVE_NODE_BASE_IMAGE=$PLANE_LIVE_NODE_BASE_IMAGE" \
          --opt "build-arg:SOURCE_SHA=$sha" --opt "build-arg:SOURCE_DATE_EPOCH=$epoch" \
          --output "type=docker,dest=$archive,rewrite-timestamp=true" --metadata-file "$metadata"
        ;;
    *) die "unknown component: $component" ;;
  esac
  built_digest="$(crane digest --tarball "$archive")"
  verify_archive_labels "$archive"
  python3 - "$metadata" "$built_digest" "$origin" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text())
payload["containerimage.digest"] = sys.argv[2]
payload["djs8.archive_origin"] = sys.argv[3]
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
}

prepare_component() {
  component="$1"; tag="$2"; archive="$3"; metadata="$4"
  set +e
  remote_digest="$(read_tag_digest "$tag")"
  remote_rc=$?
  set -e
  if [ "$remote_rc" -eq 0 ]; then
    case "$remote_digest" in sha256:[0-9a-f][0-9a-f]*) ;; *) die "$component existing digest is malformed" ;; esac
    [ "${#remote_digest}" -eq 71 ] || die "$component existing digest length is invalid"
    reuse_proof="$output_dir/reuse-signature-${component}.json"
    if verify_reusable_signature "$tag" "$remote_digest" "$reuse_proof"; then
      crane pull "${tag}@${remote_digest}" "$archive"
      local_digest="$(crane digest --tarball "$archive")"
      [ "$local_digest" = "$remote_digest" ] || die "$component reused archive digest differs from Harbor"
      # The fixed-root signature covers remote_digest. Verifying the labels in the
      # archive with that same digest proves the reused bytes came from this exact
      # reviewed repository commit rather than merely sharing its canonical tag.
      verify_archive_labels "$archive"
      python3 - "$metadata" "$remote_digest" "$(basename "$reuse_proof")" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "containerimage.digest": sys.argv[2],
    "djs8.archive_origin": "existing-harbor-exact-sha-tag",
    "djs8.reuse_trust": "fixed-cosign-root-and-signed-oci-source-labels",
    "djs8.reuse_signature_proof": sys.argv[3],
}, indent=2, sort_keys=True) + "\n")
PY
    else
      # A prior interrupted release may have created the immutable canonical tag
      # before its fixed-root signature. Rebuild from the exact reviewed source;
      # only the identical digest is eligible for the controlled signing recovery.
      build_component_archive "$component" "$archive" "$metadata" \
        "strict-rebuild-for-unsigned-canonical-recovery"
      [ "$built_digest" = "$remote_digest" ] ||
        die "$component unsigned canonical digest differs from strict exact rebuild"
      python3 - "$metadata" "$remote_digest" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text())
payload["djs8.unsigned_canonical_recovery_digest"] = sys.argv[2]
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
    fi
  elif [ "$remote_rc" -eq 4 ]; then
    build_component_archive "$component" "$archive" "$metadata" \
      "buildkit-local-docker-archive"
  else
    die "$component exact-SHA tag could not be read safely"
  fi
}

backend_tag="harbor.yunxilu.com/cloudhandstack/plane-backend:${sha}"
frontend_tag="harbor.yunxilu.com/cloudhandstack/plane-frontend:${sha}"
live_tag="harbor.yunxilu.com/cloudhandstack/plane-live:${sha}"
prepare_component backend "$backend_tag" "$output_dir/backend.tar" "$output_dir/backend-build-metadata.json"
prepare_component frontend "$frontend_tag" "$output_dir/frontend.tar" "$output_dir/frontend-build-metadata.json"
prepare_component live "$live_tag" "$output_dir/live.tar" "$output_dir/live-build-metadata.json"

export DJS8_EVIDENCE_STATUS="$evidence_status"
export DJS8_EVIDENCE_ITEM="$evidence_item"
export DJS8_EVIDENCE_STAGE="$evidence_stage"
export DJS8_EVIDENCE_VERIFIED_SOURCE_SHA="$evidence_verified_source_sha"
export DJS8_EVIDENCE_VERIFIED_WORKTREE_CLEAN="$evidence_verified_worktree_clean"
export DJS8_EVIDENCE_VERIFIED_TEST_RESULT="$evidence_verified_test_result"
export DJS8_EVIDENCE_VERIFIED_EXIT_CODE="$evidence_verified_exit_code"
export DJS8_EVIDENCE_VERIFIED_TEST_SUITE="$evidence_verified_test_suite"
export DJS8_EVIDENCE_VERIFIED_TEST_COMMAND_SHA256="$evidence_verified_test_command_sha256"
export DJS8_EVIDENCE_VERIFIED_TEST_ENTRYPOINT_SHA256="$evidence_verified_test_entrypoint_sha256"
python3 - "$output_dir/backend-build-metadata.json" "$output_dir/frontend-build-metadata.json" "$output_dir/live-build-metadata.json" \
  "$output_dir/base-images.json" "$output_dir/release.json" <<'PY'
import json, os, pathlib, re, sys
backend_metadata, frontend_metadata, live_metadata, prestored, output = map(pathlib.Path, sys.argv[1:])
def entry(path, repo):
    p = json.loads(path.read_text())
    digest = p.get("containerimage.digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SystemExit("invalid image digest in " + str(path))
    row = {"image": repo, "tag": os.environ["SOURCE_SHA"], "digest": digest,
           "archive_origin": p.get("djs8.archive_origin")}
    if row["archive_origin"] == "existing-harbor-exact-sha-tag":
        proof = p.get("djs8.reuse_signature_proof", "")
        if not re.fullmatch(r"reuse-signature-(?:backend|frontend|live)[.]json", proof):
            raise SystemExit("invalid existing-image signature proof reference")
        if p.get("djs8.reuse_trust") != "fixed-cosign-root-and-signed-oci-source-labels":
            raise SystemExit("existing-image trust proof is incomplete")
        row["reuse_verification"] = {
            "signature_verified_with_trust_root_sha256":
                "df0c4d475fb1f8d7a270a6909b0f42403d58bdf24840f8c715cda60d9272e43d",
            "signed_repository": repo,
            "signed_digest": digest,
            "signed_source_repository": "https://github.com/AndrewYGHUB/plane",
            "signed_source_revision": os.environ["SOURCE_SHA"],
            "verification_artifact": proof,
        }
    return row
prestore_payload = json.loads(prestored.read_text())
retained = {}
for row in prestore_payload.get("retained_components", []):
    component = row["component"]
    if component in retained: raise SystemExit("duplicate retained component")
    if not re.fullmatch(r"artifacts[.]plane[.]so/makeplane/plane-(?:admin|space):v1[.]4[.]1@sha256:[0-9a-f]{64}", row["origin_pinned"]):
        raise SystemExit("retained upstream origin is invalid")
    if not re.fullmatch(r"harbor[.]yunxilu[.]com/cloudhandstack/mirror/plane-(?:admin|space)@sha256:[0-9a-f]{64}", row["harbor_pinned"]):
        raise SystemExit("retained Harbor reference is invalid")
    retained[component] = {**row, "build_origin": "upstream-v1.4.1-not-fork-built"}
if set(retained) != {"admin", "space"}: raise SystemExit("retained upstream set is incomplete")
dev_ref = os.environ["DEV_TEST_EVIDENCE"]
dev_status = os.environ["DJS8_EVIDENCE_STATUS"]
dev_item = os.environ["DJS8_EVIDENCE_ITEM"]
dev_stage = os.environ["DJS8_EVIDENCE_STAGE"]
dev_verified_source_sha = os.environ["DJS8_EVIDENCE_VERIFIED_SOURCE_SHA"]
dev_verified_worktree_clean = os.environ["DJS8_EVIDENCE_VERIFIED_WORKTREE_CLEAN"] == "true"
dev_verified_test_result = os.environ["DJS8_EVIDENCE_VERIFIED_TEST_RESULT"]
dev_verified_exit_code = os.environ["DJS8_EVIDENCE_VERIFIED_EXIT_CODE"]
dev_verified_test_suite = os.environ["DJS8_EVIDENCE_VERIFIED_TEST_SUITE"]
dev_verified_test_command_sha256 = os.environ["DJS8_EVIDENCE_VERIFIED_TEST_COMMAND_SHA256"]
dev_verified_test_entrypoint_sha256 = os.environ["DJS8_EVIDENCE_VERIFIED_TEST_ENTRYPOINT_SHA256"]
payload = {
  "schema": 2,
  "release_scope": "DJS-8 Plane CE attachment Page preview",
  "source": {
    "repository": "https://github.com/AndrewYGHUB/plane",
    "commit": os.environ["SOURCE_SHA"],
    "upstream_base": {"repository": "https://github.com/makeplane/plane", "tag": "v1.4.1",
      "commit": "5662b761062b0b2f9d42a6578b55481b5b069792", "license": "AGPL-3.0-only",
      "relationship": "ancestor-verified-by-exact-source-stage"},
  },
  "self_built_components": {
    "backend": entry(backend_metadata, "harbor.yunxilu.com/cloudhandstack/plane-backend"),
    "frontend": entry(frontend_metadata, "harbor.yunxilu.com/cloudhandstack/plane-frontend"),
    "live": entry(live_metadata, "harbor.yunxilu.com/cloudhandstack/plane-live"),
  },
  "retained_upstream_components": retained,
  "release_build_validation": {"full_unit_test_suite_executed": False,
    "reason": ("release packaging reuses Plane-readback-verified development tests"
      if dev_status == "plane-readback-verified"
      else "caller supplied a format-valid evidence reference; Plane was not read back"),
    "development_evidence_reference": dev_ref,
    "development_evidence_reference_status": dev_status,
    "development_evidence_item": dev_item,
    "development_evidence_stage": dev_stage,
    "development_evidence_verified_source_sha": dev_verified_source_sha,
    "development_evidence_verified_worktree_clean": dev_verified_worktree_clean,
    "development_evidence_verified_test_result": dev_verified_test_result,
    "development_evidence_verified_exit_code":
      int(dev_verified_exit_code) if dev_verified_exit_code else None,
    "development_evidence_verified_test_suite": dev_verified_test_suite,
    "development_evidence_verified_test_command_sha256": dev_verified_test_command_sha256,
    "development_evidence_verified_test_entrypoint_sha256": dev_verified_test_entrypoint_sha256,
    "tested_source_sha": dev_verified_source_sha,
    "build_source_sha": os.environ["SOURCE_SHA"],
    "component_validation_sources": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("apk_revision_receipt", {}).get("component_validation_sources") if json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("apk_revision_receipt") else json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("apk_amendment_receipt", {}).get("component_validation_sources") if json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("apk_amendment_receipt") else json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("frontend_amendment_receipt", {}).get("component_validation_sources") if json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("frontend_amendment_receipt") else json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("rootfs_amendment_receipt", {}).get("component_validation_sources") if json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("rootfs_amendment_receipt") else json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("signing_amendment_receipt", {}).get("component_validation_sources") if json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("signing_amendment_receipt") else {"pg_web": dev_verified_source_sha, "live_amendment": os.environ["SOURCE_SHA"], "old_live_suite": "historical only"} if json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("live_amendment_receipt") else None,
    "apk_revision_receipt": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("apk_revision_receipt"),
    "apk_amendment_receipt": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("apk_amendment_receipt"),
    "frontend_amendment_receipt": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("frontend_amendment_receipt"),
    "rootfs_amendment_receipt": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("rootfs_amendment_receipt"),
    "signing_amendment_receipt": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("signing_amendment_receipt"),
    "live_amendment_receipt": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("live_amendment_receipt"),
    "ci_tree_equivalence": json.loads(pathlib.Path(os.environ.get("PLANE_EVIDENCE_STATUS_FILE", ".plane-release/development-evidence-status.json")).read_text()).get("ci_tree_equivalence")},
  "jenkins": {"job": os.environ.get("JOB_NAME", "plane-ce-build"),
    "build_number": os.environ.get("BUILD_NUMBER", ""), "build_url": os.environ.get("BUILD_URL", "")},
}
output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

printf 'Plane daemonless archives prepared (backend/frontend/live); no canonical image was pushed\n'
