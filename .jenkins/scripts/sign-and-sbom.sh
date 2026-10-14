#!/usr/bin/env bash
# Scan all three local archives, stage each digest, sign and verify it, then add
# the immutable canonical tag. Re-runs safely resume from a matching stage.
set -euo pipefail

die() { printf 'plane supply chain: %s\n' "$*" >&2; exit 2; }
for tool in cmp cosign-v2 crane jq python3 shasum syft tar trivy; do command -v "$tool" >/dev/null || die "$tool is required"; done

output_dir="${1:-.plane-release}"
release="$output_dir/release.json"
key="${ATTEST_COSIGN_KEY:-/var/run/secrets/cloudhandstack/cosign/cosign.key}"
trusted='.jenkins/trust/czs10-controller-cosign-v1.pub'
trusted_sha='df0c4d475fb1f8d7a270a6909b0f42403d58bdf24840f8c715cda60d9272e43d'
[ -s "$release" ] || die 'release.json is missing'
[ -s "$key" ] || die 'mounted signing key is missing'
[ -s "$trusted" ] || die 'fixed trusted public key is missing'
[ -s .jenkins/cosign-signing-config-no-tlog.json ] || die 'offline signing config is missing'
[ "$(shasum -a 256 "$trusted" | awk '{print $1}')" = "$trusted_sha" ] || die 'fixed trusted public key SHA-256 mismatch'
python3 - "$release" <<'PY'
import json, pathlib, re, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
validation = payload.get("release_build_validation") or {}
evidence = validation.get("development_evidence_reference")
if not isinstance(evidence, str) or not re.fullmatch(r"ev-[0-9a-f]{12}", evidence):
    raise SystemExit("release manifest has no valid Plane development evidence ID")
if validation.get("development_evidence_reference_status") != "plane-readback-verified":
    raise SystemExit("release manifest development evidence status is invalid")
source = (payload.get("source") or {}).get("commit")
import runpy
try:
    runpy.run_path(".jenkins/scripts/verify-ci-tree-equivalence.py")["validate_release_binding"](payload)
except Exception:
    raise SystemExit("release manifest scoped evidence/source binding rejected") from None
if validation.get("development_evidence_verified_worktree_clean") is not True:
    raise SystemExit("release manifest development evidence was not produced from a clean worktree")
if validation.get("development_evidence_verified_test_result") != "passed":
    raise SystemExit("release manifest development evidence does not prove a passing test")
if validation.get("development_evidence_verified_exit_code") != 0:
    raise SystemExit("release manifest development evidence does not prove exit code zero")
if validation.get("development_evidence_verified_test_suite") != "djs8-plane-release-contracts-v2":
    raise SystemExit("release manifest development evidence is not the required test suite")
if validation.get("development_evidence_verified_test_command_sha256") != "c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b":
    raise SystemExit("release manifest development evidence command identity is invalid")
if validation.get("development_evidence_verified_test_entrypoint_sha256") != "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0":
    raise SystemExit("release manifest development evidence entrypoint identity is invalid")
PY

export COSIGN_PASSWORD=''
exported_pub="$output_dir/private-key-public-export.pub"
cosign-v2 public-key --key "$key" >"$exported_pub"
[ "$(shasum -a 256 "$exported_pub" | awk '{print $1}')" = "$trusted_sha" ] || die 'signing key does not export the fixed trusted public key'
cmp -s "$exported_pub" "$trusted" || die 'signing key public export differs from fixed trusted public key'
rm -f "$exported_pub"
cp "$trusted" "$output_dir/cosign.pub"

# shellcheck source=.jenkins/scripts/lib-oci-rootfs-scan.sh
source .jenkins/scripts/lib-oci-rootfs-scan.sh
source .jenkins/scripts/lib-harbor-exact-not-found.sh
read_tag_digest() {
  tag="$1"; err="$(mktemp "$output_dir/digest-error.XXXXXX")"
  trap 'rm -f "$err"' RETURN
  if value="$(crane digest "$tag" 2>"$err")"; then printf '%s\n' "$value"; return 0; fi
  if plane_signing_digest_error_is_exact_not_found "$err" "$tag"; then return 4; fi
  return 2
}
verify_fixed_signature() {
  immutable="$1" proof="$2"
  err="$(mktemp "$output_dir/signature-error.XXXXXX")"
  trap 'rm -f "$err"' RETURN
  if cosign-v2 verify --key "$trusted" --insecure-ignore-tlog=true "$immutable" >"$proof" 2>"$err"; then
    return 0
  fi
  rm -f "$proof"
  if grep -qiE 'MANIFEST_UNKNOWN|NAME_UNKNOWN|404[[:space:]]+Not[[:space:]]+Found|no signatures found' "$err"; then
    return 4
  fi
  return 2
}
scan_local_archive_rootfs() (
  archive="$1"
  workspace="$(mktemp -d "$output_dir/rootfs-scan.XXXXXX")" || return 2
  trap 'find "$workspace" -type d -exec chmod u+rwx {} + 2>/dev/null || true; rm -rf -- "$workspace"' EXIT
  mkdir "$workspace/rootfs"
  crane export - "$workspace/rootfs.tar" <"$archive" || return 2
  tar -xf "$workspace/rootfs.tar" -C "$workspace/rootfs" || return 2
  oci_scan_rootfs "$workspace/rootfs"
)

scan_component() {
  component="$1"; archive="$output_dir/${component}.tar"
  [ -s "$archive" ] || die "$component local Docker archive is missing"
  secret_report="$output_dir/trivy-secret-${component}.json"
  vuln_report="$output_dir/trivy-vuln-${component}.json"
  sbom="$output_dir/sbom-${component}.spdx.json"

  set +e
  trivy image --input "$archive" --scanners secret --exit-code 1 --format json \
    --output "$secret_report" --cache-backend memory
  secret_rc=$?
  set -e
  if ! jq -e '.SchemaVersion >= 2 and (.Results | type == "array")' "$secret_report" >/dev/null; then
    rm -f "$secret_report"
    die "$component Trivy secret report is invalid"
  fi
  secret_count="$(jq '[.Results[]?.Secrets[]?] | length' "$secret_report")"
  if [ "$secret_rc" -ne 0 ] || [ "$secret_count" -ne 0 ]; then
    rm -f "$secret_report"
    die "$component Trivy secret policy failed (values and report suppressed)"
  fi

  set +e
  trivy image --input "$archive" --scanners vuln --severity CRITICAL --ignore-unfixed \
    --timeout 30m \
    --db-repository harbor.yunxilu.com/cloudhandstack/mirror/trivy-db:2 \
    --java-db-repository harbor.yunxilu.com/cloudhandstack/mirror/trivy-java-db:1 \
    --exit-code 1 --format json --output "$vuln_report"
  vuln_rc=$?
  set -e
  jq -e '.SchemaVersion >= 2 and (.Results | type == "array")' "$vuln_report" >/dev/null ||
    die "$component Trivy vulnerability report is invalid"
  vuln_count="$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$vuln_report")"
  [ "$vuln_rc" -eq 0 ] && [ "$vuln_count" -eq 0 ] ||
    die "$component fixed CRITICAL vulnerability policy failed"

  scan_local_archive_rootfs "$archive" || {
    rc=$?
    [ "$rc" -eq 1 ] && die "$component rootfs policy hit"
    die "$component rootfs scan did not complete"
  }
  syft scan "docker-archive:$archive" -o "spdx-json=$sbom" >/dev/null
  jq -e '.spdxVersion | startswith("SPDX-")' "$sbom" >/dev/null || die "$component SPDX JSON is invalid"
  shasum -a 256 "$sbom" >"${sbom}.sha256"
  printf '%s scan gates passed before canonical push\n' "$component"
}

# Ordering is a release invariant: all three scans finish before the first push.
scan_component backend
scan_component frontend
scan_component live

publish_and_sign() {
  component="$1"; archive="$output_dir/${component}.tar"
  staged_rc=-1
  fields="$(python3 - "$release" "$component" "$trusted_sha" <<'PY'
import json, pathlib, re, sys
entry = json.loads(pathlib.Path(sys.argv[1]).read_text())["self_built_components"][sys.argv[2]]
trusted_sha = sys.argv[3]
tag = f"{entry['image']}:{entry['tag']}"
digest = entry["digest"]
if not re.fullmatch(r"harbor[.]yunxilu[.]com/cloudhandstack/plane-(?:backend|frontend|live):[0-9a-f]{40}", tag):
    raise SystemExit("invalid canonical tag")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit("invalid expected digest")
origin = entry.get("archive_origin")
if origin == "existing-harbor-exact-sha-tag":
    proof = entry.get("reuse_verification") or {}
    expected = {
        "signature_verified_with_trust_root_sha256": trusted_sha,
        "signed_repository": entry["image"],
        "signed_digest": digest,
        "signed_source_repository": "https://github.com/AndrewYGHUB/plane",
        "signed_source_revision": entry["tag"],
    }
    if any(proof.get(key) != value for key, value in expected.items()):
        raise SystemExit("fixed-root reuse proof is incomplete")
    mode = "verify-only-fixed-root-reuse"
elif origin in {
    "buildkit-local-docker-archive",
    "strict-rebuild-for-unsigned-canonical-recovery",
}:
    mode = "sign-and-verify"
else:
    raise SystemExit("unknown archive origin")
print(tag + "\t" + digest + "\t" + mode)
PY
)"
  IFS=$'\t' read -r tag expected signing_mode <<<"$fields"
  local_digest="$(crane digest --tarball "$archive")"
  [ "$local_digest" = "$expected" ] || die "$component archive digest differs from release manifest"
  set +e
  remote="$(read_tag_digest "$tag")"
  remote_rc=$?
  set -e
  if [ "$remote_rc" -eq 0 ]; then
    [ "$remote" = "$local_digest" ] || die "$component exact-SHA tag exists with another digest"
  elif [ "$remote_rc" -eq 4 ]; then
    staging="${tag}.djs8-staging"
    set +e
    staged_digest="$(read_tag_digest "$staging")"
    staged_rc=$?
    set -e
    if [ "$staged_rc" -eq 0 ]; then
      [ "$staged_digest" = "$local_digest" ] ||
        die "$component staging tag exists with another digest"
    elif [ "$staged_rc" -eq 4 ]; then
      crane push "$archive" "$staging"
      staged_digest="$(crane digest "$staging")"
      [ "$staged_digest" = "$local_digest" ] ||
        die "$component Harbor staging digest differs after push"
    else
      die "$component staging tag could not be read safely before push"
    fi
  else
    die "$component exact-SHA tag could not be read safely before push"
  fi
  immutable="${tag%:*}@${local_digest}"
  if [ "$signing_mode" = "verify-only-fixed-root-reuse" ]; then
    [ "$remote_rc" -eq 0 ] || die "$component fixed-root reuse lost its canonical tag"
    set +e
    verify_fixed_signature "$immutable" "$output_dir/signature-${component}.json"
    signature_rc=$?
    set -e
    [ "$signature_rc" -eq 0 ] || die "$component fixed-root reuse signature no longer verifies"
  elif [ "$remote_rc" -eq 4 ] && [ "$staged_rc" -eq 0 ]; then
    # Resume after an interruption between digest signing and canonical copy.
    # Only an explicit missing-signature result may authorize a new signature;
    # auth, network, registry, or wrong-root failures stop rather than duplicate.
    set +e
    verify_fixed_signature "$immutable" "$output_dir/signature-${component}.json"
    signature_rc=$?
    set -e
    if [ "$signature_rc" -eq 4 ]; then
      cosign-v2 sign --yes --signing-config .jenkins/cosign-signing-config-no-tlog.json --key "$key" "$immutable"
    elif [ "$signature_rc" -ne 0 ]; then
      die "$component existing staging signature could not be read safely"
    fi
  else
    cosign-v2 sign --yes --signing-config .jenkins/cosign-signing-config-no-tlog.json --key "$key" "$immutable"
  fi
  verify_fixed_signature "$immutable" "$output_dir/signature-${component}.json" ||
    die "$component fixed-root signature verification failed"
  if [ "$remote_rc" -eq 4 ]; then
    # Harbor cannot atomically create an image tag and its separate cosign
    # artifact. Keeping the deterministic staging tag makes interruption safe:
    # before this point no canonical tag exists; after this point its digest has
    # already passed scans and fixed-root signature verification. The staging
    # tag is intentionally retained because deleting a shared manifest by tag
    # has registry-specific semantics and could endanger the canonical digest.
    if ! crane copy "${staging}@${local_digest}" "$tag"; then
      set +e
      raced_digest="$(read_tag_digest "$tag")"
      raced_rc=$?
      set -e
      [ "$raced_rc" -eq 0 ] && [ "$raced_digest" = "$local_digest" ] ||
        die "$component canonical publish failed"
    fi
    remote="$(crane digest "$tag")"
    [ "$remote" = "$local_digest" ] ||
      die "$component canonical digest differs after signed publish"
  fi
  verify_fixed_signature "$immutable" "$output_dir/signature-${component}.json" ||
    die "$component final fixed-root signature verification failed"
}

publish_and_sign backend
publish_and_sign frontend
publish_and_sign live

python3 - "$release" "$output_dir" "$trusted_sha" <<'PY'
import hashlib, json, pathlib, sys
release, root = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
payload = json.loads(release.read_text())
payload["trust_root"] = {
    "artifact": "cosign.pub",
    "sha256": sys.argv[3],
    "verification_policy": "fixed-root-only",
    "signing_private_key_public_export_match": True,
}
for component in ("backend", "frontend", "live"):
    sbom = root / f"sbom-{component}.spdx.json"
    verification = root / f"signature-{component}.json"
    if not verification.stat().st_size: raise SystemExit("empty signature verification")
    payload["self_built_components"][component]["supply_chain"] = {
        "prepush_secret_findings": 0,
        "prepush_fixed_critical_findings": 0,
        "prepush_rootfs_policy_findings": 0,
        "signature_verified": True,
        "signature_verified_with_trust_root_sha256": sys.argv[3],
        "verification_artifact": verification.name,
        "sbom_format": "SPDX-JSON",
        "sbom_artifact": sbom.name,
        "sbom_sha256": hashlib.sha256(sbom.read_bytes()).hexdigest(),
    }
release.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

rm -f "$output_dir/backend.tar" "$output_dir/frontend.tar" "$output_dir/live.tar"
printf 'Plane supply-chain proof complete: three images scanned before push and verified by fixed root\n'
