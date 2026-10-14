#!/usr/bin/env python3
"""Static positive and negative controls for the DJS-8 release pipeline."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re


class ContractError(RuntimeError):
    pass


@dataclass(frozen=True)
class Inputs:
    gitignore: str
    api: str
    web: str
    live: str
    pipeline: str
    auth: str
    prestore: str
    build: str
    suite: str
    supply: str
    trust: str
    exact: str


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def validate(inputs: Inputs) -> None:
    for marker in (
        "!.jenkins/scripts/",
        "!.jenkins/scripts/**",
        ".jenkins/scripts/**/__pycache__/",
        ".jenkins/scripts/**/*.py[cod]",
    ):
        require(marker in inputs.gitignore, "Jenkins script visibility/bytecode rule missing: " + marker)
    require(
        inputs.gitignore.index("!.jenkins/scripts/**")
        < inputs.gitignore.index(".jenkins/scripts/**/__pycache__/"),
        "bytecode ignore must follow the Jenkins script unignore rule",
    )
    require("FROM ${API_BASE_IMAGE}" in inputs.api, "API base must be injectable")
    require(
        "FROM ${WEB_NODE_BASE_IMAGE} AS base" in inputs.web
        and "FROM ${WEB_NGINX_BASE_IMAGE} AS production" in inputs.web,
        "web bases must be injectable",
    )
    require("FROM ${LIVE_NODE_BASE_IMAGE} AS base" in inputs.live, "live base must be injectable")
    require("# syntax=" not in inputs.web + inputs.live, "external Dockerfile frontend is forbidden")
    require("docker.io/" not in inputs.api + inputs.web + inputs.live, "Dockerfiles must default to Harbor sentinels")
    require(inputs.api.count("DJS8_BASE_REQUIRED") == 1, "API Harbor base sentinel is required")
    require(inputs.web.count("DJS8_BASE_REQUIRED") == 2, "web Harbor base sentinels are required")
    require(inputs.live.count("DJS8_BASE_REQUIRED") == 1, "live Harbor base sentinel is required")
    for dockerfile in (inputs.api, inputs.web, inputs.live):
        from_lines = [line.strip() for line in dockerfile.splitlines() if line.strip().upper().startswith("FROM ")]
        require(
            from_lines and all("${" in line or re.fullmatch(r"FROM base AS (?:builder|installer|runner)", line) for line in from_lines),
            "every external FROM must use a reviewed build argument",
        )
        require("org.opencontainers.image.revision" in dockerfile, "exact source label is required")

    require("--oci-max-parallelism=1" in inputs.pipeline, "BuildKit must be serial")
    require("--oci-max-parallelism=2" not in inputs.pipeline, "BuildKit parallelism drifted")
    require("persistentVolumeClaim: { claimName: jenkins-cache-buildkit-build }" in inputs.pipeline, "existing BuildKit cache must be reused")
    require("kubectl " not in inputs.pipeline, "build job must not mutate the cluster")
    require(
        're.fullmatch(r"ev-[0-9a-f]{12}", sys.argv[1])' in inputs.pipeline,
        "pipeline must fail fast unless a valid Plane evidence ID is supplied",
    )
    require(
        "development_evidence_reference_status'] == 'plane-readback-verified'"
        in inputs.pipeline,
        "release manifest stage must reject evidence without Plane readback",
    )
    for marker in (
        "stage('Plane development evidence readback')",
        "credentialsId: 'plane-api-token'",
        'request.add_header("X-API-Key", token)',
        'item_code = "DJS-8"',
        'marker = f"〔PLANETEST1 测试证据 · stage=dev · {evidence}〕"',
        'and "④⑤开发中" in (row.get("comment_html") or "")',
        '"status": "plane-readback-verified"',
        '"verified_source_sha": source_sha',
        '"verified_worktree_clean": True',
        '"verified_test_result": "passed"',
        '"verified_exit_code": 0',
        '"<td>结论</td><td>✅ 通过</td>"',
        '"<td>退出码</td><td><code>0</code></td>"',
        'required_test_title = "DJS-8 Plane CE release target contracts"',
        'required_test_command = ".jenkins/scripts/test-djs8-attachment-preview.sh"',
        'required_test_suite = "djs8-plane-release-contracts-v2"',
        'required_test_command_sha256 = hashlib.sha256(required_test_command.encode()).hexdigest()',
        'required_test_entrypoint_sha256 = "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0"',
        'if not source_sha.startswith(evidence_revision):',
        'if any("未提交改动" in (row.get("comment_html") or "") for row in suite_matches):',
        'Path(".plane-release/development-evidence-status.json")',
        "p['release_build_validation']['development_evidence_item'] == 'DJS-8'",
        "p['release_build_validation']['development_evidence_stage'] == 'dev'",
        "p['release_build_validation']['development_evidence_verified_source_sha'] == p['source']['commit']",
        "p['release_build_validation']['development_evidence_verified_worktree_clean'] is True",
        "p['release_build_validation']['development_evidence_verified_test_result'] == 'passed'",
        "p['release_build_validation']['development_evidence_verified_exit_code'] == 0",
        "p['release_build_validation']['development_evidence_verified_test_suite'] == 'djs8-plane-release-contracts-v2'",
        "p['release_build_validation']['development_evidence_verified_test_command_sha256'] == 'c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b'",
        "p['release_build_validation']['development_evidence_verified_test_entrypoint_sha256'] == 'b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0'",
    ):
        require(marker in inputs.pipeline, "Plane evidence readback contract missing: " + marker)
    require(
        inputs.pipeline.index("stage('Validate inputs')")
        < inputs.pipeline.index("stage('Exact public source')"),
        "format validation must fail before checkout/build work",
    )
    require(
        ".jenkins/scripts/build-plane-images.sh --self-test-evidence" in inputs.pipeline,
        "CI contract must execute the stale-source and dirty-tree evidence controls",
    )
    require("full_unit_test_suite_executed'] is False" in inputs.pipeline, "release build must state tests were skipped")
    require(
        hashlib.sha256(inputs.suite.encode()).hexdigest()
        == "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0",
        "controlled DJS-8 test entrypoint content drifted",
    )
    for marker in (
        'urlsplit(url).scheme not in {"postgres", "postgresql"}',
        '("POSTGRES_HOST", "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")',
        "plane/tests/contract/utils/test_attachment_preview_mapping.py",
        "plane/tests/contract/app/test_issue_attachment_preview_app.py",
        "plane/tests/contract/api/test_issue_attachment_preview_api.py",
        "node --test apps/web/core/components/issues/attachment/attachment-preview.test.mjs",
        "pnpm --dir apps/live exec vitest run tests/lib/auth.test.ts",
    ):
        require(marker in inputs.suite, "controlled DJS-8 suite marker missing: " + marker)
    require("jenkins-cache-trivy" in inputs.pipeline, "existing Trivy cache must be reused")
    require(
        inputs.pipeline.count(".jenkins/scripts/verify-exact-source.sh") == 2
        and ".jenkins/scripts/verify-exact-source.sh --self-test" in inputs.pipeline,
        "pipeline must execute exact-source verification and its offline contract test",
    )
    for marker in (
        "upstream_commit='5662b761062b0b2f9d42a6578b55481b5b069792'",
        "upstream_refspec='+refs/tags/v1.4.1:refs/tags/djs8-upstream-v1.4.1'",
        'validate_fetch_contract "${fetch_args[@]}" "$upstream_commit"',
        'git fetch "${fetch_args[@]}"',
        'git merge-base --is-ancestor "$upstream_commit" "$sha"',
        "extra-plus negative control unexpectedly passed",
        "changed-tag negative control unexpectedly passed",
        "changed-refspec negative control unexpectedly passed",
    ):
        require(marker in inputs.exact, "exact-source helper contract marker missing: " + marker)

    require('payload = {"credHelpers": {"harbor.yunxilu.com": "harbor-ci"}}' in inputs.auth, "Docker config must use the helper")
    require("base64" not in inputs.auth, "credential encoding in config is forbidden")
    require('json.dumps({"auths"' not in inputs.auth, "credential auth material in config is forbidden")

    require(
        inputs.prestore.count("mirror_retained ") == 2,
        "exactly two retained components must be mirrored",
    )
    for component in ("admin", "space"):
        require(
            f"mirror_retained {component} artifacts.plane.so/makeplane/plane-{component}:v1.4.1" in inputs.prestore,
            f"retained {component} origin must be explicit",
        )
        require(
            f"harbor.yunxilu.com/cloudhandstack/mirror/plane-{component}" in inputs.prestore,
            f"retained {component} must be pre-stored in Harbor",
        )
    require(
        "2>/dev/null" not in inputs.prestore,
        "Harbor target digest failures must not be discarded",
    )
    require(
        "MANIFEST_UNKNOWN|NAME_UNKNOWN|404[[:space:]]+Not[[:space:]]+Found|NOT_FOUND: artifact .* not found"
        in inputs.prestore,
        "only explicit missing-target responses may authorize a Harbor copy",
    )
    require(
        inputs.prestore.count('target_digest="$(read_target_digest "$target_tag")"') == 2
        and inputs.prestore.count('elif [ "$target_rc" -eq 4 ]') == 2,
        "base and retained mirrors must distinguish missing targets from read failures",
    )
    require(
        "$key Harbor tag could not be read safely before copy" in inputs.prestore
        and "retained $component Harbor tag could not be read safely before copy"
        in inputs.prestore,
        "authorization, throttling, server, and network errors must fail before copy",
    )
    require(
        "$key Harbor tag exists with a different digest" in inputs.prestore
        and "retained $component Harbor tag exists with a different digest"
        in inputs.prestore,
        "existing Harbor tags with another digest must be rejected",
    )
    for marker in (
        "sha256:af87513194f00b2e6f037eb9a65e339ebbb6f7c6430c456049a7f3169412948f",
        "sha256:2c752226d477b4a886378baa95b9af252be59301b725fdb0b7e15208131505a8",
        "sha256:0530961ff0592b58c10f767535cc0abdfccf9e389ff7cc90f87320c1bc7e8506",
        'target_digest="$(read_target_digest "$target_tag")"',
        'origin_digest="$(retry_read "verify reviewed origin $key" crane digest --platform linux/amd64 "$pinned_source")"',
        'actual_digest="$(retry_read "verify retained origin $component" crane digest --platform linux/amd64 "$pinned_source")"',
        "readonly RETRY_ATTEMPTS=3",
        "readonly RETRY_TOTAL_SECONDS=300",
        "readonly RETRY_BACKOFF_SECONDS=10",
        "readonly RETRY_KILL_AFTER_SECONDS=10",
        "deadline=$((SECONDS + RETRY_TOTAL_SECONDS))",
        "attempt_budget=$((remaining - RETRY_KILL_AFTER_SECONDS))",
        'timeout --signal=TERM --kill-after="${RETRY_KILL_AFTER_SECONDS}s" "${attempt_budget}s" "$@"',
        "failed after ${RETRY_ATTEMPTS} attempts within one ${RETRY_TOTAL_SECONDS}s budget",
    ):
        require(marker in inputs.prestore, "Harbor-first pre-store contract missing: " + marker)
    first_target_read = inputs.prestore.index('target_digest="$(read_target_digest "$target_tag")"')
    first_origin_read = inputs.prestore.index(
        'origin_digest="$(retry_read "verify reviewed origin $key" crane digest --platform linux/amd64 "$pinned_source")"'
    )
    require(
        first_target_read < first_origin_read,
        "warm Harbor lookup must happen before any public base-origin read",
    )
    require("timeout 300 " not in inputs.prestore, "each retry must not receive a fresh 300s timeout")
    require("--foreground" not in inputs.prestore, "timeout must retain process-group signalling")

    require(
        all(f"plane-{component}:${{sha}}" in inputs.build for component in ("backend", "frontend", "live")),
        "the three changed images must be self-built",
    )
    require(
        "--local context=apps/api" in inputs.build
        and "--local dockerfile=apps/api" in inputs.build,
        "API build must use the upstream apps/api context",
    )
    require(
        "--local context=." in inputs.build
        and "--opt filename=apps/live/Dockerfile.live" in inputs.build
        and '"build-arg:LIVE_NODE_BASE_IMAGE=' in inputs.build,
        "live build must use the repository root context and injected Harbor base",
    )
    require('"full_unit_test_suite_executed": False' in inputs.build, "release manifest must report skipped unit tests")
    require(
        '[[ "$dev_test_evidence" =~ ^ev-[0-9a-f]{12}$ ]]' in inputs.build
        and '"development_evidence_reference": dev_ref' in inputs.build
        and "evidence_status='caller-format-validated/unverified'" in inputs.build
        and '"status": "plane-readback-verified"' in inputs.build
        and '"verified_source_sha": source_sha' in inputs.build
        and '"verified_worktree_clean": True' in inputs.build
        and '"verified_test_result": "passed"' in inputs.build
        and '"verified_exit_code": 0' in inputs.build
        and '"verified_test_suite": "djs8-plane-release-contracts-v2"' in inputs.build
        and '"verified_test_command_sha256": "c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b"' in inputs.build
        and '"verified_test_entrypoint_sha256": "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0"' in inputs.build
        and '"development_evidence_reference_status": dev_status' in inputs.build,
        "build must bind the exact readback status and never infer validation from format",
    )
    require(
        '"not-provided"' not in inputs.build
        and "elif [ -n \"${PLANE_API_TOKEN:-}\" ]" in inputs.build,
        "missing evidence is forbidden and supplied readback context must fail closed",
    )
    require('set(retained) != {"admin", "space"}' in inputs.build, "retained upstream scope must be admin/space")
    require('crane pull "${tag}@${remote_digest}" "$archive"' in inputs.build, "matching existing tags must be reusable")
    require(
        "trusted_sha='df0c4d475fb1f8d7a270a6909b0f42403d58bdf24840f8c715cda60d9272e43d'" in inputs.build,
        "existing-image reuse must pin the fixed trust-root SHA",
    )
    require(
        'cosign-v2 verify --key "$trusted" --insecure-ignore-tlog=true "$immutable"' in inputs.build,
        "existing-image reuse must verify the fixed-root signature before reuse",
    )
    require(
        'identity.get("docker-reference") != repository' in inputs.build
        and 'image.get("docker-manifest-digest") != digest' in inputs.build,
        "existing signature proof must bind the repository and digest",
    )
    require(
        'verify_archive_labels "$archive"' in inputs.build
        and '"org.opencontainers.image.revision": sha' in inputs.build,
        "reused signed digest must carry the exact source labels",
    )
    require(
        '"signed_source_revision": os.environ["SOURCE_SHA"]' in inputs.build
        and '"signature_verified_with_trust_root_sha256":' in inputs.build,
        "release proof must retain the signed source and fixed-root verification",
    )
    reuse_signature = inputs.build.index('verify_reusable_signature "$tag" "$remote_digest" "$reuse_proof"')
    reuse_pull = inputs.build.index('crane pull "${tag}@${remote_digest}" "$archive"')
    reuse_labels = inputs.build.find('verify_archive_labels "$archive"', reuse_pull)
    require(reuse_labels >= 0, "reused archive labels must be verified")
    reuse_metadata = inputs.build.index('"djs8.archive_origin": "existing-harbor-exact-sha-tag"')
    require(
        reuse_signature < reuse_pull < reuse_labels < reuse_metadata,
        "fixed-root signature and signed source labels must pass before reuse is recorded",
    )
    require(
        '"strict-rebuild-for-unsigned-canonical-recovery"' in inputs.build
        and '[ "$built_digest" = "$remote_digest" ]' in inputs.build,
        "unsigned canonical recovery must strictly rebuild and match the immutable digest",
    )
    recovery_verify = inputs.build.find(
        'if verify_reusable_signature "$tag" "$remote_digest" "$reuse_proof"'
    )
    recovery_build = inputs.build.find(
        '"strict-rebuild-for-unsigned-canonical-recovery"', recovery_verify
    )
    recovery_compare = inputs.build.find(
        '[ "$built_digest" = "$remote_digest" ]', recovery_build
    )
    require(
        min(recovery_verify, recovery_build, recovery_compare) >= 0
        and recovery_verify < recovery_build < recovery_compare,
        "unsigned canonical recovery must rebuild before exact digest comparison",
    )
    require('type=docker,dest=$archive' in inputs.build, "BuildKit must emit a daemonless local archive")
    require("push=true" not in inputs.build, "build stage must not push before security scans")
    require(
        inputs.trust == (
            "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtSkJ+Z3CYDeA34ErWWc9S41GXGin\n"
            "xvEtX69Ajy9ccNMuZ2v0pHg2Q8ptiMymiFdM8aiBhbLkIWSeCS8aFgUUig==\n"
            "-----END PUBLIC KEY-----\n"
        ),
        "fixed trust root content drifted",
    )
    require("df0c4d475fb1f8d7a270a6909b0f42403d58bdf24840f8c715cda60d9272e43d" in inputs.supply,
            "fixed trust-root SHA is required")
    require(
        inputs.supply.count("--db-repository ") == 1
        and inputs.supply.count("--db-repository harbor.yunxilu.com/cloudhandstack/mirror/trivy-db:2") == 1,
        "Trivy vulnerability DB must use the sole pre-stored Harbor source",
    )
    require(
        inputs.supply.count("--java-db-repository ") == 1
        and inputs.supply.count("--java-db-repository harbor.yunxilu.com/cloudhandstack/mirror/trivy-java-db:1") == 1,
        "Trivy Java DB must use the sole pre-stored Harbor source",
    )
    require('cmp -s "$exported_pub" "$trusted"' in inputs.supply,
            "private-key public export must match the fixed trust root")
    require(
        're.fullmatch(r"ev-[0-9a-f]{12}", evidence)' in inputs.supply
        and '!= "plane-readback-verified"' in inputs.supply
        and 'development_evidence_verified_source_sha") != source' in inputs.supply,
        "signing must reject a release manifest without Plane-readback evidence",
    )
    require(
        'development_evidence_verified_worktree_clean") is not True' in inputs.supply,
        "signing must reject development evidence from a dirty worktree",
    )
    require(
        'development_evidence_verified_test_result") != "passed"' in inputs.supply
        and 'development_evidence_verified_exit_code") != 0' in inputs.supply
        and 'development_evidence_verified_test_suite") != "djs8-plane-release-contracts-v2"' in inputs.supply
        and 'development_evidence_verified_test_command_sha256") != "c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b"' in inputs.supply
        and 'development_evidence_verified_test_entrypoint_sha256") != "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0"' in inputs.supply,
        "signing must reject failed or non-zero development evidence",
    )
    require('cosign-v2 verify --key "$trusted"' in inputs.supply,
            "signature verification must use only the fixed root")
    for marker in (
        'trivy image --input "$archive" --scanners secret',
        "--severity CRITICAL --ignore-unfixed",
        'scan_local_archive_rootfs "$archive"',
        "scan_component backend",
        "scan_component frontend",
        "scan_component live",
        "publish_and_sign backend",
    ):
        require(marker in inputs.supply, "security gate/order marker missing: " + marker)
    require(
        max(
            inputs.supply.index("scan_component backend"),
            inputs.supply.index("scan_component frontend"),
            inputs.supply.index("scan_component live"),
        )
        < inputs.supply.index("publish_and_sign backend"),
        "all three local scans must execute before the first canonical publish",
    )
    require(
        'staging="${tag}.djs8-staging"' in inputs.supply,
        "new digests must use a deterministic non-canonical staging tag",
    )
    require(
        'crane push "$archive" "$tag"' not in inputs.supply,
        "an unsigned archive must never be pushed directly to the canonical tag",
    )
    require(
        inputs.supply.count("cosign-v2 sign --yes --signing-config") == 2,
        "only new staging or strict unsigned-canonical recovery may sign",
    )
    for marker in (
        'origin == "existing-harbor-exact-sha-tag"',
        '"signature_verified_with_trust_root_sha256": trusted_sha',
        'mode = "verify-only-fixed-root-reuse"',
        'elif origin in {',
        'mode = "sign-and-verify"',
        'if [ "$signing_mode" = "verify-only-fixed-root-reuse" ]',
        '[ "$remote_rc" -eq 0 ] || die "$component fixed-root reuse lost its canonical tag"',
        'verify_fixed_signature "$immutable" "$output_dir/signature-${component}.json"',
        'elif [ "$remote_rc" -eq 4 ] && [ "$staged_rc" -eq 0 ]',
        '[ "$signature_rc" -eq 4 ]',
        'die "$component existing staging signature could not be read safely"',
    ):
        require(marker in inputs.supply, "fixed-root signature reuse contract missing: " + marker)
    mode_guard = inputs.supply.index('if [ "$signing_mode" = "verify-only-fixed-root-reuse" ]')
    guarded_sign = inputs.supply.index("cosign-v2 sign --yes --signing-config", mode_guard)
    require(mode_guard < guarded_sign, "reused canonical must choose verify-only before signing")
    stage_push = inputs.supply.find('crane push "$archive" "$staging"')
    digest_sign = inputs.supply.find(
        'cosign-v2 sign --yes --signing-config', stage_push
    )
    digest_verify = inputs.supply.find(
        'verify_fixed_signature "$immutable"', digest_sign
    )
    canonical_publish = inputs.supply.find(
        'crane copy "${staging}@${local_digest}" "$tag"', digest_verify
    )
    canonical_check = inputs.supply.find(
        'remote="$(crane digest "$tag")"', canonical_publish
    )
    require(
        min(stage_push, digest_sign, digest_verify, canonical_publish, canonical_check)
        >= 0
        and stage_push
        < digest_sign
        < digest_verify
        < canonical_publish
        < canonical_check,
        "staged digest must be signed and verified before canonical publication",
    )


def expect_failure(inputs: Inputs, field: str, before: str, after: str) -> None:
    mutated = Inputs(**{**inputs.__dict__, field: getattr(inputs, field).replace(before, after, 1)})
    try:
        validate(mutated)
    except ContractError:
        return
    raise SystemExit(f"negative control unexpectedly passed: {field} {before!r}")


def main() -> None:
    inputs = Inputs(
        gitignore=Path(".gitignore").read_text(),
        api=Path("apps/api/Dockerfile.api").read_text(),
        web=Path("apps/web/Dockerfile.web").read_text(),
        live=Path("apps/live/Dockerfile.live").read_text(),
        pipeline=Path(".jenkins/Jenkinsfile.plane-ce").read_text(),
        auth=Path(".jenkins/scripts/prepare-registry-auth.sh").read_text(),
        prestore=Path(".jenkins/scripts/prestore-base-images.sh").read_text(),
        build=Path(".jenkins/scripts/build-plane-images.sh").read_text(),
        suite=Path(".jenkins/scripts/test-djs8-attachment-preview.sh").read_text(),
        supply=Path(".jenkins/scripts/sign-and-sbom.sh").read_text(),
        trust=Path(".jenkins/trust/czs10-controller-cosign-v1.pub").read_text(),
        exact=Path(".jenkins/scripts/verify-exact-source.sh").read_text(),
    )
    validate(inputs)
    expect_failure(inputs, "pipeline", "--oci-max-parallelism=1", "--oci-max-parallelism=2")
    expect_failure(inputs, "api", "FROM ${API_BASE_IMAGE}", "FROM python:3.12-slim-bookworm")
    expect_failure(inputs, "web", "FROM ${WEB_NODE_BASE_IMAGE} AS base", "FROM node:22-alpine AS base")
    expect_failure(inputs, "live", "FROM ${LIVE_NODE_BASE_IMAGE} AS base", "FROM node:22-alpine AS base")
    expect_failure(inputs, "supply", "df0c4d475fb1f8", "0f0c4d475fb1f8")
    expect_failure(
        inputs,
        "supply",
        "--db-repository harbor.yunxilu.com/cloudhandstack/mirror/trivy-db:2",
        "--db-repository ghcr.io/aquasecurity/trivy-db:2",
    )
    expect_failure(inputs, "build", 'crane pull "${tag}@${remote_digest}" "$archive"', "false")
    expect_failure(inputs, "build", "df0c4d475fb1f8", "0f0c4d475fb1f8")
    expect_failure(
        inputs,
        "build",
        'cosign-v2 verify --key "$trusted" --insecure-ignore-tlog=true "$immutable"',
        "false",
    )
    expect_failure(
        inputs,
        "build",
        'verify_archive_labels "$archive"\n      python3 - "$metadata"',
        'false\n      python3 - "$metadata"',
    )
    expect_failure(
        inputs,
        "build",
        '"signed_source_revision": os.environ["SOURCE_SHA"]',
        '"signed_source_revision": "unverified"',
    )
    expect_failure(
        inputs,
        "exact",
        "upstream_refspec='+refs/tags/v1.4.1:refs/tags/djs8-upstream-v1.4.1'",
        "upstream_refspec='+refs/tags/v1.4.2:refs/tags/djs8-upstream-v1.4.1'",
    )
    expect_failure(
        inputs,
        "supply",
        "scan_component live",
        "true",
    )
    expect_failure(
        inputs,
        "supply",
        'staging="${tag}.djs8-staging"',
        'staging="$tag"',
    )
    expect_failure(
        inputs,
        "supply",
        'cosign-v2 sign --yes --signing-config',
        "false #",
    )
    expect_failure(
        inputs,
        "supply",
        'crane copy "${staging}@${local_digest}" "$tag"',
        "false",
    )
    expect_failure(
        inputs,
        "build",
        '[ "$built_digest" = "$remote_digest" ]',
        "false",
    )
    expect_failure(
        inputs,
        "pipeline",
        're.fullmatch(r"ev-[0-9a-f]{12}", sys.argv[1])',
        "True",
    )
    expect_failure(
        inputs,
        "build",
        '[[ "$dev_test_evidence" =~ ^ev-[0-9a-f]{12}$ ]]',
        "true",
    )
    expect_failure(
        inputs,
        "supply",
        're.fullmatch(r"ev-[0-9a-f]{12}", evidence)',
        "True",
    )
    expect_failure(
        inputs,
        "prestore",
        "MANIFEST_UNKNOWN|NAME_UNKNOWN|404[[:space:]]+Not[[:space:]]+Found|NOT_FOUND: artifact .* not found",
        ".*",
    )
    expect_failure(
        inputs,
        "prestore",
        'elif [ "$target_rc" -eq 4 ]',
        "else",
    )
    expect_failure(
        inputs,
        "prestore",
        "$key Harbor tag exists with a different digest",
        "$key Harbor tag already exists",
    )
    expect_failure(
        inputs,
        "pipeline",
        'item_code = "DJS-8"',
        'item_code = "DJS-7"',
    )
    expect_failure(
        inputs,
        "pipeline",
        'if not source_sha.startswith(evidence_revision):',
        'if False:',
    )
    expect_failure(
        inputs,
        "pipeline",
        'if any("未提交改动" in (row.get("comment_html") or "") for row in suite_matches):',
        'if False:',
    )
    expect_failure(
        inputs,
        "pipeline",
        '"<td>结论</td><td>✅ 通过</td>"',
        '"<td>结论</td><td>❌ 失败</td>"',
    )
    expect_failure(
        inputs,
        "pipeline",
        '"<td>退出码</td><td><code>0</code></td>"',
        '"<td>退出码</td><td><code>1</code></td>"',
    )
    expect_failure(
        inputs,
        "pipeline",
        'required_test_title = "DJS-8 Plane CE release target contracts"',
        'required_test_title = "true"',
    )
    expect_failure(
        inputs,
        "pipeline",
        'required_test_command = ".jenkins/scripts/test-djs8-attachment-preview.sh"',
        'required_test_command = "true"',
    )
    expect_failure(
        inputs,
        "build",
        '"verified_source_sha": source_sha',
        '"verified_source_sha": ""',
    )
    expect_failure(
        inputs,
        "supply",
        'development_evidence_verified_source_sha") != source',
        'development_evidence_verified_source_sha") != "anything"',
    )
    expect_failure(
        inputs,
        "supply",
        'development_evidence_verified_worktree_clean") is not True',
        'development_evidence_verified_worktree_clean") is None',
    )
    expect_failure(
        inputs,
        "supply",
        'development_evidence_verified_test_result") != "passed"',
        'development_evidence_verified_test_result") == "passed"',
    )
    expect_failure(
        inputs,
        "supply",
        'development_evidence_verified_exit_code") != 0',
        'development_evidence_verified_exit_code") == 0',
    )
    expect_failure(
        inputs,
        "build",
        '"verified_test_suite": "djs8-plane-release-contracts-v2"',
        '"verified_test_suite": "non-target-suite"',
    )
    expect_failure(
        inputs,
        "supply",
        'development_evidence_verified_test_suite") != "djs8-plane-release-contracts-v2"',
        'development_evidence_verified_test_suite") == "djs8-plane-release-contracts-v2"',
    )
    expect_failure(
        inputs,
        "supply",
        'development_evidence_verified_test_command_sha256") != "c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b"',
        'development_evidence_verified_test_command_sha256") == "c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b"',
    )
    expect_failure(
        inputs,
        "supply",
        'development_evidence_verified_test_entrypoint_sha256") != "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0"',
        'development_evidence_verified_test_entrypoint_sha256") == "b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0"',
    )
    expect_failure(
        inputs,
        "suite",
        "node --test apps/web/core/components/issues/attachment/attachment-preview.test.mjs",
        "true",
    )
    expect_failure(
        inputs,
        "supply",
        'mode = "verify-only-fixed-root-reuse"',
        'mode = "sign-and-verify"',
    )
    expect_failure(
        inputs,
        "prestore",
        "sha256:af87513194f00b2e6f037eb9a65e339ebbb6f7c6430c456049a7f3169412948f",
        "sha256:0f87513194f00b2e6f037eb9a65e339ebbb6f7c6430c456049a7f3169412948f",
    )
    expect_failure(
        inputs,
        "prestore",
        "readonly RETRY_TOTAL_SECONDS=300",
        "readonly RETRY_TOTAL_SECONDS=900",
    )
    expect_failure(
        inputs,
        "prestore",
        '--kill-after="${RETRY_KILL_AFTER_SECONDS}s"',
        "",
    )
    expect_failure(
        inputs,
        "prestore",
        'crane digest --platform linux/amd64 "$pinned_source"',
        'crane digest --platform linux/amd64 "$source"',
    )
    expect_failure(
        inputs,
        "gitignore",
        ".jenkins/scripts/**/__pycache__/",
        "",
    )
    expect_failure(
        inputs,
        "gitignore",
        "!.jenkins/scripts/**",
        "",
    )
    print("Plane CE release CI contract: PASS (positive + 47 negative controls)")


if __name__ == "__main__":
    main()
