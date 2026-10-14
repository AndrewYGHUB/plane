#!/usr/bin/env bash
# Treat an exact tag as absent only when the registry error is bound to the
# same Harbor manifest URL and repository/tag. Harbor uses the repository-level
# NOT_FOUND shape for the first tag in a repository; accepting a generic 404 or
# "not found" would turn proxy/auth failures into an unsafe write decision.
harbor_digest_error_is_exact_not_found() {
  local log="$1" ref="$2" tag_length="${3:-40}" registry_host repo_tag repo_path tag
  local manifest_url artifact repository

  if grep -qiE 'HTTP(/[0-9.]+)?[[:space:]]+((401|403|412|429)([^0-9]|$)|5[0-9][0-9]([^0-9]|$))|(status|response|code)[^0-9]*(401|403|412|429)([^0-9]|$)|TLS handshake timeout|connection reset|connection refused|context deadline|i/o timeout|UNAUTHORIZED|DENIED|PRECONDITION(_FAILED)?|(status|response|code)[^0-9]*5[0-9][0-9]' "$log"; then
    return 1
  fi
  case "$ref" in
    harbor.yunxilu.com/*:*) ;;
    *) return 1 ;;
  esac
  registry_host="${ref%%/*}"
  repo_tag="${ref#*/}"
  repo_path="${repo_tag%:*}"
  tag="${repo_tag##*:}"
  case "$tag" in ''|*[!0-9a-f]*) return 1 ;; esac
  case "$tag_length" in 40|64) ;; *) return 1 ;; esac
  [ "${#tag}" -eq "$tag_length" ] || return 1

  manifest_url="https://${registry_host}/v2/${repo_path}/manifests/${tag}"
  artifact="NOT_FOUND: artifact ${repo_path}:${tag} not found"
  repository="NOT_FOUND: repository ${repo_path} not found"
  awk -v manifest_marker="${manifest_url}:" -v artifact="$artifact" -v repository="$repository" '
    index($0, manifest_marker) &&
      (index($0, "MANIFEST_UNKNOWN") || index($0, "NAME_UNKNOWN") ||
       index($0, artifact) || index($0, repository)) { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$log"
}

