#!/usr/bin/env bash
# Fail closed scanner copied from CloudHandStack scripts/lib-oci-rootfs-scan.sh.
# The public fork carries it so the Jenkins release proof is reproducible.

oci_scan_rootfs() {
  _oci_root="$1"
  python3 - "$_oci_root" <<'PY'
import os
import re
import sys

root = os.path.realpath(sys.argv[1])
if not os.path.isdir(root):
    print("OCI rootfs does not exist", file=sys.stderr)
    raise SystemExit(2)
control = os.path.join(root, "etc", "passwd")
try:
    with open(control, "rb") as fh:
        if b"root" not in fh.read():
            raise ValueError("control miss")
except Exception:
    print("OCI scan control failed", file=sys.stderr)
    raise SystemExit(2)

credential_names = {".env", "id_rsa", "id_ed25519", ".netrc", "credentials.json"}
file_hits = []
content_kind = ""
scan_roots = {"etc", "app", "root", "home", "srv", "opt"}
needles = (b"cpa_", b"sk-local")
basic_auth = b"BASIC_AUTH_PASS="
# Delimiters are also present in parsers and documentation. Require adjacent
# key material, not two unrelated strings somewhere in the same file. Matching
# material is rejected even when its closing delimiter/base64 is malformed or
# truncated. Do not require DER: OpenSSH and traditional encrypted PEM differ.
private_header = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[ \t]*\n")

def normalize_newlines(data):
    return data.replace(b"\\r\\n", b"\n").replace(b"\\n", b"\n").replace(b"\r\n", b"\n").replace(b"\r", b"\n")

def inspect_private(window):
    # Return pending bytes only while a header is followed by plausible material
    # or encrypted-PEM metadata. Bound that state; excessive pending input fails
    # closed instead of dropping the header at a chunk boundary.
    window = normalize_newlines(window)
    while True:
        match = private_header.search(window)
        if not match:
            return False, b""
        candidate = window[match.end():]
        material = 0
        pending = True
        for line in candidate.split(b"\n"):
            line = line.strip()
            if not line or line.startswith((b"Proc-Type:", b"DEK-Info:")):
                continue
            line = b"".join(line.split())
            part = re.match(rb"[A-Za-z0-9+/=]+", line)
            if part:
                material += len(part.group())
                if material >= 16:
                    return True, b""
                if part.end() == len(line):
                    continue
            # Placeholder/implementation text is not key material. A later
            # independent header in this same window still must be examined.
            pending = False
            break
        if pending:
            saved = window[match.start():]
            if len(saved) > 65536:
                return True, b""
            return False, saved
        window = window[match.end():]

def inspect_content(path):
    previous = b""
    private_pending = b""
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    return ""
                data = previous + chunk
                if any(item in data for item in needles):
                    return "known-secret-prefix"
                pos = data.find(basic_auth)
                value_pos = pos + len(basic_auth)
                if pos >= 0 and len(data) > value_pos and data[value_pos:value_pos + 1] not in (b"\n", b"\r"):
                    return "known-secret-prefix"
                found, private_pending = inspect_private(private_pending + chunk if private_pending else data)
                if found:
                    return "private-key"
                previous = data[-4096:]
    except OSError as exc:
        raise RuntimeError("unreadable") from exc

def walk_error(_exc):
    raise RuntimeError("unreadable-tree")

try:
    for base, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(base, name))]
        for name in files:
            if name in credential_names or name.startswith(".env.") or name.endswith(".kubeconfig"):
                file_hits.append(os.path.relpath(os.path.join(base, name), root))

    for base, dirs, files in os.walk(root, onerror=walk_error):
        rel = os.path.relpath(base, root)
        top = rel.split(os.sep, 1)[0]
        if rel == ".":
            dirs[:] = [name for name in dirs if name in scan_roots or name == "usr"]
        elif rel == os.path.join("usr", "share", "nginx") or rel.startswith(os.path.join("usr", "share", "nginx") + os.sep):
            pass
        elif rel == os.path.join("usr", "share"):
            dirs[:] = [name for name in dirs if name == "nginx"]
        elif top == "usr" and not rel.startswith(os.path.join("usr", "share", "nginx")):
            dirs[:] = [name for name in dirs if rel == "usr" and name == "share"]
            if rel != "usr":
                dirs[:] = []
        elif top not in scan_roots and rel != ".":
            dirs[:] = []
        for name in files:
            path = os.path.join(base, name)
            if content_kind or os.path.islink(path) or not os.path.isfile(path):
                continue
            try:
                found = inspect_content(path)
            except RuntimeError:
                print("OCI rootfs contains an unreadable scan target", file=sys.stderr)
                raise SystemExit(2)
            if found == "private-key" and ("/certs/" in path or "/ssl/" in path):
                found = ""
            if found:
                content_kind = found
except RuntimeError:
    print("OCI rootfs tree could not be scanned completely", file=sys.stderr)
    raise SystemExit(2)

if file_hits:
    print("OCI rootfs contains credential-shaped file names", file=sys.stderr)
if content_kind:
    print("OCI rootfs content matched a sensitive pattern (value suppressed)", file=sys.stderr)
if file_hits or content_kind:
    raise SystemExit(1)
PY
}
