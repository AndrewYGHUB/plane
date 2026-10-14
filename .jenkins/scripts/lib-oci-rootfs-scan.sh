#!/usr/bin/env bash
# Fail closed scanner copied from CloudHandStack scripts/lib-oci-rootfs-scan.sh.
# The public fork carries it so the Jenkins release proof is reproducible.

oci_scan_rootfs() {
  _oci_root="$1"
  python3 - "$_oci_root" <<'PY'
import os
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
private_begin = b"-----BEGIN "
private_end = b"PRIVATE KEY-----"

def inspect_content(path):
    previous = b""
    private_begin_seen = False
    private_end_seen = False
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
                private_begin_seen = private_begin_seen or private_begin in data
                private_end_seen = private_end_seen or private_end in data
                if private_begin_seen and private_end_seen:
                    return "private-key"
                previous = data[-128:]
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
