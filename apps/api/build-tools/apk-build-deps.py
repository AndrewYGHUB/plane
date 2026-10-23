#!/usr/bin/env python3
"""DJS-8 single-RUN dependency preparation. No CLI command or URL input.

All children use bounded RAM pipes, including pip and apk hooks. Unknown errors
fail closed; stage attribution does not claim a physical cause for build #8.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

DEPS = ('bash~=5.2', 'g++', 'gcc', 'cargo', 'git', 'make', 'postgresql-dev', 'libc-dev', 'linux-headers')
STREAM_LIMIT = 4 * 1024**2
TOTAL_LIMIT = 16 * 1024**2
INDEX_LIMIT = 128 * 1024**2
TOKEN = r'[A-Za-z0-9][A-Za-z0-9+_.~-]{0,159}'
VIRTUAL_NAME = r'\.[A-Za-z0-9][A-Za-z0-9+_.~-]{0,158}'
ACTION = re.compile(r'\((\d+)/(\d+)\) (Installing|Purging|Upgrading|Downgrading|Replacing|Reinstalling|Updating pinning) (\.build-deps|' + TOKEN + r') \((' + TOKEN + r')(?: -> (' + TOKEN + r'))?\)')
STAGES = {'acquire', 'integrity', 'offline_solve', 'install', 'pip', 'delete', 'cleanup'}
CODES = {'ok', 'acquire_unknown', 'integrity_unknown', 'offline_solve_unknown', 'install_unknown', 'pip_unknown', 'delete_unknown', 'cleanup_unknown', 'timeout', 'output_limit', 'diagnostic_failure', 'state_drift', 'plan_mismatch', 'capacity', 'format'}


class Rejected(Exception):
    def __init__(self, code='diagnostic_failure', rc=None):
        self.code = code if code in CODES else 'diagnostic_failure'
        self.rc = rc if type(rc) is int else None


def need(value, code='diagnostic_failure'):
    if not value:
        raise Rejected(code)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def regular(path, limit):
    """No-follow, bounded read; never return filesystem exception text."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_size <= limit)
        with os.fdopen(fd, 'rb', closefd=False) as f:
            data = f.read(limit + 1)
        need(len(data) <= limit)
        return data
    finally:
        os.close(fd)


class LimitedReader:
    def __init__(self, reader, limit, check):
        self.reader, self.remaining, self.check = reader, limit, check

    def read(self, size=-1):
        self.check()
        size = min(65536 if size < 0 else size, self.remaining + 1)
        data = self.reader.read(size)
        self.remaining -= len(data)
        need(self.remaining >= 0, 'capacity')
        return data


class Receiver:
    def __init__(self, total_limit=TOTAL_LIMIT, stream_limit=STREAM_LIMIT):
        self.total = 0
        self.total_limit, self.stream_limit = total_limit, stream_limit
        self.end = time.monotonic() + 3000

    def run(self, command, deadline):
        # Linux CI adopts orphaned/detached grandchildren so cleanup can reap
        # them as well. Local macOS controls exercise process-group boundaries.
        if sys.platform == 'linux':
            import ctypes
            # This receiver owns a serial helper process. Never adopt/kill a
            # caller's already-running child as if it belonged to this command.
            need(not self.children())
            need(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0)
        p = None
        sel = selectors.DefaultSelector()
        buffers = [bytearray(), bytearray()]
        try:
            need(time.monotonic() < min(deadline, self.end), 'timeout')
            p = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True, close_fds=True,
                                 env={**os.environ, 'LC_ALL': 'C', 'NO_COLOR': '1'})
            for i, stream in enumerate((p.stdout, p.stderr)):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, i)
            while sel.get_map() or p.poll() is None:
                need(time.monotonic() < min(deadline, self.end), 'timeout')
                for key, _ in sel.select(0.05):
                    data = self.read_chunk(key.fd)
                    if not data:
                        sel.unregister(key.fileobj)
                        continue
                    self.total += len(data)
                    need(self.total <= self.total_limit and len(buffers[key.data]) + len(data) <= self.stream_limit, 'output_limit')
                    buffers[key.data].extend(data)
            rc = p.wait(timeout=1)
            return rc, bytes(buffers[0]), bytes(buffers[1])
        except Rejected:
            raise
        except BaseException:
            raise Rejected() from None
        finally:
            try:
                # Kill remaining descendants even if their parent returned success.
                if p is not None:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        p.wait(timeout=2)
                    except Exception:
                        raise Rejected() from None
                    if sys.platform == 'linux':
                        end = time.monotonic() + 2
                        while True:
                            children = self.children()
                            if not children:
                                break
                            need(time.monotonic() < end)
                            for child in children:
                                need(child.isdigit())
                                try:
                                    os.kill(int(child), signal.SIGKILL)
                                    os.waitpid(int(child), os.WNOHANG)
                                except ProcessLookupError:
                                    pass
                            time.sleep(0.01)
            finally:
                # Reaping errors must not bypass FD closure or RAM disposal.
                if p is not None:
                    for stream in (p.stdout, p.stderr):
                        if stream:
                            stream.close()
                sel.close()
                for buffer in buffers:
                    buffer.clear()

    @staticmethod
    def read_chunk(fd):
        return os.read(fd, 65536)

    @staticmethod
    def children():
        # Bounded procfs read; IDs stay internal and are never log payloads.
        children = regular('/proc/self/task/' + str(os.getpid()) + '/children', 65536).split()
        need(all(child.isdigit() for child in children))
        return children


def records(data, installed=False):
    """Only package identity and signed size metadata; no arbitrary fields emitted."""
    need(len(data) <= INDEX_LIMIT, 'format')
    result = {}
    for block in data.decode('utf-8').strip().split('\n\n'):
        if not block.strip():
            continue
        fields = {}
        for line in block.splitlines():
            if line[:2] in ('P:', 'V:', 'A:', 'S:', 'I:'):
                key, value = line.split(':', 1)
                need(key not in fields, 'format')
                fields[key] = value
        need(all(k in fields for k in ('P', 'V', 'A')), 'format')
        name, version, arch = (fields[k] for k in ('P', 'V', 'A'))
        # apk --virtual accepts dot-prefixed package identities.  They may
        # occur in a base image's installed database (for example
        # .python-rundeps), but only .build-deps has plan semantics below.
        need(re.fullmatch(r'(?:' + TOKEN + '|' + VIRTUAL_NAME + r')', name) and re.fullmatch(TOKEN, version) and arch in ('x86_64', 'noarch'), 'format')
        key = (name, version, arch)
        if installed:
            value = None
        else:
            need(all(re.fullmatch(r'[0-9]{1,12}', fields.get(k, '')) for k in ('S', 'I')), 'format')
            value = (int(fields['S']), int(fields['I']))
        need(key not in result or result[key] == value, 'format')
        result[key] = value
    need(result, 'format')
    return result


def parse_plan(stdout, stderr, available, installed):
    need(not stderr, 'format')
    actions, numbers, summary = [], [], False
    for line in stdout.decode('ascii').splitlines():
        match = ACTION.fullmatch(line)
        if match:
            need(not summary, 'format')
            n, total, action, name, old, new = match.groups()
            need((action in ('Upgrading', 'Downgrading', 'Replacing')) == (new is not None), 'format')
            version = new or old
            if name == '.build-deps':
                need(action in ('Installing', 'Purging'), 'format')
                arch, version, old = 'noarch', '<virtual>', '<virtual>'
            else:
                options = {key[2] for key in (installed if action == 'Purging' else available) if key[:2] == (name, version)}
                need(len(options) == 1, 'format')
                arch = options.pop()
                if action != 'Installing':
                    need((name, old, arch) in installed, 'plan_mismatch')
            actions.append((action, name, arch, old, version))
            numbers.append((int(n), int(total)))
        else:
            need(not summary and re.fullmatch(r'OK: [0-9]+ MiB in [0-9]+ packages', line), 'format')
            summary = True
    need(summary and actions, 'format')
    need(numbers == [(i + 1, len(actions)) for i in range(len(actions))], 'format')
    need(len({row[1] for row in actions}) == len(actions), 'format')
    return actions


def expected_packages(before, plan):
    result = {(n, '<virtual>' if n == '.build-deps' else v, a) for n, v, a in before}
    for action, name, arch, old, new in plan:
        previous = (name, old, arch)
        if action != 'Installing':
            need(previous in result, 'plan_mismatch')
            result.remove(previous)
        else:
            need(not any(k[0] == name for k in result), 'plan_mismatch')
        if action != 'Purging':
            result.add((name, new, arch))
    return result


def capacity(metadata, package_keys):
    """Unreviewed candidate formula: compressed + 2*installed + 25% + 64MiB.

Expansion cap accounts for tar headers/padding, not only installed payload.
Final review must approve this formula before any real package execution.
"""
    need(package_keys and package_keys <= metadata.keys(), 'capacity')
    compressed = sum(metadata[k][0] for k in package_keys)
    installed = sum(metadata[k][1] for k in package_keys)
    need(compressed > 0 and installed > 0, 'capacity')
    expansion = 2 * installed + 64 * 1024**2
    required = (5 * (compressed + 2 * installed) + 3) // 4 + 64 * 1024**2
    return compressed, expansion, required


class Build:
    def __init__(self):
        self.receiver = Receiver()
        self.started = time.monotonic()
        self.diagnostic_end = self.started + 900
        self.stage = 'acquire'
        self.operation = 0
        self.cache = None
        self.cache_identity = None
        self.index_hash = None
        self.root_cache = None
        self.helper_identity = None
        self.control_snapshot = None
        self.control_packages = None

    def deadline(self):
        if self.stage in ('pip', 'delete', 'cleanup'):
            return self.phase_end
        return min(self.diagnostic_end, self.phase_end)

    def check_time(self):
        need(time.monotonic() < min(self.deadline(), self.receiver.end), 'timeout')

    def phase(self, stage, seconds=180):
        need(stage in STAGES)
        self.stage = stage
        self.phase_end = time.monotonic() + seconds

    def emit(self, code, rc=None, **fields):
        need(code in CODES and self.stage in STAGES)
        # Call sites pass only counts/hash, never arbitrary stdout or exceptions.
        print(json.dumps({'stage': self.stage, 'operation': self.operation, 'code': code,
                          'rc': rc, 'elapsed_ms': int((time.monotonic() - self.started) * 1000), **fields}, sort_keys=True), flush=True)

    def call(self, command):
        self.operation += 1
        rc, out, err = self.receiver.run(command, self.deadline())
        self.emit('ok' if rc == 0 else self.stage + '_unknown', rc,
                  stdout_bytes=len(out), stderr_bytes=len(err), stdout_sha256=digest(out), stderr_sha256=digest(err))
        if rc != 0:
            raise Rejected(self.stage + '_unknown', rc)
        return out, err

    def apk(self, *args):
        return ['/sbin/apk', '--no-progress', '--cache-dir', str(self.cache), '--cache-max-age', '60', *args]

    def snapshot(self):
        world = regular('/etc/apk/world', 1024**2)
        installed = regular('/lib/apk/db/installed', INDEX_LIMIT)
        return world, installed

    def unchanged(self, baseline):
        need(self.snapshot() == baseline, 'state_drift')
        if self.control_snapshot is not None:
            need(self.read_control()[0] == self.control_snapshot, 'state_drift')
        if self.index_hash:
            need(self.indices(False) == self.index_hash, 'state_drift')

    def read_control(self):
        # apk atomically replaces this one control file on update/add/del.
        entries = self.cache_entries()
        need('installed' in entries, 'state_drift')
        identity = entries['installed']
        need(identity[2] <= INDEX_LIMIT, 'capacity')
        fd = os.open(self.cache / 'installed', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'state_drift')
            need((before.st_dev, before.st_ino, before.st_size) == identity, 'state_drift')
            with os.fdopen(fd, 'rb', closefd=False) as f:
                data = f.read(INDEX_LIMIT + 1)
            after = os.fstat(fd)
            need(len(data) == before.st_size and len(data) <= INDEX_LIMIT, 'capacity')
            need((before.st_mtime_ns, before.st_ctime_ns, before.st_size) ==
                 (after.st_mtime_ns, after.st_ctime_ns, after.st_size), 'state_drift')
            need(self.cache_entries()['installed'] == identity, 'state_drift')
            return (*identity, digest(data)), data
        finally:
            os.close(fd)

    @staticmethod
    def index_headers(data, database=False):
        # apk_pkg_write_index_header fields. DB filesystem records are excluded.
        allowed = set('CPVASITULomtckDpi')
        result = {}
        need(len(data) <= INDEX_LIMIT, 'capacity')
        for block in data.decode('utf-8').strip().split('\n\n'):
            if not block:
                continue
            fields = {}
            in_files = False
            for line in block.splitlines():
                need(len(line) >= 2 and line[1] == ':', 'format')
                key = line[0]
                if database and key not in allowed:
                    in_files = True
                    continue
                need(not in_files and key in allowed and key not in fields, 'format')
                fields[key] = line[2:]
            need(set('CPVASITUL') <= fields.keys(), 'format')
            identity = next(iter(records(block.encode(), True)))
            need(identity not in result, 'format')
            need(all(re.fullmatch(r'[0-9]{1,12}', fields[k]) for k in ('S', 'I')), 'format')
            result[identity] = fields
        return result

    def bind_control(self, metadata, db):
        snapshot, data = self.read_control()
        cached = self.index_headers(data)
        installed = self.index_headers(db, database=True)
        nonrepo = {k for k in installed if k not in metadata}
        need(cached.keys() <= nonrepo, 'state_drift')
        need(all(fields == installed[k] for k, fields in cached.items()), 'state_drift')
        zero_size = {k for k in nonrepo if installed[k]['I'] == '0'}
        if self.control_packages is None:
            # Initial positive-size cached entries must already be installed and
            # absent from signed repositories; only those may survive add/del.
            need(zero_size <= cached.keys(), 'state_drift')
        else:
            need(cached.keys() == ((self.control_packages & nonrepo) | zero_size), 'state_drift')
        self.control_packages = set(cached)
        self.control_snapshot = snapshot

    def cache_entries(self):
        s = self.cache.lstat()
        need(stat.S_ISDIR(s.st_mode) and (s.st_dev, s.st_ino) == self.cache_identity)
        rows = {}
        for path in self.cache.iterdir():
            s = path.lstat()
            need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1)
            rows[path.name] = (s.st_dev, s.st_ino, s.st_size)
        return rows

    def indices(self, parse=True):
        hashes, metadata = {}, {}
        for name in self.cache_entries():
            if not re.fullmatch(r'APKINDEX\.[0-9a-f]{8}\.tar\.gz', name):
                continue
            data = regular(self.cache / name, INDEX_LIMIT)
            hashes[name] = digest(data)
            if parse:
                # APK index signature and index tar members are concatenated gzip.
                import io
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                    with tarfile.open(fileobj=LimitedReader(gz, INDEX_LIMIT, self.check_time), mode='r|', ignore_zeros=True) as archive:
                        found = 0
                        for item in archive:
                            self.check_time()
                            need(item.size <= INDEX_LIMIT, 'format')
                            if item.name == 'APKINDEX':
                                need(item.isfile(), 'format')
                                found += 1
                                incoming = records(archive.extractfile(item).read(INDEX_LIMIT + 1))
                                for k, v in incoming.items():
                                    need(k not in metadata or metadata[k] == v, 'format')
                                    metadata[k] = v
                        need(found == 1, 'format')
        need(hashes, 'format')
        return (hashes, metadata) if parse else hashes

    def solve(self, metadata, packages, delete=False, offline=False):
        args = ['--simulate'] + (['--no-network'] if offline else [])
        args += ['del', '.build-deps'] if delete else ['add', '--virtual', '.build-deps', *DEPS]
        out, err = self.call(self.apk(*args))
        return parse_plan(out, err, metadata, packages)

    def integrity(self, metadata, selected):
        compressed_cap, expansion_cap, _ = capacity(metadata, selected)
        compressed = expanded = count = 0
        manifest = []
        identities = set()
        for name, identity in sorted(self.cache_entries().items()):
            self.check_time()
            if re.fullmatch(r'APKINDEX\.[0-9a-f]{8}\.tar\.gz', name):
                continue
            if name == 'installed':
                need(self.control_snapshot is not None and self.read_control()[0] == self.control_snapshot, 'state_drift')
                continue
            # apk cache filenames bind public name/version and checksum suffix.
            matches = [k for k in selected if re.fullmatch(re.escape(k[0] + '-' + k[1]) + r'\.[0-9a-f]{8}\.apk', name)]
            need(len(matches) == 1, 'format')
            key = matches[0]
            need(key not in identities and identity[2] == metadata[key][0], 'integrity_unknown')
            identities.add(key)
            compressed += identity[2]
            need(compressed <= compressed_cap, 'capacity')
            fd = os.open(self.cache / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                s = os.fstat(fd)
                need(stat.S_ISREG(s.st_mode) and (s.st_dev, s.st_ino, s.st_size) == identity)
                h = hashlib.sha256()
                with os.fdopen(fd, 'rb', closefd=False) as raw:
                    while chunk := raw.read(65536):
                        self.check_time()
                        h.update(chunk)
                    raw.seek(0)
                    with gzip.GzipFile(fileobj=raw) as gz:
                        while chunk := gz.read(65536):
                            self.check_time()
                            expanded += len(chunk)
                            need(expanded <= expansion_cap, 'capacity')
                manifest.append({'package': key, 'bytes': identity[2], 'sha256': h.hexdigest()})
                count += 1
            finally:
                os.close(fd)
        need(count > 0 and any(k[0] == 'llvm18' for k in identities), 'integrity_unknown')
        self.emit('ok', 0, packages=count, compressed_bytes=compressed, expanded_bytes=expanded, manifest_sha256=canonical(manifest), manifest=manifest)
        return identities

    def verify_result(self, before, plan, expected_world):
        world, db = self.snapshot()
        after = records(db, True)
        actual = {(n, '<virtual>' if n == '.build-deps' else v, a) for n, v, a in after}
        need(actual == expected_packages(before, plan), 'plan_mismatch')
        virtual = [k for k in after if k[0] == '.build-deps']
        if '.build-deps' in expected_world:
            need(len(virtual) == 1, 'state_drift')
            expected_world = [('.build-deps=' + virtual[0][1]) if w == '.build-deps' else w for w in expected_world]
        need(sorted(world.decode().splitlines()) == sorted(expected_world), 'state_drift')
        need(self.indices(False) == self.index_hash, 'state_drift')
        self.emit('ok', 0, world_sha256=digest(world), installed_sha256=digest(db), plan_sha256=canonical(plan))
        return after

    def snapshot_root_cache(self):
        path = Path('/var/cache/apk')
        s = path.lstat()
        need(stat.S_ISDIR(s.st_mode) and path.resolve() == path)
        need(s.st_dev == Path('/code').stat().st_dev)
        # Original rm target, limited to flat files in this build rootfs.
        result = {}
        for entry in path.iterdir():
            self.check_time()
            t = entry.lstat()
            need(stat.S_ISREG(t.st_mode) and t.st_nlink == 1)
            result[entry.name] = (t.st_dev, t.st_ino, t.st_size, digest(regular(entry, INDEX_LIMIT)))
        return (s.st_dev, s.st_ino), result

    def cleanup(self):
        # Only our private, inode-checked flat directory; never shared caches.
        self.remove_flat(self.cache, self.cache_identity, self.cache_entries())
        need(not self.cache_entries())
        self.cache.rmdir()
        need(self.snapshot_root_cache() == self.root_cache, 'state_drift')
        self.remove_flat(Path('/var/cache/apk'), self.root_cache[0],
                         {name: row[:3] for name, row in self.root_cache[1].items()})
        # Helper is copied into this build rootfs only, never a shared mount.
        script = Path('/code/.apk-build-deps.py')
        s = script.lstat()
        need(script.resolve() == script and stat.S_ISREG(s.st_mode) and s.st_nlink == 1)
        need((s.st_dev, s.st_ino, s.st_size) == self.helper_identity)
        script.unlink()

    def remove_flat(self, directory, identity, entries):
        # Resolve the directory once without following a replacement symlink.
        # Every unlink stays relative to that FD, never a global wildcard.
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            s = os.fstat(fd)
            need((s.st_dev, s.st_ino) == identity, 'state_drift')
            need(set(os.listdir(fd)) == set(entries), 'state_drift')
            for name, expected in entries.items():
                self.check_time()
                s = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'state_drift')
                need((s.st_dev, s.st_ino, s.st_size) == expected, 'state_drift')
                os.unlink(name, dir_fd=fd)
        finally:
            os.close(fd)

    def execute(self):
        self.phase('acquire')
        need(len(sys.argv) == 1 and sys.platform == 'linux')
        out, err = self.call(['/sbin/apk', '--version'])
        need(out.strip() == b'apk-tools 2.14.12, compiled for x86_64.' and not err, 'format')
        self.cache = Path(tempfile.mkdtemp(prefix='.djs8-apk-', dir='/code'))
        s = self.cache.lstat()
        self.cache_identity = (s.st_dev, s.st_ino)
        # Reject memory-backed cache; no new mount/volume is created here.
        mounts = regular('/proc/self/mounts', 1024**2).decode().splitlines()
        candidates = [(len(row[1]), row[2]) for line in mounts if len(row := line.split()) >= 3 and (str(self.cache) + '/').startswith(row[1].rstrip('/') + '/')]
        need(candidates and max(candidates)[1] not in ('tmpfs', 'ramfs'))
        def mount_for(path):
            rows = [line.split() for line in mounts]
            matches = [row for row in rows if len(row) >= 3 and (path + '/').startswith(row[1].rstrip('/') + '/')]
            need(matches)
            return max(matches, key=lambda row: len(row[1]))[:3]
        need(mount_for('/var/cache/apk') == mount_for('/code'), 'state_drift')
        self.root_cache = self.snapshot_root_cache()
        script = Path('/code/.apk-build-deps.py')
        s = script.lstat()
        need(script.resolve() == script and stat.S_ISREG(s.st_mode) and s.st_nlink == 1)
        need(s.st_dev == self.cache_identity[0])
        self.helper_identity = (s.st_dev, s.st_ino, s.st_size)
        baseline = self.snapshot()
        initial = records(baseline[1], True)
        need(not any(k[0] == '.build-deps' for k in initial), 'state_drift')
        self.prepare_dependencies(initial, baseline)

    def prepare_dependencies(self, initial, baseline):
        self.call(self.apk('update'))
        self.unchanged(baseline)
        self.index_hash, metadata = self.indices()
        self.bind_control(metadata, baseline[1])
        normal = self.solve(metadata, initial)
        self.unchanged(baseline)
        # cache download may include existing world packages. Bound using the
        # union of current installed identities and selected install identities.
        selected = {k for k in initial if k in metadata}
        selected |= {(n, v, a) for op, n, a, old, v in normal if n != '.build-deps' and op != 'Purging'}
        _, _, required = capacity(metadata, selected)
        fs = os.statvfs(self.cache)
        need(fs.f_bavail * fs.f_frsize >= required, 'capacity')
        self.emit('ok', 0, required_bytes=required, plan_sha256=canonical(normal))
        self.call(self.apk('cache', '--add-dependencies', 'download', *DEPS))
        self.unchanged(baseline)
        self.phase('integrity')
        cached = self.integrity(metadata, selected)
        required_packages = {(n, v, a) for op, n, a, old, v in normal if n != '.build-deps' and op != 'Purging'}
        need(required_packages <= cached, 'integrity_unknown')
        self.unchanged(baseline)
        self.phase('offline_solve')
        offline = self.solve(metadata, initial, offline=True)
        need(normal == offline, 'plan_mismatch')
        self.unchanged(baseline)
        self.install_sequence(metadata, initial, normal, baseline)

    def install_sequence(self, metadata, initial, normal, baseline):
        self.phase('install')
        self.call(self.apk('--no-network', 'add', '--virtual', '.build-deps', *DEPS))
        installed = self.verify_result(initial, normal, baseline[0].decode().splitlines() + ['.build-deps'])
        self.bind_control(metadata, self.snapshot()[1])
        self.phase('pip', 1800)
        pre_pip = self.snapshot()
        self.call(['pip', 'install', '-r', 'requirements.txt', '--compile', '--no-cache-dir'])
        self.unchanged(pre_pip)
        self.phase('delete', 300)
        removal = self.solve(metadata, installed, delete=True, offline=True)
        self.unchanged(pre_pip)
        need(any(row[1] == '.build-deps' and row[0] == 'Purging' for row in removal), 'plan_mismatch')
        self.call(self.apk('--no-network', 'del', '.build-deps'))
        self.verify_result(installed, removal, baseline[0].decode().splitlines())
        self.bind_control(metadata, self.snapshot()[1])
        self.stage = 'cleanup'  # shares deletion's 300-second budget
        self.cleanup()
        self.emit('ok', 0)


def main():
    build = Build()
    try:
        build.execute()
        return 0
    except Rejected as exc:
        build.emit(exc.code, exc.rc)
    except BaseException:
        build.emit('diagnostic_failure')
    return 2


if __name__ == '__main__':
    def expired(signum, frame):
        raise Rejected('timeout')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(3000)
    sys.exit(main())
