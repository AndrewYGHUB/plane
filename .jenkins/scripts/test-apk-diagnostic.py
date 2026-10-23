#!/usr/bin/env python3
"""New APK controls only: fixtures and real isolated child pipes, never real apk."""
import contextlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('apk_build', ROOT / 'apps/api/build-tools/apk-build-deps.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
CANARY = 'DJS8_PRIVATE_CANARY_NEVER_EXTERNAL'


class Controls(unittest.TestCase):
    def child(self, code):
        return [sys.executable, '-c', code]

    def test_receiver_drops_no_bytes_to_external_streams(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            rc, out, err = m.Receiver().run(self.child("import sys; print('" + CANARY + "'); print('" + CANARY + "',file=sys.stderr)"), time.monotonic() + 5)
        self.assertEqual(rc, 0)
        self.assertIn(CANARY.encode(), out)
        self.assertIn(CANARY.encode(), err)
        self.assertEqual(capture.getvalue(), '')

    def test_each_stream_limit_and_total_limit(self):
        for stream in (1, 2):
            with self.subTest(stream=stream), self.assertRaises(m.Rejected) as caught:
                m.Receiver(stream_limit=256).run(self.child(f'import os; os.write({stream}, b"x"*1024)'), time.monotonic() + 5)
            self.assertEqual(caught.exception.code, 'output_limit')
        r = m.Receiver(total_limit=300, stream_limit=1024)
        r.run(self.child('print("x"*200)'), time.monotonic() + 5)
        with self.assertRaises(m.Rejected) as caught:
            r.run(self.child('print("x"*200)'), time.monotonic() + 5)
        self.assertEqual(caught.exception.code, 'output_limit')

    def test_timeout_kills_descendant_holding_pipe(self):
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / 'pid'
            code = 'import os,time; p=os.fork(); open(' + repr(str(pidfile)) + ',"w").write(str(p)) if p else None; time.sleep(60)'
            start = time.monotonic()
            with self.assertRaises(m.Rejected) as caught:
                m.Receiver().run(self.child(code), start + 0.3)
            self.assertEqual(caught.exception.code, 'timeout')
            self.assertLess(time.monotonic() - start, 3)
            # Descendant cannot produce a delayed side effect after group kill.
            self.assertTrue(pidfile.exists())

    def test_receiver_failure_and_launch_failure_safe(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(capture):
            # Inject after Popen has returned its owned process handle. Patching
            # os.read globally also breaks Python's internal exec-error pipe.
            with patch.object(m.Receiver, 'read_chunk', side_effect=OSError(CANARY)), self.assertRaises(m.Rejected):
                m.Receiver().run(self.child('print("hello")'), time.monotonic() + 5)
            with self.assertRaises(m.Rejected):
                m.Receiver().run(['/does-not-exist/' + CANARY], time.monotonic() + 5)
        self.assertNotIn(CANARY, capture.getvalue())

    def test_child_failures_all_stages_expose_only_safe_metadata(self):
        for stage in m.STAGES:
            with self.subTest(stage=stage):
                build = m.Build(); build.phase(stage)
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(m.Rejected) as caught:
                    build.call(self.child('import sys;print(' + repr(CANARY) + ');print(' + repr(CANARY) + ',file=sys.stderr);sys.exit(23)'))
                self.assertNotIn(CANARY, output.getvalue())
                self.assertEqual(caught.exception.rc, 23)
                row = json.loads(output.getvalue())
                self.assertEqual(row['stage'], stage)
                self.assertEqual(row['rc'], 23)

    def test_plan_all_actions_and_exact_versions(self):
        names = ('a', 'b', 'c', 'd', 'e', 'f', 'g')
        actions = ('Installing', 'Purging', 'Upgrading', 'Downgrading', 'Replacing', 'Reinstalling', 'Updating pinning')
        available = {(n, v, 'x86_64'): (3, 9) for n in names for v in ('1-r0', '2-r0')}
        before = {(n, '1-r0', 'x86_64'): None for n in names[1:]}
        rows = [f'({i+1}/7) {action} {n} (1-r0' + (' -> 2-r0)' if action in ('Upgrading','Downgrading','Replacing') else ')') for i,(n,action) in enumerate(zip(names, actions))]
        plan = m.parse_plan(('\n'.join(rows)+'\nOK: 99 MiB in 7 packages\n').encode(), b'', available, before)
        self.assertEqual(len(plan), 7)
        self.assertNotIn(('b','1-r0','x86_64'), m.expected_packages(before, plan))
        for bad in (b'unknown\n', b'(1/2) Installing a (1-r0)\nOK: 1 MiB in 1 packages\n', b'(1/1) Installing a (secret)\nOK: 1 MiB in 1 packages\n'):
            with self.subTest(bad=m.digest(bad)), self.assertRaises(m.Rejected):
                m.parse_plan(bad, b'', available, before)
        with self.assertRaises(m.Rejected):
            m.parse_plan(b'OK: 1 MiB in 1 packages\n', CANARY.encode(), available, before)

    def test_virtual_version_only_normalization(self):
        def plan(version):
            return m.parse_plan(f'(1/1) Installing .build-deps ({version})\nOK: 1 MiB in 1 packages\n'.encode(), b'', {}, {})
        self.assertEqual(plan('20261017.123456'), plan('20261017.234567'))

    def test_metadata_unknown_arch_duplicates_and_sizes(self):
        self.assertEqual(m.records(b'P:llvm18\nV:18-r0\nA:x86_64\nS:50\nI:100\n'), {('llvm18','18-r0','x86_64'):(50,100)})
        for data in (b'P:a\nV:1\nA:arm64\nS:2\nI:4', b'P:a\nP:b\nV:1\nA:x86_64', b'P:a\nV:1\nA:x86_64\nS:-1\nI:4'):
            with self.assertRaises(m.Rejected):
                m.records(data)

    def test_capacity_exact_and_missing_metadata(self):
        metadata = {('a','1','x86_64'):(100,1000)}
        self.assertEqual(m.capacity(metadata, set(metadata)), (100, 2000+64*1024**2, 2625+64*1024**2))
        with self.assertRaises(m.Rejected):
            m.capacity(metadata, {('b','1','x86_64')})

    def fixture(self, tmp, payload):
        build = m.Build(); build.phase('integrity'); build.cache = Path(tmp)
        s = build.cache.stat(); build.cache_identity = (s.st_dev, s.st_ino)
        p = build.cache/'llvm18-18-r0.12345678.apk'; p.write_bytes(payload)
        meta = {('llvm18','18-r0','x86_64'):(len(payload), 4096)}
        return build, p, meta

    def test_integrity_real_gzip_truncation_bad_crc_and_read_failure(self):
        for variant in ('good','truncated','crc','read'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                data = gzip.compress(b'public data') + gzip.compress(b'second stream')
                if variant == 'truncated': data = data[:-3]
                if variant == 'crc': data = data[:-8]+b'xxxxxxxx'
                b,p,meta = self.fixture(tmp,data)
                with contextlib.redirect_stdout(io.StringIO()):
                    if variant == 'good': self.assertEqual(b.integrity(meta,set(meta)), set(meta))
                    elif variant == 'read':
                        with patch.object(m.os,'open',side_effect=OSError(CANARY)), self.assertRaises(OSError): b.integrity(meta,set(meta))
                    else:
                        with self.assertRaises((EOFError,OSError)): b.integrity(meta,set(meta))

    def test_cache_noop_symlink_directory_replacement_and_extra(self):
        with tempfile.TemporaryDirectory() as tmp:
            b,p,meta = self.fixture(tmp,gzip.compress(b'good'))
            p.unlink()
            with self.assertRaises(m.Rejected): b.integrity(meta,set(meta))
            p.symlink_to('/etc/hosts')
            with self.assertRaises(m.Rejected): b.cache_entries()
            p.unlink(); p.mkdir()
            with self.assertRaises(m.Rejected): b.cache_entries()
            p.rmdir(); b.cache_identity = (0,0)
            with self.assertRaises(m.Rejected): b.cache_entries()

    def test_preinstall_state_drift(self):
        b=m.Build()
        with patch.object(b,'snapshot',return_value=(b'changed',b'db')), self.assertRaises(m.Rejected):
            b.unchanged((b'world',b'db'))
        b.index_hash={'a':'hash'}
        with patch.object(b,'snapshot',return_value=(b'w',b'd')),patch.object(b,'indices',return_value={'a':'changed'}),self.assertRaises(m.Rejected):
            b.unchanged((b'w',b'd'))

    def test_result_package_and_world_compare(self):
        b=m.Build(); b.phase('install'); b.index_hash={'index':'hash'}
        plan=[('Installing','.build-deps','noarch','<virtual>','<virtual>')]
        before={('base','1','x86_64'):None}
        db=b'P:base\nV:1\nA:x86_64\n\nP:.build-deps\nV:20261017.123456\nA:noarch\n'
        with patch.object(b,'indices',return_value=b.index_hash),patch.object(b,'snapshot',return_value=(b'base\n.build-deps=20261017.123456\n',db)),contextlib.redirect_stdout(io.StringIO()):
            b.verify_result(before,plan,['base','.build-deps'])
            with self.assertRaises(m.Rejected): b.verify_result(before,plan,['other','.build-deps'])

    def test_pipeline_pip_delete_failures_stop_following_steps(self):
        for failure in ('install', 'pip', 'delete', None):
            with self.subTest(failure=failure):
                b=m.Build();stages=[];actual=b.call
                def fake_call(command):
                    stages.append(b.stage)
                    rc=9 if b.stage==failure else 0
                    return actual(self.child('import sys;print('+repr(CANARY)+');sys.exit('+str(rc)+')'))
                with patch.object(b,'bind_control'),patch.object(b,'call',side_effect=fake_call),patch.object(b,'verify_result',return_value={}),patch.object(b,'snapshot',return_value=(b'w',b'd')),patch.object(b,'unchanged'),patch.object(b,'solve',return_value=[('Purging','.build-deps','noarch','<virtual>','<virtual>')]),patch.object(b,'cleanup') as cleanup,contextlib.redirect_stdout(io.StringIO()) as output:
                    if failure:
                        with self.assertRaises(m.Rejected):b.install_sequence({}, {}, [], (b'w',b'd'))
                        cleanup.assert_not_called()
                    else:
                        b.install_sequence({}, {}, [], (b'w',b'd'));cleanup.assert_called_once()
                self.assertNotIn(CANARY,output.getvalue())
                expected=['install','pip','delete']
                self.assertEqual(stages,expected[:expected.index(failure)+1] if failure else expected)

    def test_expanded_index_reader_limit(self):
        reader=m.LimitedReader(io.BytesIO(b'x'*101),100,lambda:None)
        with self.assertRaises(m.Rejected):reader.read(1024)

    def test_cleanup_failure_safe_at_main_boundary(self):
        with patch.object(m.Build,'execute',side_effect=OSError(CANARY)),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(m.main(),2)
        self.assertNotIn(CANARY,output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['code'],'diagnostic_failure')

    def test_reaping_failure_still_closes_all_receiver_fds(self):
        original=m.subprocess.Popen;children=[];selectors=[]
        original_selector=m.selectors.DefaultSelector
        def make_selector():
            value=original_selector();selectors.append(value);return value
        def launch(*args,**kwargs):
            child=original(*args,**kwargs);children.append(child);wait=child.wait
            def fail_final_wait(timeout=None):
                if timeout==2:raise m.subprocess.TimeoutExpired('hidden',2)
                return wait(timeout=timeout)
            child.wait=fail_final_wait
            return child
        with patch.object(m.subprocess,'Popen',side_effect=launch),patch.object(m.selectors,'DefaultSelector',side_effect=make_selector),self.assertRaises(m.Rejected):
            m.Receiver().run(self.child('print("public")'),time.monotonic()+5)
        self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
        self.assertIsNone(selectors[0].get_map())


    def test_acquire_faults_stop_before_integrity_or_install(self):
        # Real subprocess rc/stdout/stderr boundary with synthetic apk failure.
        # This does not claim actual apk signature or repository fault injection.
        for fault in ('update_signature', 'solve_conflict', 'download_signature',
                      'download_stream', 'download_cache_write', 'download_noop'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                b,p,meta=self.fixture(tmp,gzip.compress(b'public'))
                p.unlink();b.phase('acquire');stages=[];actual=b.call
                plan=b'(1/2) Installing llvm18 (18-r0)\n(2/2) Installing .build-deps (20261017.123456)\nOK: 1 MiB in 2 packages\n'
                def call(command):
                    op='update' if 'update' in command else 'solve' if '--simulate' in command else 'download'
                    stages.append(op)
                    failing=fault.startswith(op+'_') and fault!='download_noop'
                    payload=plan if op=='solve' and not failing else CANARY.encode()
                    return actual(self.child('import os,sys;os.write(1,'+repr(payload)+');os.write(2,'+repr(CANARY.encode() if failing else b'')+');sys.exit('+str(19 if failing else 0)+')'))
                with patch.object(b,'bind_control'),patch.object(b,'call',side_effect=call),patch.object(b,'snapshot',return_value=(b'w',b'd')),patch.object(b,'indices',side_effect=lambda parse=True: ({'idx':'hash'},meta) if parse else {'idx':'hash'}),patch.object(b,'install_sequence') as install,contextlib.redirect_stdout(io.StringIO()) as output,self.assertRaises(m.Rejected) as caught:
                    b.prepare_dependencies({},(b'w',b'd'))
                install.assert_not_called();self.assertNotIn(CANARY,output.getvalue())
                if fault=='download_noop': self.assertEqual(caught.exception.code,'integrity_unknown')
                else: self.assertEqual(caught.exception.code,'acquire_unknown');self.assertEqual(caught.exception.rc,19)
                self.assertEqual(stages, ['update'] if fault.startswith('update_') else ['update','solve'] if fault.startswith('solve_') else ['update','solve','download'])

    def test_acquire_plan_mismatch_and_missing_cached_dependency_stop_install(self):
        for fault in ('plan','missing'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                b,p,meta=self.fixture(tmp,gzip.compress(b'public'));b.phase('acquire')
                normal=[('Installing','llvm18','x86_64','18-r0','18-r0'),('Installing','.build-deps','noarch','<virtual>','<virtual>')]
                offline=normal if fault=='missing' else normal[:1]
                with patch.object(b,'bind_control'),patch.object(b,'call',return_value=(b'',b'')),patch.object(b,'unchanged'),patch.object(b,'indices',return_value=({'idx':'hash'},meta)),patch.object(b,'solve',side_effect=[normal,offline]),patch.object(b,'integrity',return_value=set() if fault=='missing' else set(meta)),patch.object(b,'install_sequence') as install,contextlib.redirect_stdout(io.StringIO()),self.assertRaises(m.Rejected) as caught:
                    b.prepare_dependencies({},(b'w',b'd'))
                install.assert_not_called();self.assertEqual(caught.exception.code,'plan_mismatch' if fault=='plan' else 'integrity_unknown')

    def test_capacity_rejected_before_downloading(self):
        with tempfile.TemporaryDirectory() as tmp:
            b,p,meta=self.fixture(tmp,gzip.compress(b'public'));b.phase('acquire')
            plan=[('Installing','llvm18','x86_64','18-r0','18-r0')]
            fs=type('EmptyFs',(),{'f_bavail':0,'f_frsize':4096})()
            with patch.object(b,'bind_control'),patch.object(b,'call',return_value=(b'',b'')) as call,patch.object(b,'unchanged'),patch.object(b,'indices',return_value=({'idx':'hash'},meta)),patch.object(b,'solve',return_value=plan),patch.object(m.os,'statvfs',return_value=fs),self.assertRaises(m.Rejected) as caught:
                b.prepare_dependencies({},(b'w',b'd'))
            self.assertEqual(caught.exception.code,'capacity');self.assertEqual(call.call_count,1)

    def test_cleanup_fd_relative_and_replacement_rejected(self):
        for fault in ('none','directory','symlink','hardlink','size'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);cache=root/'cache';cache.mkdir();target=cache/'item';target.write_bytes(b'public')
                outside=root/'outside';outside.write_bytes(b'keep')
                b=m.Build();b.phase('cleanup');s=cache.stat();identity=(s.st_dev,s.st_ino)
                s=target.stat();entries={'item':(s.st_dev,s.st_ino,s.st_size)}
                if fault=='directory':cache.rename(root/'old');cache.symlink_to(root/'old',target_is_directory=True)
                elif fault=='symlink':target.unlink();target.symlink_to(outside)
                elif fault=='hardlink':os.link(target,root/'second')
                elif fault=='size':target.write_bytes(b'changed')
                if fault=='none':b.remove_flat(cache,identity,entries);self.assertFalse(target.exists())
                else:
                    with self.assertRaises((m.Rejected,OSError)):b.remove_flat(cache,identity,entries)
                self.assertEqual(outside.read_bytes(),b'keep')

    def test_expired_phase_and_global_budget_prevent_child_start(self):
        for budget in ('phase','global'):
            b=m.Build();b.phase('install')
            if budget=='phase':b.phase_end=time.monotonic()-1
            else:b.receiver.end=time.monotonic()-1
            with patch.object(m.subprocess,'Popen') as launch,self.assertRaises(m.Rejected) as caught:
                b.call(self.child('print("must not start")'))
            launch.assert_not_called();self.assertEqual(caught.exception.code,'timeout')
        b=m.Build();b.phase('delete',300);deadline=b.deadline();b.stage='cleanup'
        self.assertEqual(b.deadline(),deadline)

    def test_integrity_read_error_has_no_external_payload_at_main_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            b,p,meta=self.fixture(tmp,gzip.compress(CANARY.encode()))
            with patch.object(m,'Build',return_value=b),patch.object(b,'execute',side_effect=lambda:b.integrity(meta,set(meta))),patch.object(m.os,'open',side_effect=OSError(CANARY)),contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(m.main(),2)
            self.assertNotIn(CANARY,output.getvalue());self.assertEqual(json.loads(output.getvalue())['stage'],'integrity')


class InstalledControls(unittest.TestCase):
    @staticmethod
    def entry(name='local', version='1', size=0):
        return f'C:Q1publicchecksum\nP:{name}\nV:{version}\nA:noarch\nS:0\nI:{size}\nT:public\nU:\nL:MIT\n\n'.encode()

    def setup_build(self, tmp, data=b''):
        b = m.Build(); b.phase('integrity'); b.cache = Path(tmp)
        st = b.cache.stat(); b.cache_identity = (st.st_dev, st.st_ino)
        (b.cache/'installed').write_bytes(data)
        return b

    def test_empty_and_nonempty_control(self):
        for data in (b'', self.entry(), self.entry(size=100)):
            with self.subTest(size=len(data)), tempfile.TemporaryDirectory() as tmp:
                b = self.setup_build(tmp, data); b.bind_control({}, data)
                self.assertEqual(b.control_snapshot, b.read_control()[0])
                with patch.object(b, 'snapshot', return_value=(b'w', data)):
                    b.unchanged((b'w', data))

    def test_control_provenance_and_header_fields(self):
        data = self.entry()
        cases = [(data, b'', {}), (data, data, {('local','1','noarch'):(0,0)}),
                 (data.replace(b'MIT', b'BAD'), data, {}),
                 (data + data, data, {}), (b'', data, {}),
                 (data.replace(b'L:MIT',b'Z:extra'), data, {})]
        for cached, db, metadata in cases:
            with self.subTest(hash=m.digest(cached+db)), tempfile.TemporaryDirectory() as tmp:
                b=self.setup_build(tmp,cached)
                with self.assertRaises(m.Rejected): b.bind_control(metadata,db)
        with tempfile.TemporaryDirectory() as tmp:
            b=self.setup_build(tmp,data)
            b.bind_control({}, data.rstrip()+b'\nF:usr\nR:file\nZ:checksum\n\n')

    def test_control_illegal_replacements_and_bounds(self):
        for fault in ('symlink','hardlink','directory','oversize','missing'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                b=self.setup_build(tmp); p=b.cache/'installed'; p.unlink()
                if fault=='symlink': p.symlink_to('outside')
                elif fault=='hardlink':
                    other=b.cache/'other';other.write_bytes(b'');os.link(other,p)
                elif fault=='directory':p.mkdir()
                elif fault=='oversize':
                    with p.open('wb') as f:f.truncate(m.INDEX_LIMIT+1)
                with self.assertRaises((m.Rejected,OSError)):b.bind_control({},b'')

    def test_interphase_identity_and_content_drift(self):
        for fault in ('replace','content'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                data=self.entry();b=self.setup_build(tmp,data);b.bind_control({},data)
                p=b.cache/'installed'
                if fault=='replace':
                    other=b.cache/'next';other.write_bytes(data);other.replace(p)
                else:p.write_bytes(data.replace(b'MIT',b'BAD'))
                with patch.object(b,'snapshot',return_value=(b'w',data)),self.assertRaises(m.Rejected):
                    b.unchanged((b'w',data))

    def test_add_del_only_expected_nonrepo_changes(self):
        old=self.entry();virtual=self.entry('.build-deps','20261018.1');repo=self.entry('llvm18','18',100)
        metadata={('llvm18','18','noarch'):(0,100)}
        with tempfile.TemporaryDirectory() as tmp:
            b=self.setup_build(tmp,old);b.bind_control(metadata,old)
            p=b.cache/'installed';p.write_bytes(old+virtual)
            b.bind_control(metadata,old+virtual+repo)
            p.write_bytes(old);b.bind_control(metadata,old)
            self.assertEqual(b.control_packages,{('local','1','noarch')})
            unexpected=self.entry('unexpected','1',100);p.write_bytes(old+unexpected)
            with self.assertRaises(m.Rejected):b.bind_control(metadata,old+unexpected)

    def test_integrity_accepts_bound_control_rejects_unknown_files(self):
        payload=gzip.compress(b'public')
        with tempfile.TemporaryDirectory() as tmp:
            b=self.setup_build(tmp);b.bind_control({},b'')
            (b.cache/'llvm18-18-r0.12345678.apk').write_bytes(payload)
            metadata={('llvm18','18-r0','x86_64'):(len(payload),4096)}
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(b.integrity(metadata,set(metadata)),set(metadata))
            (b.cache/'installed.new').write_bytes(b'')
            with self.assertRaises(m.Rejected):b.integrity(metadata,set(metadata))

    def test_bounded_cache_age_and_transition_hooks(self):
        b=m.Build();b.cache=Path('/unused')
        command=b.apk('update');age=int(command[command.index('--cache-max-age')+1])
        self.assertEqual(age,60);self.assertGreater(age*60,900);self.assertLess(age*60,2**31)
        with patch.object(b,'call',return_value=(b'',b'')),patch.object(b,'verify_result',return_value={}),patch.object(b,'snapshot',return_value=(b'w',b'd')),patch.object(b,'bind_control') as bind,patch.object(b,'unchanged'),patch.object(b,'solve',return_value=[('Purging','.build-deps','noarch','<virtual>','<virtual>')]),patch.object(b,'cleanup'),contextlib.redirect_stdout(io.StringIO()):
            b.install_sequence({}, {}, [], (b'w',b'd'))
        self.assertEqual(bind.call_count,2)


class LinuxControls(unittest.TestCase):
    def test_detached_and_double_fork_children_reaped(self):
        for double in (False, True):
            with self.subTest(double=double):
                code="""import os,time
r,w=os.pipe()
p=os.fork()
if p:
 os.close(w);os.read(r,1);os.close(r)
 if DOUBLE: os.waitpid(p,0)
 os._exit(0)
os.close(r);os.setsid()
if DOUBLE:
 q=os.fork()
 if q: os._exit(0)
os.write(1,str(os.getpid()).encode()+b'\\n');os.write(w,b'1');os.close(w)
os.close(1);os.close(2);time.sleep(30)
""".replace('DOUBLE',repr(double))
                start=time.monotonic();rc,out,err=m.Receiver().run([sys.executable,'-c',code],start+3)
                self.assertEqual(rc,0);self.assertFalse(err);self.assertLess(time.monotonic()-start,5)
                pid=int(out.strip())
                with self.assertRaises(ProcessLookupError):os.kill(pid,0)
                self.assertEqual(m.Receiver.children(),[])

    def test_preexisting_child_rejected_without_killing_it(self):
        p=m.subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],stdout=m.subprocess.DEVNULL,stderr=m.subprocess.DEVNULL)
        try:
            with self.assertRaises(m.Rejected):m.Receiver().run([sys.executable,'-c','pass'],time.monotonic()+1)
            self.assertIsNone(p.poll())
        finally:p.kill();p.wait(timeout=2)

    def test_linux_timeout_leaves_no_adopted_children(self):
        start=time.monotonic()
        with self.assertRaises(m.Rejected) as caught:
            m.Receiver().run([sys.executable,'-c','import os,time;os.fork();time.sleep(30)'],start+0.2)
        self.assertEqual(caught.exception.code,'timeout');self.assertLess(time.monotonic()-start,5)
        self.assertEqual(m.Receiver.children(),[])


if __name__ == '__main__':
    # Fixed names/status only. Never print exception text, fixture data or argv.
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(Controls).run(result)
    unittest.defaultTestLoader.loadTestsFromTestCase(InstalledControls).run(result)
    if sys.platform == 'linux':
        unittest.defaultTestLoader.loadTestsFromTestCase(LinuxControls).run(result)
    print(json.dumps({'suite':'apk-diagnostic-controls-v1','tests':result.testsRun,'failures':[test.id().split('.')[-1] for test,_ in result.failures],'errors':[test.id().split('.')[-1] for test,_ in result.errors]}))
    sys.exit(0 if result.wasSuccessful() else 1)
