#!/usr/bin/env python3
"""New APK protocol controls using temporary real Git objects and prior receipt.

No network, original suite, package operations, repository writes or publishing.
"""
import copy
import hashlib
import html
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
M=runpy.run_path(str(ROOT/'.jenkins/scripts/verify-ci-tree-equivalence.py'))
G=M['verify_tree'].__globals__
PRIOR_PATH=Path(os.environ.get('DJS8_APK_PRIOR_RECEIPT','/Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/frontend-amendment-receipt.json'))
PRIOR=json.loads(PRIOR_PATH.read_text())
assert M['canonical_sha256'](PRIOR)==M['APK_PRIOR_SHA256']


def git(*args, data=None, cwd=None):
    env={**os.environ,'GIT_AUTHOR_NAME':'DJS8 fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid','GIT_COMMITTER_NAME':'DJS8 fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid','GIT_CONFIG_NOSYSTEM':'1'}
    return subprocess.run(['git',*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,cwd=cwd,env=env).stdout


def fixture():
    parent=M['APK_BASE']
    git('read-tree', parent)
    for path in sorted(M['APK_FILES']):
        content=(ROOT/path).read_bytes()
        oid=git('hash-object','-w','--stdin',data=content).decode().strip()
        git('update-index','--add','--cacheinfo','100644',oid,path)
    tree=git('write-tree').decode().strip()
    sha=git('commit-tree',tree,'-p',parent,data=b'isolated APK control fixture\n').decode().strip()
    before,after=M['tree'](M['BASE']),M['tree'](sha)
    changed={p for p in before.keys()|after.keys() if before.get(p)!=after.get(p)}
    entries={p:{'git_entry':after[p],'sha256':hashlib.sha256(git('show',sha+':'+p)).hexdigest()} for p in changed}
    amendment={p:entries[p] for p in M['APK_FILES']}
    review={'verdict':'APPROVE','reviewer_thread_id':'00000000-1111-2222-3333-444444444444','source_sha':sha,'diff_sha256':hashlib.sha256(git('diff','--binary','--full-index','--no-ext-diff','--no-textconv',parent,sha,'--',*sorted(M['APK_FILES']))).hexdigest(),'entries_sha256':M['canonical_sha256'](amendment)}
    proof={'schema':M['APK_SCHEMA'],'tested_source_sha':M['BASE'],'build_source_sha':sha,'development_evidence':M['EVIDENCE'],'independent_review':'APPROVE','independent_review_record':review,'independent_review_record_sha256':M['canonical_sha256'](review),'parent_source_sha':parent,'previous_frontend_receipt':PRIOR,'previous_frontend_receipt_sha256':M['APK_PRIOR_SHA256'],'component_validation_sources':{**PRIOR['component_validation_sources'],'apk_diagnostic_amendment':sha},'reviewed_ci_entries':entries,'apk_amendment_entries':amendment,'unchanged_tree_sha256':M['canonical_sha256']({p:v for p,v in sorted(after.items()) if p not in M['APK_ALLOWED']}),'ci_control_evidence':'ev-0123456789ab','ci_control_log_sha256':'1'*64,'apk_validation':{'source_sha':sha,'single_concurrency':True,'cpu_budget_percent':90,**{k:{'command':v,'exit_code':0,'log_sha256':'2'*64} for k,v in M['APK_COMMANDS'].items()}},'original_suite_reexecuted':False,'frontend_validation_reexecuted':False}
    return sha,proof


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous=Path.cwd();cls.tmp=tempfile.TemporaryDirectory();cls.repo=Path(cls.tmp.name)
        git('init','-q',str(cls.repo))
        objects=git('rev-parse','--git-path','objects',cwd=ROOT).decode().strip()
        objects=Path(objects) if Path(objects).is_absolute() else ROOT/objects
        (cls.repo/'.git/objects/info/alternates').write_text(str(objects.resolve())+'\n')
        os.chdir(cls.repo)
        cls.sha,cls.base=fixture()

    @classmethod
    def tearDownClass(cls):
        os.chdir(cls.previous);cls.tmp.cleanup()

    def setUp(self):
        self.proof=copy.deepcopy(self.base)

    def verify(self):
        return M['verify_tree'](self.proof,self.sha)

    def test_real_git_positive_recursive_original_sources(self):
        self.assertEqual(self.verify(),self.proof)
        self.assertEqual(self.proof['component_validation_sources']['frontend_amendment'],M['APK_BASE'])

    def test_exact_fields_types_flags_and_control_failures(self):
        cases=[('parent_source_sha','0'*40),('previous_frontend_receipt_sha256','0'*64),('original_suite_reexecuted',True),('frontend_validation_reexecuted',0),('independent_review','PENDING'),('tested_source_sha',self.sha),('development_evidence','ev-000000000000')]
        for field,value in cases:
            with self.subTest(field=field):
                self.proof=copy.deepcopy(self.base);self.proof[field]=value
                with self.assertRaises((AssertionError,KeyError,TypeError)):self.verify()
        for field in list(self.base):
            self.proof=copy.deepcopy(self.base);del self.proof[field]
            with self.assertRaises((AssertionError,KeyError,TypeError)):self.verify()
        self.proof=copy.deepcopy(self.base);self.proof['unexpected']=True
        with self.assertRaises(AssertionError):self.verify()
        for key in M['APK_COMMANDS']:
            for field,value in [('exit_code',False),('exit_code',1),('command','old suite'),('log_sha256','invalid')]:
                self.proof=copy.deepcopy(self.base);self.proof['apk_validation'][key][field]=value
                with self.assertRaises(AssertionError):self.verify()

    def test_parent_not_merely_ancestor(self):
        real=G['git']
        def altered(*args):
            if args[:3]==('rev-list','--parents','-n'):return (self.sha+' '+'f'*40+'\n').encode()
            return real(*args)
        with patch.dict(G,{'git':altered}),self.assertRaises(AssertionError):self.verify()

    def test_original_receipt_and_sources_cannot_be_relabelled(self):
        for key in self.base['component_validation_sources']:
            self.proof=copy.deepcopy(self.base);self.proof['component_validation_sources'][key]=self.sha+'x'
            with self.assertRaises(AssertionError):self.verify()
        self.proof=copy.deepcopy(self.base);self.proof['previous_frontend_receipt']['build_source_sha']=self.sha
        self.proof['previous_frontend_receipt_sha256']=M['canonical_sha256'](self.proof['previous_frontend_receipt'])
        with self.assertRaises(AssertionError):self.verify()

    def test_independent_review_record_and_blob_hash(self):
        for key in self.base['independent_review_record']:
            self.proof=copy.deepcopy(self.base);self.proof['independent_review_record'][key]='invalid'
            self.proof['independent_review_record_sha256']=M['canonical_sha256'](self.proof['independent_review_record'])
            with self.assertRaises(AssertionError):self.verify()
        self.proof=copy.deepcopy(self.base);self.proof['apk_amendment_entries']['apps/api/Dockerfile.api']['sha256']='0'*64
        with self.assertRaises(AssertionError):self.verify()

    def test_business_deletion_symlink_and_scope_tampering(self):
        real=G['tree']
        for path,entry in [('apps/api/requirements.txt',['100644','blob','f'*40]),('apps/api/Dockerfile.api',['120000','blob','f'*40]),('apps/api/Dockerfile.api',None),('new-business.py',['100644','blob','f'*40])]:
            def altered(sha):
                result=copy.deepcopy(real(sha))
                if sha==self.sha:
                    if entry is None:result.pop(path,None)
                    else:result[path]=entry
                return result
            with patch.dict(G,{'tree':altered}),self.assertRaises(AssertionError):self.verify()

    def test_prior_trusted_comment_uniqueness_author_and_payload(self):
        prior=self.proof['previous_frontend_receipt']
        row={'created_by':M['TRUSTED_AUTHOR'],'actor':M['TRUSTED_AUTHOR'],'comment_html':M['MARKERS'][M['FRONTEND_SCHEMA']]+M['APK_BASE']+'<pre>'+html.escape(json.dumps(prior))+'</pre>'}
        # Recursion boundary captured only after exact frontend comment validation.
        original=G['validate_prior_live_comment'];calls=[]
        def recurse(comments,proof):
            if proof['schema']==M['APK_SCHEMA']:return original(comments,proof)
            calls.append(proof['schema'])
        with patch.dict(G,{'validate_control_comment':lambda *a:True,'validate_prior_live_comment':recurse}):
            original([row],self.proof);self.assertEqual(calls,[M['FRONTEND_SCHEMA']])
            for rows in ([],[row,row],[{**row,'actor':'unknown'}],[{**row,'comment_html':row['comment_html'].replace('APPROVE','REJECT')}]):
                with self.assertRaises(AssertionError):original(rows,self.proof)

    def test_release_conflicting_modes_and_source(self):
        v={'apk_amendment_receipt':self.proof,'development_evidence_reference':M['EVIDENCE'],'development_evidence_verified_source_sha':M['BASE'],'tested_source_sha':M['BASE'],'build_source_sha':self.sha,'full_unit_test_suite_executed':False,'component_validation_sources':self.proof['component_validation_sources']}
        payload={'source':{'commit':self.sha},'release_build_validation':v}
        with patch.dict(G,{'verify':lambda proof,sha:M['verify_tree'](proof,sha)}):
            self.assertTrue(M['validate_release_binding'](payload))
            v['frontend_amendment_receipt']=PRIOR
            with self.assertRaises(AssertionError):M['validate_release_binding'](payload)
            del v['frontend_amendment_receipt'];v['build_source_sha']='0'*40
            with self.assertRaises(AssertionError):M['validate_release_binding'](payload)

    def test_duplicate_json_fields_rejected(self):
        for value in ('{"schema":"a","schema":"b"}', '{"nested":{"exit_code":0,"exit_code":1}}'):
            with self.assertRaises(AssertionError):M['strict_json'](value)

    def test_optimized_python_cannot_disable_receipt_checks(self):
        p=subprocess.run([sys.executable,'-O',str(ROOT/'.jenkins/scripts/verify-ci-tree-equivalence.py')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertNotEqual(p.returncode,0)
        self.assertIn(b'Optimized Python cannot enforce the receipt contract',p.stderr)


if __name__=='__main__':
    result=unittest.TestResult();unittest.defaultTestLoader.loadTestsFromTestCase(Controls).run(result)
    print(json.dumps({'suite':'apk-amendment-controls-v1','tests':result.testsRun,'failures':[t.id().split('.')[-1] for t,_ in result.failures],'errors':[t.id().split('.')[-1] for t,_ in result.errors]}))
    sys.exit(0 if result.wasSuccessful() else 1)
