#!/usr/bin/env python3
"""Only the APK follow-up protocol controls; temporary Git, no old suite/network."""
import copy,hashlib,html,json,os,pathlib,runpy,subprocess,sys,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
M=runpy.run_path(str(ROOT/'.jenkins/scripts/verify-ci-tree-equivalence.py'))
G=M['verify_tree'].__globals__
PRIOR_PATH=pathlib.Path(os.environ.get('DJS8_APK_REVISION_PRIOR_RECEIPT','/Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/apk-release-20261024/apk-receipt.json'))
PRIOR=M['strict_json'](PRIOR_PATH.read_text())
assert M['canonical_sha256'](PRIOR)==M['APK_REVISION_PRIOR_SHA256']
def git(*args,data=None,cwd=None):
 env={**os.environ,'GIT_AUTHOR_NAME':'DJS8 revision fixture','GIT_AUTHOR_EMAIL':'fixture@example.invalid','GIT_COMMITTER_NAME':'DJS8 revision fixture','GIT_COMMITTER_EMAIL':'fixture@example.invalid','GIT_CONFIG_NOSYSTEM':'1'}
 return subprocess.run(['git',*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,cwd=cwd,env=env).stdout

def fixture():
 parent=M['APK_REVISION_BASE'];git('read-tree',parent);parent_tree=M['tree'](parent)
 for path in sorted(M['APK_REVISION_FILES']):
  raw=(ROOT/path).read_bytes();oid=git('hash-object','-w','--stdin',data=raw).decode().strip()
  mode=parent_tree.get(path,['100644'])[0];git('update-index','--add','--cacheinfo',mode,oid,path)
 sha=git('commit-tree',git('write-tree').decode().strip(),'-p',parent,data=b'isolated APK revision fixture\n').decode().strip()
 before,after=M['tree'](M['BASE']),M['tree'](sha)
 changed={p for p in before.keys()|after.keys() if before.get(p)!=after.get(p)}
 entries={p:{'git_entry':after[p],'sha256':hashlib.sha256(git('show',sha+':'+p)).hexdigest()} for p in changed}
 delta={p:entries[p] for p in M['APK_REVISION_FILES']}
 review={'verdict':'APPROVE','reviewer_thread_id':'00000000-1111-2222-3333-444444444444','source_sha':sha,'diff_sha256':hashlib.sha256(git('diff','--binary','--full-index','--no-ext-diff','--no-textconv',parent,sha,'--',*sorted(M['APK_REVISION_FILES']))).hexdigest(),'entries_sha256':M['canonical_sha256'](delta)}
 return sha,{'schema':M['APK_REVISION_SCHEMA'],'tested_source_sha':M['BASE'],'build_source_sha':sha,'development_evidence':M['EVIDENCE'],'independent_review':'APPROVE','independent_review_record':review,'independent_review_record_sha256':M['canonical_sha256'](review),'parent_source_sha':parent,'previous_apk_receipt':PRIOR,'previous_apk_receipt_sha256':M['APK_REVISION_PRIOR_SHA256'],'component_validation_sources':{**PRIOR['component_validation_sources'],'apk_diagnostic_revision':sha},'reviewed_ci_entries':entries,'apk_revision_entries':delta,'unchanged_tree_sha256':M['canonical_sha256']({p:v for p,v in sorted(after.items()) if p not in M['APK_REVISION_ALLOWED']}),'ci_control_evidence':'ev-0123456789ab','ci_control_log_sha256':'1'*64,'apk_revision_validation':{'source_sha':sha,'single_concurrency':True,'cpu_budget_percent':90,**{k:{'command':command,'exit_code':0,'log_sha256':'2'*64} for k,command in M['APK_REVISION_COMMANDS'].items()}},'original_suite_reexecuted':False,'frontend_validation_reexecuted':False}

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.previous=pathlib.Path.cwd();cls.tmp=tempfile.TemporaryDirectory();cls.repo=pathlib.Path(cls.tmp.name)
  git('init','-q',str(cls.repo));objects=pathlib.Path(git('rev-parse','--git-path','objects',cwd=ROOT).decode().strip())
  if not objects.is_absolute():objects=ROOT/objects
  (cls.repo/'.git/objects/info/alternates').write_text(str(objects.resolve())+'\n')
  os.chdir(cls.repo);cls.sha,cls.base=fixture()
 @classmethod
 def tearDownClass(cls):os.chdir(cls.previous);cls.tmp.cleanup()
 def setUp(self):self.proof=copy.deepcopy(self.base)
 def verify(self):return M['verify_tree'](self.proof,self.sha)
 def test_real_candidate_parent_and_recursive_original_receipts(self):
  self.assertEqual(self.verify(),self.proof)
  self.assertEqual(self.proof['component_validation_sources']['apk_diagnostic_amendment'],M['APK_REVISION_BASE'])
  self.assertEqual(self.proof['component_validation_sources']['frontend_amendment'],M['APK_BASE'])
  self.assertEqual(M['verify_tree'](PRIOR,M['APK_REVISION_BASE']),PRIOR)
 def test_exact_new_shape_parent_prior_hash_and_historical_flags(self):
  for key,value in [('parent_source_sha',M['APK_BASE']),('previous_apk_receipt_sha256','0'*64),('original_suite_reexecuted',True),('frontend_validation_reexecuted',0),('development_evidence','ev-000000000000'),('tested_source_sha',self.sha),('independent_review','PENDING')]:
   with self.subTest(key=key):
    self.proof=copy.deepcopy(self.base);self.proof[key]=value
    with self.assertRaises(AssertionError):self.verify()
  for key in self.base:
   self.proof=copy.deepcopy(self.base);del self.proof[key]
   with self.assertRaises((AssertionError,KeyError)):self.verify()
  self.proof=copy.deepcopy(self.base);self.proof['apk_amendment_entries']={}
  with self.assertRaises(AssertionError):self.verify()
 def test_exact_direct_parent_not_ancestor_or_merge(self):
  old=G['git']
  for parents in ([self.sha,M['APK_BASE']],[self.sha,M['APK_REVISION_BASE'],'f'*40]):
   def altered(*args):
    if args[:3]==('rev-list','--parents','-n') and args[-1]==self.sha:return (' '.join(parents)+'\n').encode()
    return old(*args)
   with patch.dict(G,{'git':altered}),self.assertRaises(AssertionError):self.verify()
 def test_prior_receipt_cannot_be_relabelled_or_recanonicalized(self):
  self.proof['previous_apk_receipt']['build_source_sha']=self.sha
  self.proof['previous_apk_receipt_sha256']=M['canonical_sha256'](self.proof['previous_apk_receipt'])
  with self.assertRaises(AssertionError):self.verify()
 def test_historical_component_sources_stay_exact(self):
  for key in PRIOR['component_validation_sources']:
   self.proof=copy.deepcopy(self.base);self.proof['component_validation_sources'][key]=self.sha
   with self.assertRaises(AssertionError):self.verify()
 def test_only_new_narrow_control_commands_can_pass(self):
  for group in M['APK_REVISION_COMMANDS']:
   for key,value in [('command','python3 .jenkins/scripts/test-apk-diagnostic.py'),('exit_code',False),('exit_code',1),('log_sha256','invalid')]:
    self.proof=copy.deepcopy(self.base);self.proof['apk_revision_validation'][group][key]=value
    with self.assertRaises(AssertionError):self.verify()
 def test_new_review_and_delta_digest_cannot_be_forged(self):
  for key,value in [('source_sha',M['APK_REVISION_BASE']),('verdict','PENDING'),('reviewer_thread_id','unknown'),('diff_sha256','0'*64),('entries_sha256','0'*64)]:
   self.proof=copy.deepcopy(self.base);self.proof['independent_review_record'][key]=value
   self.proof['independent_review_record_sha256']=M['canonical_sha256'](self.proof['independent_review_record'])
   with self.assertRaises(AssertionError):self.verify()
 def test_exact_seven_delta_and_business_mode_boundaries(self):
  real=G['tree']
  for path,entry in [('apps/api/requirements.txt',['100644','blob','f'*40]),('apps/api/build-tools/apk-build-deps.py',None),('apps/api/build-tools/apk-build-deps.py',['120000','blob','f'*40]),('.jenkins/scripts/test-apk-revision.py',['160000','commit','f'*40]),('apps/api/Dockerfile.api',['100644','blob','f'*40])]:
   def changed(sha):
    out=copy.deepcopy(real(sha))
    if sha==self.sha:
     if entry is None:out.pop(path,None)
     else:out[path]=entry
    return out
   with patch.dict(G,{'tree':changed}),self.assertRaises(AssertionError):self.verify()
 def test_prior_apk_comment_unique_trusted_exact_and_recursive(self):
  prior=self.proof['previous_apk_receipt'];row={'created_by':M['TRUSTED_AUTHOR'],'actor':M['TRUSTED_AUTHOR'],'comment_html':M['MARKERS'][M['APK_SCHEMA']]+M['APK_REVISION_BASE']+'<pre>'+html.escape(json.dumps(prior))+'</pre>'}
  original=G['validate_prior_live_comment'];calls=[]
  def recurse(comments,proof):
   if proof['schema']==M['APK_REVISION_SCHEMA']:return original(comments,proof)
   calls.append(proof['schema'])
  with patch.dict(G,{'validate_control_comment':lambda *a:True,'validate_prior_live_comment':recurse}):
   original([row],self.proof);self.assertEqual(calls,[M['APK_SCHEMA']])
   for rows in ([],[row,row],[{**row,'actor':'untrusted'}],[{**row,'comment_html':row['comment_html'].replace('APPROVE','REJECT')}]):
    with self.assertRaises(AssertionError):original(rows,self.proof)
 def test_revision_control_comment_exact_command_validation_and_source(self):
  v=self.proof['apk_revision_validation'];sha=self.sha
  body='④⑤开发中<td>结论</td><td>✅ 通过</td><td>退出码</td><td><code>0</code></td><td>测的是什么</td><td>'+M['APK_REVISION_TITLE']+'</td><td>命令</td><td><code>'+html.escape(M['APK_REVISION_COMMAND']+' '+sha)+'</code></td>CI_BUILD_SOURCE_SHA='+sha+'CI_CONTROL_LOG_SHA256='+self.proof['ci_control_log_sha256']+'APK_REVISION_VALIDATION_SHA256='+M['canonical_sha256'](v)+'<td>代码</td><td><code>fixture</code> @ <code>'+sha+'</code>〔PLANETEST1 测试证据 · stage=dev · '+self.proof['ci_control_evidence']+'〕'
  row={'created_by':M['TRUSTED_AUTHOR'],'actor':M['TRUSTED_AUTHOR'],'comment_html':body}
  self.assertTrue(M['validate_control_comment']([row],self.proof,sha))
  for original,replacement in [(M['APK_REVISION_COMMAND'],M['APK_COMMAND']),('APK_REVISION_VALIDATION_SHA256=','APK_VALIDATION_SHA256='),('CI_BUILD_SOURCE_SHA='+sha,'CI_BUILD_SOURCE_SHA='+M['APK_REVISION_BASE'])]:
   with self.assertRaises(AssertionError):M['validate_control_comment']([{**row,'comment_html':body.replace(original,replacement)}],self.proof,sha)
 def test_release_revision_exact_and_conflicting_modes_rejected(self):
  v={'apk_revision_receipt':self.proof,'development_evidence_reference':M['EVIDENCE'],'development_evidence_verified_source_sha':M['BASE'],'tested_source_sha':M['BASE'],'build_source_sha':self.sha,'full_unit_test_suite_executed':False,'component_validation_sources':self.proof['component_validation_sources']}
  payload={'source':{'commit':self.sha},'release_build_validation':v}
  with patch.dict(G,{'verify':lambda proof,sha:M['verify_tree'](proof,sha)}):
   self.assertTrue(M['validate_release_binding'](payload))
   v['apk_amendment_receipt']=PRIOR
   with self.assertRaises(AssertionError):M['validate_release_binding'](payload)
   del v['apk_amendment_receipt'];v['component_validation_sources']=PRIOR['component_validation_sources']
   with self.assertRaises(AssertionError):M['validate_release_binding'](payload)

if __name__=='__main__':
 result=unittest.TestResult();unittest.defaultTestLoader.loadTestsFromTestCase(Controls).run(result)
 print(json.dumps({'suite':'apk-revision-controls-v1','tests':result.testsRun,'failures':[t.id().split('.')[-1] for t,_ in result.failures],'errors':[t.id().split('.')[-1] for t,_ in result.errors]}))
 sys.exit(0 if result.wasSuccessful() else 1)
