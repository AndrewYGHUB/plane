#!/usr/bin/env python3
"""Validate separately scoped reviewed Plane receipts; never relabel old tests."""
import hashlib,html,json,pathlib,re,subprocess,sys
BASE='9f93a7b4ebf12f73b2f42022081d6530a1fac02c'
EVIDENCE='ev-a57cc79a0483'
ALLOWED=frozenset(['.jenkins/Jenkinsfile.plane-ce','.jenkins/scripts/build-plane-images.sh','.jenkins/scripts/lib-harbor-exact-not-found.sh','.jenkins/scripts/verify-ci-tree-equivalence.py','CHANGELOG.md'])

LIVE_ALLOWED=ALLOWED|frozenset(['apps/live/src/lib/auth.ts','apps/live/tests/lib/auth.test.ts'])
LIVE_COMMAND='python3 /Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/verify-committed-plane-live.py'
LIVE_TITLE='Plane scoped Live amendment actual protocol types build and receipt controls'

TRUSTED_AUTHOR='97e3f3ff-f92a-4003-a961-0465c458b993'
CONTROL_COMMAND='python3 /Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/verify-committed-plane-ci.py'
CONTROL_TITLE='Plane CI-only committed tree and independent control binding'
def validate_control_comment(comments,proof,sha):
 marker='〔PLANETEST1 测试证据 · stage=dev · '+proof['ci_control_evidence']+'〕'
 rows=[r for r in comments if marker in (r.get('comment_html') or '')]
 assert len(rows)==1,'one actual PLANETEST1 control comment required'
 row=rows[0];body=row.get('comment_html') or ''
 assert row.get('created_by')==row.get('actor')==TRUSTED_AUTHOR,'control author is not the fixed trusted evidence publisher'
 command=LIVE_COMMAND if proof['schema']=='djs8-scoped-live-amendment-v1' else CONTROL_COMMAND
 title=LIVE_TITLE if proof['schema']=='djs8-scoped-live-amendment-v1' else CONTROL_TITLE
 for required in ['④⑤开发中','<td>结论</td><td>✅ 通过</td>','<td>退出码</td><td><code>0</code></td>', '<td>测的是什么</td><td>'+title+'</td>', '<td>命令</td><td><code>'+html.escape(command+' '+sha)+'</code></td>', 'CI_BUILD_SOURCE_SHA='+sha, 'CI_CONTROL_LOG_SHA256='+proof['ci_control_log_sha256']]:
  assert required in body,'committed CI control contract is missing'
 assert '未提交改动' not in body,'committed control tree must be clean'
 revisions=re.findall(r'<td>代码</td><td><code>[^<]+</code>\s*@\s*<code>([0-9a-f]{9,40})</code>',body)
 assert len(revisions)==1 and sha.startswith(revisions[0]),'control must execute from actual candidate Git source'
 return True

def git(*args):return subprocess.check_output(['git',*args])
def tree(sha):
 result={}
 for entry in git('ls-tree','-rz','--full-tree',sha).split(b'\0'):
  if not entry:continue
  meta,path=entry.split(b'\t',1);mode,kind,oid=meta.decode().split();result[path.decode()]=[mode,kind,oid]
 return result
def verify(proof,sha):
 assert re.fullmatch('[0-9a-f]{40}',sha) and git('rev-parse','HEAD').decode().strip()==sha
 assert not git('status','--porcelain','--untracked-files=no'),'tracked worktree must be clean'
 assert proof['schema'] in ['djs8-ci-tree-equivalence-v1','djs8-scoped-live-amendment-v1'] and proof['tested_source_sha']==BASE and proof['build_source_sha']==sha and proof['development_evidence']==EVIDENCE
 assert proof['independent_review']=='APPROVE' and re.fullmatch('ev-[0-9a-f]{12}',proof['ci_control_evidence']) and re.fullmatch('[0-9a-f]{64}',proof['ci_control_log_sha256'])
 allowed=LIVE_ALLOWED if proof['schema']=='djs8-scoped-live-amendment-v1' else ALLOWED
 if proof['schema']=='djs8-scoped-live-amendment-v1':
  assert proof['live_validation']=={'source_sha':sha,'actual_locked_client_connection_protocol':True,'preview_updates_rejected':True,'ordinary_updates_accepted':True,'denied_auth_no_connection':True,'credential_safe_logging':True,'tsc_and_complete_live_build':True,'original_suite_reexecuted':False}
 before,after=tree(BASE),tree(sha);changed={p for p in before.keys()|after.keys() if before.get(p)!=after.get(p)}
 assert changed and changed<=allowed,'change outside exact mode whitelist'
 assert set(proof['reviewed_ci_entries'])==changed,'receipt entries must match all changed paths'
 for path in changed:
  assert path in after and after[path][1]=='blob' and after[path][0] in ['100644','100755'],'CI deletions/symlinks/submodules rejected'
  expected=proof['reviewed_ci_entries'][path];assert set(expected)=={'git_entry','sha256'} and expected['git_entry']==after[path]
  assert hashlib.sha256(git('show',sha+':'+path)).hexdigest()==expected['sha256'],'CI blob differs from independent receipt'
 canonical=json.dumps({p:v for p,v in sorted(after.items()) if p not in allowed},sort_keys=True,separators=(',',':')).encode()
 assert hashlib.sha256(canonical).hexdigest()==proof['unchanged_tree_sha256'],'protected tree digest mismatch'
 if proof['schema']=='djs8-scoped-live-amendment-v1':
  assert {'apps/live/src/lib/auth.ts','apps/live/tests/lib/auth.test.ts'}<=changed,'explicit Live source and typed/protocol controls required'
 return proof
if __name__=='__main__':
 try:
  proof=verify(json.loads(pathlib.Path(sys.argv[1]).read_text()),sys.argv[2]);print(json.dumps({'tested_source_sha':BASE,'build_source_sha':sys.argv[2],'full_unit_test_suite_executed':False,'receipt_mode':proof['schema'],'protected_tree_verified':True,'ci_tree_equivalence_verified':proof['schema']=='djs8-ci-tree-equivalence-v1'}))
 except Exception:raise SystemExit('Scoped receipt/tree verification rejected') from None
