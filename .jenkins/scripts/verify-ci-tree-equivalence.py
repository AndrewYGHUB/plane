#!/usr/bin/env python3
"""Validate separately scoped reviewed Plane receipts; never relabel old tests."""
import hashlib,html,json,pathlib,re,subprocess,sys
BASE='9f93a7b4ebf12f73b2f42022081d6530a1fac02c'
EVIDENCE='ev-a57cc79a0483'
ALLOWED=frozenset(['.jenkins/Jenkinsfile.plane-ce','.jenkins/scripts/build-plane-images.sh','.jenkins/scripts/lib-harbor-exact-not-found.sh','.jenkins/scripts/verify-ci-tree-equivalence.py','CHANGELOG.md'])

LIVE_ALLOWED=ALLOWED|frozenset(['apps/live/src/lib/auth.ts','apps/live/tests/lib/auth.test.ts'])
LIVE_COMMAND='python3 /Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/verify-committed-plane-live.py'
LIVE_TITLE='Plane scoped Live amendment actual protocol types build and receipt controls'

SIGNING_SCHEMA='djs8-scoped-signing-amendment-v1'
LIVE_SOURCE='46aa52c93fe7a461350ca3b7609034c8705347a1'
SIGNING_ALLOWED=LIVE_ALLOWED|frozenset(['.jenkins/scripts/sign-and-sbom.sh','.jenkins/scripts/verify-ci-contract.py'])
SIGNING_COMMAND='python3 /Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/verify-committed-plane-signing.py'
SIGNING_TITLE='Plane signing amendment source binding and exact registry controls'
ROOTFS_SCHEMA='djs8-scoped-rootfs-amendment-v1'
SIGNING_SOURCE='76f51e3a22e2bfc27db6e1c2bedf167924dc68b6'
ROOTFS_ALLOWED=SIGNING_ALLOWED|frozenset(['.jenkins/scripts/lib-oci-rootfs-scan.sh'])
ROOTFS_COMMAND='python3 /Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/verify-committed-plane-rootfs.py'
ROOTFS_TITLE='Plane rootfs material detection and inherited evidence binding controls'
FRONTEND_SCHEMA='djs8-scoped-frontend-amendment-v1'
FRONTEND_BASE='5047bf3f79ef0a7ca3652b268b3299983f847e9c'
FRONTEND_PRIOR_SHA256='e6ad6f3d7528e1e4ccb518bd7924c8829accdca07a82d08bca9f9e38c1dc572f'
FRONTEND_FILES=frozenset([
 'apps/web/core/hooks/editor/use-editor-config.ts',
 'packages/editor/src/core/extensions/custom-image/components/block.tsx',
 'packages/editor/src/core/helpers/image-helpers.ts',
 'packages/editor/src/core/plugins/file/delete.ts',
 'packages/editor/src/core/plugins/file/restore.ts',
 'packages/utils/src/editor/common.ts',
 'packages/utils/src/editor/inline-attachment.ts',
 'packages/utils/src/editor/inline-attachment.test.mjs',
])
FRONTEND_CI=frozenset(['.jenkins/Jenkinsfile.plane-ce','.jenkins/scripts/build-plane-images.sh','.jenkins/scripts/verify-ci-tree-equivalence.py','.jenkins/scripts/test-frontend-amendment.py'])
FRONTEND_ALLOWED=ROOTFS_ALLOWED|FRONTEND_FILES|FRONTEND_CI
FRONTEND_COMMAND='python3 /Users/andrewyang/.codex/worktrees/djs1-brand-20261014/CloudHandStack/scratch/brand-20261014/verify-committed-plane-frontend.py'
FRONTEND_TITLE='Plane frontend amendment actual scoped controls types and complete Web build'
FRONTEND_VALIDATION_COMMANDS={
 'controls':'node --test --test-concurrency=1 packages/utils/src/editor/inline-attachment.test.mjs',
 'types':'pnpm exec turbo run check:types --filter=web --filter=@plane/editor --filter=@plane/utils --concurrency=1',
 'build':'pnpm exec turbo run build --filter=web --concurrency=1',
}

def canonical_sha256(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def frontend_validation_sources(sha):
 return {'pg':BASE,'old_web_suite':'historical only','live_amendment':LIVE_SOURCE,'signing_amendment':SIGNING_SOURCE,'rootfs_amendment':FRONTEND_BASE,'frontend_amendment':sha}

def validate_frontend_validation(proof,sha):
 v=proof['frontend_validation']
 assert set(v)=={'source_sha','controls','types','build','single_concurrency','cpu_budget_percent'}
 assert v['source_sha']==sha and v['single_concurrency'] is True and v['cpu_budget_percent']==90
 for key,command in FRONTEND_VALIDATION_COMMANDS.items():
  row=v[key]
  assert set(row)=={'command','exit_code','log_sha256'} and row['command']==command
  assert type(row['exit_code']) is int and row['exit_code']==0 and re.fullmatch('[0-9a-f]{64}',row['log_sha256'])
 assert proof['component_validation_sources']==frontend_validation_sources(sha)
 assert proof['original_suite_reexecuted'] is False and proof['live_validation_reexecuted'] is False
 return True

MARKERS={'djs8-ci-tree-equivalence-v1':'DJS8-CI-TREE-EQUIVALENCE-V1:', 'djs8-scoped-live-amendment-v1':'DJS8-SCOPED-LIVE-AMENDMENT-V1:',SIGNING_SCHEMA:'DJS8-SCOPED-SIGNING-AMENDMENT-V1:',ROOTFS_SCHEMA:'DJS8-SCOPED-ROOTFS-AMENDMENT-V1:',FRONTEND_SCHEMA:'DJS8-SCOPED-FRONTEND-AMENDMENT-V1:'}
RECEIPT_KEYS={'djs8-ci-tree-equivalence-v1':'ci_tree_equivalence','djs8-scoped-live-amendment-v1':'live_amendment_receipt',SIGNING_SCHEMA:'signing_amendment_receipt',ROOTFS_SCHEMA:'rootfs_amendment_receipt',FRONTEND_SCHEMA:'frontend_amendment_receipt'}
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
 if proof['schema']==SIGNING_SCHEMA:command=SIGNING_COMMAND
 if proof['schema']==ROOTFS_SCHEMA:command=ROOTFS_COMMAND
 if proof['schema']==FRONTEND_SCHEMA:command=FRONTEND_COMMAND
 title=LIVE_TITLE if proof['schema']=='djs8-scoped-live-amendment-v1' else CONTROL_TITLE
 if proof['schema']==SIGNING_SCHEMA:title=SIGNING_TITLE
 if proof['schema']==ROOTFS_SCHEMA:title=ROOTFS_TITLE
 if proof['schema']==FRONTEND_SCHEMA:title=FRONTEND_TITLE
 for required in ['④⑤开发中','<td>结论</td><td>✅ 通过</td>','<td>退出码</td><td><code>0</code></td>', '<td>测的是什么</td><td>'+title+'</td>', '<td>命令</td><td><code>'+html.escape(command+' '+sha)+'</code></td>', 'CI_BUILD_SOURCE_SHA='+sha, 'CI_CONTROL_LOG_SHA256='+proof['ci_control_log_sha256']]:
  assert required in body,'committed CI control contract is missing'
 if proof['schema']==FRONTEND_SCHEMA:
  validate_frontend_validation(proof,sha)
  assert 'FRONTEND_VALIDATION_SHA256='+canonical_sha256(proof['frontend_validation']) in body,'actual frontend validation record binding required'
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
 return verify_tree(proof,sha)

def verify_tree(proof,sha):
 assert re.fullmatch('[0-9a-f]{40}',sha)
 assert proof['schema'] in MARKERS and proof['tested_source_sha']==BASE and proof['build_source_sha']==sha and proof['development_evidence']==EVIDENCE
 assert proof['independent_review']=='APPROVE' and re.fullmatch('ev-[0-9a-f]{12}',proof['ci_control_evidence']) and re.fullmatch('[0-9a-f]{64}',proof['ci_control_log_sha256'])
 allowed=FRONTEND_ALLOWED if proof['schema']==FRONTEND_SCHEMA else ROOTFS_ALLOWED if proof['schema']==ROOTFS_SCHEMA else SIGNING_ALLOWED if proof['schema']==SIGNING_SCHEMA else LIVE_ALLOWED if proof['schema']=='djs8-scoped-live-amendment-v1' else ALLOWED
 if proof['schema']==FRONTEND_SCHEMA:
  prior=proof['previous_rootfs_receipt']
  assert prior['schema']==ROOTFS_SCHEMA and prior['build_source_sha']==FRONTEND_BASE
  assert prior['ci_control_evidence']=='ev-172565ad2125','must inherit original committed rootfs control'
  assert canonical_sha256(prior)==proof['previous_rootfs_receipt_sha256']==FRONTEND_PRIOR_SHA256,'fixed inherited rootfs receipt mismatch'
  verify_tree(prior,FRONTEND_BASE)
  previous,current=tree(FRONTEND_BASE),tree(sha)
  amendment={p for p in previous.keys()|current.keys() if previous.get(p)!=current.get(p)}
  assert amendment==FRONTEND_FILES|FRONTEND_CI,'frontend amendment requires exact reviewed eight sources and four protocol files only'
  validate_frontend_validation(proof,sha)
 if proof['schema']==ROOTFS_SCHEMA:
  prior=proof['previous_signing_receipt']
  assert prior['schema']==SIGNING_SCHEMA and prior['build_source_sha']==SIGNING_SOURCE
  assert prior['ci_control_evidence']=='ev-8754072a6d6f','must reuse actual committed signing control'
  verify_tree(prior,SIGNING_SOURCE)
  assert hashlib.sha256(json.dumps(prior,sort_keys=True,separators=(',',':')).encode()).hexdigest()==proof['previous_signing_receipt_sha256']
  previous,current=tree(SIGNING_SOURCE),tree(sha)
  amendment={p for p in previous.keys()|current.keys() if previous.get(p)!=current.get(p)}
  assert amendment and amendment <= frozenset(['.jenkins/Jenkinsfile.plane-ce','.jenkins/scripts/build-plane-images.sh','.jenkins/scripts/verify-ci-tree-equivalence.py','.jenkins/scripts/lib-oci-rootfs-scan.sh','CHANGELOG.md']),'rootfs amendment must change scanner and evidence routing only'
  assert '.jenkins/scripts/lib-oci-rootfs-scan.sh' in amendment
  assert proof['component_validation_sources']=={'pg_web':BASE,'live_amendment':LIVE_SOURCE,'signing_amendment':SIGNING_SOURCE,'rootfs_amendment':sha,'old_live_suite':'historical only'}
  assert proof['original_suite_reexecuted'] is False and proof['live_validation_reexecuted'] is False
 if proof['schema']==SIGNING_SCHEMA:
  prior=proof['previous_live_receipt']
  assert prior['schema']=='djs8-scoped-live-amendment-v1' and prior['build_source_sha']==LIVE_SOURCE
  assert prior['ci_control_evidence']=='ev-9705105277b5','must reuse the actual committed Live control'
  verify_tree(prior,LIVE_SOURCE)
  assert hashlib.sha256(json.dumps(prior,sort_keys=True,separators=(',',':')).encode()).hexdigest()==proof['previous_live_receipt_sha256']
  previous,current=tree(LIVE_SOURCE),tree(sha)
  amendment={p for p in previous.keys()|current.keys() if previous.get(p)!=current.get(p)}
  assert amendment and amendment <= (ALLOWED|frozenset(['.jenkins/scripts/sign-and-sbom.sh','.jenkins/scripts/verify-ci-contract.py'])),'signing amendment must change CI only'
  assert '.jenkins/scripts/sign-and-sbom.sh' in amendment
  assert proof['component_validation_sources']=={'pg_web':BASE,'live_amendment':LIVE_SOURCE,'signing_amendment':sha,'old_live_suite':'historical only'}
  assert proof['original_suite_reexecuted'] is False and proof['live_validation_reexecuted'] is False
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

def validate_prior_live_comment(comments,proof):
 if proof['schema']==FRONTEND_SCHEMA:
  prior=proof['previous_rootfs_receipt'];marker=MARKERS[ROOTFS_SCHEMA]+FRONTEND_BASE
  rows=[r for r in comments if marker in (r.get('comment_html') or '')]
  assert len(rows)==1,'exact original rootfs receipt required'
  row=rows[0];assert row.get('created_by')==row.get('actor')==TRUSTED_AUTHOR
  encoded=re.search(r'<pre>(.*?)</pre>',row.get('comment_html') or '',re.S)
  assert encoded and json.loads(html.unescape(encoded.group(1)))==prior,'prior rootfs receipt differs from trusted Plane readback'
  validate_control_comment(comments,prior,FRONTEND_BASE)
  validate_prior_live_comment(comments,prior)
  return
 if proof['schema']==ROOTFS_SCHEMA:
  prior=proof['previous_signing_receipt'];marker=MARKERS[SIGNING_SCHEMA]+SIGNING_SOURCE
  rows=[r for r in comments if marker in (r.get('comment_html') or '')]
  assert len(rows)==1,'exact original signing receipt required'
  row=rows[0];assert row.get('created_by')==row.get('actor')==TRUSTED_AUTHOR
  encoded=re.search(r'<pre>(.*?)</pre>',row.get('comment_html') or '',re.S)
  assert encoded and json.loads(html.unescape(encoded.group(1)))==prior,'prior signing receipt differs from trusted Plane readback'
  validate_control_comment(comments,prior,SIGNING_SOURCE)
  validate_prior_live_comment(comments,prior)
  return
 if proof['schema']!=SIGNING_SCHEMA:return
 prior=proof['previous_live_receipt'];marker=MARKERS[prior['schema']]+LIVE_SOURCE
 rows=[r for r in comments if marker in (r.get('comment_html') or '')]
 assert len(rows)==1,'exact original Live receipt required'
 row=rows[0];assert row.get('created_by')==row.get('actor')==TRUSTED_AUTHOR
 encoded=re.search(r'<pre>(.*?)</pre>',row.get('comment_html') or '',re.S)
 assert encoded and json.loads(html.unescape(encoded.group(1)))==prior,'prior receipt differs from trusted Plane readback'
 validate_control_comment(comments,prior,LIVE_SOURCE)

def validate_release_binding(payload):
 v=payload['release_build_validation'];source=payload['source']['commit']
 active=[(schema,key) for schema,key in RECEIPT_KEYS.items() if v.get(key)]
 assert len(active)<=1,'conflicting evidence modes'
 if active:
  schema,key=active[0];proof=v[key];assert proof['schema']==schema
  verify(proof,source)
  assert v['development_evidence_reference']==proof['development_evidence']
  assert v['development_evidence_verified_source_sha']==v['tested_source_sha']==proof['tested_source_sha']
  assert v['build_source_sha']==source and v['full_unit_test_suite_executed'] is False
  if schema in (SIGNING_SCHEMA,ROOTFS_SCHEMA,FRONTEND_SCHEMA):assert v['component_validation_sources']==proof['component_validation_sources']
  elif schema=='djs8-scoped-live-amendment-v1':assert v['component_validation_sources']=={'pg_web':BASE,'live_amendment':source,'old_live_suite':'historical only'}
 else:assert v['development_evidence_verified_source_sha']==source
 return True
