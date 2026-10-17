#!/usr/bin/env python3
"""Scoped frontend receipt controls; synthetic candidate, unchanged real inherited receipt.

Requires a read-only copy of the original rootfs receipt. Does not execute any old
suite, image verification, build, push, or network request.
"""
import argparse
import copy
import hashlib
import io
from contextlib import redirect_stdout
import html
import json
from pathlib import Path
import runpy
import unittest
import sys
import tempfile
from functools import lru_cache
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
MODULE = runpy.run_path(str(ROOT / '.jenkins/scripts/verify-ci-tree-equivalence.py'))
G = MODULE['verify_tree'].__globals__
CANDIDATE = 'a' * 40
REAL_GIT = lru_cache(maxsize=None)(G['git'])
REAL_TREE = lru_cache(maxsize=None)(G['tree'])
PRIOR = None


def digest(value):
    return G['canonical_sha256'](value)


def candidate_fixture():
    """Model only the uncommitted candidate; inherited commits use real Git objects."""
    candidate = copy.deepcopy(REAL_TREE(G['FRONTEND_BASE']))
    blobs = {}
    for path in G['FRONTEND_FILES'] | G['FRONTEND_CI']:
        content = (ROOT / path).read_bytes()
        oid = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        candidate[path] = ['100644', 'blob', oid]
        blobs[path] = content
    base = REAL_TREE(G['BASE'])
    changed = {p for p in base.keys() | candidate.keys() if base.get(p) != candidate.get(p)}
    entries = {}
    for path in changed:
        content = blobs.get(path)
        if content is None:
            content = REAL_GIT('show', G['FRONTEND_BASE'] + ':' + path)
        entries[path] = {'git_entry': candidate[path], 'sha256': hashlib.sha256(content).hexdigest()}
    proof = {
        'schema': G['FRONTEND_SCHEMA'], 'tested_source_sha': G['BASE'],
        'build_source_sha': CANDIDATE, 'development_evidence': G['EVIDENCE'],
        'independent_review': 'APPROVE', 'ci_control_evidence': 'ev-0123456789ab',
        'ci_control_log_sha256': '1' * 64, 'previous_rootfs_receipt': PRIOR,
        'previous_rootfs_receipt_sha256': G['FRONTEND_PRIOR_SHA256'],
        'component_validation_sources': G['frontend_validation_sources'](CANDIDATE),
        'original_suite_reexecuted': False, 'live_validation_reexecuted': False,
        'frontend_validation': {
            'source_sha': CANDIDATE, 'single_concurrency': True, 'cpu_budget_percent': 90,
            **{key: {'command': command, 'exit_code': 0, 'log_sha256': str(i) * 64}
               for i, (key, command) in enumerate(G['FRONTEND_VALIDATION_COMMANDS'].items(), start=2)},
        },
        'reviewed_ci_entries': entries,
        'unchanged_tree_sha256': digest({p: v for p, v in sorted(candidate.items()) if p not in G['FRONTEND_ALLOWED']}),
    }
    return proof, candidate, blobs


class FrontendProtocolControls(unittest.TestCase):
    def setUp(self):
        self.proof, self.candidate, self.blobs = candidate_fixture()
        self.tree_patch = patch.dict(G, {
            'tree': lambda sha: self.candidate if sha == CANDIDATE else REAL_TREE(sha),
            'git': lambda *args: self.blobs[args[1].split(':', 1)[1]]
                if args[0] == 'show' and args[1].startswith(CANDIDATE + ':')
                and args[1].split(':', 1)[1] in self.blobs
                else REAL_GIT(*(('show', G['FRONTEND_BASE'] + ':' + args[1].split(':', 1)[1])
                               if args[0] == 'show' and args[1].startswith(CANDIDATE + ':') else args)),
        })
        self.tree_patch.start()
        self.addCleanup(self.tree_patch.stop)

    def verify(self, proof=None):
        return G['verify_tree'](proof or self.proof, CANDIDATE)

    def test_positive_real_inherited_receipt_and_exact_candidate_scope(self):
        self.assertEqual(digest(PRIOR), G['FRONTEND_PRIOR_SHA256'])
        self.assertEqual(self.verify(), self.proof)

    def test_inherited_receipt_cannot_be_replaced_or_relabelled(self):
        for field, value in [('build_source_sha', CANDIDATE), ('ci_control_evidence', 'ev-aaaaaaaaaaaa'), ('ci_control_log_sha256', '0' * 64)]:
            with self.subTest(field=field):
                proof = copy.deepcopy(self.proof)
                proof['previous_rootfs_receipt'][field] = value
                proof['previous_rootfs_receipt_sha256'] = digest(proof['previous_rootfs_receipt'])
                with self.assertRaises(AssertionError): self.verify(proof)

    def test_unreviewed_source_or_security_protocol_change_rejected(self):
        for path in ['apps/api/plane/app/views/issue/attachment.py', '.jenkins/scripts/sign-and-sbom.sh', '.jenkins/scripts/lib-oci-rootfs-scan.sh', '.jenkins/scripts/verify-ci-contract.py', 'CHANGELOG.md']:
            with self.subTest(path=path):
                previous = self.candidate.get(path)
                self.candidate[path] = ['100644', 'blob', 'f' * 40]
                with self.assertRaises(AssertionError): self.verify()
                if previous is None: self.candidate.pop(path)
                else: self.candidate[path] = previous

    def test_missing_reviewed_file_and_symlink_rejected(self):
        path = 'packages/utils/src/editor/inline-attachment.ts'
        previous = self.candidate.pop(path)
        with self.assertRaises(AssertionError): self.verify()
        self.candidate[path] = ['120000', 'blob', previous[2]]
        with self.assertRaises(AssertionError): self.verify()

    def test_source_blob_receipt_and_protected_tree_tampering_rejected(self):
        for field in ['unchanged_tree_sha256', 'build_source_sha']:
            proof = copy.deepcopy(self.proof)
            proof[field] = '0' * len(proof[field])
            with self.assertRaises(AssertionError): self.verify(proof)
        proof = copy.deepcopy(self.proof)
        next(iter(proof['reviewed_ci_entries'].values()))['sha256'] = '0' * 64
        with self.assertRaises(AssertionError): self.verify(proof)

    def test_actual_frontend_controls_types_build_and_resource_binding_required(self):
        for key in G['FRONTEND_VALIDATION_COMMANDS']:
            for field, value in [('command', 'old-suite'), ('exit_code', 1), ('exit_code', False), ('log_sha256', ''), ('log_sha256', 'x' * 64)]:
                with self.subTest(key=key, field=field, value=value):
                    proof = copy.deepcopy(self.proof)
                    proof['frontend_validation'][key][field] = value
                    with self.assertRaises(AssertionError): self.verify(proof)
        for field, value in [('source_sha', G['BASE']), ('single_concurrency', False), ('cpu_budget_percent', 100)]:
            proof = copy.deepcopy(self.proof)
            proof['frontend_validation'][field] = value
            with self.assertRaises(AssertionError): self.verify(proof)
        proof = copy.deepcopy(self.proof)
        del proof['frontend_validation']['build']
        with self.assertRaises(AssertionError): self.verify(proof)

    def test_historical_web_cannot_claim_new_source_or_old_suite_rerun(self):
        for field in ['original_suite_reexecuted', 'live_validation_reexecuted']:
            proof = copy.deepcopy(self.proof)
            proof[field] = True
            with self.assertRaises(AssertionError): self.verify(proof)
        proof = copy.deepcopy(self.proof)
        proof['component_validation_sources']['old_web_suite'] = CANDIDATE
        with self.assertRaises(AssertionError): self.verify(proof)

    def test_trusted_control_comment_binds_validation_json_and_new_sha(self):
        proof = self.proof
        body = ''.join([
            '〔PLANETEST1 测试证据 · stage=dev · ' + proof['ci_control_evidence'] + '〕',
            '④⑤开发中', '<td>结论</td><td>✅ 通过</td>', '<td>退出码</td><td><code>0</code></td>',
            '<td>测的是什么</td><td>' + G['FRONTEND_TITLE'] + '</td>',
            '<td>命令</td><td><code>' + html.escape(G['FRONTEND_COMMAND'] + ' ' + CANDIDATE) + '</code></td>',
            'CI_BUILD_SOURCE_SHA=' + CANDIDATE, 'CI_CONTROL_LOG_SHA256=' + proof['ci_control_log_sha256'],
            'FRONTEND_VALIDATION_SHA256=' + digest(proof['frontend_validation']),
            '<td>代码</td><td><code>fixture</code> @ <code>' + CANDIDATE + '</code>',
        ])
        row = {'created_by': G['TRUSTED_AUTHOR'], 'actor': G['TRUSTED_AUTHOR'], 'comment_html': body}
        self.assertTrue(G['validate_control_comment']([row], proof, CANDIDATE))
        for mutation in [dict(row, actor='untrusted'), dict(row, comment_html=body.replace('FRONTEND_VALIDATION_SHA256=', 'MISSING=')), dict(row, comment_html=body.replace(G['FRONTEND_COMMAND'], G['ROOTFS_COMMAND']))]:
            with self.assertRaises(AssertionError): G['validate_control_comment']([mutation], proof, CANDIDATE)
        with self.assertRaises(AssertionError): G['validate_control_comment']([row, row], proof, CANDIDATE)

    def test_prior_plane_readback_chain_requires_exact_trusted_original_receipts(self):
        comments = []
        receipt = PRIOR
        while True:
            sha = receipt['build_source_sha']
            schema = receipt['schema']
            command, title = {
                G['ROOTFS_SCHEMA']: (G['ROOTFS_COMMAND'], G['ROOTFS_TITLE']),
                G['SIGNING_SCHEMA']: (G['SIGNING_COMMAND'], G['SIGNING_TITLE']),
                'djs8-scoped-live-amendment-v1': (G['LIVE_COMMAND'], G['LIVE_TITLE']),
            }[schema]
            body = ''.join([
                '〔PLANETEST1 测试证据 · stage=dev · ' + receipt['ci_control_evidence'] + '〕',
                '④⑤开发中', '<td>结论</td><td>✅ 通过</td>', '<td>退出码</td><td><code>0</code></td>',
                '<td>测的是什么</td><td>' + title + '</td>',
                '<td>命令</td><td><code>' + html.escape(command + ' ' + sha) + '</code></td>',
                'CI_BUILD_SOURCE_SHA=' + sha, 'CI_CONTROL_LOG_SHA256=' + receipt['ci_control_log_sha256'],
                '<td>代码</td><td><code>fixture</code> @ <code>' + sha + '</code>',
            ])
            comments.extend([
                {'created_by': G['TRUSTED_AUTHOR'], 'actor': G['TRUSTED_AUTHOR'], 'comment_html': body},
                {'created_by': G['TRUSTED_AUTHOR'], 'actor': G['TRUSTED_AUTHOR'],
                 'comment_html': G['MARKERS'][schema] + sha + '<pre>' + html.escape(json.dumps(receipt)) + '</pre>'},
            ])
            if schema == 'djs8-scoped-live-amendment-v1': break
            receipt = receipt['previous_signing_receipt' if schema == G['ROOTFS_SCHEMA'] else 'previous_live_receipt']
        G['validate_prior_live_comment'](comments, self.proof)
        for rows in [comments[2:], [dict(row, actor='untrusted') for row in comments]]:
            with self.assertRaises(AssertionError): G['validate_prior_live_comment'](rows, self.proof)
        altered = copy.deepcopy(comments)
        altered[1]['comment_html'] = altered[1]['comment_html'].replace('APPROVE', 'REJECT')
        with self.assertRaises(AssertionError): G['validate_prior_live_comment'](altered, self.proof)

    def test_build_status_parser_accepts_only_new_frontend_mode_and_rejects_conflicts(self):
        source = (ROOT / '.jenkins/scripts/build-plane-images.sh').read_text()
        code = source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        payload = {
            'evidence_id': G['EVIDENCE'], 'item': 'DJS-8', 'stage': 'dev',
            'status': 'plane-readback-verified', 'verified_source_sha': G['BASE'],
            'verified_worktree_clean': True, 'verified_test_result': 'passed', 'verified_exit_code': 0,
            'verified_test_suite': 'djs8-plane-release-contracts-v2',
            'verified_test_command_sha256': 'c0043f78de72ec04445aaf019e3797f84aecab4a223d154a8bf1c5d22004c29b',
            'verified_test_entrypoint_sha256': 'b7af763704b4ea4cbb64884dcc42320d15a72c4b616d0e811759999979728fb0',
            'frontend_amendment_receipt': self.proof,
        }
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory) / 'status.json'
            with patch.object(sys, 'argv', ['status-parser', str(status), G['EVIDENCE'], CANDIDATE]), \
                 patch('runpy.run_path', return_value={**G, 'verify': G['verify_tree']}), redirect_stdout(io.StringIO()):
                status.write_text(json.dumps(payload))
                exec(compile(code, '<build-status-parser>', 'exec'), {})
                payload['rootfs_amendment_receipt'] = PRIOR
                status.write_text(json.dumps(payload))
                with self.assertRaises(AssertionError): exec(compile(code, '<build-status-parser>', 'exec'), {})
        pipeline = (ROOT / '.jenkins/Jenkinsfile.plane-ce').read_text()
        self.assertIn('"DJS8-SCOPED-FRONTEND-AMENDMENT-V1:" + build_source_sha', pipeline)
        self.assertIn('"frontend_amendment_receipt": json.loads', source)

    def test_release_binding_new_receipt_and_conflicting_modes(self):
        validation = {
            'frontend_amendment_receipt': self.proof,
            'development_evidence_reference': G['EVIDENCE'],
            'development_evidence_verified_source_sha': G['BASE'], 'tested_source_sha': G['BASE'],
            'build_source_sha': CANDIDATE, 'full_unit_test_suite_executed': False,
            'component_validation_sources': self.proof['component_validation_sources'],
        }
        payload = {'source': {'commit': CANDIDATE}, 'release_build_validation': validation}
        with patch.dict(G, {'verify': G['verify_tree']}):
            self.assertTrue(G['validate_release_binding'](payload))
            validation['rootfs_amendment_receipt'] = PRIOR
            with self.assertRaises(AssertionError): G['validate_release_binding'](payload)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prior-receipt', required=True, type=Path)
    args = parser.parse_args()
    PRIOR = json.loads(args.prior_receipt.read_text())
    if digest(PRIOR) != G['FRONTEND_PRIOR_SHA256']:
        raise SystemExit('original fixed rootfs receipt required; no test performed')
    unittest.main(argv=[__file__], verbosity=2)
