/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  getIssueAttachmentPreviewErrorReason,
  resolveIssueAttachmentPreview,
} from "./attachment-preview.ts";

const workspaceSlug = "cloudhandstack";
const projectId = "27929ddc-faac-445c-9a78-8a9e46d1770f";
const previewPageId = "3f01e59e-167d-4684-a7e2-2fa5e2be6bbd";

test("resolves a verified Plane Page preview to a project-scoped route", () => {
  assert.deepEqual(
    resolveIssueAttachmentPreview(workspaceSlug, projectId, {
      preview_status: "ready",
      preview_kind: "plane_page",
      preview_page_id: previewPageId,
    }),
    {
      status: "ready",
      href: `/cloudhandstack/projects/${projectId}/pages/${previewPageId}`,
    }
  );
});

test("rejects malformed or non-Page preview data instead of constructing an arbitrary URL", () => {
  assert.deepEqual(
    resolveIssueAttachmentPreview(workspaceSlug, projectId, {
      preview_status: "ready",
      preview_kind: "plane_page",
      preview_page_id: "../../api/assets/download",
    }),
    { status: "unavailable" }
  );

  assert.deepEqual(
    resolveIssueAttachmentPreview(workspaceSlug, "not-a-project-id", {
      preview_status: "ready",
      preview_kind: "plane_page",
      preview_page_id: previewPageId,
    }),
    { status: "unavailable" }
  );

  assert.deepEqual(
    resolveIssueAttachmentPreview(workspaceSlug, projectId, {
      preview_status: "ready",
      preview_kind: "external_url",
      preview_page_id: previewPageId,
    }),
    { status: "unavailable" }
  );
});

test("maps backend preview failures to explicit UI reasons", () => {
  assert.equal(getIssueAttachmentPreviewErrorReason({ code: "preview_not_configured" }), "not_configured");
  assert.equal(getIssueAttachmentPreviewErrorReason({ code: "preview_mapping_invalid" }), "unavailable");
  assert.equal(getIssueAttachmentPreviewErrorReason({ code: "preview_target_unavailable" }), "unavailable");
  assert.equal(getIssueAttachmentPreviewErrorReason({ code: "preview_target_forbidden" }), "forbidden");
  assert.equal(getIssueAttachmentPreviewErrorReason({ code: "anything_else" }), "unknown");
  assert.equal(getIssueAttachmentPreviewErrorReason(null), "unknown");
});

test("both attachment click surfaces use the verified same-tab preview path and contain no raw asset fallback", async () => {
  const [detailSource, listSource, previewHookSource] = await Promise.all([
    readFile(new URL("./attachment-detail.tsx", import.meta.url), "utf8"),
    readFile(new URL("./attachment-list-item.tsx", import.meta.url), "utf8"),
    readFile(new URL("./use-issue-attachment-preview.ts", import.meta.url), "utf8"),
  ]);

  for (const clickSurfaceSource of [detailSource, listSource]) {
    assert.match(clickSurfaceSource, /openAttachmentPreview\(attachmentId\)/);
    assert.doesNotMatch(clickSurfaceSource, /asset_url|getFileURL|download/i);
    assert.doesNotMatch(clickSurfaceSource, /window\.open/);
  }

  assert.match(previewHookSource, /getIssueAttachmentPreview/);
  assert.match(previewHookSource, /resolveIssueAttachmentPreview/);
  assert.match(previewHookSource, /window\.location\.assign\(resolution\.href\)/);
  assert.doesNotMatch(previewHookSource, /window\.open/);
  assert.doesNotMatch(previewHookSource, /asset_url|getFileURL|download/i);
});

test("the list-item preview and action boundary does not bubble clicks to the dropzone", async () => {
  const [listSource, listContainerSource] = await Promise.all([
    readFile(new URL("./attachment-list-item.tsx", import.meta.url), "utf8"),
    readFile(new URL("./attachment-item-list.tsx", import.meta.url), "utf8"),
  ]);
  const itemBoundaryStart = listSource.indexOf('<div\n        className="group');
  const previewButtonStart = listSource.indexOf('<button\n          type="button"', itemBoundaryStart);
  const itemBoundary = listSource.slice(itemBoundaryStart, previewButtonStart);

  assert.notEqual(itemBoundaryStart, -1);
  assert.notEqual(previewButtonStart, -1);
  assert.match(listContainerSource, /\{\.\.\.getRootProps\(\)\}/);
  assert.match(itemBoundary, /onClick=\{\(event\) => event\.stopPropagation\(\)\}/);
  assert.match(listSource, /onClick=\{\(\) => void openAttachmentPreview\(attachmentId\)\}/);
  assert.doesNotMatch(listSource, /asset_url|getFileURL|download|window\.open/i);
});
