/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import type { TIssueAttachmentPreview } from "@plane/types";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type TIssueAttachmentPreviewErrorReason = "forbidden" | "not_configured" | "unavailable" | "unknown";

type TIssueAttachmentPreviewResolution =
  | {
      status: "ready";
      href: string;
    }
  | {
      status: "unavailable";
    };

export const resolveIssueAttachmentPreview = (
  workspaceSlug: string,
  projectId: string,
  preview: TIssueAttachmentPreview
): TIssueAttachmentPreviewResolution => {
  if (
    !workspaceSlug ||
    !UUID_PATTERN.test(projectId) ||
    preview.preview_status !== "ready" ||
    preview.preview_kind !== "plane_page" ||
    !UUID_PATTERN.test(preview.preview_page_id)
  )
    return { status: "unavailable" };

  return {
    status: "ready",
    href: `/${encodeURIComponent(workspaceSlug)}/projects/${encodeURIComponent(projectId)}/pages/${encodeURIComponent(preview.preview_page_id)}`,
  };
};

export const getIssueAttachmentPreviewErrorReason = (error: unknown): TIssueAttachmentPreviewErrorReason => {
  if (!error || typeof error !== "object") return "unknown";

  const code = "code" in error && typeof error.code === "string" ? error.code : undefined;

  if (code === "preview_not_configured") return "not_configured";
  if (code === "preview_target_forbidden") return "forbidden";
  if (code === "preview_mapping_invalid" || code === "preview_target_unavailable") return "unavailable";

  return "unknown";
};
