/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { useCallback } from "react";
import { useTranslation } from "@plane/i18n";
import { TOAST_TYPE, setToast } from "@plane/propel/toast";
import { IssueAttachmentService } from "@/services/issue";
import { getIssueAttachmentPreviewErrorReason, resolveIssueAttachmentPreview } from "./attachment-preview";

const issueAttachmentService = new IssueAttachmentService();

type TUseIssueAttachmentPreview = {
  workspaceSlug: string;
  projectId: string;
  issueId: string;
};

export const useIssueAttachmentPreview = (params: TUseIssueAttachmentPreview) => {
  const { workspaceSlug, projectId, issueId } = params;
  const { t } = useTranslation();

  const showPreviewError = useCallback(
    (reason: ReturnType<typeof getIssueAttachmentPreviewErrorReason>) => {
      const messageKey =
        reason === "not_configured"
          ? "attachment.preview_not_ready"
          : reason === "forbidden"
            ? "attachment.preview_forbidden"
            : reason === "unavailable"
              ? "attachment.preview_unavailable"
              : "attachment.preview_failed";

      setToast({
        type: TOAST_TYPE.ERROR,
        title: t("toast.error"),
        message: t(messageKey),
      });
    },
    [t]
  );

  const openAttachmentPreview = useCallback(
    async (attachmentId: string) => {
      try {
        const preview = await issueAttachmentService.getIssueAttachmentPreview(
          workspaceSlug,
          projectId,
          issueId,
          attachmentId
        );
        const resolution = resolveIssueAttachmentPreview(workspaceSlug, projectId, preview);

        if (resolution.status !== "ready") {
          showPreviewError("unavailable");
          return;
        }

        window.location.assign(resolution.href);
      } catch (error) {
        showPreviewError(getIssueAttachmentPreviewErrorReason(error));
      }
    }, [issueId, projectId, showPreviewError, workspaceSlug]
  );

  return { openAttachmentPreview };
};
