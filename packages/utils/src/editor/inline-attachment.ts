/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

const UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
const INLINE_ATTACHMENT_PATH = new RegExp(
  `^/api/assets/v2/workspaces/([a-zA-Z0-9_-]+)/projects/(${UUID})/issues/(${UUID})/attachments/(${UUID})/inline/$`
);

/** Only allow the exact authenticated inline route in the current editor scope. */
export const isEditorInlineAttachment = (args: {
  assetId: string;
  projectId?: string;
  workspaceSlug: string;
}): boolean => {
  const match = INLINE_ATTACHMENT_PATH.exec(args.assetId);
  return !!match && match[0] === args.assetId && match[1] === args.workspaceSlug && match[2] === args.projectId;
};
