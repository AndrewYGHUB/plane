/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

// plane imports
import type { onAuthenticatePayload } from "@hocuspocus/server";
import type { TUserDetails } from "@plane/editor";
import type { TPage } from "@plane/types";
import { logger } from "@plane/logger";
import { AppError } from "@/lib/errors";
// services
import { UserService } from "@/services/user.service";
import { getPageService } from "@/services/page/handler";
// types
import type { HocusPocusServerContext, TDocumentTypes } from "@/types";

type OnAuthenticatePayloadWithContext = Omit<onAuthenticatePayload, "context"> & {
  context: HocusPocusServerContext;
};

type AttachmentPreviewPageDetails = TPage & {
  attachment_preview_read_only?: boolean;
};

/**
 * Authenticate the user
 * @param requestHeaders - The request headers
 * @param context - The context
 * @param token - The token
 * @returns The authenticated user
 */
export const onAuthenticate = async ({
  requestHeaders,
  requestParameters,
  context,
  token,
  documentName,
  connection,
}: OnAuthenticatePayloadWithContext) => {
  let cookie: string | undefined = undefined;
  let userId: string | undefined = undefined;

  // Extract cookie (fallback to request headers) and userId from token (for scenarios where
  // the cookies are not passed in the request headers)
  try {
    const parsedToken = JSON.parse(token) as TUserDetails;
    userId = parsedToken.id;
    cookie = parsedToken.cookie;
  } catch (error) {
    const appError = new AppError(error, {
      context: { operation: "onAuthenticate" },
    });
    logger.error("Token parsing failed, using request headers", appError);
  } finally {
    // If cookie is still not found, fallback to request headers
    if (!cookie) {
      cookie = requestHeaders.cookie?.toString();
    }
  }

  if (!cookie || !userId) {
    const appError = new AppError("Credentials not provided", { code: "AUTH_MISSING_CREDENTIALS" });
    logger.error("Credentials not provided", appError);
    throw appError;
  }

  // set cookie in context, so it can be used throughout the ws connection
  context.cookie = cookie ?? requestParameters.get("cookie") ?? "";
  context.documentType = requestParameters.get("documentType")?.toString() as TDocumentTypes;
  context.projectId = requestParameters.get("projectId");
  context.userId = userId;
  context.workspaceSlug = requestParameters.get("workspaceSlug");

  const authenticatedUser = await handleAuthentication({
    cookie: context.cookie,
    userId: context.userId,
  });

  // Hocuspocus authentication must authorize the requested document, not just
  // the user identity. The API Page detail endpoint is the policy authority;
  // it also enforces attachment-derived Page visibility for restricted Guests.
  const pageService = getPageService(context.documentType, context);
  let pageDetails: AttachmentPreviewPageDetails;
  try {
    pageDetails = (await pageService.fetchDetails(documentName)) as AttachmentPreviewPageDetails;
  } catch (error) {
    // AppError deliberately drops Axios config/headers so a denied Page lookup
    // can never place the session cookie in Live logs.
    const appError = new AppError(error, {
      context: { operation: "authorizeDocument", documentName },
    });
    logger.error("Document authorization failed", appError);
    throw appError;
  }

  if (pageDetails.attachment_preview_read_only === true) {
    connection.readOnly = true;
  }

  return authenticatedUser;
};

export const handleAuthentication = async ({ cookie, userId }: { cookie: string; userId: string }) => {
  // fetch current user info
  try {
    const userService = new UserService();
    const user = await userService.currentUser(cookie);
    if (user.id !== userId) {
      throw new AppError("Authentication unsuccessful: User ID mismatch", { code: "AUTH_USER_MISMATCH" });
    }

    return {
      user: {
        id: user.id,
        name: user.display_name,
      },
    };
  } catch (error) {
    const appError = new AppError(error, {
      context: { operation: "handleAuthentication" },
    });
    logger.error("Authentication failed", appError);
    throw new AppError("Authentication unsuccessful", { code: appError.code });
  }
};
