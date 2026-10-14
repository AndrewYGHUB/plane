/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppError } from "@/lib/errors";

const mocks = vi.hoisted(() => ({
  currentUser: vi.fn(),
  fetchDetails: vi.fn(),
  loggerError: vi.fn(),
}));

vi.mock("@/services/user.service", () => ({
  UserService: class {
    currentUser = mocks.currentUser;
  },
}));

vi.mock("@/services/page/handler", () => ({
  getPageService: () => ({ fetchDetails: mocks.fetchDetails }),
}));

vi.mock("@plane/logger", () => ({
  logger: { error: mocks.loggerError },
}));

import { onAuthenticate } from "@/lib/auth";

const payload = (readOnly = false) => {
  const connectionConfig = { readOnly };
  return {
    connectionConfig,
    value: {
      requestHeaders: {},
      requestParameters: new URLSearchParams([
        ["documentType", "project_page"],
        ["projectId", "project-id"],
        ["workspaceSlug", "workspace"],
      ]),
      context: {},
      token: JSON.stringify({ id: "user-id", cookie: "session=private" }),
      documentName: "page-id",
      connectionConfig,
    } as Parameters<typeof onAuthenticate>[0],
  };
};

describe("onAuthenticate attachment preview access", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.currentUser.mockResolvedValue({ id: "user-id", display_name: "User" });
  });

  it("makes attachment-derived Page collaboration read-only", async () => {
    mocks.fetchDetails.mockResolvedValue({ attachment_preview_read_only: true });
    const request = payload();

    await onAuthenticate(request.value);

    expect(request.connectionConfig.readOnly).toBe(true);
  });

  it("does not change collaboration mode for an ordinary Page", async () => {
    mocks.fetchDetails.mockResolvedValue({ attachment_preview_read_only: false });
    const request = payload();

    await onAuthenticate(request.value);

    expect(request.connectionConfig.readOnly).toBe(false);
  });

  it("sanitizes a denied Page lookup before logging", async () => {
    mocks.fetchDetails.mockRejectedValue({
      isAxiosError: true,
      message: "Request failed",
      code: "ERR_BAD_RESPONSE",
      config: {
        method: "get",
        url: "/pages/page-id/",
        headers: { Cookie: "session=must-not-log" },
      },
      response: { status: 403, data: { message: "Permission denied" } },
    });

    await expect(onAuthenticate(payload().value)).rejects.toBeInstanceOf(AppError);

    const loggedError = mocks.loggerError.mock.calls.at(-1)?.[1] as AppError;
    expect(loggedError).toBeInstanceOf(AppError);
    expect(loggedError.statusCode).toBe(403);
    expect(loggedError).not.toHaveProperty("config");
    expect(JSON.stringify(loggedError)).not.toContain("must-not-log");
  });
});
