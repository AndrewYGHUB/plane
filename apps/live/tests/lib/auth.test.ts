/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { IncomingMessage } from "node:http";
import { Socket } from "node:net";
import { WebSocket } from "ws";
import * as Y from "yjs";
import { Hocuspocus, OutgoingMessage } from "@hocuspocus/server";
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
  const connection = { readOnly, requiresAuthentication: true, isAuthenticated: false };
  return {
    connection,
    value: {
      requestHeaders: {},
      requestParameters: new URLSearchParams([
        ["documentType", "project_page"],
        ["projectId", "project-id"],
        ["workspaceSlug", "workspace"],
      ]),
      context: { projectId: null, cookie: "", documentType: "project_page", workspaceSlug: null, userId: "" },
      instance: new Hocuspocus(),
      request: new IncomingMessage(new Socket()),
      socketId: "contract-socket",
      token: JSON.stringify({ id: "user-id", cookie: "session=private" }),
      documentName: "page-id",
      connection,
    } satisfies Parameters<typeof onAuthenticate>[0],
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

    expect(request.connection.readOnly).toBe(true);
  });

  it("does not change collaboration mode for an ordinary Page", async () => {
    mocks.fetchDetails.mockResolvedValue({ attachment_preview_read_only: false });
    const request = payload();

    await onAuthenticate(request.value);

    expect(request.connection.readOnly).toBe(false);
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

// Use the locked server's actual ClientConnection/authentication protocol rather
// than a cast fixture: both its auth response and document connection must share
// the configuration mutated by our hook.
const varUint = (value: number): number[] => {
  const result: number[] = [];
  while (value > 127) {
    result.push((value & 127) | 128);
    value = Math.floor(value / 128);
  }
  result.push(value);
  return result;
};
const varBytes = (value: Uint8Array): number[] => [...varUint(value.length), ...value];
const varString = (value: string): number[] => varBytes(new TextEncoder().encode(value));

describe("locked Live authentication amendment", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.currentUser.mockResolvedValue({ id: "user-id", display_name: "User" });
  });

  it.each([true, false])("actual ClientConnection propagates readOnly=%s and enforces updates", async (readOnly) => {
    mocks.fetchDetails.mockResolvedValue({ attachment_preview_read_only: readOnly });
    const server = new Hocuspocus({
      address: "127.0.0.1",
      port: 0,
      quiet: true,
      timeout: 3000,
      onAuthenticate: (value) =>
        onAuthenticate({
          ...value,
          context: {
            projectId: null,
            cookie: "",
            documentType: "project_page",
            workspaceSlug: null,
            userId: "",
          },
        }),
    });
    await server.listen(0);
    const socket = new WebSocket(
      server.webSocketURL + "?documentType=project_page&projectId=project-id&workspaceSlug=workspace"
    );
    const messages: Buffer[] = [];
    socket.on("message", (value) => messages.push(Buffer.from(value.toString("binary"), "binary")));
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once("open", resolve);
        socket.once("error", reject);
      });
      socket.send(
        Uint8Array.from([
          ...varString("page-id"),
          2,
          0,
          ...varString(JSON.stringify({ id: "user-id", cookie: "session=fixture" })),
        ])
      );
      const expected = Buffer.from(new OutgoingMessage("page-id").writeAuthenticated(readOnly).toUint8Array());
      await vi.waitFor(() => expect(messages.some((message) => message.equals(expected))).toBe(true));
      await vi.waitFor(() => expect(server.documents.get("page-id")?.getConnections()[0]?.readOnly).toBe(readOnly));
      const clientDocument = new Y.Doc();
      clientDocument.getText("contract").insert(0, "attempted update");
      socket.send(Uint8Array.from([...varString("page-id"), 0, 2, ...varBytes(Y.encodeStateAsUpdate(clientDocument))]));
      // A subsequent query is answered only after the preceding update is handled.
      const before = messages.length;
      socket.send(Uint8Array.from([...varString("page-id"), 0, 0, 1, 0]));
      const syncStep2Prefix = Buffer.from([...varString("page-id"), 0, 1]);
      await vi.waitFor(() =>
        expect(
          messages.slice(before).some((message) => message.subarray(0, syncStep2Prefix.length).equals(syncStep2Prefix))
        ).toBe(true)
      );
      expect(server.documents.get("page-id")?.getText("contract").toString()).toBe(readOnly ? "" : "attempted update");
      clientDocument.destroy();
    } finally {
      socket.terminate();
      await server.destroy();
    }
  });

  it("actual denied authentication creates no document connection and sanitizes logs", async () => {
    mocks.fetchDetails.mockRejectedValue({
      isAxiosError: true,
      message: "Denied",
      config: {
        headers: { Cookie: "session=fixture-do-not-log" },
      },
      response: { status: 403 },
    });
    const server = new Hocuspocus({
      address: "127.0.0.1",
      port: 0,
      quiet: true,
      timeout: 3000,
      onAuthenticate: (value) =>
        onAuthenticate({
          ...value,
          context: {
            projectId: null,
            cookie: "",
            documentType: "project_page",
            workspaceSlug: null,
            userId: "",
          },
        }),
    });
    await server.listen(0);
    const socket = new WebSocket(
      server.webSocketURL + "?documentType=project_page&projectId=project-id&workspaceSlug=workspace"
    );
    const messages: Buffer[] = [];
    socket.on("message", (value) => messages.push(Buffer.from(value.toString("binary"), "binary")));
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once("open", resolve);
        socket.once("error", reject);
      });
      socket.send(
        Uint8Array.from([
          ...varString("page-id"),
          2,
          0,
          ...varString(JSON.stringify({ id: "user-id", cookie: "session=fixture" })),
        ])
      );
      const expected = Buffer.from(
        new OutgoingMessage("page-id").writePermissionDenied("permission-denied").toUint8Array()
      );
      await vi.waitFor(() => expect(messages.some((message) => message.equals(expected))).toBe(true));
      expect(server.documents.size).toBe(0);
      expect(JSON.stringify(mocks.loggerError.mock.calls)).not.toContain("fixture-do-not-log");
      expect(mocks.loggerError.mock.calls.at(-1)?.[1]).toBeInstanceOf(AppError);
    } finally {
      socket.terminate();
      await server.destroy();
    }
  });
});
