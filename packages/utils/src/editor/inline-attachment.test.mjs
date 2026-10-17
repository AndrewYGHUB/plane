/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */
/* Sequential mutation probes deliberately match the single-concurrency validation budget. */
/* eslint-disable no-await-in-loop */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import vm from "node:vm";

function pluginMock(spec) {
  return { spec };
}
function pluginKeyMock() {
  return {};
}

const root = new URL("../../../../", import.meta.url);
const require = createRequire(new URL("packages/utils/package.json", root));
const ts = require("typescript");
const load = (path, imports = {}) => {
  const source = readFileSync(new URL(path, root), "utf8");
  const result = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
    reportDiagnostics: true,
  });
  assert.equal(result.diagnostics.length, 0, path);
  const exports = {};
  vm.runInNewContext(result.outputText, {
    exports,
    require: (name) => {
      assert.ok(Object.hasOwn(imports, name), `${path}: unexpected import ${name}`);
      return imports[name];
    },
    console: { error() {} },
  });
  return exports;
};
const inline = load("packages/utils/src/editor/inline-attachment.ts");
const assetUtils = load("packages/utils/src/editor/common.ts", {
  "../file": { getFileURL: (path) => `https://api.example${path}` },
  "./inline-attachment": inline,
});
const workspaceSlug = "cloudhandstack";
const projectId = "27929ddc-faac-445c-9a78-8a9e46d1770f";
const issueId = "40138247-0b17-4dae-837a-c5fcef807d4e";
const assetId = "60fe448e-2e49-481d-94dd-3a7ac963878c";
const path = `/api/assets/v2/workspaces/${workspaceSlug}/projects/${projectId}/issues/${issueId}/attachments/${assetId}/inline/`;
const sourceArgs = (source) => ({ workspaceSlug, projectId, assetId: source });

test("only the fully anchored current-scope inline route resolves; bare assets remain compatible", () => {
  assert.equal(assetUtils.getEditorAssetSrc(sourceArgs(path)), `https://api.example${path}`);
  assert.equal(assetUtils.getEditorAssetDownloadSrc(sourceArgs(path)), undefined);
  assert.equal(
    assetUtils.getEditorAssetSrc(sourceArgs(assetId)),
    `https://api.example/api/assets/v2/workspaces/${workspaceSlug}/projects/${projectId}/${assetId}/`
  );
  assert.equal(
    assetUtils.getEditorAssetDownloadSrc(sourceArgs(assetId)),
    `https://api.example/api/assets/v2/workspaces/${workspaceSlug}/projects/${projectId}/download/${assetId}/`
  );
  assert.equal(
    assetUtils.getEditorAssetSrc({ workspaceSlug, assetId }),
    `https://api.example/api/assets/v2/workspaces/${workspaceSlug}/${assetId}/`
  );
  for (const rejected of [
    path.replace(workspaceSlug, "other"),
    path.replace(projectId, issueId),
    path.replace(issueId, "not-uuid"),
    path.replace(assetId, "not-uuid"),
    `${path}?download=1`,
    `${path}#x`,
    `${path}\n`,
    `${path}extra`,
    path.slice(0, -1),
    `${path}../`,
    path.replace("issues/", "issues/../issues/"),
    path.replace("issues/", "issues/%2e%2e/"),
    path.replace("issues/", "issues\\"),
    `/${path}`,
    `https://evil.example${path}`,
    `../${assetId}`,
    `${assetId}?x`,
  ]) {
    assert.equal(inline.isEditorInlineAttachment(sourceArgs(rejected)), false, rejected);
    assert.equal(assetUtils.getEditorAssetSrc(sourceArgs(rejected)), undefined, rejected);
    assert.equal(assetUtils.getEditorAssetDownloadSrc(sourceArgs(rejected)), undefined, rejected);
  }
  assert.equal(assetUtils.getEditorAssetSrc({ workspaceSlug, assetId: path }), undefined);
});

test("editor handlers resolve inline without download, restore or delete; ordinary asset mutations still work", async () => {
  const calls = [];
  class FileService {
    deleteOldWorkspaceAsset = (...args) => calls.push(["delete-old", ...args]);
    deleteNewAsset = (...args) => calls.push(["delete", ...args]);
    restoreOldEditorAsset = (...args) => calls.push(["restore-old", ...args]);
    restoreNewAsset = (...args) => calls.push(["restore", ...args]);
  }
  const { useEditorConfig } = load("apps/web/core/hooks/editor/use-editor-config.ts", {
    react: { useCallback: (fn) => fn },
    "@plane/utils": assetUtils,
    "@/hooks/store/use-editor-asset": { useEditorAsset: () => ({}) },
    "@/hooks/editor/use-extended-editor-config": {
      useExtendedEditorConfig: () => ({ getExtendedEditorFileHandlers: () => ({}) }),
    },
    "@/hooks/use-file-size": { useFileSize: () => ({ maxFileSize: 100 }) },
    "@/services/file.service": { FileService },
  });
  const handlers = useEditorConfig().getEditorFileHandlers({ workspaceSlug, projectId, workspaceId: "workspace-id" });
  assert.equal(await handlers.getAssetSrc(path), `https://api.example${path}`);
  assert.equal(await handlers.getAssetDownloadSrc(path), "");
  for (const source of [path, `${path}?x`, path.replace(projectId, issueId), `../${assetId}`]) {
    await handlers.restore(source);
    await handlers.delete(source);
  }
  assert.equal(calls.length, 0);
  await handlers.restore(assetId);
  await handlers.delete(assetId);
  assert.equal(calls.length, 2);
  assert.equal(await handlers.getAssetSrc("https://images.example/a.png"), "https://images.example/a.png");
});

const react = {
  useRef: () => ({ current: null }),
  useState: (value) => [value, () => {}],
  useCallback: (fn) => fn,
  useLayoutEffect() {},
  useEffect() {},
};
const jsx = (type, props) => ({ type, props });
const block = load("packages/editor/src/core/extensions/custom-image/components/block.tsx", {
  react,
  "react/jsx-runtime": { jsx, jsxs: jsx },
  "@tiptap/pm/state": { NodeSelection: {} },
  "@plane/utils": { cn: () => "" },
  "../types": { ECustomImageAttributeNames: { ID: "id" } },
  "../utils": {
    ensurePixelString: (value, fallback) => value ?? fallback,
    getImageBlockId: (id) => id,
    isImageDuplicating: () => false,
  },
  "./toolbar": { ImageToolbarRoot() {} },
  "./upload-status": { ImageUploadStatus() {} },
});
const findImage = (node) => {
  if (!node || typeof node !== "object") return;
  if (node?.type === "img") return node;
  for (const child of [node?.props?.children].flat(Infinity)) {
    const found = findImage(child);
    if (found) return found;
  }
};
test("real image onError emits zero restore calls in readonly and retains editable restore", async () => {
  for (const isEditable of [false, true]) {
    let restores = 0;
    let failures = 0;
    const tree = block.CustomImageBlock({
      editor: { isEditable, storage: {} },
      node: { attrs: { src: assetId } },
      extension: {
        options: {
          restoreImage: async () => {
            restores++;
          },
        },
      },
      setFailedToLoadImage: () => {
        failures++;
      },
      src: "https://api.example/image",
    });
    findImage(tree).props.onError();
    await new Promise(setImmediate);
    assert.equal(restores, isEditable ? 1 : 0);
    assert.equal(failures, 1);
  }
});

test("readonly onCreate and transaction plugins emit zero mutations, including after editability changes", async () => {
  let calls = 0;
  const { restorePublicImages } = load("packages/editor/src/core/helpers/image-helpers.ts", {
    "@/constants/extension": { CORE_EXTENSIONS: { IMAGE: "image", CUSTOM_IMAGE: "imageComponent" } },
  });
  const editor = {
    isEditable: false,
    state: { doc: { descendants: (fn) => fn({ type: { name: "image" }, attrs: { src: "https://image.example/a" } }) } },
  };
  restorePublicImages(editor, () => {
    calls++;
  });
  assert.equal(calls, 0);
  editor.isEditable = true;
  restorePublicImages(editor, () => {
    calls++;
  });
  assert.equal(calls, 1);
  for (const name of ["restore", "delete"]) {
    const imports = {
      "@tiptap/pm/state": { Plugin: pluginMock, PluginKey: pluginKeyMock },
      "@plane/utils": { CORE_EXTENSIONS: {} },
      "@/helpers/assets": { CORE_ASSETS_META_DATA_RECORD: {} },
      "@/plane-editor/constants/utility": { NODE_FILE_MAP: {} },
      "@/constants/meta": { CORE_EDITOR_META: {} },
    };
    const pluginModule = load(`packages/editor/src/core/plugins/file/${name}.ts`, imports);
    const plugin = pluginModule[name === "restore" ? "TrackFileRestorationPlugin" : "TrackFileDeletionPlugin"](
      editor,
      () => {
        calls++;
      }
    );
    editor.isEditable = false;
    assert.equal(plugin.spec.appendTransaction([{ docChanged: true }], {}, {}), null);
    assert.equal(calls, 1);
    editor.isEditable = true;
  }
});
