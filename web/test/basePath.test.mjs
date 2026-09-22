import assert from "node:assert/strict";
import { after, test } from "node:test";
import { readFile } from "node:fs/promises";

import { createMemoryHistory } from "@tanstack/react-router";
import { Window } from "happy-dom";
import { createServer } from "vite";

const browser = new Window({ url: "https://example.test/vault/vaults/demo/services" });
browser.document.head.innerHTML = '<base href="/vault/" />';
Object.assign(globalThis, {
  window: browser,
  self: browser,
  document: browser.document,
  location: browser.location,
  history: browser.history,
  Node: browser.Node,
  HTMLElement: browser.HTMLElement,
});

const vite = await createServer({
  configFile: "./vite.config.ts",
  logLevel: "error",
  server: { middlewareMode: true, hmr: false },
  appType: "custom",
  optimizeDeps: { noDiscovery: true },
});

after(() => vite.close());

test("Vite development HTML resolves its entry module at root and nested routes", async () => {
  const source = await readFile(new URL("../index.html", import.meta.url), "utf8");

  for (const routePath of ["/", "/login"]) {
    const html = await vite.transformIndexHtml(routePath, source);
    const page = new Window({ url: `https://example.test${routePath}` });
    page.document.write(html);
    assert.equal(page.document.baseURI, "https://example.test/");

    const entry = page.document.querySelector('script[src$="src/main.tsx"]');
    assert.ok(entry);
    assert.equal(new URL(entry.src, page.document.baseURI).pathname, "/src/main.tsx");
  }
});

test("base href selects the runtime prefix and joins API URLs", async () => {
  const { basePath, basePathFromBaseHref, joinBasePath } = await vite.ssrLoadModule("/src/lib/basePath.ts");

  assert.equal(basePath, "/vault");
  assert.equal(basePathFromBaseHref("/"), "");
  assert.equal(basePathFromBaseHref("/tools/vault/"), "/tools/vault");
  assert.equal(basePathFromBaseHref("https://example.test/vault/"), "/vault");
  assert.equal(basePathFromBaseHref(null), "");
  assert.equal(joinBasePath("", "/v1/status"), "/v1/status");
  assert.equal(joinBasePath("/vault", "/v1/status"), "/vault/v1/status");
  assert.equal(joinBasePath("/vault", "https://example.test/x"), "https://example.test/x");
});

test("router strips and emits the runtime prefix", async () => {
  const { router } = await vite.ssrLoadModule("/src/router.tsx");

  assert.equal(router.basepath, "/vault");
  router.update({ history: createMemoryHistory({ initialEntries: ["/vault/"] }) });
  assert.equal(router.latestLocation.pathname, "/");
  assert.equal(router.buildLocation({ to: "/login" }).href, "/vault/login");

  router.update({ history: createMemoryHistory({ initialEntries: ["/vault/users"] }) });
  assert.equal(router.latestLocation.pathname, "/users");
  assert.deepEqual(
    router.matchRoutes(router.latestLocation).map((match) => match.routeId),
    ["__root__", "/_auth", "/_auth/_home", "/_auth/_home/users"],
  );
});
