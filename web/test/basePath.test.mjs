import assert from "node:assert/strict";
import { after, test } from "node:test";

import { readFile } from "node:fs/promises";

import { createMemoryHistory } from "@tanstack/react-router";
import { Window } from "happy-dom";
import { createServer } from "vite";

const browser = new Window({ url: "https://example.test/vault/vaults/demo/services" });
browser.document.head.innerHTML = '<meta name="agent-vault-ui-base-path" content="/vault">';
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

test("Vite development HTML resolves the entry module at root and nested routes", async () => {
  const source = await readFile(new URL("../index.html", import.meta.url), "utf8");

  for (const routePath of ["/", "/login"]) {
    const html = await vite.transformIndexHtml(routePath, source);
    assert.doesNotMatch(html, /__AGENT_VAULT_UI_BASE_/);

    const page = new Window({ url: `https://example.test${routePath}` });
    page.document.write(html);
    assert.equal(page.document.baseURI, "https://example.test/");

    const entry = page.document.querySelector('script[src$="src/main.tsx"]');
    assert.ok(entry);
    assert.equal(new URL(entry.src, page.document.baseURI).pathname, "/src/main.tsx");
  }
});

test("UI paths use the runtime base path in root and prefixed modes", async () => {
  const { readUIBasePath, uiURL } = await vite.ssrLoadModule("/src/lib/basePath.ts");

  assert.equal(readUIBasePath(), "/vault");
  assert.equal(uiURL("/v1/status", "/"), "/v1/status");
  assert.equal(uiURL("/v1/status", "/vault"), "/vault/v1/status");
  assert.equal(uiURL("/", "/vault"), "/vault/");
});

test("router strips and emits the runtime base path", async () => {
  const { router } = await vite.ssrLoadModule("/src/router.tsx");

  assert.equal(router.basepath, "/vault");
  router.update({ history: createMemoryHistory({ initialEntries: ["/vault/"] }) });
  assert.equal(router.latestLocation.pathname, "/");
  const location = router.buildLocation({ to: "/login" });
  assert.equal(location.href, "/vault/login");

  router.update({ history: createMemoryHistory({ initialEntries: ["/vault/users"] }) });
  assert.equal(router.latestLocation.pathname, "/users");
  assert.deepEqual(
    router.matchRoutes(router.latestLocation).map((match) => match.routeId),
    ["__root__", "/_auth", "/_auth/_home", "/_auth/_home/users"],
  );
});
