import assert from "node:assert/strict";
import { after, test } from "node:test";

import react from "@vitejs/plugin-react";
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
  configFile: false,
  logLevel: "error",
  plugins: [react()],
  server: { middlewareMode: true, hmr: false },
  appType: "custom",
  optimizeDeps: { noDiscovery: true },
});

after(() => vite.close());

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
  const location = router.buildLocation({ to: "/login" });
  assert.equal(location.href, "/vault/login");
});
