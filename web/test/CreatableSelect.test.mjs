import assert from "node:assert/strict";
import { after, test } from "node:test";

import react from "@vitejs/plugin-react";
import { Window } from "happy-dom";
import React, { act, useState } from "react";
import { createRoot } from "react-dom/client";
import { createServer } from "vite";

const browser = new Window({ url: "http://localhost" });
Object.assign(globalThis, {
  window: browser,
  document: browser.document,
  Node: browser.Node,
  HTMLElement: browser.HTMLElement,
  Event: browser.Event,
  FocusEvent: browser.FocusEvent,
  MouseEvent: browser.MouseEvent,
  IS_REACT_ACT_ENVIRONMENT: true,
});

browser.HTMLElement.prototype.getBoundingClientRect = function getBoundingClientRect() {
  const selectedCount = this.querySelectorAll?.('button[aria-label^="Remove "]').length ?? 0;
  const bottom = 146 + selectedCount * 50;
  return { x: 20, y: 100, top: 100, right: 420, bottom, left: 20, width: 400, height: bottom - 100, toJSON: () => ({}) };
};

const vite = await createServer({
  configFile: false,
  logLevel: "error",
  plugins: [react()],
  server: { middlewareMode: true },
  appType: "custom",
  optimizeDeps: { noDiscovery: true },
});
const { default: CreatableSelect } = await vite.ssrLoadModule("/src/components/CreatableSelect.tsx");
const { OAUTH_PROVIDERS } = await vite.ssrLoadModule("/src/lib/oauthProviders.ts");

after(() => vite.close());

const scopes = [
  "https://www.googleapis.com/auth/spreadsheets.readonly",
  "https://www.googleapis.com/auth/documents.readonly",
  "https://www.googleapis.com/auth/presentations.readonly",
];
const options = scopes.map((value) => ({ value, description: `Description for ${value}` }));

async function mountPicker(initialValues = [], bulkOptions = []) {
  document.body.innerHTML = '<div id="root" style="width: 220px"></div>';
  const root = createRoot(document.getElementById("root"));

  function Harness() {
    const [values, setValues] = useState(initialValues);
    return React.createElement(
      React.Fragment,
      null,
      React.createElement(CreatableSelect, { values, onChange: setValues, options, bulkOptions, placeholder: "Add scopes" }),
      React.createElement("output", { "data-testid": "values" }, values.join("|")),
    );
  }

  await act(async () => root.render(React.createElement(Harness)));
  return root;
}

function optionButton(scope) {
  return [...document.querySelectorAll("button")].find((button) => button.textContent.includes(scope) && !button.getAttribute("aria-label"));
}

async function mouseDown(element) {
  await act(async () => element.dispatchEvent(new MouseEvent("mousedown", { bubbles: true })));
}

function selectedValues() {
  return document.querySelector('[data-testid="values"]').textContent.split("|").filter(Boolean);
}

test("dropdown stays open and repositions while selecting multiple scopes", async () => {
  const root = await mountPicker();
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  assert.equal(document.querySelector('div[style*="top: 150px"]') !== null, true);
  await mouseDown(optionButton(scopes[0]));
  assert.equal(optionButton(scopes[0]).getAttribute("aria-pressed"), "true");
  assert.equal(document.querySelector('div[style*="top: 200px"]') !== null, true);

  await mouseDown(optionButton(scopes[1]));
  assert.equal(optionButton(scopes[0]).getAttribute("aria-pressed"), "true");
  assert.equal(optionButton(scopes[1]).getAttribute("aria-pressed"), "true");
  assert.equal(document.querySelector('div[style*="top: 250px"]') !== null, true);

  await act(async () => root.unmount());
});

test("selected chips and suggestions expose full scope values without truncation", async () => {
  const root = await mountPicker([scopes[0]]);
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  const labels = [...document.querySelectorAll(`span[title="${scopes[0]}"]`)];
  assert.equal(labels.length, 2);
  for (const label of labels) {
    assert.equal(label.textContent, scopes[0]);
    assert.equal(label.classList.contains("break-all"), true);
    assert.equal(label.classList.contains("truncate"), false);
  }
  assert.equal(labels[0].parentElement.classList.contains("max-w-[200px]"), false);

  await act(async () => root.unmount());
});

test("Google exposes complete all-scope and read-only bundles", () => {
  const google = OAUTH_PROVIDERS.find((provider) => provider.id === "google");
  const allScopes = google.scopeBundles.find((bundle) => bundle.label === "ALL SCOPES");
  const readScopes = google.scopeBundles.find((bundle) => bundle.label === "ALL READ SCOPES");

  assert.deepEqual(allScopes.values, google.scopes.map((scope) => scope.value));
  assert.deepEqual(
    readScopes.values,
    google.scopes
      .map((scope) => scope.value)
      .filter((value) => ["openid", "email", "profile"].includes(value) || value.endsWith(".readonly")),
  );
});

test("bulk options add missing scopes, preserve custom scopes, and keep the dropdown open", async () => {
  const google = OAUTH_PROVIDERS.find((provider) => provider.id === "google");
  const root = await mountPicker(["custom.scope"], google.scopeBundles);
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  await mouseDown(optionButton("ALL READ SCOPES"));
  const readBundle = google.scopeBundles.find((bundle) => bundle.label === "ALL READ SCOPES");
  assert.deepEqual(selectedValues(), ["custom.scope", ...readBundle.values]);
  assert.equal(optionButton("ALL READ SCOPES").getAttribute("aria-pressed"), "true");
  assert.equal(optionButton("ALL SCOPES").getAttribute("aria-pressed"), "false");

  await mouseDown(optionButton("ALL SCOPES"));
  const allSelectedValues = selectedValues();
  assert.equal(allSelectedValues.length, google.scopes.length + 1);
  assert.deepEqual(new Set(allSelectedValues), new Set(["custom.scope", ...google.scopes.map((scope) => scope.value)]));
  assert.equal(optionButton("ALL READ SCOPES").getAttribute("aria-pressed"), "true");
  assert.equal(optionButton("ALL SCOPES").getAttribute("aria-pressed"), "true");

  await mouseDown(optionButton("ALL SCOPES"));
  assert.deepEqual(selectedValues(), ["custom.scope"]);
  assert.equal(optionButton("ALL SCOPES").getAttribute("aria-pressed"), "false");

  await act(async () => root.unmount());
});
