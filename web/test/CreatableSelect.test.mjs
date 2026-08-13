import assert from "node:assert/strict";
import { after, afterEach, test } from "node:test";

import react from "@vitejs/plugin-react";
import { Window } from "happy-dom";
import { createServer } from "vite";

const browser = new Window({ url: "http://localhost" });
Object.assign(globalThis, {
  window: browser,
  document: browser.document,
  Node: browser.Node,
  HTMLElement: browser.HTMLElement,
  Event: browser.Event,
  FocusEvent: browser.FocusEvent,
  InputEvent: browser.InputEvent,
  KeyboardEvent: browser.KeyboardEvent,
  MouseEvent: browser.MouseEvent,
  IS_REACT_ACT_ENVIRONMENT: true,
});
const { default: React, act, useState } = await import("react");
const { createRoot } = await import("react-dom/client");

let wrapperTop = 100;
let viewportHeight = 768;
let nextAnimationFrameId = 1;
const pendingAnimationFrames = new Map();
Object.defineProperty(browser, "innerHeight", { configurable: true, get: () => viewportHeight });
browser.requestAnimationFrame = (callback) => {
  const id = nextAnimationFrameId++;
  pendingAnimationFrames.set(id, callback);
  return id;
};
browser.cancelAnimationFrame = (id) => pendingAnimationFrames.delete(id);
Object.defineProperty(browser.HTMLElement.prototype, "scrollHeight", {
  configurable: true,
  get() {
    if (this.getAttribute?.("role") === "listbox") {
      return Math.min(256, this.querySelectorAll('[role="option"]').length * 40);
    }
    return 0;
  },
});
browser.HTMLElement.prototype.getBoundingClientRect = function getBoundingClientRect() {
  const selectedCount = this.querySelectorAll?.('button[aria-label^="Remove "]').length ?? 0;
  const selectedValues = this.querySelector?.("[data-selected-values]");
  const visibleSelectedCount = selectedValues?.classList.contains("max-h-40") ? Math.min(selectedCount, 3) : selectedCount;
  const bottom = wrapperTop + 46 + visibleSelectedCount * 50;
  return { x: 20, y: wrapperTop, top: wrapperTop, right: 420, bottom, left: 20, width: 400, height: bottom - wrapperTop, toJSON: () => ({}) };
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
let mountedRoot;
afterEach(async () => {
  if (mountedRoot) await act(async () => mountedRoot.unmount());
  mountedRoot = undefined;
  document.body.innerHTML = "";
  wrapperTop = 100;
  viewportHeight = 768;
  pendingAnimationFrames.clear();
});

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
  mountedRoot = root;
  return root;
}

function optionButton(scope) {
  return [...document.querySelectorAll("button")].find((button) => button.textContent.includes(scope) && !button.getAttribute("aria-label"));
}

async function mouseDown(element) {
  await act(async () => element.dispatchEvent(new MouseEvent("mousedown", { bubbles: true })));
}

async function clickElement(element) {
  await act(async () => {
    element.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    element.dispatchEvent(new MouseEvent("mouseup", { bubbles: true }));
    element.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  });
}

async function setQuery(input, value) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(browser.HTMLInputElement.prototype, "value").set.call(input, value);
    input.dispatchEvent(new InputEvent("input", { bubbles: true, data: value, inputType: "insertText" }));
  });
}

async function keyDown(element, key) {
  await act(async () => element.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true })));
}

async function flushAnimationFrames() {
  const callbacks = [...pendingAnimationFrames.values()];
  pendingAnimationFrames.clear();
  await act(async () => callbacks.forEach((callback) => callback(0)));
}

function selectedValues() {
  return document.querySelector('[data-testid="values"]').textContent.split("|").filter(Boolean);
}

test("dropdown stays open and repositions while selecting multiple scopes", async () => {
  const root = await mountPicker();
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  assert.equal(document.querySelector('div[style*="top: 150px"]') !== null, true);
  await clickElement(optionButton(scopes[0]));
  assert.equal(optionButton(scopes[0]).getAttribute("aria-selected"), "true");
  assert.equal(document.querySelector('div[style*="top: 200px"]') !== null, true);

  await clickElement(optionButton(scopes[1]));
  assert.equal(optionButton(scopes[0]).getAttribute("aria-selected"), "true");
  assert.equal(optionButton(scopes[1]).getAttribute("aria-selected"), "true");
  assert.equal(document.querySelector('div[style*="top: 250px"]') !== null, true);

  await act(async () => root.unmount());
  mountedRoot = undefined;
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
  mountedRoot = undefined;
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

  await clickElement(optionButton("ALL READ SCOPES"));
  const readBundle = google.scopeBundles.find((bundle) => bundle.label === "ALL READ SCOPES");
  assert.deepEqual(selectedValues(), ["custom.scope", ...readBundle.values]);
  assert.equal(optionButton("ALL READ SCOPES").getAttribute("aria-selected"), "true");
  assert.equal(optionButton("ALL SCOPES").getAttribute("aria-selected"), "false");
  const selectedValuesContainer = document.querySelector("[data-selected-values]");
  assert.equal(selectedValuesContainer.classList.contains("max-h-40"), true);
  assert.equal(selectedValuesContainer.classList.contains("overflow-y-auto"), true);
  assert.equal(document.querySelector('div[style*="top: 300px"]') !== null, true);

  await clickElement(optionButton("ALL SCOPES"));
  const allSelectedValues = selectedValues();
  assert.equal(allSelectedValues.length, google.scopes.length + 1);
  assert.deepEqual(new Set(allSelectedValues), new Set(["custom.scope", ...google.scopes.map((scope) => scope.value)]));
  assert.equal(optionButton("ALL READ SCOPES").getAttribute("aria-selected"), "true");
  assert.equal(optionButton("ALL SCOPES").getAttribute("aria-selected"), "true");

  await clickElement(optionButton("ALL SCOPES"));
  assert.deepEqual(selectedValues(), ["custom.scope"]);
  assert.equal(optionButton("ALL SCOPES").getAttribute("aria-selected"), "false");

  await act(async () => root.unmount());
  mountedRoot = undefined;
});

test("multiselect exposes a named combobox, listbox, and active option", async () => {
  const root = await mountPicker([scopes[0]]);
  const input = document.querySelector("input");

  assert.equal(input.getAttribute("aria-label"), "Add scopes");
  assert.equal(input.getAttribute("role"), "combobox");
  assert.equal(input.getAttribute("aria-expanded"), "false");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  const listboxId = input.getAttribute("aria-controls");
  const listbox = document.getElementById(listboxId);
  assert.equal(input.getAttribute("aria-expanded"), "true");
  assert.equal(listbox.getAttribute("role"), "listbox");
  assert.equal(listbox.getAttribute("aria-multiselectable"), "true");
  assert.equal(document.getElementById(input.getAttribute("aria-activedescendant")).getAttribute("role"), "option");

  await keyDown(input, "ArrowDown");
  assert.equal(document.getElementById(input.getAttribute("aria-activedescendant")).getAttribute("role"), "option");

  await act(async () => root.unmount());
  mountedRoot = undefined;
});

test("listbox options stay out of the Tab order and activate through click", async () => {
  const root = await mountPicker();
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  const option = optionButton(scopes[0]);
  assert.equal(option.tabIndex, -1);
  await act(async () => option.click());
  assert.deepEqual(selectedValues(), [scopes[0]]);
  assert.equal(document.querySelector('[role="listbox"]') !== null, true);

  await act(async () => root.unmount());
  mountedRoot = undefined;
});

test("menu remeasures after filtering and reanchors on scroll and resize", async () => {
  wrapperTop = 620;
  const root = await mountPicker();
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));
  assert.equal(document.querySelector('[role="listbox"]').style.top, "496px");

  await setQuery(input, scopes[0]);
  assert.equal(document.querySelector('[role="listbox"]').style.top, "670px");

  wrapperTop = 300;
  await act(async () => document.getElementById("root").dispatchEvent(new Event("scroll", { bubbles: false })));
  await act(async () => document.getElementById("root").dispatchEvent(new Event("scroll", { bubbles: false })));
  assert.equal(pendingAnimationFrames.size, 1);
  assert.equal(document.querySelector('[role="listbox"]').style.top, "670px");
  await flushAnimationFrames();
  assert.equal(document.querySelector('[role="listbox"]').style.top, "350px");

  await setQuery(input, "");
  viewportHeight = 400;
  await act(async () => window.dispatchEvent(new Event("resize")));
  assert.equal(pendingAnimationFrames.size, 1);
  await flushAnimationFrames();
  assert.equal(document.querySelector('[role="listbox"]').style.top, "176px");

  await act(async () => root.unmount());
  mountedRoot = undefined;
});

test("menu height never exceeds the available viewport space", async () => {
  wrapperTop = 30;
  viewportHeight = 100;
  const root = await mountPicker();
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  const listbox = document.querySelector('[role="listbox"]');
  assert.equal(listbox.style.top, "4px");
  assert.equal(listbox.style.maxHeight, "26px");

  await act(async () => root.unmount());
  mountedRoot = undefined;
});

test("keyboard bulk selection never stores its label and custom creation still works", async () => {
  const google = OAUTH_PROVIDERS.find((provider) => provider.id === "google");
  const root = await mountPicker([], google.scopeBundles);
  const input = document.querySelector("input");
  await act(async () => input.dispatchEvent(new FocusEvent("focusin", { bubbles: true })));

  await setQuery(input, "ALL SCOPES");
  assert.equal(input.value, "ALL SCOPES");
  assert.equal([...document.querySelectorAll("button")].some((button) => button.textContent.includes('Add "ALL SCOPES"')), false);
  await keyDown(input, "Enter");
  assert.equal(selectedValues().includes("ALL SCOPES"), false);
  assert.deepEqual(new Set(selectedValues()), new Set(google.scopes.map((scope) => scope.value)));

  await mouseDown(document.querySelector('button[aria-label="Clear all"]'));
  await setQuery(input, "custom.scope.created");
  assert.equal(input.value, "custom.scope.created");
  await keyDown(input, "Enter");
  assert.deepEqual(selectedValues(), ["custom.scope.created"]);

  await act(async () => root.unmount());
  mountedRoot = undefined;
});
