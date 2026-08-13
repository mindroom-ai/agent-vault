import assert from "node:assert/strict";
import { after, test } from "node:test";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import react from "@vitejs/plugin-react";
import { createServer } from "vite";

const vite = await createServer({
  configFile: false,
  logLevel: "error",
  plugins: [react()],
  server: { middlewareMode: true },
  appType: "custom",
  optimizeDeps: { noDiscovery: true },
});
const { default: CreatableSelect, getVisibleOptions } = await vite.ssrLoadModule("/src/components/CreatableSelect.tsx");

after(() => vite.close());

test("selected options remain visible for repeated multi-selection", () => {
  const options = [
    { value: "scope-one", label: "Scope one" },
    { value: "scope-two", label: "Scope two" },
  ];

  assert.deepEqual(
    getVisibleOptions(options, ["scope-one"], "").map(({ value, selected }) => ({ value, selected })),
    [
      { value: "scope-one", selected: true },
      { value: "scope-two", selected: false },
    ],
  );
});

test("selected scopes render their full value without truncation", () => {
  const scope = "https://www.googleapis.com/auth/spreadsheets.readonly";
  const markup = renderToStaticMarkup(
    React.createElement(CreatableSelect, {
      values: [scope],
      onChange: () => {},
      placeholder: "Add scopes",
    }),
  );

  assert.match(markup, new RegExp(`title="${scope}"`));
  assert.doesNotMatch(markup, /truncate|max-w-\[200px\]/);
});
