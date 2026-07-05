import { test } from "node:test";
import assert from "node:assert/strict";
import { isIgnored } from "../src/config.js";
import { DEFAULT_CONFIG } from "../src/schema.js";

const paths = DEFAULT_CONFIG.ignore.paths;

test("default ignores cover build output at any depth (the .next noise case)", () => {
  // Real-world case: scan started one directory above the repo, so every
  // path carries a "k-p/" prefix - ignores must still match.
  assert.ok(isIgnored("k-p/.next/static/chunks/app/page.js", paths));
  assert.ok(isIgnored("k-p/.next/server/server-reference-manifest.json", paths));
  assert.ok(isIgnored("k-p/node_modules/lodash/index.js", paths));
  // Root-level (no prefix) still matches - `**/` matches zero segments.
  assert.ok(isIgnored(".next/static/chunks/main.js", paths));
  assert.ok(isIgnored("node_modules/x/y.js", paths));
  assert.ok(isIgnored("dist/bundle.js", paths));
});

test("default ignores do not swallow real source files", () => {
  assert.ok(!isIgnored("src/app/page.tsx", paths));
  assert.ok(!isIgnored("components/JsonLd.jsx", paths));
  assert.ok(!isIgnored("package-lock.json", paths));
  assert.ok(!isIgnored("k-p/package-lock.json", paths));
});
