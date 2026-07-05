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

test("default ignores cover non-JS ecosystems too", () => {
  // Rust/Maven, Python, Gradle, .NET, iOS, Elixir, Flutter, Terraform
  assert.ok(isIgnored("myapp/target/debug/build/serde-abc/output", paths));
  assert.ok(isIgnored("api/__pycache__/views.cpython-312.pyc", paths));
  assert.ok(isIgnored("api/venv/lib/python3.12/site-packages/x.py", paths));
  assert.ok(isIgnored("android/.gradle/caches/x.bin", paths));
  assert.ok(isIgnored("Service/obj/Debug/net8.0/Service.dll", paths));
  assert.ok(isIgnored("ios/Pods/Alamofire/Source/Session.swift", paths));
  assert.ok(isIgnored("phoenix/_build/dev/lib/app/ebin/app.beam", paths));
  assert.ok(isIgnored("phoenix/deps/ecto/lib/ecto.ex", paths));
  assert.ok(isIgnored("flutter/.dart_tool/package_config.json", paths));
  assert.ok(isIgnored("infra/.terraform/providers/aws/provider.exe", paths));
});

test("default ignores do not swallow real source files", () => {
  assert.ok(!isIgnored("src/app/page.tsx", paths));
  assert.ok(!isIgnored("components/JsonLd.jsx", paths));
  assert.ok(!isIgnored("package-lock.json", paths));
  assert.ok(!isIgnored("k-p/package-lock.json", paths));
  // lockfiles are how trivy finds dep CVEs - must never be ignored
  assert.ok(!isIgnored("Cargo.lock", paths));
  assert.ok(!isIgnored("go.mod", paths));
  assert.ok(!isIgnored("poetry.lock", paths));
  // "deps"/"obj" only match as whole path segments, not substrings
  assert.ok(!isIgnored("src/deps_parser.ts", paths));
  assert.ok(!isIgnored("src/object_store.rs", paths));
});
