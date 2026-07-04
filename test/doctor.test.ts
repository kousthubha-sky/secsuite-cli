import { test } from "node:test";
import assert from "node:assert/strict";
import { checkNode } from "../src/doctor.js";

test("checkNode enforces the >=22.5 engine floor", () => {
  assert.equal(checkNode("22.4.9").ok, false);
  assert.equal(checkNode("22.5.0").ok, true);
  assert.equal(checkNode("23.0.0").ok, true);
  assert.equal(checkNode("21.99.0").ok, false);
});
