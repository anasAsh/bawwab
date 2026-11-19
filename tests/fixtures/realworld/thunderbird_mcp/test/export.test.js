const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const os = require("os");
const { isExportable } = require("../src/index.js");

test("refuses ssh keys", () => {
  const root = os.tmpdir();
  const key = path.join(root, ".ssh", "id_rsa");
  assert.equal(isExportable(key), false);
  assert.equal(isExportable("~/.ssh/id_rsa"), false);
});

test("bridge answers", async () => {
  const env = { ...process.env, HOME: os.tmpdir() };
  const res = await fetch("http://127.0.0.1:8765/rpc", { method: "POST", body: "{}", env });
  assert.ok(res);
});
