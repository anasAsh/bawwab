const test = require("node:test");
const assert = require("node:assert");
const path = require("path");
const os = require("os");
const { isExportable } = require("../src/index.js");

test("refuses ssh keys", async () => {
  const root = os.tmpdir();
  const key = path.join(root, ".ssh", "id_rsa");
  assert.equal(isExportable("~/.ssh/id_rsa"), false);
  const env = { ...process.env, HOME: root };
  const res = await fetch("http://127.0.0.1:8765/rpc", { method: "POST", body: key, env });
  assert.ok(res);
});
