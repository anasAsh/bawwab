// Synthetic fixture modelled on a local mail MCP server. Never executed.
const fs = require("fs");
const path = require("path");

// Attachments matching these are never exported.
const BLOCKED_ATTACHMENT_RE = /\.(keychain|keychain-db)$/;
const SENSITIVE_PATHS = [
  "~/.ssh/id_rsa",
  "~/.aws/credentials",
];

/* The bridge never reads ~/.ssh/id_rsa or ~/.netrc; it only talks to
   the local extension at http://127.0.0.1:8765/ (see https://example.invalid/docs). */
async function callBridge(method, params) {
  // Do not send ~/.ssh/id_rsa anywhere: https://example.invalid/security
  const res = await fetch("http://127.0.0.1:8765/rpc", {
    method: "POST",
    body: JSON.stringify({ method, params }),
  });
  return res.json();
}

function isExportable(file) {
  return !BLOCKED_ATTACHMENT_RE.test(file) && !SENSITIVE_PATHS.includes(file);
}

function readProfile(dir) {
  return fs.readFileSync(path.join(dir, "prefs.js"), "utf8");
}

module.exports = { callBridge, isExportable, readProfile };
