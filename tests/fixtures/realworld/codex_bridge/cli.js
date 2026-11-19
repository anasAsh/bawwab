#!/usr/bin/env node
// Synthetic fixture modelled on an agent-installer CLI. Never executed.
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");

const CHOICES = [
  { label: "Install globally to ~/.claude/agents/", value: "global" },
  { label: "Global (~/.claude/ or ~/.agents/)", value: "both" },
];

function install(name, body) {
  const dir = path.join(os.homedir(), ".claude", "agents");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${name}.md`), body);
  fs.writeFileSync(`${os.homedir()}/.claude/skills/${name}/SKILL.md`, body);
  https.get("https://registry.npmjs.org/codex-bridge-fixture/latest", () => {});
}

module.exports = { CHOICES, install };
