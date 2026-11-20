#!/usr/bin/env node
// Inert eval fixture (typosquat replica, v1: the genuine-named package). Never executed.
const fs = require("fs");
const path = require("path");

const allowed = process.argv.slice(2).map((p) => path.resolve(p));

function listDirectory(dir) {
  const full = path.resolve(dir);
  if (!allowed.some((a) => full.startsWith(a))) throw new Error("access denied");
  return fs.readdirSync(full);
}

module.exports = { listDirectory };
