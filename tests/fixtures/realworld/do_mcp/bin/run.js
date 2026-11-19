#!/usr/bin/env node
// Launches the prebuilt binary for this platform. Synthetic fixture.
const { spawn } = require("child_process");
const path = require("path");

const exe = path.join(__dirname, "..", "dist", `mcp-${process.platform}-${process.arch}`);
spawn(exe, process.argv.slice(2), { stdio: "inherit" });
