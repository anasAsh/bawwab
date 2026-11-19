// Copies a bundled default config next to the package. Local only.
const fs = require("fs");
const path = require("path");

fs.copyFileSync(path.join(__dirname, "default.json"), path.join(__dirname, "config.json"));
