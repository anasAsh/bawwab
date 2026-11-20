// Loads the extension script into a VM context for unit tests.
const fs = require("fs");
const vm = require("vm");

function load(file, env) {
  const sandbox = vm.createContext({ console, atob, btoa, Buffer, env: { ...env } });
  const code = fs.readFileSync(file, "utf8");
  vm.runInContext(code, sandbox);
  return sandbox;
}

function loadStdin() {
  const sandbox = vm.createContext({ atob });
  return vm.runInContext(fs.readFileSync(0, "utf8"), sandbox);
}

module.exports = { load, loadStdin };
