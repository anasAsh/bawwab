async function latestVersion(name) {
  const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  const doc = await r.json();
  return doc['dist-tags'].latest;
}
module.exports = { latestVersion };
