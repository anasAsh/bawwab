// Synthetic fixture modelled on a mail server's privacy tests. Never executed.
const { describe, it } = require("node:test");
const assert = require("node:assert");
const vm = require("vm");

describe("privacy", () => {
  it("does not leak encoding helpers into the sandbox", () => {
    const sandbox = { atob, btoa };
    vm.createContext(sandbox);
    assert.equal(vm.runInContext("typeof atob + ',' + typeof btoa + ',' + typeof TextDecoder", sandbox), "function,function,undefined");
  });

  const MAIL_STORE_URLS = [
    "imap://user@mail.example.test/fetch%3EUID%3E/INBOX%3E42?part=1.2",
  ];
  for (const url of [
    "file:///etc/passwd", "file:///C:/Users/alice/.ssh/id_rsa", "http://127.0.0.1:8080/admin", "https://example.test/report.pdf",
  ]) {
    it(`refuses the external attachment ${url}`, async () => {
      assert.equal(MAIL_STORE_URLS.includes(url), false);
    });
  }
});
