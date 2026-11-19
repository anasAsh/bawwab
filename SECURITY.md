# Security Policy

Bawwab is a security tool, so a weakness in Bawwab is a weakness in everyone who relies on it.
Thank you for helping keep the gate shut.

## What counts as a security issue

- **Bypasses.** A malicious MCP server, skill or plugin that ends up installed or active without Bawwab blocking or quarantining it.
- **False "clean".** Malicious code that Bawwab scans as *clean*. This matters most for code that reads credentials and sends them out, or that evaluates downloaded or decoded code.
- **Breaking the gatekeeper.** Making Bawwab approve something, clear a quarantine, or disable itself without the user.
- **Execution during a scan.** Any way scanning a package runs that package's code outside the sandbox.
- **Injection through reports.** Scanned text that steers Claude through Bawwab's own output.

False positives (a legitimate package flagged as suspicious) are bugs, not security issues. Please open a normal issue for those.

## How to report

**Please don't open a public issue for an unfixed bypass.**

Report it privately through GitHub's **[Report a vulnerability](https://github.com/anasAsh/bawwab/security/advisories/new)** button
(Security tab → Advisories). Include:

1. The Bawwab version or commit (`bawwab --version`, or `git rev-parse HEAD`).
2. A **minimal, harmless** reproduction. Use canary values such as `BAWWAB-CANARY` and `.invalid` hosts. Never use live malware or real credentials.
3. What you expected Bawwab to do, and what it did.

## What to expect

- An acknowledgement within **7 days**.
- A fix, or a documented limitation, usually within **30 days**, depending on severity.
- Credit in the release notes and the **Bypass Hall of Fame** below, unless you'd rather stay anonymous.

## Known limitations

Static analysis can be dodged by determined obfuscation. Bawwab's defence in depth (a Claude review that can only raise risk,
a "never below suspicious" floor for credential-plus-network code, and an effect check on what actually changed) raises the bar
but does not promise perfection. Reports that show a way past *all* layers are especially valuable.

## Bypass Hall of Fame

*Be the first.*
