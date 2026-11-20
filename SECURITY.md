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

Bawwab and Claude's tool shell run as the same OS user, so bawwab cannot fully keep its user-only commands
(`approve`, `reject`, `init --skip`, `effects --retry`) from Claude. What the gate refuses is exactly this:

- direct and wrapper invocations it recognises: under bawwab's name, through a renamed symlink or copy of its
  launcher or console script, through `python -m bawwab` or `python -c` code that imports bawwab, and shell writes
  to its store, plugin data dir or venv;
- scripts it reads: a file named on the command line and run by `sh`/`bash`/`dash`/`zsh`/`ksh`, `.`/`source`,
  `./file`, `make` (its makefiles and literal includes) or `python`/`node`/… (that file only), read as it is when
  the gate checks it, three nested files deep;
- git `!` aliases holding such a call (`git -c alias.X='!…'`, `git config alias.X '!…'`);
- writing such a call, in a form the gate recognises, into a file (Write/Edit, `tee`, heredocs, redirects, copying
  a script).

It does **not** cover: interpreter imports, git hooks and other config-borne commands, npm/yarn/pnpm/just/tox
scripts, build tools, process substitution, `$(cat f)` and `eval`, `BASH_ENV`, a script changed after the gate read
it, compiled programs, runtime-computed paths, or any program Claude writes and then runs. An agent instructed to
bypass bawwab (for example by prompt injection) could approve through those routes, or by forging bawwab's state
directly. Isolating bawwab's state from Claude (a separate OS user or a sandbox) is the only full answer today;
user-presence approval through a channel the model can't drive is planned for v1.1. Reports of a route the list
above says is refused are in scope; the routes it says are not covered are known limitations.

## Bypass Hall of Fame

*Be the first.*
