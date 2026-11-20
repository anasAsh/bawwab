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
- calls inside scripts it reads: a file named on the command line and run by `sh`/`bash`/`dash`/`zsh`/`ksh`,
  `.`/`source`, `./file` or `make` (its makefiles and the literal, non-glob includes that exist in make's own
  directory), checked as it is when the gate reads it, three nested files deep; and in a file run by
  `python`/`node`/…, calls in a form the gate recognises (literal single-line calls in plain strings or argv lists
  in that file only). A script the gate can't read, over 1 MB or nested deeper is refused too;
- git `!` aliases holding such a call, set on the command line: `git -c alias.X='!…'` and
  `git config [--global|--local|-f F] alias.X '!…'`;
- writing such a call, in a form the gate recognises, into a file (Write/Edit, `tee`, heredocs, redirects).

Every hit is a deny. Whether a deny is a plain refusal (no pending approval, no `bawwab approve` suggestion: the
user runs the command themselves) or an approvable block is best-effort. Hits inside files the gate reads, in
command-line aliases and in writes are usually plain; direct calls and files it can't check are usually
approvable; some write and alias forms still get an approvable block, and a few direct calls can come out plain.

It does **not** cover: a script changed earlier in the same command (a `git checkout`, `git pull`, `cp` or
download before running it), copies, moves, install and rsync of scripts are not checked (a copied script is still read when a covered runner runs it), multi-line argv lists, JS template literals and other interpolated strings, and
imports in Python/Node code, aliases written into a git config file or set through `GIT_CONFIG_*`, git hooks and
other config-borne commands, npm/yarn/pnpm/just/tox scripts, build tools, make includes computed at make time or
matched by a glob, `make -I` include paths, `MAKEFILES=`, `make --eval`, `SHELL :=` in a makefile, process
substitution, `$(cat f)` and `eval`,
`BASH_ENV`, compiled programs, runtime-computed paths, or any program Claude writes and then runs. An agent
instructed to bypass bawwab (for example by prompt injection) could approve through those routes, or by forging
bawwab's state directly. Isolating bawwab's state from Claude (a separate OS user or a sandbox) is the only full
answer today; user-presence approval through a channel the model can't drive is planned for v1.1. Reports of a
route the list above says is refused are in scope; the routes it says are not covered are known limitations.

## Bypass Hall of Fame

*Be the first.*
