---
description: Bawwab — show what is on hold, help you decide on each item, then offer a full scan
allowed-tools: Bash(bawwab effects), Bash(bawwab init --scan), Bash(bawwab scan --all), AskUserQuestion
---

The user ran /bawwab-run to see what Bawwab (the security scanner for MCP servers, skills and plugins) is doing.

1. Run `bawwab effects`.
   - If the call is blocked with a "⛔ bawwab" message, things are on hold: follow that message's own
     instructions (show it as is, ask about each item with AskUserQuestion, give the commands back). Stop there.
   - If it prints items on hold, show its output in a code block and ask about each item with AskUserQuestion
     (at most 4 per call; options Keep, Remove, Not now). In each question, name the item and its verdict, and
     when the output has a "Claude's recommendation (advice, not a verdict)" line for it, include that
     recommendation and say it is advice: the user decides, and a MALICIOUS item is never presented as safe.
     Then reply with the exact command lines for the answers, copied from that output, one line per item with
     its name as a trailing `# comment`.
   - If it prints "nothing is quarantined", say in one line that nothing is on hold.
2. Then ask with AskUserQuestion whether to start a full scan of everything installed now (it runs in the
   background; results come back as warnings). On yes, run `bawwab scan --all`; if Bawwab says it has not
   scanned this machine yet, run `bawwab init --scan` instead. On no, stop.

Never run `bawwab approve`, `bawwab reject` or `bawwab init --skip`: only the user can, as `!` commands.
