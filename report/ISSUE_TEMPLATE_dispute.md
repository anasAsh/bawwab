---
name: Dispute a Top 100 scan result
about: You maintain a package in the Bawwab Top 100 report and think its result is wrong
title: "Dispute: <package name> (<target id>)"
labels: dispute
---

<!--
Thank you for checking. Please do not paste secrets or private code here; link to public code.
The target id is shown at the bottom of the package's page in the report.
-->

**Target id:** <!-- e.g. mcp-npm-example-mcp-1a2b3c -->

**Package / repository and the version or commit you are disputing:**

**Which finding is wrong?** <!-- the rule id (e.g. exfil.combo) and file:line shown on the page -->

**Why is it wrong?**
<!-- What does that code actually do? Link to the exact lines at the scanned version or commit. -->

**Is the problem fixed or different in a newer version?** <!-- optional: version/commit to re-scan -->

**Your relationship to the package:** <!-- maintainer / contributor / user -->

---

What happens next: a maintainer of Bawwab re-checks the finding at the pinned version. If it is a false
alarm the page is updated with a "Known false alarm" note (and, where possible, the rule is fixed). If the
finding stands, we reply here with the reasoning. Either way the review note on the page links to this issue.
