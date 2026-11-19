from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RuleInfo:
    id: str
    title: str
    why: str
    fix: str


def _r(id: str, title: str, why: str, fix: str) -> tuple[str, RuleInfo]:
    return id, RuleInfo(id, title, why, fix)


CATALOG: dict[str, RuleInfo] = dict(
    [
        _r("files.truncated", "Scan limit reached", "Some files were not scanned, so malicious code could hide in them.", "Review the unscanned files manually or raise the limits."),
        _r("rules.error", "A scan rule failed", "A rule crashed, so its findings are missing; the result is incomplete.", "Review the target manually; report the failing rule."),
        _r("install-script", "Runs code at install time", "Install hooks run automatically with your privileges before you can review anything.", "Read the script; prefer packages with no install hooks."),
        _r("install-script.remote", "Install script fetches remote content", "An install hook that downloads content can deliver a payload that differs from what was reviewed.", "Do not install; vendor the download or pin it by hash."),
        _r("remote-code.pipe-shell", "Pipes a download into a shell", "Executes whatever the remote server returns, unreviewed.", "Download, verify a checksum, then run."),
        _r("remote-code.eval-fetch", "Evaluates fetched content", "Code fetched at runtime can change after review.", "Bundle the code instead of fetching it."),
        _r("obfuscation.eval-decoded", "Evaluates decoded content", "Decoding then executing a string is a standard way to hide a payload.", "Replace with plain code; treat the package as hostile."),
        _r("obfuscation.blob", "Large encoded literal", "Long base64/hex strings can carry hidden payloads.", "Check what the blob decodes to."),
        _r("credential-access", "Touches credentials or secrets", "Reads files or environment holding keys, tokens or sessions.", "Confirm the tool needs this; otherwise do not install."),
        _r("exfil.host", "References an exfiltration-style host", "Paste, webhook and tunnel services are commonly used to receive stolen data.", "Remove or justify the destination."),
        _r("exfil.combo", "Reads credentials and makes network calls", "Credential access together with outbound requests in one file is the shape of data theft.", "Do not install unless the flow is understood and benign."),
        _r("deps.unpinned", "Unpinned dependency", "A floating dependency can be swapped for a malicious release later.", "Pin an exact version or commit."),
        _r("injection.override", "Tries to override the AI's instructions", "Text read by the AI that says to ignore earlier instructions, reveal the system prompt or hide things from you is a classic prompt-injection attempt.", "Do not install; the text is trying to steer the assistant against you."),
        _r("injection.covert-action", "Tells the AI to read or send sensitive data", "Instructions to read keys or secrets, include them in replies or send them somewhere, or to do a hidden step first, are how injected text steals data.", "Do not install unless you can explain why this text needs those files."),
        _r("injection.hidden-unicode", "Contains invisible characters", "Zero-width and direction-control characters can hide instructions that you cannot see but the AI reads.", "Remove the invisible characters, or do not install."),
        _r("injection.html-comment", "Hidden instruction in an HTML comment", "HTML comments are invisible when a document is rendered but are still read by the AI, so they can carry instructions meant to stay unseen.", "Read the comment; remove it or do not install."),
        _r("tool-shadowing", "Tool description changes how another tool is used", "A description that names a different tool and tells the AI how to use it (or to use it instead) can quietly hijack that tool, for example by adding a recipient to emails.", "Do not install; a tool should only describe itself."),
        _r("plugin.hook-broad", "Plugin hook runs on every tool call", "A hook with no specific matcher runs a command each time the assistant uses any tool, giving it constant access to your session.", "Check the hook command, and prefer plugins whose hooks match specific tools."),
        _r("plugin.hook-network", "Plugin hook uses the network", "A hook that runs curl, wget, nc or contacts a URL can send data from your machine each time it fires.", "Do not install unless the destination is known and expected."),
        _r("plugin.bundled-mcp", "Plugin bundles an MCP server", "The plugin installs additional MCP servers that run code on your machine and are not covered by this layer alone.", "Review each bundled server as if you were installing it separately."),
        _r("identity.typosquat", "Name is close to a popular package", "Attackers publish packages with names one or two letters off a popular one hoping you mistype it.", "Check the exact spelling and publisher against the official project."),
        _r("identity.new-package", "Package was published very recently", "Brand-new packages have no track record and are a common vehicle for short-lived malicious releases.", "Wait, or verify the author and repository before installing."),
        _r("identity.repo-mismatch", "Repository does not match the package name", "A package whose linked repository has an unrelated name may point to someone else's code to look legitimate.", "Open the repository and confirm it is the real source of this package."),
        _r("fetch.unsafe-entry", "Archive or repo contains an unsafe entry", "Path traversal, absolute paths, links pointing outside the package, or oversized archives are used to overwrite files or exhaust disk during extraction.", "Do not install; the unsafe entries were skipped during scanning."),
        _r("fetch.docker-unscanned", "Docker image was not scanned", "Container images are not statically scanned, so their contents are unreviewed.", "Run a deep scan in the sandbox or review the image manually."),
        _r("fetch.failed", "Target could not be fetched", "The package or server could not be downloaded, so nothing was reviewed.", "Check the name, version and network, then retry."),
    ]
)
