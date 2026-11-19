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
    ]
)
