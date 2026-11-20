"""A Python script fed to `python3 -` by a quoted heredoc that edits bawwab's own source (a dev checkout).

Seen while developing bawwab in its own repo: a heredoc script that rewrote `bawwab/effects.py` with
`s.replace(...)` / `p.write_text(s)` was refused with "interpreter may write Claude/bawwab config: python3;
bawwab approval via tool call", although it never ran bawwab and wrote no Claude/bawwab state or config.

Root causes (bawwab/gate/detect.py):
- "interpreter may write Claude/bawwab config": the interpreter branch of `_bash_pass` checks the script text
  (stdin heredoc included) with `_sensitive_text`, whose `_BAWWAB_CODE` pattern matched `from bawwab` inside a
  Python string literal (the new source being written).
- "bawwab approval via tool call": the heredoc fail-safe at the end of `_bash_pass` (every terminated body is
  also read as commands, in prose mode) read `p = Path("bawwab/effects.py")` as a subshell whose lone command word `bawwab/effects.py` resolves to a
  file whose head imports bawwab (`bawwab_exe_file`), so `_bawwab_decision`'s lone-word rule failed closed;
  `_run_file` also read that module as a shell script.

Not fixed: each narrowing found drops a case the gate refuses today (see the xfail reasons). The true
positives below pin what any future fix must keep refusing.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from bawwab.gate.detect import HookInput, Protected, detect_install

HEREDOC = "python3 - <<'EOF'\n{}\nEOF"

# Modelled on the refused command: the new source sits in a ''' string; it imports bawwab and holds f-strings
# naming approve/reject. The script only reads and writes bawwab/effects.py (relative to cwd).
EDIT_SOURCE = '''from pathlib import Path
p = Path("bawwab/effects.py")
s = p.read_text()
start = s.index("def _summary(q: dict) -> str:")
end = s.index("def _deny(reason: str) -> dict:")
new = \'\'\'def _why(q: dict, findings: list) -> str:
    from bawwab.scan.rules.catalog import CATALOG

    return "; ".join(CATALOG)


def quarantine_text(entries: list[dict]) -> str:
    keep: list[str] = []
    lines: list[str] = []
    if keep:
        lines.append(f"  keep:     ! {cmd('approve')} {' '.join(keep)}")
    lines.append(f"  remove:   ! {cmd('reject')} <ID>")
    return "\\\\n".join(lines)


\'\'\'
s = s[:start] + new + s[end:]
p.write_text(s)'''

# The same edit with no bawwab code in its strings: isolates the fail-safe's lone-word hit.
EDIT_PLAIN = '''from pathlib import Path
p = Path("bawwab/effects.py")
s = p.read_text()
p.write_text(s.replace("old", "new"))'''

EFFECTS_STUB = '''"""Effect check (stub of the real module)."""
from __future__ import annotations

from bawwab.clicmd import cmd


def _summary(q: dict) -> str:
    return ""


def _deny(reason: str) -> dict:
    return {}
'''


def _det(cmd: str, cwd: Path):
    return detect_install(HookInput("Bash", {"command": cmd}, str(cwd)))


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    """A bawwab dev checkout: bawwab/effects.py imports bawwab (not executable)."""
    repo = tmp_path / "repo"
    (repo / "bawwab").mkdir(parents=True)
    (repo / "bawwab" / "effects.py").write_text(EFFECTS_STUB)
    return repo


@pytest.fixture
def plain_dir(tmp_path: Path) -> Path:
    d = tmp_path / "plain"
    d.mkdir()
    return d


# ------------------------------------------------------------------ the false positive (documented, not fixed)

@pytest.mark.xfail(strict=True, reason=(
    "FP not fixed: `from bawwab` inside a string literal trips _BAWWAB_CODE (_sensitive_text). Blanking "
    "string literals would let a heredoc script write new bawwab-importing code that Write/Edit refuse as an "
    "added protected line (R56 b), or exec/import it from a string; see the module docstring."))
def test_fp_bawwab_code_in_string_literal(plain_dir: Path):
    assert _det(HEREDOC.format(EDIT_SOURCE), plain_dir) is None


@pytest.mark.xfail(strict=True, reason=(
    "FP not fixed: the R55 heredoc fail-safe re-reads the Python body as shell; `Path(\"bawwab/effects.py\")` "
    "gives the lone command word bawwab/effects.py, which resolves to a module that imports bawwab. Skipping "
    "the fail-safe for Python bodies drops its cover for heredocs the parser misjudges."))
def test_fp_python_path_literal_read_as_command(checkout: Path):
    assert _det(HEREDOC.format(EDIT_PLAIN), checkout) is None


@pytest.mark.xfail(strict=True, reason="FP not fixed: both causes above (the command as refused).")
def test_fp_as_refused(checkout: Path):
    assert _det(f"cd {checkout} && " + HEREDOC.format(EDIT_SOURCE), checkout) is None


def test_fp_reasons_today(checkout: Path, plain_dir: Path):
    """Pins the two causes as they fire today, so a fix shows up here (and in the xfails above)."""
    r1 = _det(HEREDOC.format(EDIT_SOURCE), plain_dir)
    assert isinstance(r1, Protected) and r1.reason == "interpreter may write Claude/bawwab config: python3"
    r2 = _det(HEREDOC.format(EDIT_PLAIN), checkout)
    assert isinstance(r2, Protected) and r2.reason == "bawwab approval via tool call"
    assert _det(HEREDOC.format(EDIT_PLAIN), plain_dir) is None  # no module at that path: nothing to resolve


# ------------------------------------------------------------------ the closest true positives (must stay refused)

def _bh() -> str:
    return os.environ["BAWWAB_HOME"]


def _claude() -> str:
    return os.path.join(os.environ["HOME"], ".claude")


RUNS_BAWWAB = {
    "subprocess-argv": 'import subprocess\nsubprocess.run(["bawwab", "approve", "DL32"])',
    "subprocess-argv-split": 'import subprocess\nsubprocess.run([\n    "bawwab",\n    "approve",\n    "DL32",\n])',
    "subprocess-argv-var": 'import subprocess\nsub = "approve"\nsubprocess.run(["bawwab", sub, "DL32"])',
    "subprocess-shell": 'import subprocess\nsubprocess.run("bawwab reject DL32", shell=True)',
    "os-system": 'import os\nos.system("bawwab approve DL32 --force")',
    "fstring-cmd": 'import os\nqid = "DL32"\nos.system(f"bawwab approve {qid}")',
    "init-skip": 'import subprocess\nsubprocess.run(["bawwab", "init", "--skip"])',
    "effects-retry": 'import subprocess\nsubprocess.check_call("bawwab effects --retry", shell=True)',
}


def _drives_bawwab() -> dict[str, str]:
    return {
        "import-store": 'from bawwab.store import open_store\nopen_store().approve("DL32")',
        "import-module": 'import bawwab.store\nbawwab.store.open_store().approve("DL32")',
        "importlib": 'import importlib\nimportlib.import_module("bawwab.store").open_store().approve("DL32")',
        "dunder-import": '__import__("bawwab.store")',
        "exec-string": 'exec("from bawwab.store import open_store; open_store().approve(\'DL32\')")',
        "runpy-module": 'import runpy, sys\nsys.argv = ["bawwab", "approve", "DL32"]\nrunpy.run_module("bawwab.cli")',
    }


def _writes_state() -> dict[str, str]:
    bh, ch = _bh(), _claude()
    return {
        "bawwab-db": f'open("{bh}/bawwab.db", "wb").write(b"")',
        "bawwab-db-pathlib": f'from pathlib import Path\nPath("{bh}", "bawwab.db").write_bytes(b"")',
        "quarantine-flag": f'import os\nos.remove("{bh}/quarantine.flag")',
        "claude-settings": (f'import json\np = "{ch}/settings.json"\nd = json.load(open(p))\n'
                            'd["hooks"] = {}\njson.dump(d, open(p, "w"))'),
        "claude-settings-local": f'open("{ch}/settings.local.json", "w").write("{{}}")',
        "claude-json": f'import os\nopen(os.path.join(os.environ["HOME"], ".claude.json"), "w").write("{{}}")',
        "claude-json-literal": f'open("{os.environ["HOME"]}/.claude.json", "w").write("{{}}")',
        "bawwab-config": f'open("{ch}/bawwab.json", "w").write(\'{{"level": "low"}}\')',
        "install-marker": f'import os\nos.remove("{ch}/.bawwab-initialised")',
    }


@pytest.mark.parametrize("name", sorted(RUNS_BAWWAB))
def test_tp_heredoc_python_runs_bawwab(name: str, checkout: Path, plain_dir: Path):
    for cwd in (checkout, plain_dir):
        det = _det(HEREDOC.format(RUNS_BAWWAB[name]), cwd)
        assert isinstance(det, Protected), (name, cwd)
        assert "bawwab approval via tool call" in det.reason, (name, det.reason)


@pytest.mark.parametrize("name", ["dunder-import", "exec-string", "import-module", "import-store", "importlib",
                                  "runpy-module"])
def test_tp_heredoc_python_drives_bawwab_code(name: str, checkout: Path, plain_dir: Path):
    body = _drives_bawwab()[name]
    for cwd in (checkout, plain_dir):
        det = _det(HEREDOC.format(body), cwd)
        assert isinstance(det, Protected), (name, cwd)


@pytest.mark.parametrize("name", ["bawwab-config", "bawwab-db", "bawwab-db-pathlib", "claude-json",
                                  "claude-json-literal", "claude-settings", "claude-settings-local",
                                  "install-marker", "quarantine-flag"])
def test_tp_heredoc_python_writes_state_or_config(name: str, checkout: Path, plain_dir: Path):
    body = _writes_state()[name]
    for cwd in (checkout, plain_dir):
        det = _det(HEREDOC.format(body), cwd)
        assert isinstance(det, Protected), (name, cwd)
        assert "interpreter may write Claude/bawwab config: python3" in det.reason, (name, det.reason)


def test_tp_edit_script_that_also_runs_bawwab(checkout: Path):
    """The refused edit's shape, plus a real approve call: refused whatever the narrowing."""
    body = EDIT_PLAIN + '\nimport subprocess\nsubprocess.run(["bawwab", "approve", "DL32"])'
    det = _det(HEREDOC.format(body), checkout)
    assert isinstance(det, Protected) and "bawwab approval via tool call" in det.reason


def test_tp_edit_script_that_writes_new_bawwab_code(checkout: Path):
    """Writing new code that imports bawwab and approves into a module (Write/Edit refuse the added lines,
    R56 b): a heredoc script doing it stays refused."""
    body = ('from pathlib import Path\np = Path("bawwab/helper.py")\n'
            "p.write_text('from bawwab.store import open_store\\nopen_store().approve(\"DL32\")\\n')")
    assert isinstance(_det(HEREDOC.format(body), checkout), Protected)


def test_tp_unquoted_heredoc_command_substitution(checkout: Path):
    """An unquoted delimiter: bash expands $(...) in the body before python reads it."""
    cmd = "python3 - <<EOF\nprint('$(bawwab approve DL32)')\nEOF"
    det = _det(cmd, checkout)
    assert isinstance(det, Protected) and "bawwab approval via tool call" in det.reason

