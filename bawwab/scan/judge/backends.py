from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

from bawwab.config import Config


class Backend(Protocol):
    def complete(self, system: str, user: str, schema: dict, timeout_s: float) -> str: ...


class _FakeBackend:
    def __init__(self, path: str) -> None:
        self.path = path

    def complete(self, system: str, user: str, schema: dict, timeout_s: float) -> str:
        return Path(self.path).read_text()


class _CliBackend:
    def __init__(self, model: str) -> None:
        self.model = model

    def complete(self, system: str, user: str, schema: dict, timeout_s: float) -> str:
        exe = shutil.which("claude")
        if not exe:
            raise FileNotFoundError("claude CLI not found")
        argv = [
            exe, "-p", "--model", self.model, "--tools", "", "--strict-mcp-config",
            "--setting-sources", "", "--no-session-persistence", "--output-format", "json",
            "--json-schema", json.dumps(schema), "--system-prompt", system,
        ]
        from bawwab.paths import child_env

        env = child_env()
        with tempfile.TemporaryDirectory(prefix="bawwab-judge-") as cwd:
            try:
                from bawwab.limits import child_argv

                proc = subprocess.run(
                    child_argv(argv, env), input=user, capture_output=True, text=True, timeout=timeout_s,
                    env=env, cwd=cwd, shell=False,  # child_argv: the judge keeps the original rlimit (R1-I1)
                )
            except subprocess.TimeoutExpired as e:
                raise TimeoutError("claude CLI timed out") from e
        if proc.returncode != 0:
            raise RuntimeError(f"claude CLI exited {proc.returncode}")
        data = json.loads(proc.stdout)
        if not isinstance(data, dict) or data.get("is_error"):
            raise RuntimeError("claude CLI reported an error")
        so = data.get("structured_output")
        if so is not None:
            return so if isinstance(so, str) else json.dumps(so)
        res = data.get("result")
        if not isinstance(res, str):
            raise RuntimeError("claude CLI returned no result")
        return res


class _ApiBackend:
    def __init__(self, model: str) -> None:
        self.model = model

    def complete(self, system: str, user: str, schema: dict, timeout_s: float) -> str:
        import anthropic

        client = anthropic.Anthropic(timeout=timeout_s, max_retries=0)
        resp = client.messages.create(
            model=self.model,
            max_tokens=8000,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
        )
        if resp.stop_reason in ("refusal", "max_tokens"):
            raise RuntimeError(f"stop_reason {resp.stop_reason}")
        for block in resp.content:
            if block.type == "text":
                return block.text
        raise RuntimeError("no text block in response")


def cli_backend(model: str) -> Backend:
    return _CliBackend(model)


def api_backend(model: str) -> Backend:
    return _ApiBackend(model)


def backend_for(cfg: Config) -> Backend:
    fake = os.environ.get("BAWWAB_FAKE_JUDGE")
    if fake:  # test/e2e only
        return _FakeBackend(fake)
    if cfg.llm_backend == "claude-cli" and (shutil.which("claude") or not os.environ.get("ANTHROPIC_API_KEY")):
        return cli_backend(cfg.llm_model)
    return api_backend(cfg.llm_model)
