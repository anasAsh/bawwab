# The evaluation sandbox image: `uv run python eval/run_eval.py --sandbox docker` builds and runs it.
#
#   docker build -t bawwab-eval:local -f eval/Dockerfile --build-arg UID=$(id -u) --build-arg GID=$(id -g) .
#
# A copy of the repo is baked in (no host mount at run time), with its locked dependencies and the tree-sitter
# grammars fetched at build time. The run itself has no network (--network none), a read-only root, no
# capabilities and a non-root user; only a scratch dir is mounted (see eval/isolation.py DockerRunner).
# Base images are pinned by tag; pin them by digest for byte-for-byte rebuilds.
FROM ghcr.io/astral-sh/uv:0.13.9 AS uv
FROM python:3.12.16-slim-bookworm

ARG UID=1000
ARG GID=1000
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g "${GID}" eval \
 && useradd -m -u "${UID}" -g "${GID}" -d /home/eval eval
COPY --from=uv /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PYTHON=/usr/local/bin/python3.12 UV_NO_PROGRESS=1
WORKDIR /src
COPY --chown=eval:eval . /src
USER eval
RUN uv sync --frozen \
 && /src/.venv/bin/python -c "from tree_sitter_language_pack import get_parser; \
[get_parser(l) for l in ('javascript', 'typescript', 'tsx')]" \
 && rm -rf /home/eval/.cache/uv
