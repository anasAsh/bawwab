# Bawwab deep-mode sandbox image. Build it with `bawwab sandbox build` (which records the image id that the
# runner then uses), or by hand from the bawwab/sandbox directory:
#   docker build -t bawwab-sandbox:local -f image/Dockerfile .
#
# The same image runs both containers of a deep scan:
#   - the sandbox:  python3 -I /opt/bawwab/harness.py   (the default command)
#   - the trap:     python3 -I /opt/bawwab/proxy.py
# Isolation comes from the `docker run` flags (bawwab/sandbox/docker.py), not from this image.
#
# Base pinned by digest: the multi-arch index of node:22-bookworm-slim, resolved from registry-1.docker.io on
# 2026-11-21. The Debian packages below are not pinned (apt resolves them at build time).
FROM node:22-bookworm-slim@sha256:e9f565d32859f0cbfb52125eafe8be39390f24dac302dc3cdf566e8ba3ab21ee

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-pip python3-setuptools python3-wheel \
      python3-hatchling python3-poetry-core \
      strace ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 sandbox \
 && useradd -u 10001 -g 10001 -d /home/sandbox -M -s /usr/sbin/nologin sandbox \
 && mkdir -p /home/sandbox /work /target /opt/bawwab \
 && chown 10001:10001 /home/sandbox /work

COPY canary.py image/harness.py image/proxy.py /opt/bawwab/
RUN chmod 0755 /opt/bawwab && chmod 0644 /opt/bawwab/*.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false

LABEL org.opencontainers.image.title="bawwab-sandbox" \
      org.opencontainers.image.description="Bawwab deep-mode sandbox (harness + network trap)"

USER 10001:10001
WORKDIR /work
ENTRYPOINT []
CMD ["python3", "-I", "/opt/bawwab/harness.py"]
