# Supply-chain tools image (uv for locking, pip-audit for OSV audits). Hash-locked; non-root.
ARG PY_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
FROM ${PY_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_CACHE_DIR=/tmp/uv-cache XDG_CACHE_HOME=/tmp/cache
COPY engines/tools/requirements.lock /tmp/tools.lock
RUN pip install --root-user-action=ignore --require-hashes --only-binary=:all: -r /tmp/tools.lock && rm /tmp/tools.lock \
 && useradd --system --uid 10001 --home-dir /w --shell /usr/sbin/nologin sentinel
USER 10001:10001
WORKDIR /w
