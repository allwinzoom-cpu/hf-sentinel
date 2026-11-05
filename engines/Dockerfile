# Generic engine image (plan 16.11; DECISIONS D-009 Linux-only, D-010 CPU-only). One image per engine.
# Built by engines/build.py from engines/versions.json — not by hand.
ARG PY_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
FROM ${PY_IMAGE}
ARG ENGINE
ARG TORCH_CPU=0
ARG GIT_REPO=""
ARG GIT_COMMIT=""
ARG GIT_SHA256=""
ARG GIT_KIND=""
# Comma-separated packages allowed to build from (hash-pinned) source; everything else must be a wheel.
ARG SDIST_ALLOW=""
# Optional Python statement run once at build (as root) for libraries that write into site-packages on first import.
ARG BUILD_WARMUP=""
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp XDG_CACHE_HOME=/tmp/cache XDG_DATA_HOME=/tmp/data XDG_CONFIG_HOME=/tmp/config \
    HF_HOME=/tmp/hf CUDA_VISIBLE_DEVICES="" \
    PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=5 \
    LITELLM_LOCAL_MODEL_COST_MAP=True DEEPEVAL_TELEMETRY_OPT_OUT=YES HF_HUB_DISABLE_TELEMETRY=1 \
    DO_NOT_TRACK=1 ANONYMIZED_TELEMETRY=False SEMGREP_SEND_METRICS=off

COPY engines/${ENGINE}/requirements.lock /tmp/req.lock
# --require-hashes pins every artifact, so the extra CPU-torch index cannot substitute packages.
RUN set -eu; \
    extra=""; if [ "$TORCH_CPU" = "1" ]; then extra="--extra-index-url https://download.pytorch.org/whl/cpu"; fi; \
    if [ -n "$SDIST_ALLOW" ]; then extra="$extra --no-binary $SDIST_ALLOW"; fi; \
    pip install --root-user-action=ignore --require-hashes --only-binary=:all: $extra -r /tmp/req.lock; \
    rm /tmp/req.lock

# Engine-side adapters (16.22): emit the EngineResult contract; engines are named by alias only (D-014).
COPY engines/adapters/ /opt/hfsentinel-adapters/
# E2 sink rules: the core module itself (stdlib only), so engine and core apply identical rules.
COPY hfsentinel/judges/code_sinks.py /opt/hfsentinel-adapters/code_sinks.py
COPY engines/fetch_git.py /tmp/fetch_git.py
RUN set -eu; \
    if [ -n "$GIT_REPO" ]; then \
      python /tmp/fetch_git.py "$GIT_REPO" "$GIT_COMMIT" "$GIT_SHA256" "/opt/$ENGINE"; \
      if [ "$GIT_KIND" = "package" ]; then \
        # Import straight from the sha256-verified tree (keeps undeclared package data, e.g. strong_reject eval_files).
        echo "/opt/$ENGINE" > "$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/hfsentinel-$ENGINE.pth"; \
      fi; \
    fi; \
    if [ -n "$BUILD_WARMUP" ]; then python -W ignore -c "$BUILD_WARMUP"; fi; \
    rm /tmp/fetch_git.py; \
    chmod -R a+rX,go-w /opt 2>/dev/null || true; \
    useradd --system --uid 10001 --home-dir /tmp --shell /usr/sbin/nologin sentinel
USER 10001:10001
WORKDIR /tmp
