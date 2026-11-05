# HF-Sentinel core image (DECISIONS D-009: Linux containers only).
# Targets:  runtime (default) — scanner;  test — lint + unit tests + plan harness.
# Build:    docker buildx build --platform linux/amd64,linux/arm64 --target test -t hfsentinel:test .
# Secrets are never baked in: mount the token file at runtime (see README "Running in containers").

FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337 AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app
RUN groupadd --system --gid 10001 sentinel \
 && useradd --system --uid 10001 --gid sentinel --home-dir /app --shell /usr/sbin/nologin sentinel
WORKDIR /app

FROM base AS runtime
COPY requirements/core.lock /tmp/core.lock
RUN pip install --require-hashes --only-binary=:all: -r /tmp/core.lock && rm /tmp/core.lock
COPY --chown=root:root hfsentinel/ /app/hfsentinel/
COPY --chown=root:root config/ /app/config/
# Host file modes vary (e.g. 0600); normalize so the non-root user can read but never write app code.
RUN chmod -R a+rX,go-w /app
USER 10001:10001
ENTRYPOINT ["python", "-m", "hfsentinel"]
CMD ["--help"]

FROM runtime AS test
USER root
COPY requirements/dev.lock /tmp/dev.lock
RUN pip install --require-hashes --only-binary=:all: -r /tmp/dev.lock && rm /tmp/dev.lock
COPY --chown=root:root pyproject.toml test_plan.py hf-llm-security-scanner-project-plan.md /app/
COPY --chown=root:root tests/ /app/tests/
COPY --chown=root:root calibration/ /app/calibration/
COPY --chown=root:root engines/ /app/engines/
COPY --chown=root:root docs/spike/ /app/docs/spike/
COPY --chown=root:root docs/judges/ /app/docs/judges/
RUN chmod -R a+rX,go-w /app
USER 10001:10001
ENV RUFF_CACHE_DIR=/tmp/ruff PYTEST_ADDOPTS="-p no:cacheprovider"
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["ruff check --exclude test_plan.py . && python -m pytest -q && python test_plan.py"]
