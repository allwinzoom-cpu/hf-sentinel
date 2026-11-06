# Laya System-1 decision layer (plan 16.19; D-009 Linux-only, D-013 CPU-only and capped). Weights are NOT baked in:
# fetch + sha256-verify with `python -m hfsentinel.engines.laya_fetch` (writes each variant to <dir>/<variant>/), then
# mount one variant's subdir read-only at /models/laya and set HFS_LAYA_VARIANT. Two instances (English + multilingual)
# back the core's non-Latin routing (SystemOne multilingual_client, plan 16.19).
# Build: docker buildx build --platform linux/arm64 -f engines/laya/Dockerfile -t hfsentinel-laya:arm64 --load .
# Run (English):      docker run --rm --network none --cpus 2 --memory 4g --read-only --tmpfs /tmp --cap-drop ALL \
#          --security-opt no-new-privileges -v "$HFS_LAYA_DIR/typed-decisions:/models/laya:ro" hfsentinel-laya:arm64 --selftest
# Run (multilingual): add -e HFS_LAYA_VARIANT=multilingual and mount "$HFS_LAYA_DIR/multilingual:/models/laya:ro".
ARG PY_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
FROM ${PY_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=5 \
    HOME=/tmp XDG_CACHE_HOME=/tmp/cache HF_HOME=/tmp/hf CUDA_VISIBLE_DEVICES="" \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 DO_NOT_TRACK=1 TOKENIZERS_PARALLELISM=false \
    PYTHONPATH=/opt/core HFS_LAYA_DIR=/models/laya HFS_LAYA_MANIFEST=/opt/core/config/laya_model.json

COPY engines/laya/requirements.lock /tmp/req.lock
RUN pip install --root-user-action=ignore --require-hashes --only-binary=:all: \
      --extra-index-url https://download.pytorch.org/whl/cpu -r /tmp/req.lock && rm /tmp/req.lock

COPY config/laya_model.json /opt/core/config/laya_model.json
# Vendored, reviewed inference code (sha256-pinned in laya_model.json; verified at load).
COPY engines/laya/rl_agent_api.py engines/laya/rl_common.py engines/laya/server.py /opt/laya/
RUN chmod -R a+rX,go-w /opt \
 && useradd --system --uid 10001 --home-dir /tmp --shell /usr/sbin/nologin sentinel
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python", "/opt/laya/server.py"]
CMD ["--selftest"]
