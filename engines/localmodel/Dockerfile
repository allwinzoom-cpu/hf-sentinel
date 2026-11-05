# Local helper-model server (plan 16.14; D-009 Linux-only, D-010/D-013 CPU-only and capped). Weights are NOT baked
# in: they are fetched + sha256-verified by `python -m hfsentinel.targets.local_hf fetch` and mounted read-only.
# Build: docker buildx build --platform linux/arm64 -f engines/localmodel/Dockerfile -t hfsentinel-localmodel:arm64 --load .
# Run:   docker run --rm --network none --cpus 2 --memory 4g --read-only --tmpfs /tmp --cap-drop ALL \
#          --security-opt no-new-privileges -v "$HFS_MODELS_DIR:/models:ro" hfsentinel-localmodel:arm64 --selftest
ARG PY_IMAGE=python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
FROM ${PY_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=120 PIP_RETRIES=5 \
    HOME=/tmp XDG_CACHE_HOME=/tmp/cache HF_HOME=/tmp/hf CUDA_VISIBLE_DEVICES="" \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1 DO_NOT_TRACK=1 TOKENIZERS_PARALLELISM=false \
    PYTHONPATH=/opt/core HFS_MODELS_DIR=/models

COPY engines/localmodel/requirements.lock /tmp/req.lock
# --require-hashes pins every artifact, so the extra CPU-torch index cannot substitute packages.
RUN pip install --root-user-action=ignore --require-hashes --only-binary=:all: \
      --extra-index-url https://download.pytorch.org/whl/cpu -r /tmp/req.lock && rm /tmp/req.lock

# Only the stdlib core pieces the server needs: the standard adapter (self-test) and pin verification.
COPY hfsentinel/__init__.py /opt/core/hfsentinel/__init__.py
COPY hfsentinel/targets/__init__.py hfsentinel/targets/openai_compat.py hfsentinel/targets/local_hf.py \
     /opt/core/hfsentinel/targets/
COPY config/local_models.json /opt/core/config/local_models.json
COPY engines/localmodel/server.py /opt/localmodel/server.py
RUN chmod -R a+rX,go-w /opt \
 && useradd --system --uid 10001 --home-dir /tmp --shell /usr/sbin/nologin sentinel
USER 10001:10001
WORKDIR /tmp
ENTRYPOINT ["python", "/opt/localmodel/server.py"]
CMD ["--selftest"]
