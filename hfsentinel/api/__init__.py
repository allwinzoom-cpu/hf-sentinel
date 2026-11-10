"""Optional FastAPI layer for HF-Sentinel — a secure, scalable HTTP front end over :mod:`hfsentinel.sdk`.

Requires the optional ``api`` extra (``pip install hfsentinel[api]`` → fastapi + uvicorn). Importing this package never
hard-fails: if FastAPI is absent, :data:`FASTAPI_AVAILABLE` is False and :func:`create_app` raises a clear error, so the
core scanner has no new runtime dependency.
"""
from hfsentinel.api.app import FASTAPI_AVAILABLE, create_app

__all__ = ["FASTAPI_AVAILABLE", "create_app"]
