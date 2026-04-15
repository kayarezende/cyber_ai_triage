# sentient-common

Shared Python utilities used across Sentient Layer services.

Modules:

- `sentient_common.logging` — `configure_logging(service, level)` wires structlog
  to emit JSON lines to stdout with a `service` field on every record. Bridges
  stdlib logging (uvicorn, redis-py, etc.) through the same pipeline.
- `sentient_common.crypto` — Fernet wrapper reading `TENANT_SECRET_KEY` from
  the environment. `encrypt(str) -> bytes` and `decrypt(bytes) -> str`.
