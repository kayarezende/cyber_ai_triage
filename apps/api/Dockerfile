# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.12

FROM ghcr.io/astral-sh/uv:0.9.26 AS uvbin

FROM python:${PYTHON_VERSION}-slim AS builder
COPY --from=uvbin /uv /usr/local/bin/uv

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY libs/common ./libs/common
COPY libs/ocsf ./libs/ocsf
COPY apps/api ./apps/api
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --package sentient-api


FROM python:${PYTHON_VERSION}-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app /app
COPY libs/ocsf ./libs/ocsf
COPY apps/api ./apps/api

# Migrations + alembic.ini ride along so the same image can run as the
# `migrate` one-shot service in compose (alembic + sqlalchemy already in
# the api venv). Cluster A migration `e5f7a1b9c4d6` creates the
# `app_runtime` Postgres role; cold-start is broken without it.
COPY alembic.ini ./alembic.ini
COPY db/migrations ./db/migrations

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["/app/.venv/bin/uvicorn", "sentient_api.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
