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
COPY apps/orchestrator ./apps/orchestrator
COPY apps/worker ./apps/worker
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --package sentient-worker


FROM python:${PYTHON_VERSION}-slim AS runtime

WORKDIR /app
COPY --from=builder /app /app
COPY libs/ocsf ./libs/ocsf
COPY apps/orchestrator ./apps/orchestrator
COPY apps/worker ./apps/worker

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD test -f /tmp/ready && [ $(( $(date +%s) - $(stat -c %Y /tmp/ready) )) -lt 90 ] || exit 1

CMD ["/app/.venv/bin/python", "-m", "sentient_worker.main"]
