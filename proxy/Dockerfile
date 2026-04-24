# Install uv
FROM python:3.13-bookworm AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=proxy/uv.lock,target=uv.lock \
    --mount=type=bind,source=proxy/pyproject.toml,target=pyproject.toml \
    uv sync --no-dev --frozen --no-install-project --no-editable

# Copy proxy source
COPY proxy/src /app/src
COPY proxy/pyproject.toml proxy/uv.lock /app/

# Copy shared protocol.py into the package
COPY custom_components/intelbras/protocol.py /app/src/an24net/protocol.py

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev --frozen --no-editable

FROM python:3.13-bookworm

ENV PYTHONOPTIMIZE=2
WORKDIR /app

COPY --from=builder --chown=app:app /app/.venv /app/.venv

CMD [".venv/bin/server"]
