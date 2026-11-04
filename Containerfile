# lanwatch container. Build: podman build -t lanwatch .
# Run (rootful, needs raw sockets): see deploy/quadlet/lanwatch.container
# Run (rootless + host helper):    see deploy/quadlet/lanwatch-rootless.container

FROM python:3.13-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap arp-scan iproute2 iputils-ping git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/.venv /app/.venv
COPY evals /app/evals
ENV PATH=/app/.venv/bin:$PATH \
    LANWATCH_DATA_DIR=/var/lib/lanwatch \
    PYTHONUNBUFFERED=1
WORKDIR /app
VOLUME /var/lib/lanwatch
EXPOSE 8321
# Health check lives in the quadlet units (HealthCmd); OCI images have no HEALTHCHECK.
ENTRYPOINT ["lanwatch"]
CMD ["run"]
