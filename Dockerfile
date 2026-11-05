# Stage 1: Build virtual environment and install package
FROM python:3.11-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip build

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Stage 2: Runtime image with non-root security user
FROM python:3.11-slim AS runner

RUN groupadd -r appgroup && useradd -r -g appgroup -d /app appuser

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/log-analyzer /usr/local/bin/log-analyzer

USER appuser

ENTRYPOINT ["log-analyzer"]
CMD ["--help"]
