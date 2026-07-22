FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md ./
COPY barbarossa ./barbarossa

# Building and installing the wheel exercises the same artifact shipped to users.
RUN pip wheel --no-cache-dir --wheel-dir /wheels .


FROM python:3.12-slim

RUN groupadd --system barbarossa \
    && useradd --system --gid barbarossa --uid 1000 barbarossa \
    && mkdir -p /app/reports \
    && chown -R barbarossa:barbarossa /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels barbarossa \
    && rm -rf /wheels

WORKDIR /app
USER barbarossa

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD barbarossa --help || exit 1

ENTRYPOINT ["barbarossa"]
CMD ["--help"]

LABEL maintainer="BARBAROSSA Contributors"
LABEL description="BARBAROSSA - Deterministic Web Application Security Testing Toolkit"
LABEL version="0.1.0"
LABEL org.opencontainers.image.source="https://github.com/PetiRu/Barbarossa"
