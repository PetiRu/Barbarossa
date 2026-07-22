# BARBAROSSA - Docker Image
# Multi-stage build for minimal production image

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Install dependencies to user site
RUN pip install --user --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Security: Create non-root user
RUN groupadd -r barbarossa && useradd -r -g barbarossa -u 1000 barbarossa

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/barbarossa/.local

# Copy application code
COPY --chown=barbarossa:barbarossa barbarossa/ ./barbarossa/
COPY --chown=barbarossa:barbarossa main.py ./
COPY --chown=barbarossa:barbarossa pyproject.toml ./
COPY --chown=barbarossa:barbarossa README.md ./

# Create directories for reports and config
RUN mkdir -p /app/reports /app/config && chown -R barbarossa:barbarossa /app

# Security: Drop privileges
USER barbarossa

# Add user site to PATH
ENV PATH=/home/barbarossa/.local/bin:$PATH
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import barbarossa; print('OK')" || exit 1

# Default entrypoint
ENTRYPOINT ["python3", "-m", "barbarossa.cli"]

# Default command shows help
CMD ["--help"]

# Labels
LABEL maintainer="PetiRu <petiru@github.com>"
LABEL description="BARBAROSSA - Deterministic Web Application Security Testing Toolkit"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/PetiRu/Barbarossa"
LABEL org.opencontainers.image.documentation="https://github.com/PetiRu/Barbarossa/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"