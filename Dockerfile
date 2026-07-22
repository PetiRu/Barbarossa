# Use Python 3.12 slim image for a small footprint
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Install dependencies
RUN pip install --user --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.12-slim

# Security: Create non-root user
RUN groupadd -r barbarossa && useradd -r -g barbarossa -u 1000 barbarossa

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /home/barbarossa/.local

# Copy application code
COPY --chown=barbarossa:barbarossa . .

# Create directories for reports
RUN mkdir -p /app/reports && chown -R barbarossa:barbarossa /app

# Security: Drop privileges
USER barbarossa

# Add user site to PATH
ENV PATH=/home/barbarossa/.local/bin:$PATH
ENV PYTHONPATH=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install the package in editable mode for the user
RUN pip install --user --no-cache-dir -e .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD barbarossa --help || exit 1

# Set entrypoint
ENTRYPOINT ["barbarossa"]

# Default command
CMD ["--help"]

# Labels
LABEL maintainer="BARBAROSSA Contributors"
LABEL description="BARBAROSSA - Deterministic Web Application Security Testing Toolkit"
LABEL version="0.1.0"
LABEL org.opencontainers.image.source="https://github.com/PetiRu/Barbarossa"
