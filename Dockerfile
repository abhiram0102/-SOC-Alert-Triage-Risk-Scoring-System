# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="SOC Triage System"
LABEL description="AI-Powered SOC Alert Triage & Risk Scoring Engine"
LABEL version="2.0"

WORKDIR /app

# Runtime system dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY config/   ./config/
COPY enrichment/ ./enrichment/
COPY ml/       ./ml/
COPY pipeline/ ./pipeline/
COPY scripts/  ./scripts/

# Create required directories
RUN mkdir -p logs model data/elasticsearch

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash socuser \
 && chown -R socuser:socuser /app

USER socuser

# Environment defaults (override via docker-compose or -e flags)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ELASTICSEARCH_HOST=http://elasticsearch:9200 \
    ELASTICSEARCH_INDEX=suricata-alerts-* \
    POLL_INTERVAL=30 \
    BATCH_SIZE=50 \
    LOG_LEVEL=INFO \
    LOG_FILE=logs/pipeline.log \
    MODEL_DIR=model \
    USE_REDIS=false

# Health check: verify Python can import core modules
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 -c "import ml.ml_scorer; print('OK')" || exit 1

# Default: start the pipeline (overridden by docker-compose command)
CMD ["python3", "pipeline/pipeline.py"]
