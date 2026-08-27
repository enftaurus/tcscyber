FROM python:3.11-slim

LABEL maintainer="ScanForge"
LABEL description="Static PE threat analysis — no binary execution"

WORKDIR /app

# Install dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY . .

# Generate synthetic demo PE samples at build time (EICAR is served
# in-memory by the app — never written to disk, see main.py)
RUN python samples/generate_samples.py

# Run as a non-root user — the app never needs root, and this limits the
# blast radius if a dependency vulnerability is ever exploited.
RUN useradd --system --create-home --uid 10001 scanforge \
    && chown -R scanforge:scanforge /app
USER scanforge

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Single worker by default (fine for a demo). For real traffic, override
# with e.g. `--workers 4`, or run under gunicorn+uvicorn workers.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
