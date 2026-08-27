FROM python:3.11-slim

LABEL maintainer="ScanForge Demo"
LABEL description="Static PE threat analysis — no binary execution"

WORKDIR /app

# Install dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Generate synthetic demo PE samples at build time
RUN python samples/generate_samples.py

EXPOSE 8000

# Run with a single worker (demo/hackathon; add --workers N for prod)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
