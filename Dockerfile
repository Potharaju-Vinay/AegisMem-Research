# AegisMem Backend - Production Dockerfile
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install minimal OS dependencies for cryptography and PostgreSQL driver
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Python dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . /app

# Ensure directories exist with proper permissions
RUN mkdir -p /app/data /app/security/keys /app/security/integrity_manifests /app/security/trust_vault /app/security/recovery_attestations

# Create non-privileged service user
RUN useradd -m -u 1000 aegis && \
    chown -R aegis:aegis /app

USER aegis

# Gateway API runs on port 8000
EXPOSE 8000

# Container healthcheck probing the AegisMem health endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start FastAPI application via Uvicorn
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]

