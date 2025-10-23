# Backend Dockerfile for SecureVault
FROM python:3.11-slim

# Set security best practices
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create non-root user for security (ISO 27001 A.9.2)
RUN groupadd -r securevault && \
    useradd -r -g securevault -s /bin/bash securevault && \
    mkdir -p /app && \
    chown -R securevault:securevault /app

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY --chown=securevault:securevault requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=securevault:securevault . .

# Switch to non-root user
USER securevault

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]