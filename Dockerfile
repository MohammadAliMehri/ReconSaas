FROM python:3.11-slim

LABEL maintainer="recon-framework" \
      description="Zero-cost open-source reconnaissance framework" \
      version="1.0.0"

WORKDIR /app

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        curl \
        dnsutils \
        && rm -rf /var/lib/apt/lists/*

# Python deps (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt flask gunicorn

# App code
COPY . .
RUN pip install --no-cache-dir -e .

# Output volume
RUN mkdir -p /app/recon-output
VOLUME ["/app/recon-output"]

# Expose web UI port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/modules || exit 1

# Default: run web UI
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "300", "--access-logfile", "-", "recon_framework.web.app:create_app()"]
