# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
# build-essential: for mmh3, pyjarm, etc.
# libpq-dev: for psycopg2 build
# libffi-dev: for cffi (weasyprint dependency)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt

# Stage 2: Final
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.app \
    FLASK_ENV=production \
    REQUESTS_CA_BUNDLE=/certs/ca-bundle.crt

WORKDIR /app

# Install runtime dependencies
# WeasyPrint needs: libpango-1.0-0, libpangoft2-1.0-0, libjpeg62-turbo, libopenjp2-7, shared-mime-info
# Psycopg2 needs: libpq5
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libjpeg62-turbo \
    libopenjp2-7 \
    libpq5 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1001 appuser

# Create certs directory with correct permissions
RUN mkdir -p /certs && chown -R appuser:appgroup /certs

# Copy wheels from builder and install
COPY --from=builder /wheels /wheels
COPY --from=builder /app/requirements.txt .
RUN pip install --no-cache /wheels/*

# Copy application code
COPY . .

# Ensure permissions for app user
# Especially for logs and uploads directories which might need write access
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER 1001

# Expose port
EXPOSE 8080

# Run with Gunicorn
CMD ["gunicorn", "-c", "gunicorn_config.py", "wsgi:app"]
