FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for GeoIP
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy processing service
COPY processing_service.py /app/

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/processing_service.py"]