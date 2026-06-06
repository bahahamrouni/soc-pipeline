FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY ingestion_service.py /app/

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/ingestion_service.py"]