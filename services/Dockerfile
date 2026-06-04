FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir kafka-python

COPY ingestion_service.py /app/

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/ingestion_service.py"]