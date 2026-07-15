FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

COPY processing_service.py /app/

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/processing_service.py"]
