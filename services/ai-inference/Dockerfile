FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ai_inference_service.py .

CMD ["python", "-u", "ai_inference_service.py"]