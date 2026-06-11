# Stage 1: Build React frontend
FROM node:20-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package.json ./
RUN npm install
COPY frontend/index.html ./
COPY frontend/vite.config.js ./
COPY frontend/tailwind.config.js ./
COPY frontend/postcss.config.js ./
COPY frontend/src ./src
RUN npm run build

# Stage 2: FastAPI backend + built frontend
FROM python:3.11-slim
WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/main.py .
COPY --from=frontend-build /frontend/dist /app/static

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]