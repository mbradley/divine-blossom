# ABOUTME: Dockerfile for Blossom upload Cloud Run service
# ABOUTME: Uses Python 3.12 with Flask and GCS client for blob uploads

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY main.py .

ENV PORT=8080

# Use gunicorn with 4 workers
CMD exec gunicorn --bind :$PORT --workers 4 --threads 2 --timeout 300 main:app
