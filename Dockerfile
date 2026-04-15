# Root Dockerfile for Render deployment
FROM python:3.11-slim

WORKDIR /app

# Copy backend requirements and code
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend .

# Expose port
EXPOSE 8000

# Start FastAPI
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
