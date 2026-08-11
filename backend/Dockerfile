# CPEDS-X Backend - Render.com / Hugging Face Spaces free tier
FROM python:3.10-slim

WORKDIR /app

# System deps for lightgbm
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render provides $PORT; default to 8000 locally
ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
