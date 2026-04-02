FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/postgresql/data \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code (only backend directory as requested)
COPY backend ./backend

ENV PYTHONPATH=/app
# Default DB URL, can be overridden by docker-compose
ENV DATABASE_URL=postgresql://postgres:postgres@db:5432/aivulnhunter

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
