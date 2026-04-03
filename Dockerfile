FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for Docker cache efficiency
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Node.js for building the React frontend
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/*

# Copy application source
COPY . .

# Build the frontend
WORKDIR /app/frontend
RUN npm install
RUN npm run build

WORKDIR /app
# Hugging Face Spaces expects port 7860
EXPOSE 7860

# Default task — can be overridden with -e TASK_ID=medium
ENV TASK_ID=easy

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:7860/health'); assert r.status_code == 200" || exit 1

CMD ["python", "app.py"]
