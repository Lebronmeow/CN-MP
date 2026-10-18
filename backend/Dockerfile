FROM python:3.12-slim

LABEL maintainer="Computer Networks Project Team"
LABEL description="Application Tier - Flask REST API & Business Logic Server"

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DOCKER_ENV=1

WORKDIR /app

# Copy dependency definition and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY . .

# Only expose Flask service port 5000 internally to Nginx (app_tier network)
EXPOSE 5000

CMD ["python", "app.py"]
