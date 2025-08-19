FROM python:3.12-slim

WORKDIR /app

# System deps (timezone, certs)
RUN apt-get update && apt-get install -y --no-install-recommends \
      tzdata ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy parser + web UI
COPY logsearch.py /app/logsearch.py
COPY webui /app/webui

# Install web UI deps
RUN pip install --no-cache-dir fastapi uvicorn jinja2 python-multipart

# Create runtime folders
RUN mkdir -p /app/webui/uploads /app/webui/results

EXPOSE 8000
WORKDIR /app/webui

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "."]

