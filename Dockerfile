FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
RUN python -m pip install --no-cache-dir . \
    && mkdir /data \
    && chown 10001:10001 /data
USER 10001:10001
ENV ASP_DB_PATH=/data/security.db
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)"
CMD ["uvicorn", "adaptive_security.api:app", "--host", "0.0.0.0", "--port", "8000"]
