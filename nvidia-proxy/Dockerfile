FROM python:3.12-slim

RUN pip install --no-cache-dir aiohttp

WORKDIR /app
COPY nemotron_proxy.py /app/nemotron_proxy.py

ENV PORT=8448 \
    REASONING_BUDGET=16384 \
    UPSTREAM_TIMEOUT=600 \
    LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1

EXPOSE 8448

CMD ["python", "/app/nemotron_proxy.py"]
