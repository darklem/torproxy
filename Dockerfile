FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# SOCKS5 proxy port + HTTP status API
EXPOSE 10800 10801

# Persist the SQLite proxy cache across restarts
VOLUME ["/root/.torproxy-chain"]

# Auto-envvar prefix: TORPROXY_COUNTRY=FR maps to --country FR, etc.
ENV TORPROXY_HEADLESS=1 \
    TORPROXY_SKIP_MITM_CHECK=1 \
    TORPROXY_STATUS_PORT=10801

ENTRYPOINT ["python", "main.py"]
