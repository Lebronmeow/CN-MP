FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    traceroute \
    netcat-openbsd \
    nmap \
    curl \
    procps \
    tcpdump \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /entrypoint.sh
COPY shopledger_cli.py /app/
COPY shopledger_ui.py /app/
RUN chmod +x /entrypoint.sh /app/shopledger_cli.py /app/shopledger_ui.py

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
