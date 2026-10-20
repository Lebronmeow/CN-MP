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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["tail", "-f", "/dev/null"]
