FROM alpine:3.20

RUN apk add --no-cache \
    iptables \
    iproute2 \
    conntrack-tools \
    bash \
    tcpdump \
    python3 \
    curl

WORKDIR /opt/firewall

COPY entrypoint.sh ./
COPY fw_daemon.py ./
COPY rules/ ./rules/

RUN chmod +x entrypoint.sh fw_daemon.py rules/*.sh

EXPOSE 9099

ENTRYPOINT ["/opt/firewall/entrypoint.sh"]
