FROM alpine:3.20

RUN apk add --no-cache tcpdump bash coreutils

WORKDIR /opt/sniffer

COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/opt/sniffer/entrypoint.sh"]
