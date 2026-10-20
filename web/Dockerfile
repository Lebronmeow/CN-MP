FROM alpine:3.20

RUN apk add --no-cache iproute2 bash python3

WORKDIR /app
COPY entrypoint.sh ./
COPY mock.py ./
RUN chmod +x entrypoint.sh

EXPOSE 443
ENTRYPOINT ["/app/entrypoint.sh"]
