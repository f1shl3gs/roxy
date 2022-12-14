FROM alpine:3.16.2

RUN apk add --no-cache ca-certificates

COPY roxy /roxy
COPY config.yaml /config.yaml

ENTRYPOINT ["/roxy"]
