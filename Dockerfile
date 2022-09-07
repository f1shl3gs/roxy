FROM alpine:3.16.2

RUN apk add --no-cache ca-certificates tzdata

COPY roxy /roxy

ENTRYPOINT ["/roxy"]