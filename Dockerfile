FROM alpine:3.16.2

COPY target/x86_64-unknown-linux-musl/release/roxy /

RUN apk add --no-cache ca-certificates tzdata

ENTRYPOINT ["/roxy"]