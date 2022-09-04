FROM alpine:3.16.2

RUN apk add --no-cache curl wget ca-certificates tzdata vim
COPY run.sh /run.sh

ENTRYPOINT ["/bin/sh", "/run.sh"]