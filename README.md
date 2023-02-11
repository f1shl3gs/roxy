# Roxy

Roxy is a lightweight and fast tunnel proxy that helps you bypass `walls`.

Tested on my Workstation(AMD & Rocky Linux) and Mikrotik RB5009(awesome).

## Limitations
1. Only `aes-128-gcm` and `aes-256-gcm` supported.
2. Only HTTP 1.x, HTTP 2.0 & TLS supported, and there target port must be 80 
     or 443(Limited by THP).
3. OBFS plugin is not supported.

## Build
In addition to `rust`, you will need to following prerequisites installed on your system:
- [cross](https://github.com/cross-rs/cross) for cross complition
- Docker
- [buildx](https://github.com/docker/buildx)

```shell
# Native
make build

# Other architecture
make aarch64-unknown-linux-musl
```

### Docker Image
Note: For now, RouterOS(7.6rc3) cannot mount files into container, and file management is not as flexible as
any Linux distribution. Therefore you `must provide your own configuration file`.

```
# For example, build docker image for aarch64-unknown-linux-musl

# By default, you cannot build other architecture image, so you might need run this
docker run --privileged --rm tonistiigi/binfmt --install all

# Copy binary
cp target/aarch64-unknown-linux-musl/release/roxy ./roxy

# Build image
docker build -t roxy:aarch64-unknown-linux-musl --platform linux/arm64 .
```

## Configuration
```yaml
# If this is not set, default value (cpu count) will be used.
#
# Optional
# worker: 4

# Resolver used for resolve the domains of providers, DNS over HTTP(S) and shadowsocks server
#
# Required
resolvers:
  - 114.114.114.114:53

# Configuration for logs
#
# Optional
log:
  # Available values is `trace`, `debug`, `info`, `warn` and `error`.
  # Note: Release build Roxy will not allowed `trace`.
  #
  # Required
  level: info

  # Sometimes timestamp is redundant, for example, running this in a container
  #
  # Optional
  timestamp: true

# RESTful API for Roxy stats
#
# Optional
controller:
  # Controller's listen address
  #
  # Required
  listen: 0.0.0.0:9000

# DNS server
#
# Required
dns:
  # TCP and UDP are listened
  #
  # Required
  listen: 0.0.0.0:53

  # If the request domain not match `hosts`, `reject`,
  # this will handle the request
  #
  # Required
  upstream:
    # If port is not provided, default value is used.
    # tcp://1.1.1.1 or udp://1.1.1.1
    - tls://dot.pub # Tencent DNS over TLS
    - tls://dns.alidns.com # Aliyun DNS over TLS

  # Cache dns result from response, TTL will be set automatically.
  #
  # Optional
  cache:
    # max size of cached response
    size: 512

  # Reject some dns request by response with no records, it could be used
  # for removing ads
  #
  # Optional
  reject:
    endpoint: https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/reject.txt
    # cron might be a better solution, with cron we can update it as soon as possible
    interval: 24h

  # If the request domain match this it should be proxy by outbounds
  #
  # Optional
  hijack:
    endpoint: https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release/gfw.txt
    # cron might be a better solution, with cron we can update it as soon as possible
    interval: 24h
    # return this address to client, it should be the address Roxy listen to.
    hijack: 127.0.0.1

# upstream is used to define servers that can be referenced by THP
#
# Required
upstream:
  # Specifies a load balance method
  #   1. `best`: the lowest latency server
  #   2. `etld`: requests are distributed between servers based on request domain,
  #      dead server will be skipped.
  #
  # Optional, default best
  load_balance: best

  # Check proxy's health.
  #
  # Required
  check:
    # Interval seconds between each check
    # Required
    interval: 1h
    # Timeout for check servers
    # Required
    timeout: 5s

  # Load proxy server lists dynamically
  #
  # Required
  provider:
    # endpoint is the uri to fetch servers, The content is encoded with base64,
    # after decode, the content is `ss` urls, looks like
    # ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmQ@127.0.0.1:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.baidu.com
    #
    # Required
    # NOTE: replace this with your own uri
    endpoint: https://for.example.com/blah/blah

    # Update servers every 24h, if this not specified, it will never update it
    #
    # Optional
    interval: 24h

# Transparent Http Proxy, this must works with dns hijack.
# This component will read the first 1024 bytes of the TCP connect,
# and parse it.
#   1. Start with `GET`, `POST` and other HTTP's request head, then parse `Host` header,
#      if roxy cannot find this `Host` header, the connection will be closed.
#   2. Start with Handshake(ascii define, u8 = 22), the parse TLS' sni extention to find
#      which domain the request want to connect.
#
# Required
thp:
  # Address listen to
  #
  # Required
  listen:
  - 0.0.0.0:80
  - 0.0.0.0:443
```

## Rules

Note: `Bloom Filter` is used to save memory, it works fine at most time, but 
`False Positives` is still there.

Rule is used for handing dns request, it works like blacklist and whitelist.
the Syntax looks like
```text
bar.com     # exact match
.bar.com    # wildcard match any domain with suffix `.bar.com`
```

### Compatible rules
1. https://github.com/Loyalsoldier/surge-rules

## Relay
### Transparent HTTP Proxy
This component will read the first 1024 bytes of the TCP connection, and parse it to
find out destination domain.
1. HTTP: start with `GET`, `POST` and other http method
2. HTTPS/TLS: start with 0x22 (it's not printable), See: https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1

## Controller HTTP API
Roxy's stats
```shell
curl -s 10.18.0.4:9000/stats | jq .
{
    "open_fds": 20,
    "max_fds": 500000,
    "cpu_seconds": 78.95,
    "threads": 5,
    "start": 849974.67,
    "vss": 12779520,
    "rss": 7864320
}
```

Get upstream stats
```shell
curl -s 10.18.0.4:9000/upstream | jq .
[
    {
        "remarks": "foo 01",
        "address": "some.example.com:1234",
        "recv": 569,
        "sent": 342,
        "latencies": [
            {
                "timestamp": "2022-10-26T14:10:16.170341Z",
                "value": 1724
            },
            {
                "timestamp": "2022-10-26T14:14:02.744491Z",
                "value": 421
            }
        ]
    }
]
```

## Allocators
- `Scudo` allocator can reduce some cpu usage, but memory usage is increased(increase from 4M to 9M on aarch64-unknown-linux-musl)

## TODO:
1. Adaptive health check: The dead node is unlikely became alive again in a short time, 
   so we might be increase the interval of check task for this server, which should help
   us to reduce resource usage(and your proxy data package).
2. Cipher optimization: `https://github.com/RustCrypto/asm-hashes` and use [crypto2](https://github.com/shadowsocks/crypto2)
   to speed up AEAD cipher.
3. THP does not resolve target domain itself, you might have some wired anomalies.
