# Roxy

Roxy is a lightweight and fast tunnel proxy that helps you bypass `walls`.

Tested on my Workstation(AMD & Rocky Linux) and Mikrotik RB5009(awesome).

## Limitations
1. Only `aes-128-gcm` and `aes-256-gcm` supported.
2. Only HTTP 1.x, HTTP 2.0 & TLS supported, and there target port must be 80 
     or 443(Limited by THP).
3. OBFS plugin is not supported.

## Configuration
examples/config.yaml

## Rules

Note: `Bloom Filter` is used to save memory, it works fine at most time, but 
`False Positives` is still there.

Rule is used for handing dns request, it can works like blacklist and whitelist.
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

## TODO:
1. Adaptive health check: The dead node is unlikely became alive again in a short time, 
   so we might be increase the interval of check task for this server, which should help
   us to reduce resource usage(and your proxy data package).
2. Cipher optimization: `https://github.com/RustCrypto/asm-hashes` and use [crypto2](https://github.com/shadowsocks/crypto2)
   to speed up AEAD cipher.
3. THP does not resolve target domain itself, you might have some wired anomalies.