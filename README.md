# dotdns

`dotdns` is a Rust single-node DNS-over-TLS (DoT) forwarding cache resolver. It listens for DoT client queries, forwards misses to configured upstream resolvers, caches eligible DNS responses by TTL, and can apply an AdGuard Home-compatible DNS blocklist subset.

## Deployment

- Public client-facing service: DoT on port `853`.
- TLS certificate and private key are provided by the operator via `tls.cert_path` and `tls.key_path`.
- Binding port `853` as a non-root user may require elevated permissions or a platform-specific capability such as `CAP_NET_BIND_SERVICE` on Linux.
- The management interface is local-only by default, using Unix socket `/tmp/dotdns.sock`.

Start the service with:

```sh
dotdns serve --config /etc/dotdns/dotdns.toml
```

See `examples/dotdns.toml` for a full configuration template.

## Configuration

Upstreams are tried in order until one succeeds, so later entries act as fallback resolvers when earlier entries fail. Supported upstream protocols are:

- ordinary DNS: `protocol = "plain"`
- DNS-over-TLS: `protocol = "dot"`
- DNS-over-HTTPS: `protocol = "doh"`

Cache settings include `capacity`, `min_ttl`, and `max_ttl`. Blocklists are configured under `[blocklist]` with `enabled` and `paths`.

DoT upstreams must use a hostname, not a raw IP address, so TLS SNI and certificate validation can work. Per-upstream `tls_cert_path` pinning is not implemented and is rejected during upstream setup.

## CLI

Management commands use `/tmp/dotdns.sock` by default. Pass `--config <path>` to read the management socket or loopback TCP setting from a config file.

```sh
dotdns status
dotdns status --config /etc/dotdns/dotdns.toml
dotdns cache stats
dotdns cache stats --config /etc/dotdns/dotdns.toml
dotdns cache flush --config /etc/dotdns/dotdns.toml
dotdns blocklist reload --config /etc/dotdns/dotdns.toml
```

`dotdns status` reports uptime, total queries, cache hits, cache misses, blocked queries, upstream failures, and cache entries. `dotdns cache stats` prints cache entries and hit/miss counters.

## Blocklist Subset

The parser supports this AdGuard Home-compatible subset:

- comments and blank lines (`#`, `!`)
- plain domain rules (`example.com`)
- hosts-style rules (`0.0.0.0 example.com`, `127.0.0.1 example.com`, `::1 example.com`)
- anchored domain rules (`||example.com^`)
- exception rules (`@@example.com`, `@@||example.com^`)

Unsupported advanced features are skipped, including regex rules, cosmetic/CSS rules, scriptlet rules, and rules with modifiers such as `$third-party` or `$important`.

Blocked `A` queries return `0.0.0.0`; blocked `AAAA` queries return `::`. Exception rules override block rules.

## Limitations / TODO

- `serve_stale` config option is accepted but does nothing right now.
- `tls_cert_path` pinning isn't implemented.
- Cache eviction is naive (not LRU) — should fix eventually.
- Unix socket cleanup on shutdown is missing; restart handles stale sockets.
- No AdGuard regex/modifier support, no cert automation, no clustering.
