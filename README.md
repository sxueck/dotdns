# dotdns

`dotdns` is a Rust single-node DNS-over-TLS (DoT) forwarding cache resolver. It listens for DoT client queries, forwards misses to configured upstream resolvers, caches eligible DNS responses by TTL, and can apply an AdGuard Home-compatible DNS blocklist subset.

## Deployment

- Public client-facing service: DoT on port `853`.
- DoT listen addresses are configured with `server.binds`; include both `"0.0.0.0:853"` and `"[::]:853"` to listen on IPv4 and IPv6.
- TLS certificate and private key are provided by the operator via `tls.cert_path` and `tls.key_path`.
- Binding port `853` as a non-root user may require elevated permissions or a platform-specific capability such as `CAP_NET_BIND_SERVICE` on Linux.
- The management interface is local-only by default. The example systemd deployment uses Unix socket `/run/dotdns/dotdns.sock`.

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

Cache settings include `capacity`, `min_ttl`, and `max_ttl`. EDNS settings live under `[edns]`; enabling `[edns.client_subnet]` sends an ECS option derived from the client IP to upstream resolvers, using `/24` for IPv4 and `/56` for IPv6 by default while excluding private/local addresses. Client-provided ECS is preserved when `preserve_client = true`.

Blocklists are configured under `[blocklist]` with `enabled`, local `paths`, and optional remote subscription `urls`. Allowlist sources use `allowlist_paths` and `allowlist_urls`; they support the same local and remote loading flow and take precedence over block rules. Remote subscriptions are downloaded to `download_dir` on startup, on `dotdns blocklist reload`, and periodically when `refresh_interval` is set.

DoT upstreams must use a hostname, not a raw IP address, so TLS SNI and certificate validation can work. Per-upstream `tls_cert_path` pinning is not implemented and is rejected during upstream setup.

DoH upstreams use HTTPS POST with `application/dns-message`. DoH hostnames are resolved once when the upstream pool is built and injected into the HTTPS client, so steady-state queries do not need to resolve the DoH hostname through `dotdns` itself. Optional `bootstrap` IPs can override that startup resolution when you need fixed DoH endpoint addresses.

## CLI

Management commands read `/etc/dotdns/dotdns.toml` automatically when it exists; otherwise they use `/tmp/dotdns.sock`. Pass `--config <path>` to read another management socket or loopback TCP setting.

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

## systemd

Example units live under `packaging/systemd`. They assume the binary is installed in `/usr/local/bin`, configuration is copied to `/etc/dotdns/dotdns.toml`, runtime sockets stay under `/run/dotdns`, and downloaded blocklists stay under `/var/lib/dotdns/blocklists` so they survive restarts.

```sh
install -Dm755 target/release/dotdns /usr/local/bin/dotdns
install -Dm644 examples/dotdns.toml /etc/dotdns/dotdns.toml
install -Dm644 packaging/systemd/dotdns.service /etc/systemd/system/dotdns.service
install -Dm644 packaging/systemd/dotdns.tmpfiles /etc/tmpfiles.d/dotdns.conf
systemd-tmpfiles --create /etc/tmpfiles.d/dotdns.conf
systemctl daemon-reload
systemctl enable --now dotdns.service
```

Create the `dotdns` system user before enabling the service, and ensure `/etc/dotdns/dotdns.toml` points at valid TLS certificate and key files. `systemctl reload dotdns.service` maps to `dotdns blocklist reload`, which fetches remote subscriptions and swaps in the parsed rules without restarting the resolver.

## Limitations / TODO

- `serve_stale` config option is accepted but does nothing right now.
- `tls_cert_path` pinning isn't implemented.
- Cache eviction is naive (not LRU) — should fix eventually.
- Unix socket cleanup on shutdown is missing; restart handles stale sockets.
- No AdGuard regex/modifier support, no cert automation, no clustering.
