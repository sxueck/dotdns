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

Blocklists are configured under `[blocklist]` with `enabled`, local `paths`, and optional remote subscription `urls`. Allowlist sources use `allowlist_paths` and `allowlist_urls`; they support the same local and remote loading flow and take precedence over block rules. Remote subscriptions are downloaded to `download_dir` on startup, on `dotdns blocklist reload`, and periodically when `refresh_interval` is set. Blocked responses default to `response_mode = "null_ip"` with `blocked_ttl = "5m"`; `no_data` and `nx_domain` modes include SOA negative caching.

DoT upstreams must use a hostname, not a raw IP address, so TLS SNI and certificate validation can work. Per-upstream `tls_cert_path` pinning is not implemented and is rejected during upstream setup.

DoT and DoH upstream hostnames are resolved once when the upstream pool is built. Configure global `[bootstrap].dns` servers to resolve those hostnames through plain DNS at startup; when empty, dotdns uses the system resolver. DoH endpoints are injected into per-endpoint HTTPS clients, so steady-state queries do not need to resolve the DoH hostname through `dotdns` itself and a bad endpoint does not poison the whole DoH upstream.

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

In the default `null_ip` mode, blocked `A` queries return `0.0.0.0` and blocked `AAAA` queries return `::`, which avoids client DNS retry storms. `no_data` returns `NOERROR` with empty answers and SOA negative caching; `nx_domain` returns `NXDOMAIN` with SOA negative caching. Exception rules override block rules.

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

### User and permissions

The service runs as an unprivileged `dotdns` user. You must create this user before starting the service. The preferred method on modern distributions is `systemd-sysusers`:

```sh
install -Dm644 packaging/systemd/dotdns-sysusers.conf /usr/lib/sysusers.d/dotdns.conf
systemd-sysusers
```

If `systemd-sysusers` is unavailable, create the user manually:

```sh
useradd --system --no-create-home --home-dir /var/lib/dotdns dotdns
```

Ensure `/etc/dotdns/dotdns.toml` points at valid TLS certificate and key files that are readable by the `dotdns` user.

### Binding to port 853 as a non-root user

The service file uses `AmbientCapabilities=CAP_NET_BIND_SERVICE` (requires **systemd >= 228**) so the unprivileged `dotdns` user can listen on the privileged DoT port 853. If you are running an older systemd version where this directive is ignored, grant the capability directly to the binary instead:

```sh
setcap cap_net_bind_service=+ep /usr/local/bin/dotdns
```

`systemctl reload dotdns.service` maps to `dotdns blocklist reload`, which fetches remote subscriptions and swaps in the parsed rules without restarting the resolver.

## Limitations / TODO

- `tls_cert_path` pinning isn't implemented.
- Cache eviction is naive (not LRU) — should fix eventually.
- Unix socket cleanup on shutdown is missing; restart handles stale sockets.
- No AdGuard regex/modifier support, no cert automation, no clustering.
