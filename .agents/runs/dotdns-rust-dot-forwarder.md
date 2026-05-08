# Runbook: dotdns-rust-dot-forwarder

**Spec path:** `.agents/specs/dotdns-rust-dot-forwarder.md`  
**Status:** WS-001..WS-007 all done; final state verified  
**Last updated:** 2026-05-08

## Confirmed User Requirements Summary
- Build a Rust-based single-node public DNS-over-TLS forwarding resolver named `dotdns`.
- DoT-only client-facing service (port 853); no plain DNS listener.
- Upstream support for ordinary DNS, DoT, and DoH.
- TTL-aware response caching.
- AdGuard Home-compatible DNS ad blocking (A -> `0.0.0.0`, AAAA -> `::`).
- Backend CLI commands (`dotdns status`, `dotdns cache stats`, `dotdns cache flush`, `dotdns blocklist reload`).
- Management interface local-only by default.
- No frontend, no authoritative records, no clustering.

## Workstreams
| ID | Name | Preferred Agent | Status | Depends On |
|----|------|-----------------|--------|------------|
| WS-001 | Project Skeleton, Config, and Runtime Foundation | implementer | done | — |
| WS-002 | Upstream Resolver Transports | implementer | done | WS-001 |
| WS-002A | Upstream Review Polish | implementer | done | WS-002, WS-004 |
| WS-003 | DoT Server, Resolver Pipeline, EDNS, and Cache | implementer | done | WS-001, WS-002, WS-002A, WS-004 |
| WS-004 | AdGuard-Compatible Blocklist | implementer | done | WS-001 |
| WS-005 | Management API and CLI Operations | implementer | done | WS-003, WS-004 |
| WS-006 | Tests and Documentation | test-writer | done | WS-002, WS-003, WS-004, WS-005 |
| WS-007 | Final Verification | verifier | done | WS-006 |

## Next Steps
1. ~~Dispatch WS-002 and WS-004 in parallel.~~ (done)
2. ~~Once WS-002 and WS-004 both complete, dispatch WS-002A.~~ (done)
3. ~~Dispatch WS-003.~~ (done)
4. ~~Dispatch WS-005.~~ (done)
5. ~~Once WS-005 completes, unblock WS-006.~~ (done)
6. ~~Dispatch WS-006.~~ (done)
7. ~~Dispatch WS-007~~ for final verification. (done)

## Checkpoint: WS-001
- status: done
- files_touched: Cargo.toml, src/main.rs, src/cli.rs, src/config.rs, src/metrics.rs, src/upstream.rs, src/cache.rs, src/blocklist.rs, src/management.rs, src/server.rs, examples/dotdns.toml
- checks_run:
  - cargo build succeeded
  - cargo test succeeded (10 tests)
  - dotdns --help checked
  - serve config parse smoke checked
- open_risks:
  - placeholder modules may emit dead_code warnings until downstream work fills them
  - DNS transport/server crate selection deferred to WS-002/WS-003
- dependency_updates:
  - WS-001 cleared; WS-002 and WS-004 unblocked for parallel dispatch
- blocked_by: none

## Checkpoint: Review-Only Verifier Result
- status: pass
- notes: verifier identified localized quality findings that should be resolved before resolver integration to avoid propagating config/semantics issues into WS-003.
- findings:
  - DoT SNI hostname extraction should handle host:port and [ipv6]:port cases correctly.
  - `tls_cert_path` in config may be a silent no-op and should be removed or warned.
  - `ParseReport.total` documentation vs count behavior may be mismatched.
- resolution: handled by WS-002A.
- next_action: done.

## Checkpoint: WS-002
- status: done
- files_touched: Cargo.toml, src/upstream.rs
- checks_run:
  - cargo build succeeded
  - cargo test 35 passed
- open_risks: real DoT/DoH network interoperability not integration-tested
- dependency_updates: hickory-proto, reqwest, rustls, tokio-rustls, webpki-roots
- blocked_by: none

## Checkpoint: WS-004
- status: done
- files_touched: src/blocklist.rs
- checks_run:
  - cargo build succeeded
  - cargo test 27 passed
- open_risks: dead_code until consumed by WS-003
- dependency_updates: API ready for WS-003
- blocked_by: none

## Checkpoint: WS-002A
- status: done
- files_touched: src/upstream.rs, src/config.rs, src/blocklist.rs
- checks_run:
  - cargo build succeeded
  - cargo test 40 passed
- open_risks: none (review findings resolved)
- dependency_updates: fixed DoT host extraction, unsupported tls_cert_path no-op, ParseReport semantics
- blocked_by: none

## Checkpoint: WS-003
- status: done
- files_touched: Cargo.toml, src/blocklist.rs, src/cache.rs, src/server.rs, src/main.rs
- checks_run:
  - cargo build passed with warnings only
  - cargo test 51 passed, 0 failed
- open_risks:
  - serve_stale config is accepted but no-op
  - cache eviction is arbitrary not LRU
  - no max-message hardening beyond 65535 DNS frame limit
  - verifier did not rerun cargo due environment
- dependency_updates:
  - WS-003 cleared; WS-005 unblocked
  - verified: DoT 2-byte framing, TLS cert/key loading, EDNS preservation, blocklist-before-cache/upstream, cache TTL expiry and TTL adjustment, metrics coverage, no locks across await, no WS-005 scope creep
- blocked_by: none

## Checkpoint: WS-005
- status: done
- files_touched: src/management.rs, src/cli.rs, src/main.rs
- checks_run:
  - cargo build success
  - cargo test 59 passed
- open_risks:
  - Unix socket file not cleaned on shutdown but restart self-heals
  - no idle timeout on management connections
  - NotImplemented variant unused
  - cache stats reuses Status wire command
- dependency_updates:
  - WS-005 done; next ready task WS-006 Tests and Documentation
- blocked_by: none

## Checkpoint: WS-006
- status: done
- files_touched: README.md, src/blocklist.rs, src/cache.rs, src/cli.rs, src/config.rs, src/main.rs, src/management.rs, src/server.rs, src/upstream.rs
- checks_run:
  - cargo fmt --check passed after cargo fmt
  - cargo build passed with existing dead-code warnings
  - cargo test passed 64 passed / 0 failed
  - examples/dotdns.toml covered by config::tests::example_config_matches_implemented_schema
- open_risks:
  - dead-code warnings remain
  - example config unchanged
- dependency_updates:
  - WS-006 done; next ready task WS-007 final verification
- blocked_by: none
- implementation_note: fixed narrow blocklist parser bug where cosmetic AdGuard rules containing `#` were treated as inline comments before unsupported-feature detection
- docs: README covers deployment, TLS/853, CLI, upstream protocols, AdGuard subset/limitations, known risks

## Checkpoint: WS-007
- status: done
- files_touched: .agents/specs/dotdns-rust-dot-forwarder.md, .agents/runs/dotdns-rust-dot-forwarder.md
- checks_run:
  - spec status updated to verified
  - implementation outcome recorded
  - runbook DAG state updated to all done
- open_risks:
  - dead-code warnings remain
  - serve_stale config accepted but no-op
  - cache eviction is arbitrary not LRU
  - Unix socket cleanup self-heals on restart
  - no real network DoT/DoH integration test
  - no systemd files
- dependency_updates:
  - WS-007 done; DAG all done
- blocked_by: none

## Residual Non-Blocking Risks
- dead-code warnings
- serve_stale no-op
- arbitrary cache eviction not LRU
- Unix socket cleanup self-heals on restart
- no real network DoT/DoH integration test
- no systemd files
