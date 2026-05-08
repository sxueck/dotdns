---
slug: dotdns-rust-dot-forwarder
title: Rust DoT Forwarding DNS Service
status: verified
---

# Rust DoT Forwarding DNS Service

## Goal
- Build a Rust-based single-node public DNS-over-TLS forwarding resolver named `dotdns`.
- Provide backend-only operational CLI commands similar in spirit to `chronyc`.
- Support forwarding to ordinary DNS, DoT, and DoH upstreams while adding TTL cache, EDNS compatibility, metrics, and AdGuard Home-compatible DNS ad blocking.

## Scope
- In scope: initialize a new Rust/Cargo project in the current repository.
- In scope: produce one `dotdns` binary with service and CLI subcommands.
- In scope: expose only a DoT server to clients.
- In scope: forward DNS queries to configured upstream resolvers over ordinary DNS, DoT, or DoH.
- In scope: implement TTL-aware response caching.
- In scope: implement AdGuard Home-compatible blocklist loading and matching for DNS ad blocking.
- In scope: provide local-only management operations for status, cache stats, cache flush, and blocklist reload.
- In scope: provide example config and concise deployment documentation.

## Non-Goals
- No frontend, Web UI, or dashboard.
- No authoritative DNS records or custom local zone management.
- No UDP/TCP plain DNS server exposed to clients.
- No distributed mode, clustering, shared cache, or database.
- No certificate issuance/renewal automation.
- No HTTP content filtering, SNI filtering, proxying, or non-DNS traffic inspection.
- No full AdGuard Home feature parity in the first version.

## Constraints
- Repository evidence: `/Users/yshen/GolandProjects/dotdns` was initially empty; the user initialized git, but no Rust/Cargo project exists yet.
- Runtime target is single-machine public deployment.
- TLS certificate and private key are supplied by the operator and loaded from config.
- Management interface MUST default to local-only access.
- DNS protocol handling, EDNS parsing/serialization, and upstream protocol transports SHOULD use mature third-party Rust crates where practical.
- The service SHOULD keep custom logic focused on orchestration, cache policy, blocklist matching, statistics, configuration, and CLI control.
- AdGuard-compatible rules are broad; the first version MUST document supported and unsupported rule features.

## Common Summary
- Objective: create `dotdns`, a Rust single-node DoT forwarding cache resolver with CLI operations.
- Boundary: clients talk DoT only; upstreams may be ordinary DNS, DoT, or DoH; the service does not generate authoritative records.
- Shared contracts: config file, upstream abstraction, cache key/value behavior, blocklist matcher, metrics recorder and snapshot, local management API, CLI output.
- Key dependency ordering: project/config/contracts first, then DNS service/upstream/cache/blocking, then management CLI, tests, docs.
- Unknowns: exact management socket default path and complete upstream crate choice are implementation decisions unless they affect behavior.

## Context Facts
- The working directory is `/Users/yshen/GolandProjects/dotdns`.
- The directory had no files before git initialization.
- The user requested Rust, public deployment, single-node mode, no frontend, DoT-only client-facing service, EDNS, cache, and CLI backend operations.
- The user clarified that upstream resolution must support ordinary DNS, DoH, and DoT.
- The user clarified that the service only forwards and caches; it does not produce its own DNS records.
- The user clarified that ad blocking is required and blocklists should be compatible with AdGuard Home lists.
- The user accepted the recommended blocked response behavior: A returns `0.0.0.0`, AAAA returns `::`.

## User Outcomes
- An operator can run `dotdns serve --config <path>` on a public server with a TLS certificate and expose DoT on port `853`.
- A DoT client can query through `dotdns` and receive upstream DNS answers.
- Repeated queries benefit from TTL-aware cache hits.
- Ad/tracking domains from AdGuard-compatible lists are blocked before upstream forwarding.
- An operator can inspect status and counters using commands such as `dotdns status`.
- An operator can flush cache and reload blocklists without restarting the service.

## Functional Requirements
- FR-1: The project MUST build a `dotdns` binary using Cargo.
- FR-2: `dotdns serve --config <path>` MUST start the DoT server using the configured listen address, TLS certificate, private key, upstreams, cache settings, blocklist paths, and management interface.
- FR-3: The client-facing DNS service MUST accept DNS-over-TLS queries and MUST NOT expose a plain DNS listener unless explicitly added in a future spec.
- FR-4: The resolver MUST forward non-blocked cache-miss queries to configured upstream resolvers.
- FR-5: Upstream resolver configuration MUST support ordinary DNS, DoT, and DoH entries.
- FR-6: When an upstream request fails, the resolver MUST attempt fallback to the next configured upstream and increment upstream failure metrics.
- FR-7: The resolver MUST handle common EDNS queries without rejecting them solely because an OPT record is present.
- FR-8: The cache MUST key responses by DNS question-relevant fields that affect answer correctness, including at least query name, query type, and query class.
- FR-9: Cached responses MUST expire according to the DNS response TTL, bounded by configured cache policy if min/max TTL settings are present.
- FR-10: The cache MUST record hit, miss, entry count, and flush behavior for management reporting.
- FR-11: The blocklist loader MUST support a documented AdGuard Home-compatible subset including comments, plain domain rules, hosts-style entries, `||domain^` rules, and `@@` exception rules.
- FR-12: If a query matches a block rule and no exception rule applies, the resolver MUST NOT forward it upstream.
- FR-13: For blocked A queries, the resolver MUST return `0.0.0.0`.
- FR-14: For blocked AAAA queries, the resolver MUST return `::`.
- FR-15: For blocked query types other than A/AAAA, the resolver SHOULD return a protocol-valid empty success response unless a third-party DNS crate provides a more compatible standard blocking response.
- FR-16: The service MUST maintain counters for total queries, cache hits, cache misses, blocked queries, upstream failures, and start time.
- FR-17: `dotdns status` MUST retrieve a metrics snapshot from the running service and print a human-readable status.
- FR-18: `dotdns cache stats` MUST show cache entry count and cache hit/miss counters.
- FR-19: `dotdns cache flush` MUST request the running service to clear cache entries.
- FR-20: `dotdns blocklist reload` MUST request the running service to reload configured blocklist files without restarting; if reload fails, the previously active rules MUST remain in effect.
- FR-21: Management interface MUST default to Unix domain socket with owner-only permissions; TCP fallback MUST allow loopback only and MUST deny binding to `0.0.0.0` by default.
- FR-22: The config parser MUST reject missing required runtime fields with actionable errors.

## Non-Functional Requirements
- NFR-1: The implementation SHOULD use async Rust for network I/O.
- NFR-2: The service SHOULD use structured logging suitable for daemon deployment.
- NFR-3: The code SHOULD isolate DNS protocol transport details from cache, blocklist, and management logic.
- NFR-4: The service SHOULD avoid holding global locks across network awaits.
- NFR-5: Management command output SHOULD be stable enough for human operation, but machine-readable output is optional unless added later.
- NFR-6: Tests SHOULD prefer public behavior assertions over implementation-detail coupling.

## Edge Cases
- Scenario: All upstreams fail.
  Expected: The resolver returns a DNS error response and increments upstream failure metrics.
- Scenario: Query contains EDNS OPT data.
  Expected: The service preserves compatibility and does not fail solely because EDNS is present.
- Scenario: Cached response TTL has expired.
  Expected: The resolver treats it as a cache miss and queries upstream again.
- Scenario: A block rule and exception rule both match.
  Expected: The exception rule wins and the query proceeds through cache/upstream flow.
- Scenario: Blocklist file contains unsupported AdGuard modifiers.
  Expected: The loader skips or ignores unsupported features in a documented way without crashing the service.
- Scenario: `dotdns status` runs while service is not running.
  Expected: CLI returns a clear connection error.
- Scenario: `dotdns blocklist reload` loads an invalid file.
  Expected: Existing active rules remain in use and the management response reports the reload failure.

## Shared Contracts
- Contract: Configuration file schema.
  Owner: WS-001.
  Consumers: service startup, upstream factory, cache setup, blocklist loader, management interface, docs.
  Notes: Prefer `dotdns.toml` with explicit sections for `server`, `tls`, `upstreams`, `cache`, `blocklist`, `management`, and `logging`.

- Contract: Upstream resolver abstraction.
  Owner: WS-002.
  Consumers: resolver pipeline and tests.
  Notes: Must support ordinary DNS, DoT, and DoH implementations behind one async query interface.

- Contract: Resolver pipeline.
  Owner: WS-003.
  Consumers: DoT server, metrics, tests.
  Notes: Query flow is blocklist check -> cache lookup -> upstream fallback -> cache insert -> response.

- Contract: Blocklist matcher.
  Owner: WS-004.
  Consumers: resolver pipeline, reload command, tests.
  Notes: Must support documented AdGuard-compatible subset and exception precedence.

- Contract: Metrics recorder and snapshot.
  Owner: WS-001/WS-003 define primitives; WS-005 exposes and formats.
  Consumers: resolver pipeline, cache, blocklist, management API, `status`, `cache stats`, tests.
  Notes: Minimal MetricsRecorder/MetricsSnapshot types should be stable in the foundation/pipeline phase. Include total queries, cache hits, cache misses, blocked queries, upstream failures, cache entries, uptime/start time.

- Contract: Local management API.
  Owner: WS-005.
  Consumers: CLI commands.
  Notes: Default Unix domain socket with owner-only permissions; default path configurable (examples: `/tmp/dotdns.sock` or run-directory path). TCP fallback allows loopback only and denies `0.0.0.0` management binding. `blocklist reload` reloads only configured blocklist paths; invalid reload preserves old rules.

## Workstreams
### WS-001 Project Skeleton, Config, and Runtime Foundation
- `workstream_id`: ws-001-project-config-runtime
- `preferred_agent`: implementer
- Goal: Initialize Cargo project, dependency baseline, config schema, logging, and runtime entrypoint.
- In scope: `Cargo.toml`, `src/main.rs`, module layout, `dotdns serve`, config loading, example config.
- Depends on: none
- Unblocks: all implementation workstreams.
- Files or surfaces: Cargo project files, config module, CLI skeleton, example `dotdns.toml`.
- Contract touchpoints: configuration file schema, command structure, metrics recorder primitives.
- Validation path: `cargo build`; config parsing tests if practical.
- Review sensitivity: dependency choices and config contract stability.

### WS-002 Upstream Resolver Transports
- `workstream_id`: ws-002-upstream-transports
- `preferred_agent`: implementer
- Goal: Provide a shared upstream abstraction with ordinary DNS, DoT, and DoH support using third-party crates where practical.
- In scope: upstream config parsing, async resolver trait/interface, fallback ordering, transport-specific adapters.
- Depends on: ws-001-project-config-runtime
- Unblocks: resolver pipeline integration.
- Files or surfaces: upstream module, config mapping, upstream tests.
- Contract touchpoints: upstream resolver abstraction.
- Validation path: unit tests with mocked upstream interface; optional integration smoke test when external networking is available.
- Review sensitivity: avoiding custom DNS protocol reinvention and preserving fallback behavior.

### WS-002A Upstream Review Polish
- `workstream_id`: ws-002a-upstream-review-polish
- `preferred_agent`: implementer
- Goal: Address verifier quality findings before resolver integration.
- In scope: fix or document DoT SNI hostname extraction for host:port / [ipv6]:port cases; remove or warn on unsupported `tls_cert_path` to avoid silent no-op; correct `ParseReport.total` doc/count mismatch if still present.
- Depends on: ws-002-upstream-transports, ws-004-adguard-blocklist
- Unblocks: ws-003-dot-server-cache-pipeline
- Files or surfaces: src/upstream.rs, src/config.rs, src/blocklist.rs, tests/docs as needed.
- Contract touchpoints: upstream config semantics and blocklist parse report semantics.
- Validation path: cargo build; cargo test.
- Review sensitivity: low/moderate, localized quality fixes before integration.

### WS-003 DoT Server, Resolver Pipeline, EDNS, and Cache
- `workstream_id`: ws-003-dot-server-cache-pipeline
- `preferred_agent`: implementer
- Goal: Implement client-facing DoT server and resolver pipeline with EDNS-compatible forwarding and TTL cache.
- In scope: TLS listener, DNS request handling, cache key/value logic, TTL expiry, cache insert/lookup/flush primitives.
- Depends on: ws-001-project-config-runtime, ws-002-upstream-transports, ws-002a-upstream-review-polish, ws-004-adguard-blocklist
- Unblocks: metrics, management operations, end-to-end behavior.
- Files or surfaces: server module, resolver module, cache module, DNS message handling tests.
- Contract touchpoints: resolver pipeline, cache behavior, EDNS compatibility, metrics snapshot primitives.
- Validation path: unit tests for cache TTL and resolver flow; local DoT smoke test if feasible.
- Review sensitivity: protocol correctness, cache correctness, async locking.

### WS-004 AdGuard-Compatible Blocklist
- `workstream_id`: ws-004-adguard-blocklist
- `preferred_agent`: implementer
- Goal: Add AdGuard Home-compatible blocklist parsing and DNS blocking behavior.
- In scope: load blocklist files, parse supported rule subset, exception precedence, domain/subdomain matching, blocked responses for A/AAAA/other types, reloadable rule set. Does not own resolver pipeline integration.
- Depends on: ws-001-project-config-runtime
- Unblocks: resolver pipeline blocking integration and blocklist reload.
- Files or surfaces: blocklist module, blocked response helper, blocklist tests.
- Contract touchpoints: blocklist matcher and blocked response behavior.
- Validation path: tests for plain domains, hosts entries, `||domain^`, `@@`, subdomain matching, A/AAAA response values.
- Review sensitivity: AdGuard compatibility claims and false-positive risk.

### WS-005 Management API and CLI Operations
- `workstream_id`: ws-005-management-cli
- `preferred_agent`: implementer
- Goal: Implement local management interface and CLI commands for service status, cache stats, cache flush, and blocklist reload.
- In scope: metrics snapshot, local management server, client-side CLI commands, status formatting, cache flush request, reload request.
- Depends on: ws-003-dot-server-cache-pipeline, ws-004-adguard-blocklist
- Unblocks: operator workflows and final docs.
- Files or surfaces: management module, CLI command handlers, metrics module.
- Contract touchpoints: metrics snapshot formatting, local management API.
- Validation path: unit tests for command handlers/API serialization; manual status behavior if daemon can run locally.
- Review sensitivity: management interface exposure and stale metrics.

### WS-006 Tests and Documentation
- `workstream_id`: ws-006-tests-docs
- `preferred_agent`: test-writer
- Goal: Add coverage and concise operator documentation.
- In scope: README, example config, test coverage for cache TTL, blocklist matching, upstream fallback abstraction, management command logic, documented unsupported AdGuard features.
- Depends on: ws-002-upstream-transports, ws-003-dot-server-cache-pipeline, ws-004-adguard-blocklist, ws-005-management-cli
- Unblocks: final verification.
- Files or surfaces: README, examples, test modules.
- Contract touchpoints: acceptance criteria and documented operational behavior.
- Validation path: `cargo test`; `cargo build`.
- Review sensitivity: docs matching implemented behavior.

### WS-007 Final Verification
- `workstream_id`: ws-007-final-verification
- `preferred_agent`: verifier
- Goal: Verify implementation against acceptance criteria and inspect integration risks.
- In scope: review completeness, correctness, coherence; map each acceptance criterion to verified/deviated/missing/blocked.
- Depends on: ws-006-tests-docs
- Unblocks: final handoff.
- Files or surfaces: changed source, tests, README, example config.
- Contract touchpoints: all shared contracts.
- Validation path: review implementation evidence, observed `cargo build` / `cargo test` results, targeted spot checks.
- Review sensitivity: high, because DNS protocol behavior, network security, and blocklist compatibility cross module boundaries.

## Acceptance Criteria
- AC-1: `cargo build` produces a `dotdns` binary.
- AC-2: `dotdns serve --config <path>` starts a TLS-backed DoT listener from config.
- AC-3: A DoT query can be accepted, resolved through an upstream, and returned to the client.
- AC-4: Configured upstreams can include ordinary DNS, DoT, and DoH.
- AC-5: Upstream failures fallback to later upstreams and increment failure metrics.
- AC-6: EDNS OPT presence does not cause otherwise valid queries to be rejected.
- AC-7: Repeated eligible queries hit cache before TTL expiry.
- AC-8: Expired cache entries are not served as valid responses.
- AC-9: AdGuard-compatible supported rules block matching domains before upstream forwarding.
- AC-10: Exception rules override block rules.
- AC-11: Blocked A queries return `0.0.0.0`.
- AC-12: Blocked AAAA queries return `::`.
- AC-13: `dotdns status` reports running state, uptime/start time, total queries, cache hits, cache misses, blocked queries, and upstream failures.
- AC-14: `dotdns cache stats` reports cache entry and hit/miss information.
- AC-15: `dotdns cache flush` clears active cache entries.
- AC-16: `dotdns blocklist reload` reloads configured blocklists without service restart and preserves old rules if reload fails.
- AC-17: Management interface is local-only by default.
- AC-18: README and example config document deployment, certificate paths, port `853`, upstreams, cache, blocklists, CLI operations, and unsupported AdGuard rule features.
- AC-19: Tests cover cache TTL behavior, blocklist parsing/matching, blocked response behavior, upstream fallback abstraction, and management command core logic.

## Review Plan
- Completeness: verify all CLI commands, config sections, resolver flow, cache behavior, blocklist behavior, and docs exist and map to acceptance criteria.
- Correctness: inspect DNS response construction, TTL handling, upstream fallback semantics, exception precedence, local-only management binding, and EDNS compatibility.
- Coherence: ensure module boundaries match shared contracts, config names match docs, CLI names match README, and custom protocol logic is not unnecessarily reinvented.
- Checks: run `cargo build` and `cargo test` where environment permits.
- Residual risks to inspect: real-world DoT/DoH interoperability, complete AdGuard rule compatibility, systemd/daemon deployment hardening, and privileged port `853` binding.

## Source Coverage Audit
- User request: Rust DoT-only public single-node service -> WS-001, WS-003, AC-1, AC-2, AC-3.
- User request: no frontend and chronyc-like backend CLI -> WS-005, AC-13 through AC-16.
- User request: status can show resolution counts -> WS-005, FR-16, FR-17, AC-13.
- User request: EDNS and cache -> WS-003, FR-7 through FR-10, AC-6 through AC-8.
- User clarification: upstream ordinary DNS/DoH/DoT with third-party libraries -> WS-002, FR-4 through FR-6, NFR-3, AC-4, AC-5.
- User clarification: forwarding cache only, no own records -> Scope, Non-Goals, FR-4.
- User clarification: ad blocking and AdGuard Home-compatible lists -> WS-004, FR-11 through FR-15, AC-9 through AC-12, AC-18.
- Repo evidence: empty/new git repo with no Cargo project -> Context Facts, WS-001.
- Security/deployment requirement: public deployment with local-only management -> Constraints, FR-21, AC-17.
- Anything not traced: full AdGuard feature parity, Web UI, authoritative records, distributed mode, and certificate automation are explicitly out of scope.

## Open Questions
- None blocking. Default management interface will be local-only; Unix domain socket is preferred if practical.

## Implementation Outcome
已实现 Rust DoT forwarding cache resolver `dotdns`，支持 ordinary DNS/DoT/DoH upstream、EDNS、TTL cache、AdGuard-compatible blocking、local CLI management。最终验证 AC-1..AC-19 全部 verified；检查为 `cargo fmt --check`、`cargo build`、`cargo test` 64 passed（build/test 结果来自执行证据，最终 verifier observed-not-rerun）。
