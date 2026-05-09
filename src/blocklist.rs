//! AdGuard Home-compatible blocklist parsing and matching.
//!
//! Supports a documented subset of AdGuard rules:
//! - Comments (`#`, `!`) and blank lines.
//! - Plain domain rules (`example.com`).
//! - Hosts-style entries (`127.0.0.1 example.com`, `0.0.0.0 example.com`).
//! - Anchored domain rules (`||example.com^`).
//! - Exception rules (`@@example.com`, `@@||example.com^`).
//!
//! Unsupported features (modifiers after `$`, regex rules, CSS rules, etc.)
//! are skipped during parsing without crashing.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

use crate::config::BlocklistConfig;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockDecision {
    Allow,
    Block,
    Exception,
}

impl BlockDecision {
    pub fn is_blocked(&self) -> bool {
        matches!(self, BlockDecision::Block)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NormalizedRule {
    Domain(String),
}

#[derive(Debug, Clone, Copy)]
enum RuleTarget {
    Block,
    Allow,
}

#[derive(Debug, Clone, Default)]
pub struct BlocklistEngine {
    blocks: HashSet<NormalizedRule>,
    exceptions: HashSet<NormalizedRule>,
}

impl BlocklistEngine {
    pub fn empty() -> Self {
        Self {
            blocks: HashSet::new(),
            exceptions: HashSet::new(),
        }
    }

    // Returns (engine, report). report tells you how many lines were skipped.
    pub fn from_paths(paths: &[PathBuf]) -> Result<(Self, ParseReport), BlocklistError> {
        Self::from_sources(paths, &[])
    }

    pub fn from_sources(
        block_paths: &[PathBuf],
        allow_paths: &[PathBuf],
    ) -> Result<(Self, ParseReport), BlocklistError> {
        let mut engine = Self::empty();
        let mut report = ParseReport::default();
        engine.load_paths(block_paths, RuleTarget::Block, &mut report)?;
        engine.load_paths(allow_paths, RuleTarget::Allow, &mut report)?;
        Ok((engine, report))
    }

    fn load_paths(
        &mut self,
        paths: &[PathBuf],
        target: RuleTarget,
        report: &mut ParseReport,
    ) -> Result<(), BlocklistError> {
        for path in paths {
            let file = fs::File::open(path).map_err(|e| BlocklistError::Io {
                path: path.clone(),
                source: e,
            })?;
            let reader = io::BufReader::new(file);
            for line in reader.lines() {
                let line = line.map_err(|e| BlocklistError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                match parse_line(&line) {
                    ParsedLine::Skip => {}
                    ParsedLine::Block(rule) => {
                        self.insert_rule(rule, target);
                    }
                    ParsedLine::Exception(rule) => {
                        self.exceptions.insert(rule);
                    }
                    ParsedLine::Unsupported => {
                        report.unsupported += 1;
                    }
                }
                report.total += 1;
            }
        }
        Ok(())
    }

    fn insert_rule(&mut self, rule: NormalizedRule, target: RuleTarget) {
        match target {
            RuleTarget::Block => {
                self.blocks.insert(rule);
            }
            RuleTarget::Allow => {
                self.exceptions.insert(rule);
            }
        }
    }

    // Exception rules win over block rules.
    pub fn decide(&self, domain: &str) -> BlockDecision {
        let normalized = normalize_domain(domain);
        if self.matches_exception(&normalized) {
            return BlockDecision::Exception;
        }
        if self.matches_block(&normalized) {
            return BlockDecision::Block;
        }
        BlockDecision::Allow
    }

    fn matches_block(&self, normalized: &str) -> bool {
        self.rule_matches(&self.blocks, normalized)
    }

    fn matches_exception(&self, normalized: &str) -> bool {
        self.rule_matches(&self.exceptions, normalized)
    }

    fn rule_matches(&self, rules: &HashSet<NormalizedRule>, normalized: &str) -> bool {
        for suffix in domain_suffixes(normalized) {
            if rules.contains(&NormalizedRule::Domain(suffix.to_string())) {
                return true;
            }
        }
        false
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn exception_count(&self) -> usize {
        self.exceptions.len()
    }

    pub fn add_block(&mut self, domain: &str) {
        self.blocks
            .insert(NormalizedRule::Domain(normalize_domain(domain)));
    }

    pub fn add_exception(&mut self, domain: &str) {
        self.exceptions
            .insert(NormalizedRule::Domain(normalize_domain(domain)));
    }
}

/// Thread-safe reloadable wrapper.
#[derive(Debug)]
pub struct ReloadableBlocklist {
    engine: RwLock<BlocklistEngine>,
    paths: Vec<PathBuf>,
    allowlist_paths: Vec<PathBuf>,
    remote: RemoteBlocklists,
    allowlist_remote: RemoteBlocklists,
    refresh_lock: Mutex<()>,
}

impl ReloadableBlocklist {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            engine: RwLock::new(BlocklistEngine::empty()),
            paths,
            allowlist_paths: Vec::new(),
            remote: RemoteBlocklists::default(),
            allowlist_remote: RemoteBlocklists::default(),
            refresh_lock: Mutex::new(()),
        }
    }

    pub fn from_config(config: &BlocklistConfig) -> Self {
        Self {
            engine: RwLock::new(BlocklistEngine::empty()),
            paths: config.paths.clone(),
            allowlist_paths: config.allowlist_paths.clone(),
            remote: RemoteBlocklists {
                urls: config.urls.clone(),
                download_dir: config.download_dir.clone(),
                timeout: config.download_timeout,
                file_prefix: "subscription".into(),
            },
            allowlist_remote: RemoteBlocklists {
                urls: config.allowlist_urls.clone(),
                download_dir: config.download_dir.clone(),
                timeout: config.download_timeout,
                file_prefix: "allowlist".into(),
            },
            refresh_lock: Mutex::new(()),
        }
    }

    pub fn from_engine(engine: BlocklistEngine, paths: Vec<PathBuf>) -> Self {
        Self {
            engine: RwLock::new(engine),
            paths,
            allowlist_paths: Vec::new(),
            remote: RemoteBlocklists::default(),
            allowlist_remote: RemoteBlocklists::default(),
            refresh_lock: Mutex::new(()),
        }
    }

    // If reload fails, old rules stick around.
    pub fn reload(&self) -> Result<ParseReport, BlocklistError> {
        let block_paths = self.all_block_paths();
        let allow_paths = self.all_allow_paths();
        let (new_engine, report) = BlocklistEngine::from_sources(&block_paths, &allow_paths)?;
        let mut guard = self.engine.write().expect("blocklist write lock poisoned");
        *guard = new_engine;
        Ok(report)
    }

    pub async fn refresh_and_reload(&self) -> Result<ParseReport, BlocklistError> {
        let _guard = self.refresh_lock.lock().await;
        self.remote.refresh().await?;
        self.allowlist_remote.refresh().await?;
        self.reload()
    }

    pub fn decide(&self, domain: &str) -> BlockDecision {
        let guard = self.engine.read().expect("blocklist read lock poisoned");
        guard.decide(domain)
    }

    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    fn all_block_paths(&self) -> Vec<PathBuf> {
        let mut paths = self.paths.clone();
        paths.extend(self.remote.paths());
        paths
    }

    fn all_allow_paths(&self) -> Vec<PathBuf> {
        let mut paths = self.allowlist_paths.clone();
        paths.extend(self.allowlist_remote.paths());
        paths
    }

    pub fn block_count(&self) -> usize {
        let guard = self.engine.read().expect("blocklist read lock poisoned");
        guard.block_count()
    }

    pub fn exception_count(&self) -> usize {
        let guard = self.engine.read().expect("blocklist read lock poisoned");
        guard.exception_count()
    }
}

#[derive(Debug, Clone, Default)]
struct RemoteBlocklists {
    urls: Vec<String>,
    download_dir: PathBuf,
    timeout: Duration,
    file_prefix: String,
}

impl RemoteBlocklists {
    async fn refresh(&self) -> Result<(), BlocklistError> {
        if self.urls.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.download_dir).map_err(|e| BlocklistError::Io {
            path: self.download_dir.clone(),
            source: e,
        })?;

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(BlocklistError::HttpClient)?;

        let mut staged = Vec::with_capacity(self.urls.len());
        for (idx, url) in self.urls.iter().enumerate() {
            let body = client
                .get(url)
                .send()
                .await
                .map_err(|source| BlocklistError::Download {
                    url: url.clone(),
                    source,
                })?
                .error_for_status()
                .map_err(|source| BlocklistError::Download {
                    url: url.clone(),
                    source,
                })?
                .bytes()
                .await
                .map_err(|source| BlocklistError::Download {
                    url: url.clone(),
                    source,
                })?;
            let body = String::from_utf8_lossy(&body);

            let final_path = self.path_for(idx);
            let tmp_path = final_path.with_extension("tmp");
            fs::write(&tmp_path, body.as_bytes()).map_err(|e| BlocklistError::Io {
                path: tmp_path.clone(),
                source: e,
            })?;
            staged.push((tmp_path, final_path));
        }

        for (tmp_path, final_path) in staged {
            fs::rename(&tmp_path, &final_path).map_err(|e| BlocklistError::Io {
                path: final_path,
                source: e,
            })?;
        }
        Ok(())
    }

    fn paths(&self) -> Vec<PathBuf> {
        (0..self.urls.len()).map(|idx| self.path_for(idx)).collect()
    }

    fn path_for(&self, idx: usize) -> PathBuf {
        self.download_dir
            .join(format!("{}-{idx:04}.txt", self.file_prefix))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlocklistError {
    #[error("failed to read blocklist {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("failed to create HTTP client for blocklist downloads: {0}")]
    HttpClient(reqwest::Error),
    #[error("failed to download blocklist {url}: {source}")]
    Download { url: String, source: reqwest::Error },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseReport {
    pub total: u64,
    pub unsupported: u64,
}

impl fmt::Display for ParseReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parsed {} lines, {} unsupported skipped",
            self.total, self.unsupported
        )
    }
}

/// Blocked response IPs.
pub struct BlockedResponse;

impl BlockedResponse {
    /// IPv4 address to return for blocked A queries.
    pub const IPV4: &str = "0.0.0.0";
    /// IPv6 address to return for blocked AAAA queries.
    pub const IPV6: &str = "::";

    /// Returns the IPv4 blocked address.
    pub fn ipv4() -> &'static str {
        Self::IPV4
    }

    /// Returns the IPv6 blocked address.
    pub fn ipv6() -> &'static str {
        Self::IPV6
    }

    /// Other query types get an empty NOERROR response.
    pub fn empty_for_other_types() -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Parsing internals
// ---------------------------------------------------------------------------

enum ParsedLine {
    Skip,
    Block(NormalizedRule),
    Exception(NormalizedRule),
    Unsupported,
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().to_lowercase()
}

fn parse_line(line: &str) -> ParsedLine {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ParsedLine::Skip;
    }
    if trimmed.starts_with('#') || trimmed.starts_with('!') {
        return ParsedLine::Skip;
    }

    // Unsupported: modifiers and cosmetic/network features outside this DNS-only subset.
    if trimmed.contains('$')
        || trimmed.contains("##")
        || trimmed.contains("#@#")
        || trimmed.contains("#?#")
    {
        return ParsedLine::Unsupported;
    }

    // Strip inline comments (only `#`; `!` is usually a full-line comment) after
    // detecting AdGuard cosmetic markers that also use `#`.
    let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
    if without_comment.is_empty() {
        return ParsedLine::Skip;
    }

    let mut rest = without_comment;

    // Detect exception.
    let is_exception = rest.starts_with("@@");
    if is_exception {
        rest = &rest[2..];
    }

    // Detect anchored rule `||domain^`.
    if rest.starts_with("||") {
        rest = &rest[2..];
        if rest.ends_with('^') {
            rest = &rest[..rest.len() - 1];
        }
        let domain = normalize_domain(rest);
        if domain.is_empty() || !looks_like_domain(&domain) {
            return ParsedLine::Unsupported;
        }
        let rule = NormalizedRule::Domain(domain);
        return if is_exception {
            ParsedLine::Exception(rule)
        } else {
            ParsedLine::Block(rule)
        };
    }

    // Detect hosts-style entries: `<ip> <domain>` or `<ip> <domain> <alias>...`
    // Valid IPs start with digits, `::`, or `fe80` etc.
    if let Some(rule) = try_parse_hosts(rest) {
        return if is_exception {
            ParsedLine::Exception(rule)
        } else {
            ParsedLine::Block(rule)
        };
    }

    // Plain domain rule.
    let domain = normalize_domain(rest);
    if domain.is_empty() || !looks_like_domain(&domain) {
        return ParsedLine::Unsupported;
    }
    let rule = NormalizedRule::Domain(domain);
    if is_exception {
        ParsedLine::Exception(rule)
    } else {
        ParsedLine::Block(rule)
    }
}

/// Try to interpret `rest` as a hosts-style line.
fn try_parse_hosts(rest: &str) -> Option<NormalizedRule> {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let first = parts[0];
    // Heuristic: first token must look like an IP address.
    if !looks_like_ip(first) {
        return None;
    }
    // Use the first domain token after the IP.
    let domain = normalize_domain(parts[1]);
    if domain.is_empty() || !looks_like_domain(&domain) {
        return None;
    }
    Some(NormalizedRule::Domain(domain))
}

fn looks_like_ip(token: &str) -> bool {
    // IPv4 starts with digit, IPv6 with `:` or hex digit.
    token.starts_with(|c: char| c.is_ascii_digit() || c == ':')
}

fn looks_like_domain(domain: &str) -> bool {
    // Minimal sanity check: contains at least one dot, no spaces,
    // no slashes (regex), and no asterisks.
    domain.contains('.')
        && domain.chars().all(|c| !c.is_whitespace())
        && !domain.starts_with('/')
        && !domain.contains('*')
}

/// Yield the domain and each parent domain suffix that could match a rule.
fn domain_suffixes(domain: &str) -> impl Iterator<Item = &str> {
    let mut start = 0usize;
    std::iter::from_fn(move || {
        if start >= domain.len() {
            return None;
        }
        let suffix = &domain[start..];
        // Advance start to the next label after a dot.
        if let Some(dot_pos) = domain[start..].find('.') {
            start += dot_pos + 1;
        } else {
            start = domain.len();
        }
        Some(suffix)
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BlocklistConfig;
    use std::io::Write;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt as _;

    fn make_temp_file(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn empty_engine_allows_everything() {
        let engine = BlocklistEngine::empty();
        assert_eq!(engine.decide("example.com"), BlockDecision::Allow);
        assert_eq!(engine.decide("sub.example.com"), BlockDecision::Allow);
    }

    #[test]
    fn plain_domain_blocks_exact_and_subdomains() {
        let mut engine = BlocklistEngine::empty();
        engine
            .blocks
            .insert(NormalizedRule::Domain("example.com".into()));

        assert_eq!(engine.decide("example.com"), BlockDecision::Block);
        assert_eq!(engine.decide("www.example.com"), BlockDecision::Block);
        assert_eq!(engine.decide("a.b.example.com"), BlockDecision::Block);
        assert_eq!(engine.decide("otherexample.com"), BlockDecision::Allow);
        assert_eq!(engine.decide("example.com.au"), BlockDecision::Allow);
    }

    #[test]
    fn exception_overrides_block() {
        let mut engine = BlocklistEngine::empty();
        engine
            .blocks
            .insert(NormalizedRule::Domain("example.com".into()));
        engine
            .exceptions
            .insert(NormalizedRule::Domain("example.com".into()));

        assert_eq!(engine.decide("example.com"), BlockDecision::Exception);
        assert_eq!(engine.decide("www.example.com"), BlockDecision::Exception);
    }

    #[test]
    fn allowlist_paths_override_blocklist_paths() {
        let block_file = make_temp_file("ads.example.com\n");
        let allow_file = make_temp_file("ads.example.com\n");

        let (engine, _) = BlocklistEngine::from_sources(
            &[block_file.path().to_path_buf()],
            &[allow_file.path().to_path_buf()],
        )
        .unwrap();

        assert_eq!(engine.decide("ads.example.com"), BlockDecision::Exception);
    }

    #[test]
    fn subdomain_exception_does_not_override_parent_block() {
        let mut engine = BlocklistEngine::empty();
        engine
            .blocks
            .insert(NormalizedRule::Domain("example.com".into()));
        engine
            .exceptions
            .insert(NormalizedRule::Domain("sub.example.com".into()));

        // sub.example.com is excepted.
        assert_eq!(engine.decide("sub.example.com"), BlockDecision::Exception);
        // www.example.com is still blocked by the parent rule.
        assert_eq!(engine.decide("www.example.com"), BlockDecision::Block);
        // example.com itself is still blocked.
        assert_eq!(engine.decide("example.com"), BlockDecision::Block);
    }

    #[test]
    fn parse_comments_and_blank_lines() {
        let content = r#"
# This is a comment
! Also a comment

  
"#;
        let file = make_temp_file(content);
        let (engine, report) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.block_count(), 0);
        assert_eq!(engine.exception_count(), 0);
        assert_eq!(report.unsupported, 0);
        // 5 lines: empty, comment, comment, blank, spaces
        assert_eq!(report.total, 5);
    }

    #[test]
    fn parse_report_counts_all_lines() {
        let content = r#"
# comment
! comment

example.com
||tracker.com^
/example.*banner/
"#;
        let file = make_temp_file(content);
        let (_, report) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        // 7 lines: empty, comment, comment, blank, example.com, ||tracker.com^, /example.*banner/
        assert_eq!(report.total, 7);
        // Only the regex rule is unsupported.
        assert_eq!(report.unsupported, 1);
    }

    #[test]
    fn parse_plain_domain_rules() {
        let content = "example.com\nanother.org\n";
        let file = make_temp_file(content);
        let (engine, _) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.decide("example.com"), BlockDecision::Block);
        assert_eq!(engine.decide("another.org"), BlockDecision::Block);
        assert_eq!(engine.decide("notlisted.com"), BlockDecision::Allow);
    }

    #[test]
    fn parse_hosts_style_entries() {
        let content = r#"
127.0.0.1 bad.example.com
0.0.0.0 worse.example.com
::1 ipv6.example.com
"#;
        let file = make_temp_file(content);
        let (engine, _) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.decide("bad.example.com"), BlockDecision::Block);
        assert_eq!(engine.decide("worse.example.com"), BlockDecision::Block);
        assert_eq!(engine.decide("ipv6.example.com"), BlockDecision::Block);
    }

    #[test]
    fn parse_anchored_rules() {
        let content = "||tracker.com^\n||ads.net^\n";
        let file = make_temp_file(content);
        let (engine, _) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.decide("tracker.com"), BlockDecision::Block);
        assert_eq!(engine.decide("sub.tracker.com"), BlockDecision::Block);
        assert_eq!(engine.decide("nottracker.com"), BlockDecision::Allow);
    }

    #[test]
    fn parse_exception_rules() {
        let content = r#"
||ads.com^
@@whitelist.ads.com
@@||allowed.org^
"#;
        let file = make_temp_file(content);
        let (engine, _) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.decide("ads.com"), BlockDecision::Block);
        assert_eq!(engine.decide("sub.ads.com"), BlockDecision::Block);
        assert_eq!(engine.decide("whitelist.ads.com"), BlockDecision::Exception);
        assert_eq!(engine.decide("allowed.org"), BlockDecision::Exception);
        assert_eq!(engine.decide("sub.allowed.org"), BlockDecision::Exception);
    }

    #[test]
    fn unsupported_modifiers_are_skipped() {
        let content = r#"
||ads.com^$third-party
example.com$important
"#;
        let file = make_temp_file(content);
        let (engine, report) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.block_count(), 0);
        assert_eq!(report.unsupported, 2);
    }

    #[test]
    fn unsupported_regex_rules_are_skipped() {
        let content = r#"
/example.*banner/
"#;
        let file = make_temp_file(content);
        let (engine, report) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.block_count(), 0);
        assert!(report.unsupported > 0);
    }

    #[test]
    fn unsupported_cosmetic_rules_are_skipped() {
        let content = r#"
example.org##.ad-banner
example.org#@#.sponsored
example.org#?#div:-abp-has(.ad)
supported.example
"#;
        let file = make_temp_file(content);
        let (engine, report) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.decide("supported.example"), BlockDecision::Block);
        assert_eq!(
            engine.decide("example.org##.ad-banner"),
            BlockDecision::Allow
        );
        assert_eq!(report.unsupported, 3);
    }

    #[test]
    fn blocked_response_helpers() {
        assert_eq!(BlockedResponse::ipv4(), "0.0.0.0");
        assert_eq!(BlockedResponse::ipv6(), "::");
        assert!(BlockedResponse::empty_for_other_types());
    }

    #[test]
    fn reloadable_preserves_old_on_failure() {
        let content = "blocked.com\n";
        let file = make_temp_file(content);
        let paths = vec![file.path().to_path_buf()];

        let (engine, _) = BlocklistEngine::from_paths(&paths).unwrap();
        let reloadable = ReloadableBlocklist::from_engine(engine, paths.clone());

        assert_eq!(reloadable.decide("blocked.com"), BlockDecision::Block);
        assert_eq!(reloadable.block_count(), 1);

        // Point to a nonexistent path; reload should fail.
        let bad_paths = vec![PathBuf::from("/nonexistent/blocklist.txt")];
        let bad_reloadable = ReloadableBlocklist::new(bad_paths);
        // The new reloadable starts empty.
        assert_eq!(bad_reloadable.decide("blocked.com"), BlockDecision::Allow);

        // Attempting to reload with bad paths returns an error.
        assert!(bad_reloadable.reload().is_err());
        // Old (empty) rules are preserved.
        assert_eq!(bad_reloadable.decide("blocked.com"), BlockDecision::Allow);
    }

    #[test]
    fn reloadable_updates_on_success() {
        let content = "old.com\n";
        let file = make_temp_file(content);
        let paths = vec![file.path().to_path_buf()];

        let (engine, _) = BlocklistEngine::from_paths(&paths).unwrap();
        let reloadable = ReloadableBlocklist::from_engine(engine, paths);
        assert_eq!(reloadable.decide("old.com"), BlockDecision::Block);

        // Replace file contents and reload.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&reloadable.paths()[0])
            .unwrap();
        file.write_all(b"new.com\n").unwrap();
        file.flush().unwrap();
        drop(file);

        let report = reloadable.reload().unwrap();
        assert_eq!(report.unsupported, 0);
        assert_eq!(reloadable.decide("old.com"), BlockDecision::Allow);
        assert_eq!(reloadable.decide("new.com"), BlockDecision::Block);
    }

    #[test]
    fn inline_comments_stripped() {
        let content = "example.com # inline comment\n";
        let file = make_temp_file(content);
        let (engine, _) = BlocklistEngine::from_paths(&[file.path().to_path_buf()]).unwrap();
        assert_eq!(engine.decide("example.com"), BlockDecision::Block);
    }

    #[test]
    fn case_insensitive_matching() {
        let mut engine = BlocklistEngine::empty();
        engine
            .blocks
            .insert(NormalizedRule::Domain("example.com".into()));
        assert_eq!(engine.decide("EXAMPLE.COM"), BlockDecision::Block);
        assert_eq!(engine.decide("Www.Example.COM"), BlockDecision::Block);
    }

    #[test]
    fn multi_file_loading() {
        let file1 = make_temp_file("a.com\n");
        let file2 = make_temp_file("b.com\n");
        let paths = vec![file1.path().to_path_buf(), file2.path().to_path_buf()];
        let (engine, _) = BlocklistEngine::from_paths(&paths).unwrap();
        assert_eq!(engine.decide("a.com"), BlockDecision::Block);
        assert_eq!(engine.decide("b.com"), BlockDecision::Block);
    }

    #[tokio::test]
    async fn refresh_and_reload_downloads_remote_subscription() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            for body in ["remote.test", "remote.test"] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let config = BlocklistConfig {
            urls: vec![format!("http://{addr}/list.txt")],
            allowlist_urls: vec![format!("http://{addr}/allow.txt")],
            download_dir: dir.path().to_path_buf(),
            download_timeout: Duration::from_secs(5),
            ..BlocklistConfig::default()
        };
        let reloadable = ReloadableBlocklist::from_config(&config);

        let report = reloadable.refresh_and_reload().await.unwrap();

        assert_eq!(report.total, 2);
        assert_eq!(reloadable.decide("remote.test"), BlockDecision::Exception);
        assert!(dir.path().join("subscription-0000.txt").exists());
        assert!(dir.path().join("allowlist-0000.txt").exists());
    }
}
