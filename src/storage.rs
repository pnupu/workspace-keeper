//! Read-only storage context. Inventory never authorizes or executes cleanup.
use super::*;
use cap_std::fs::{Dir, Metadata, MetadataExt as CapMetadataExt};
use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::MetadataExt;

const MAX_AREAS: usize = 256;
const MAX_REFERENCES: usize = 4096;
const MAX_REFERENCE_EXAMPLES: usize = 5;
const MAX_ERRORS: usize = 100;
const MAX_WALK_DEPTH: usize = 64;
const MAX_PROCESS_CONTEXT_PATHS: usize = 50_000;
type DirectoryId = (u64, u64);

struct PreparedRoot {
    path: PathBuf,
    identity: DirectoryId,
}

#[derive(Clone, Copy, Default)]
struct Stats {
    bytes: u64,
    newest: i64,
    complete: bool,
}

struct Kind {
    category: &'static str,
    manager: Option<&'static str>,
    version: Option<String>,
    opaque: bool,
}
impl Kind {
    fn new(category: &'static str, manager: Option<&'static str>, opaque: bool) -> Self {
        Self {
            category,
            manager,
            version: None,
            opaque,
        }
    }
}

fn suffix(path: &Path, tail: &str) -> bool {
    path.ends_with(Path::new(tail))
}
fn regular(dir: &Dir, path: &str) -> bool {
    dir.symlink_metadata(path).is_ok_and(|m| m.is_file())
}
fn app_bundle(dir: &Dir) -> bool {
    let Ok(before) = dir.symlink_metadata("Contents") else {
        return false;
    };
    if !before.is_dir() {
        return false;
    }
    let Ok(contents) = dir.open_dir("Contents") else {
        return false;
    };
    contents
        .dir_metadata()
        .is_ok_and(|after| after.dev() == before.dev() && after.ino() == before.ino())
        && regular(&contents, "Info.plist")
}

fn classify(path: &Path, dir: &Dir, is_home: bool) -> Kind {
    let parent = path.parent().unwrap_or(Path::new("/"));
    if path.ancestors().any(|p| {
        p.extension() == Some(OsStr::new("app"))
            && if p == path {
                app_bundle(dir)
            } else {
                Dir::open_ambient_dir(p, cap_std::ambient_authority())
                    .is_ok_and(|ancestor| app_bundle(&ancestor))
            }
    }) {
        return Kind::new("installed_application", None, true);
    }
    let application_support = path
        .ancestors()
        .any(|p| suffix(p, "Library/Application Support"));
    for (tail, manager) in [
        ("Unity/Hub/Editor", "unity"),
        (".rustup/toolchains", "rustup"),
        (".nvm/versions/node", "node"),
    ] {
        if suffix(parent, tail) {
            let mut kind = Kind::new("toolchain", Some(manager), true);
            kind.version = path.file_name().map(|n| n.to_string_lossy().into_owned());
            return kind;
        }
    }
    for (tail, manager) in [
        ("Library/pnpm/store", "pnpm"),
        (".local/share/pnpm/store", "pnpm"),
        (".pnpm-store", "pnpm"),
        (".cargo/registry", "cargo"),
        (".cargo/git", "cargo"),
        ("go/pkg/mod", "go"),
        (".npm", "npm"),
        (".bun/install/cache", "bun"),
        ("Library/Caches/Yarn", "yarn"),
        (".cache/yarn", "yarn"),
    ] {
        if suffix(path, tail) {
            return Kind::new("package_store", Some(manager), true);
        }
    }
    if suffix(path, "Library/Containers/com.docker.docker") {
        return Kind::new("application_data", Some("docker"), true);
    }
    if suffix(path, "Google/Chrome/OptGuideOnDeviceModel") {
        return Kind::new("downloaded_component", Some("chrome"), true);
    }
    let name = path.file_name().unwrap_or_default();
    if [".t3", ".codex", ".claude", ".cursor"]
        .iter()
        .any(|n| name == OsStr::new(n))
    {
        return Kind::new("agent_state", None, false);
    }
    if name == ".git" {
        return Kind::new("git_history", Some("git"), true);
    }
    if path.parent().is_some()
        && !is_home
        && dir
            .symlink_metadata(".git")
            .is_ok_and(|m| m.is_file() || m.is_dir())
    {
        return Kind::new("project", Some("git"), false);
    }
    if [".venv", "venv"].iter().any(|n| name == OsStr::new(n)) && regular(dir, "pyvenv.cfg") {
        return Kind::new("environment", Some("python"), true);
    }
    if name == "node_modules" {
        return Kind::new("dependency_installation", Some("node"), true);
    }
    if !application_support
        && [
            "target",
            "build",
            "dist",
            "out",
            "artifacts",
            ".next",
            ".turbo",
        ]
        .iter()
        .any(|n| name == OsStr::new(n))
    {
        return Kind::new("build_output", None, false);
    }
    if suffix(parent, "Library/Application Support") {
        return Kind::new("application_data", None, false);
    }
    if suffix(parent, "Library/Caches") || name == ".cache" {
        return Kind::new("application_cache", None, true);
    }
    Kind::new("other", None, false)
}

fn advice(category: &str) -> &'static str {
    match category {
        "project" => "Review checkout retirement: verify remote availability, unpublished commits and preservation of ignored/untracked local data. Git status is not inspected by inventory.",
        "git_history" => "Preserve local history. Review repository reachability and backups before any Git maintenance or checkout retirement.",
        "toolchain" => "Review project version requirements and active use before uninstalling through the toolchain manager. A missing reference is not proof of disuse.",
        "package_store" => "Inspect with the package manager before pruning; account for offline use and locally modified cached packages. Recovery may require network access and credentials.",
        "environment" => "Verify a complete dependency specification and recreation procedure; preserve local files or edits inside the environment before retiring it.",
        "dependency_installation" => "Use keeper plan on the owning project for recovery evidence and fresh cleanup checks. Inventory alone does not establish recoverability.",
        "build_output" => "Directory-name classification only. Verify the build recipe and exclude source, fixtures and local data before considering removal.",
        "application_cache" => "Use the application's cleanup mechanism after checking active use. Cache contents may regrow.",
        "downloaded_component" => "Review the owning application's settings and re-download behavior before removing this component.",
        "application_data" => "Inspect through the owning application. Images and build caches may be reproducible; volumes and application state may contain unique data.",
        "installed_application" => "Installed application files: manage or uninstall the whole application through its supported mechanism; preserve its internal files.",
        "agent_state" => "Preserve conversations, state and credentials. Use an explicit retention/export policy before retiring any agent data.",
        _ => "Inspect this area to identify its owner and recovery requirements; contents are not classified as disposable.",
    }
}

struct Walker {
    started: Instant,
    max_seconds: u64,
    max_entries: usize,
    report_depth: usize,
    visited: usize,
    hardlinks: HashSet<(u64, u64)>,
    directories: HashMap<(u64, u64), bool>,
    repeated_directories: usize,
    repeated_directory_examples: Vec<String>,
    shared_bytes: u64,
    symlinks: usize,
    areas: Vec<Value>,
    omitted_areas: usize,
    references: Vec<Value>,
    reference_overflow: bool,
    reference_excluded_count: usize,
    reference_excluded_examples: Vec<Value>,
    home: Option<DirectoryId>,
    roots_not_prepared: usize,
    errors: Vec<Value>,
    error_count: usize,
    stopped: Option<&'static str>,
}
impl Walker {
    fn new(report_depth: usize, max_entries: usize, max_seconds: u64) -> Self {
        Self {
            started: Instant::now(),
            max_seconds,
            max_entries,
            report_depth,
            visited: 0,
            hardlinks: HashSet::new(),
            directories: HashMap::new(),
            repeated_directories: 0,
            repeated_directory_examples: Vec::new(),
            shared_bytes: 0,
            symlinks: 0,
            areas: Vec::new(),
            omitted_areas: 0,
            references: Vec::new(),
            reference_overflow: false,
            reference_excluded_count: 0,
            reference_excluded_examples: Vec::new(),
            home: std::env::var_os("HOME")
                .and_then(|p| fs::metadata(p).ok())
                .filter(|m| m.is_dir())
                .map(|m| (m.dev(), m.ino())),
            roots_not_prepared: 0,
            errors: Vec::new(),
            error_count: 0,
            stopped: None,
        }
    }
    fn error(&mut self, path: &Path, message: impl ToString) {
        self.error_count += 1;
        if self.errors.len() < MAX_ERRORS {
            self.errors
                .push(json!({"path": path.to_string_lossy(), "error": message.to_string()}));
        }
    }
    fn within_time(&mut self) -> bool {
        if self.stopped.is_none() && self.started.elapsed().as_secs() >= self.max_seconds {
            self.stopped = Some("time limit reached");
        }
        self.stopped.is_none()
    }
    fn charge_entry(&mut self) -> bool {
        if !self.within_time() {
            return false;
        }
        if self.visited >= self.max_entries {
            self.stopped = Some("entry limit reached");
            return false;
        }
        self.visited += 1;
        true
    }
    fn prepare_roots(&mut self, roots: &[OsString]) -> (Vec<PreparedRoot>, Vec<String>) {
        let mut canonical = BTreeMap::new();
        for (index, root) in roots.iter().enumerate() {
            if !self.charge_entry() {
                self.roots_not_prepared = roots.len() - index;
                break;
            }
            let result = (|| -> Result<_> {
                let path = fs::canonicalize(root)?;
                let meta = fs::metadata(&path)?;
                if !meta.is_dir() {
                    return Err("Inventory root is not a directory".into());
                }
                Ok((path, (meta.dev(), meta.ino())))
            })();
            match result {
                Ok((path, identity)) => {
                    canonical.insert(path, identity);
                }
                Err(e) => self.error(Path::new(root), e),
            }
        }
        // Index identities once instead of comparing every pair of roots.
        let mut roots_by_id = HashMap::new();
        for (path, identity) in &canonical {
            if !self.within_time() {
                break;
            }
            roots_by_id.entry(*identity).or_insert(path.clone());
        }
        let mut ancestry = HashMap::new();
        let mut selected = Vec::new();
        let mut overlaps = Vec::new();
        for (path, identity) in canonical {
            if !self.within_time() {
                self.roots_not_prepared += 1;
                continue;
            }
            let mut covered = roots_by_id
                .get(&identity)
                .is_some_and(|first| first != &path);
            if !covered {
                for parent in path.ancestors().skip(1) {
                    if !self.within_time() {
                        break;
                    }
                    let candidate = ancestry.entry(parent.to_owned()).or_insert_with(|| {
                        fs::symlink_metadata(parent)
                            .ok()
                            .filter(|m| m.is_dir())
                            .map(|m| (m.dev(), m.ino()))
                    });
                    let Some(candidate) = *candidate else {
                        break;
                    };
                    if candidate.0 != identity.0 {
                        break;
                    }
                    if candidate != identity && roots_by_id.contains_key(&candidate) {
                        covered = true;
                        break;
                    }
                }
            }
            if !self.within_time() {
                self.roots_not_prepared += 1;
            } else if covered {
                overlaps.push(path.to_string_lossy().into_owned());
            } else {
                selected.push(PreparedRoot { path, identity });
            }
        }
        (selected, overlaps)
    }
    fn measure_root(&mut self, root: &PreparedRoot) -> Result<(Stats, bool)> {
        // Root attempts were charged before normalization, including failures.
        if !self.within_time() {
            return Ok((Stats::default(), false));
        }
        let path = &root.path;
        let entry = fs::symlink_metadata(path)?;
        if !entry.is_dir() || (entry.dev(), entry.ino()) != root.identity {
            return Err("Root changed after preparation".into());
        }
        let dir = Dir::open_ambient_dir(path, cap_std::ambient_authority())?;
        let before = dir.dir_metadata()?;
        if (before.dev(), before.ino()) != root.identity {
            return Err("Root changed while opening it".into());
        }
        let already_counted = self.directories.contains_key(&(before.dev(), before.ino()));
        let mut stats = self.walk(&dir, path, 0, before.dev(), false, None)?;
        if !fs::symlink_metadata(path)
            .is_ok_and(|after| after.is_dir() && (after.dev(), after.ino()) == root.identity)
        {
            self.error(path, "Root changed or became inaccessible during inventory");
            stats.complete = false;
        }
        Ok((stats, already_counted))
    }
    fn allocation(&mut self, m: &Metadata) -> u64 {
        let bytes = m.blocks() * 512;
        if !m.is_dir() && m.nlink() > 1 && !self.hardlinks.insert((m.dev(), m.ino())) {
            self.shared_bytes += bytes;
            0
        } else {
            bytes
        }
    }
    fn keep_area(&mut self, area: Value) {
        self.areas.push(area);
        if self.areas.len() > MAX_AREAS {
            let smallest = self
                .areas
                .iter()
                .enumerate()
                .min_by_key(|(_, a)| a["allocated_bytes"].as_u64().unwrap_or(0))
                .map(|(i, _)| i)
                .unwrap();
            self.areas.swap_remove(smallest);
            self.omitted_areas += 1;
        }
    }
    fn reference(&mut self, dir: &Dir, name: &OsStr, path: &Path, meta: &Metadata) {
        let manager = if name == "rust-toolchain" || name == "rust-toolchain.toml" {
            "rustup"
        } else if name == "ProjectVersion.txt"
            && path
                .parent()
                .is_some_and(|p| p.ends_with("ProjectSettings"))
        {
            "unity"
        } else {
            return;
        };
        if self.references.len() >= MAX_REFERENCES {
            self.reference_overflow = true;
            return;
        }
        let read = || -> Result<String> {
            if !meta.is_file() || meta.len() > 64 * 1024 {
                return Err("Unsupported toolchain declaration".into());
            }
            let file = dir.open(name)?;
            let after = file.metadata()?;
            if after.dev() != meta.dev() || after.ino() != meta.ino() || !after.is_file() {
                return Err("Toolchain declaration changed while opening it".into());
            }
            let mut bytes = Vec::new();
            file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 64 * 1024 {
                return Err("Toolchain declaration exceeds size limit".into());
            }
            String::from_utf8(bytes)
                .map_err(|_| "Unsupported toolchain declaration encoding".into())
        };
        let version = read()
            .ok()
            .and_then(|text| reference_version(manager, name, &text));
        self.references.push(json!({"path": path.to_string_lossy(), "manager": manager,
            "version": version, "status": if version.is_some() { "parsed" } else { "unreadable_or_unsupported" }}));
    }
    fn walk(
        &mut self,
        dir: &Dir,
        path: &Path,
        depth: usize,
        device: u64,
        opaque: bool,
        owner: Option<&Path>,
    ) -> Result<Stats> {
        // The caller charges this entry before any fallible inspection/open.
        let meta = dir.dir_metadata()?;
        let identity = (meta.dev(), meta.ino());
        if let Some(previous) = self.directories.get(&identity) {
            self.repeated_directories += 1;
            if self.repeated_directory_examples.len() < MAX_REFERENCE_EXAMPLES {
                self.repeated_directory_examples
                    .push(path.to_string_lossy().into_owned());
            }
            return Ok(Stats {
                bytes: 0,
                newest: meta.mtime(),
                complete: *previous,
            });
        }
        // Also prevents loops through same-filesystem directory aliases. A
        // failed or still-running traversal must not be reported complete.
        self.directories.insert(identity, false);
        let mut stats = Stats {
            bytes: self.allocation(&meta),
            newest: meta.mtime(),
            complete: true,
        };
        let kind = if opaque {
            Kind::new("other", None, true)
        } else {
            classify(path, dir, self.home == Some(identity))
        };
        if !opaque && kind.opaque {
            self.reference_excluded_count += 1;
            if self.reference_excluded_examples.len() < MAX_REFERENCE_EXAMPLES {
                self.reference_excluded_examples
                    .push(json!({"path": path.to_string_lossy(), "category": kind.category}));
            }
        }
        let owner = if kind.category == "project" {
            Some(path)
        } else {
            owner
        };
        let child_opaque = opaque || kind.opaque;
        if depth >= MAX_WALK_DEPTH {
            self.error(path, "Traversal depth limit reached");
            stats.complete = false;
        } else {
            let entries = dir.entries()?;
            for entry in entries {
                if !self.charge_entry() {
                    stats.complete = false;
                    break;
                }
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        self.error(path, e);
                        stats.complete = false;
                        continue;
                    }
                };
                let name = entry.file_name();
                let child_path = path.join(&name);
                let result = (|| -> Result<Stats> {
                    let m = dir.symlink_metadata(&name)?;
                    if m.dev() != device {
                        return Err("Filesystem boundary skipped".into());
                    }
                    // Detect unsupported declaration types too, including directories.
                    if !child_opaque {
                        self.reference(dir, &name, &child_path, &m);
                    }
                    if m.is_dir() {
                        let child = dir.open_dir(&name)?;
                        let after = child.dir_metadata()?;
                        if after.dev() != m.dev() || after.ino() != m.ino() {
                            return Err("Directory changed while opening it".into());
                        }
                        self.walk(&child, &child_path, depth + 1, device, child_opaque, owner)
                    } else {
                        if m.is_symlink() {
                            self.symlinks += 1;
                        }
                        Ok(Stats {
                            bytes: self.allocation(&m),
                            newest: m.mtime(),
                            complete: true,
                        })
                    }
                })();
                match result {
                    Ok(child) => {
                        stats.bytes += child.bytes;
                        stats.newest = stats.newest.max(child.newest);
                        stats.complete &= child.complete;
                    }
                    Err(e) => {
                        self.error(&child_path, e);
                        stats.complete = false;
                    }
                }
            }
        }
        if !opaque && (kind.category != "other" || (depth > 0 && depth <= self.report_depth)) {
            self.keep_area(json!({"path": path.to_string_lossy(), "path_utf8": path.to_str().is_some(), "category": kind.category, "manager": kind.manager,
                "directory_identity": [meta.dev(), meta.ino()],
                "version": kind.version, "project": owner.map(|p| p.to_string_lossy()), "allocated_bytes": stats.bytes,
                "measurement_complete": stats.complete, "latest_modified_unix": stats.newest,
                "classification_basis": if kind.category == "project" { "Git marker present" } else { "directory name/layout heuristic" },
                "cleanup_approved": false}));
        }
        self.directories.insert(identity, stats.complete);
        Ok(stats)
    }
}

// Deliberately small TOML subset. Anything outside it is unsupported, not parsed
// optimistically: one table, single-line quoted strings or string arrays, no escapes.
fn quoted(value: &str) -> Option<(&str, &str)> {
    let quote = value.chars().next()?;
    if !['\'', '"'].contains(&quote) {
        return None;
    }
    let (contents, rest) = value[1..].split_once(quote)?;
    if !contents
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return None;
    }
    Some((contents, rest.trim()))
}
fn line_end(rest: &str) -> bool {
    rest.is_empty() || rest.starts_with('#')
}
fn string_array(value: &str) -> bool {
    let Some(mut rest) = value.strip_prefix('[').map(str::trim) else {
        return false;
    };
    loop {
        if let Some(end) = rest.strip_prefix(']') {
            return line_end(end.trim());
        }
        let Some((_, tail)) = quoted(rest) else {
            return false;
        };
        if let Some(end) = tail.strip_prefix(']') {
            return line_end(end.trim());
        }
        let Some(tail) = tail.strip_prefix(',') else {
            return false;
        };
        rest = tail.trim();
    }
}
fn rust_toml_channel(text: &str) -> Option<&str> {
    let mut section = false;
    let mut keys = HashSet::new();
    let mut result = None;
    for line in text.lines().map(str::trim) {
        if line_end(line) {
            continue;
        }
        if let Some(rest) = line.strip_prefix("[toolchain]") {
            if section || !line_end(rest.trim()) {
                return None;
            }
            section = true;
            continue;
        }
        if !section {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        let key = key.trim();
        if !keys.insert(key) {
            return None;
        }
        let value = value.trim();
        match key {
            "channel" | "profile" => {
                let (parsed, rest) = quoted(value)?;
                if !line_end(rest) {
                    return None;
                }
                if key == "channel" {
                    result = Some(parsed);
                }
            }
            "components" | "targets" if string_array(value) => {}
            _ => return None,
        }
    }
    result
}

fn reference_version(manager: &str, name: &OsStr, text: &str) -> Option<String> {
    let candidate = if manager == "unity" {
        text.lines()
            .find_map(|l| l.trim().strip_prefix("m_EditorVersion:").map(str::trim))?
    } else if name == "rust-toolchain" {
        text.trim()
    } else {
        rust_toml_channel(text)?
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let valid = if manager == "unity" {
        let parts: Vec<_> = candidate.split('.').collect();
        candidate.len() <= 32
            && parts.len() == 3
            && digits(parts[0])
            && digits(parts[1])
            && parts[2]
                .find(['a', 'b', 'f', 'p'])
                .is_some_and(|i| digits(&parts[2][..i]) && digits(&parts[2][i + 1..]))
    } else {
        ["stable", "beta", "nightly"].contains(&candidate)
            || candidate.strip_prefix("nightly-").is_some_and(|s| {
                s.len() == 10
                    && s.is_ascii()
                    && &s[4..5] == "-"
                    && &s[7..8] == "-"
                    && digits(&s[..4])
                    && digits(&s[5..7])
                    && digits(&s[8..])
            })
            || (candidate.len() <= 20
                && (2..=3).contains(&candidate.split('.').count())
                && candidate.split('.').all(digits))
    };
    valid.then(|| candidate.to_owned())
}

fn toolchain_matches(manager: &str, installed: &str, declaration: &str) -> bool {
    if installed == declaration {
        return true;
    }
    if manager != "rustup" {
        return false;
    }
    // A host starts with an architecture, never a date. Do not let rolling
    // channels match dated installations or pinned versions match other versions.
    let Some(host) = installed
        .strip_prefix(declaration)
        .and_then(|s| s.strip_prefix('-'))
    else {
        return false;
    };
    (3..=4).contains(&host.split('-').count())
        && host.split('-').all(|part| {
            part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
}

struct ProcessPaths {
    paths: Vec<PathBuf>,
    warnings: Vec<String>,
}

fn collect_process_paths(
    output: &[u8],
    started: Instant,
    max_seconds: u64,
) -> Result<ProcessPaths> {
    let mut paths = HashSet::new();
    let mut warnings = Vec::new();
    let mut uncertain_encoding = false;
    let mut pid = 0;
    for field in output.split(|c| *c == 0) {
        if started.elapsed().as_secs() >= max_seconds {
            warnings.push(
                "Process path collection time budget exhausted; negative activity is unknown"
                    .to_owned(),
            );
            break;
        }
        let field = field.strip_prefix(b"\n").unwrap_or(field);
        if let Some(value) = field.strip_prefix(b"p") {
            pid = String::from_utf8_lossy(value).parse::<u32>()?;
        }
        if field.starts_with(b"n/") && pid != std::process::id() {
            let Some((path, ambiguous)) = decode_process_path(&field[1..]) else {
                uncertain_encoding = true;
                continue;
            };
            uncertain_encoding |= ambiguous;
            if !paths.contains(&path) {
                if paths.len() >= MAX_PROCESS_CONTEXT_PATHS {
                    warnings.push(format!("Process path collection cap ({MAX_PROCESS_CONTEXT_PATHS}) reached; negative activity is unknown"));
                    break;
                }
                paths.insert(path);
            }
        }
    }
    if uncertain_encoding {
        warnings.push(
            "Process path encoding is ambiguous or unsupported; negative activity is unknown"
                .to_owned(),
        );
    }
    Ok(ProcessPaths {
        paths: paths.into_iter().collect(),
        warnings,
    })
}

fn inventory_process_paths(started: Instant, max_seconds: u64) -> Result<ProcessPaths> {
    // Keep cleanup's existing collector unchanged. Inventory deduplicates raw
    // names without filesystem calls, then resolves identities under its budget.
    let output = run(Command::new("lsof")
        .current_dir("/")
        .args(process_args(current_uid()?)))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("Process inspection incomplete; activity is unknown".into());
    }
    collect_process_paths(&output.stdout, started, max_seconds)
}

#[derive(Clone, Copy)]
enum ProcessLookup {
    Directory(DirectoryId),
    OtherOrMissing,
    Unresolved,
}

struct ProcessIdentities {
    active: HashSet<DirectoryId>,
    uncertain_ancestors: HashSet<DirectoryId>,
    cache: HashMap<PathBuf, ProcessLookup>,
    failed_lookups: usize,
    stopped: Option<&'static str>,
    started: Instant,
    max_seconds: u64,
}
impl ProcessIdentities {
    fn lookup(&mut self, path: &Path) -> Option<ProcessLookup> {
        if self.started.elapsed().as_secs() >= self.max_seconds {
            self.stopped = Some("Process identity resolution time budget exhausted");
            return None;
        }
        if let Some(value) = self.cache.get(path) {
            return Some(*value);
        }
        if self.cache.len() >= MAX_PROCESS_CONTEXT_PATHS {
            self.stopped = Some("Process identity path cap reached");
            return None;
        }
        let value = match fs::metadata(path) {
            Ok(meta) if meta.is_dir() => ProcessLookup::Directory((meta.dev(), meta.ino())),
            Ok(_) => ProcessLookup::OtherOrMissing,
            // Deleted-open paths still have useful surviving ancestors.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ProcessLookup::OtherOrMissing,
            Err(_) => {
                self.failed_lookups += 1;
                ProcessLookup::Unresolved
            }
        };
        self.cache.insert(path.to_owned(), value);
        Some(value)
    }
    fn inspect_ancestors(&mut self, path: &Path) -> Option<(PathBuf, DirectoryId)> {
        let mut nearest = None;
        let mut unresolved_below = false;
        for ancestor in path.ancestors() {
            match self.lookup(ancestor) {
                Some(ProcessLookup::Directory(identity)) => {
                    nearest.get_or_insert_with(|| (ancestor.to_owned(), identity));
                    self.active.insert(identity);
                    if unresolved_below {
                        // A denied lookup only clouds descendants of its
                        // nearest resolved directory, not unrelated areas.
                        self.uncertain_ancestors.insert(identity);
                        unresolved_below = false;
                    }
                }
                Some(ProcessLookup::Unresolved) => unresolved_below = true,
                Some(ProcessLookup::OtherOrMissing) => {}
                None => return None,
            }
        }
        if unresolved_below {
            self.stopped = Some("Process path has no resolvable directory ancestor");
        }
        nearest
    }
    #[cfg(target_os = "macos")]
    fn inspect_data_alias(&mut self, path: &Path, identity: DirectoryId) {
        let data = Path::new("/System/Volumes/Data");
        let alias = if let Ok(relative) = path.strip_prefix(data) {
            Path::new("/").join(relative)
        } else if let Ok(relative) = path.strip_prefix("/") {
            data.join(relative)
        } else {
            return;
        };
        match self.lookup(&alias) {
            Some(ProcessLookup::Directory(other)) if other == identity => {
                // Firmlink targets have the same identity, but their parents
                // need not: /usr/local also belongs to Data/usr, not just /usr.
                // Verify the alias before adding its containing directories.
                self.inspect_ancestors(&alias);
            }
            Some(ProcessLookup::Unresolved) => {
                self.stopped = Some("Process Data-volume alias could not be resolved");
            }
            _ => {}
        }
    }
    fn inspect(paths: &[PathBuf], started: Instant, max_seconds: u64) -> Self {
        let mut result = Self {
            active: HashSet::new(),
            uncertain_ancestors: HashSet::new(),
            cache: HashMap::new(),
            failed_lookups: 0,
            stopped: None,
            started,
            max_seconds,
        };
        for path in paths {
            let nearest = result.inspect_ancestors(path);
            if result.stopped.is_some() {
                break;
            }
            #[cfg(target_os = "macos")]
            if let Some((directory, identity)) = nearest {
                result.inspect_data_alias(&directory, identity);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = nearest;
            if result.stopped.is_some() {
                break;
            }
        }
        result
    }
    fn area_uncertain(&mut self, path: &Path, observed: DirectoryId) -> bool {
        if self.stopped.is_some() {
            return true;
        }
        if self.uncertain_ancestors.is_empty() {
            return false;
        }
        for (depth, ancestor) in path.ancestors().enumerate() {
            match self.lookup(ancestor) {
                Some(ProcessLookup::Directory(identity)) => {
                    if (depth == 0 && identity != observed)
                        || self.uncertain_ancestors.contains(&identity)
                    {
                        return true;
                    }
                }
                _ => return true,
            }
        }
        false
    }
}

pub fn inventory(
    roots: &[OsString],
    depth: usize,
    max_entries: usize,
    max_seconds: u64,
) -> Result<Value> {
    if !(1..=10_000_000).contains(&max_entries)
        || !(1..=3600).contains(&max_seconds)
        || depth > MAX_WALK_DEPTH
    {
        return Err(
            "Inventory limits: 1..10000000 entries, 1..3600 seconds, reporting depth 0..64".into(),
        );
    }
    let mut walker = Walker::new(depth, max_entries, max_seconds);
    let (selected, mut overlaps) = walker.prepare_roots(roots);
    let processes = if walker.within_time() {
        inventory_process_paths(walker.started, max_seconds)
    } else {
        Err("Process inspection skipped after inventory limit".into())
    };
    let host = match host_context() {
        Ok(host) => host,
        Err(_) => {
            walker.error(Path::new(""), "Cannot identify the inventory host");
            Value::Null
        }
    };
    let mut measured = Vec::new();
    for root in &selected {
        let path = &root.path;
        match walker.measure_root(root) {
            Ok((stats, already_counted)) => {
                if already_counted {
                    overlaps.push(path.to_string_lossy().into_owned());
                }
                measured.push(json!({"path": path.to_string_lossy(), "allocated_bytes": stats.bytes, "measurement_complete": stats.complete, "already_counted_as_alias": already_counted}));
            }
            Err(e) => {
                walker.error(path, e);
                measured.push(json!({"path": path.to_string_lossy(), "allocated_bytes": 0, "measurement_complete": false, "already_counted_as_alias": false}));
            }
        }
    }
    let mut process_context = processes.unwrap_or_else(|e| ProcessPaths {
        paths: Vec::new(),
        warnings: vec![e.to_string()],
    });
    let mut process_ids =
        ProcessIdentities::inspect(&process_context.paths, walker.started, max_seconds);
    for area in &mut walker.areas {
        let path = Path::new(area["path"].as_str().unwrap_or(""));
        let identity = (
            area["directory_identity"][0].as_u64().unwrap(),
            area["directory_identity"][1].as_u64().unwrap(),
        );
        area["open_paths_detected"] = if area["path_utf8"] == false {
            Value::Null
        } else if process_ids.active.contains(&identity) {
            json!(true)
        } else if process_context.warnings.is_empty() && !process_ids.area_uncertain(path, identity)
        {
            json!(false)
        } else {
            Value::Null
        };
        if area["category"] == "toolchain" {
            let manager = area["manager"].as_str().unwrap_or("");
            if !["rustup", "unity"].contains(&manager) {
                area["reference_check"] = "not_supported".into();
                continue;
            }
            let version = area["version"].as_str().unwrap_or("");
            let references: Vec<_> = walker
                .references
                .iter()
                .filter(|r| {
                    r["manager"] == manager
                        && r["version"]
                            .as_str()
                            .is_some_and(|v| toolchain_matches(manager, version, v))
                })
                .map(|r| r["path"].clone())
                .collect();
            area["reference_count"] = json!(references.len());
            area["referenced_by"] = json!(references
                .into_iter()
                .take(MAX_REFERENCE_EXAMPLES)
                .collect::<Vec<_>>());
            area["reference_check"] = "supported_declarations_in_scanned_roots".into();
        }
    }
    if let Some(reason) = process_ids.stopped {
        process_context
            .warnings
            .push(format!("{reason}; some activity remains unknown"));
    }
    if process_ids.failed_lookups > 0 {
        process_context.warnings.push(format!("Process identity lookup failed for {} paths; activity is unknown only in potentially affected areas", process_ids.failed_lookups));
    }
    let process_warning =
        (!process_context.warnings.is_empty()).then(|| process_context.warnings.join("; "));
    walker.areas.sort_by_key(|a| {
        (
            std::cmp::Reverse(a["allocated_bytes"].as_u64().unwrap_or(0)),
            a["path"].as_str().unwrap_or("").to_owned(),
        )
    });
    let total: u64 = measured
        .iter()
        .filter_map(|r| r["allocated_bytes"].as_u64())
        .sum();
    let complete = walker.error_count == 0
        && walker.stopped.is_none()
        && measured
            .iter()
            .all(|root| root["measurement_complete"] == true);
    let references_complete = complete
        && !walker.reference_overflow
        && walker.reference_excluded_count == 0
        && walker.references.iter().all(|r| r["status"] == "parsed");
    let guidance: serde_json::Map<_, _> = [
        "project",
        "git_history",
        "toolchain",
        "package_store",
        "environment",
        "dependency_installation",
        "build_output",
        "application_cache",
        "downloaded_component",
        "application_data",
        "installed_application",
        "agent_state",
        "other",
    ]
    .into_iter()
    .map(|category| (category.to_owned(), json!(advice(category))))
    .collect();
    Ok(
        json!({"schema": 1, "action": "inventory", "read_only": true, "host": host,
        "complete": complete, "roots": measured, "overlapping_roots_omitted": overlaps,
        "roots_not_prepared": walker.roots_not_prepared,
        "observed_allocated_bytes": total, "cleanup_eligible_bytes": Value::Null,
        "accounting": "Nested area rows overlap: do not add them. Root totals count observed hard links and physical directories once, assigned to the first visited path; alias subtrees contribute zero on later visits. APFS clones/compression can change actual reclaimed capacity. Concurrent changes are not a snapshot.",
        "classification": "Directory layouts are hints, not evidence of recoverability. Inventory cannot be applied as a cleanup plan.",
        "review_guidance_by_category": guidance,
        "entries_visited": walker.visited, "elapsed_ms": walker.started.elapsed().as_millis(),
        "limits": {"max_entries": max_entries, "max_seconds": max_seconds, "max_traversal_depth": MAX_WALK_DEPTH, "report_depth": depth, "max_areas": MAX_AREAS, "max_references": MAX_REFERENCES, "max_reference_examples_per_area": MAX_REFERENCE_EXAMPLES, "max_process_context_paths": MAX_PROCESS_CONTEXT_PATHS},
        "time_limit_semantics": "Cooperative checks between entries; individual filesystem or process-inspection calls can exceed the requested duration.",
        "stopped_reason": walker.stopped, "symlinks_not_followed": walker.symlinks,
        "repeated_directories_not_counted": walker.repeated_directories, "repeated_directory_examples": walker.repeated_directory_examples,
        "repeated_hardlink_bytes_not_counted": walker.shared_bytes, "areas_omitted": walker.omitted_areas, "areas": walker.areas,
        "toolchain_references": walker.references, "reference_collection_complete": references_complete,
        "reference_limit_reached": walker.reference_overflow,
        "reference_excluded_area_count": walker.reference_excluded_count, "reference_excluded_area_examples": walker.reference_excluded_examples,
        "reference_scope": "Unity and Rust declarations, including projects in build and agent directories. Installed applications, toolchains, dependencies, stores, Git internals and classified caches are measured but excluded from declaration discovery; any exclusion makes reference context incomplete. Per-area referenced_by lists are bounded examples; reference_count is the total among collected declarations. Projects outside these roots, environment overrides and other configuration may require a toolchain even with no matching reference.",
        "process_inspection_warning": process_warning,
        "error_count": walker.error_count, "errors": walker.errors}),
    )
}

pub fn print(report: &Value, all: bool) {
    println!("Workspace Keeper — read-only storage inventory");
    println!(
        "Observed allocation: {} across {} roots; {} entries.",
        size(report["observed_allocated_bytes"].as_u64().unwrap_or(0)),
        report["roots"].as_array().map_or(0, Vec::len),
        report["entries_visited"]
    );
    println!("Sizes are storage footprints, not cleanup approvals. Nested rows overlap; do not add them.");
    if report["repeated_directories_not_counted"]
        .as_u64()
        .unwrap_or(0)
        > 0
    {
        println!(
            "{} directory aliases skipped; their storage is counted under the first visited path.",
            report["repeated_directories_not_counted"]
        );
    }
    if let Some(roots) = report["roots"].as_array() {
        for root in roots {
            println!(
                "Root: {}  {}{}{}",
                size(root["allocated_bytes"].as_u64().unwrap_or(0)),
                root["path"].as_str().unwrap_or("?").escape_debug(),
                if root["measurement_complete"] == true {
                    ""
                } else {
                    " (partial)"
                },
                if root["already_counted_as_alias"] == true {
                    " (alias; storage counted under an earlier root)"
                } else {
                    ""
                }
            );
        }
    }
    if let Some(overlaps) = report["overlapping_roots_omitted"].as_array() {
        for path in overlaps {
            println!(
                "Overlapping root omitted (covered on the same filesystem): {}",
                path.as_str().unwrap_or("?").escape_debug()
            );
        }
    }
    if report["complete"] != true {
        println!(
            "INCOMPLETE: {} errors; stop reason: {}. Sizes are partial.",
            report["error_count"],
            report["stopped_reason"]
                .as_str()
                .unwrap_or("unreadable paths")
        );
        if report["roots_not_prepared"].as_u64().unwrap_or(0) > 0 {
            println!(
                "{} input roots were not fully prepared before the budget was exhausted.",
                report["roots_not_prepared"]
            );
        }
    }
    if let Some(warning) = report["process_inspection_warning"].as_str() {
        println!("Process activity warning: {}", warning.escape_debug());
    }
    if report["reference_collection_complete"] != true {
        println!("Toolchain reference context is incomplete; do not infer that unreferenced versions are unused.");
        println!("  {} opaque areas excluded from declaration discovery; {} reference records retained{}.",
            report["reference_excluded_area_count"], report["toolchain_references"].as_array().map_or(0, Vec::len),
            if report["reference_limit_reached"] == true { " (reference limit reached)" } else { "" });
    }
    if let Some(areas) = report["areas"].as_array() {
        for area in areas
            .iter()
            .filter(|a| all || a["allocated_bytes"].as_u64().unwrap_or(0) >= 1024 * 1024)
            .take(if all { MAX_AREAS } else { 25 })
        {
            println!(
                "\n{}  {} [{}]{}",
                size(area["allocated_bytes"].as_u64().unwrap_or(0)),
                area["path"].as_str().unwrap_or("?").escape_debug(),
                area["category"].as_str().unwrap_or("other"),
                if area["measurement_complete"] == true {
                    ""
                } else {
                    " (partial)"
                }
            );
            if area["open_paths_detected"] == true {
                println!("  Running process has an open path in this area.");
            }
            if let Some(count) = area["reference_count"].as_u64() {
                println!("  {count} matching toolchain declarations found in scanned roots; absence does not establish disuse.");
            }
            println!("  {}", advice(area["category"].as_str().unwrap_or("other")));
        }
    }
    if let Some(errors) = report["errors"].as_array() {
        for error in errors.iter().take(5) {
            println!(
                "Uninspected: {}: {}",
                error["path"].as_str().unwrap_or("").escape_debug(),
                error["error"].as_str().unwrap_or("").escape_debug()
            );
        }
    }
    if report["areas_omitted"].as_u64().unwrap_or(0) > 0 {
        println!(
            "{} smaller area summaries omitted; only the largest {MAX_AREAS} are retained.",
            report["areas_omitted"]
        );
    }
    println!(
        "\nUse --json for agent context and --all for all retained areas. No data was deleted."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_mount_roots_are_not_collapsed() {
        // /dev is a separate mounted filesystem on the supported macOS host.
        let root = Path::new("/");
        let dev = Path::new("/dev");
        if fs::metadata(root).unwrap().dev() != fs::metadata(dev).unwrap().dev() {
            let mut walker = Walker::new(0, 100, 60);
            let (selected, overlaps) = walker.prepare_roots(&[root.into(), dev.into()]);
            assert_eq!(selected.len(), 2);
            assert!(overlaps.is_empty());
        }
    }

    #[test]
    fn home_git_marker_is_not_checkout_retirement_advice() {
        let path =
            std::env::temp_dir().join(format!("keeper-home-classification-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join(".git")).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        let mut spellings = vec![path.clone()];
        if cfg!(target_os = "macos") {
            spellings.push(Path::new("/System/Volumes/Data").join(path.strip_prefix("/").unwrap()));
        }
        for spelling in spellings {
            let root = PreparedRoot {
                path: spelling,
                identity: (meta.dev(), meta.ino()),
            };
            let mut walker = Walker::new(3, 100, 60);
            walker.home = Some((meta.dev(), meta.ino()));
            let (stats, _) = walker.measure_root(&root).unwrap();
            assert!(stats.complete);
            assert!(walker.areas.iter().all(|a| a["category"] != "project"));
            let mut walker = Walker::new(3, 100, 60);
            walker.home = None;
            walker.measure_root(&root).unwrap();
            assert!(walker.areas.iter().any(|a| a["category"] == "project"));
        }
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn root_already_visited_through_another_traversal_is_an_alias() {
        let path = std::env::temp_dir().join(format!("keeper-root-alias-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("payload"), [1; 4096]).unwrap();
        let mut walker = Walker::new(3, 100, 60);
        let (roots, _) = walker.prepare_roots(&[path.clone().into_os_string()]);
        let (first, alias) = walker.measure_root(&roots[0]).unwrap();
        assert!(!alias);
        assert!(first.bytes >= 4096 && first.complete);
        let (second, alias) = walker.measure_root(&roots[0]).unwrap();
        assert!(alias && second.complete);
        assert_eq!(second.bytes, 0);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn prepared_root_replacement_is_rejected_before_traversal() {
        let fixture =
            std::env::temp_dir().join(format!("keeper-prepared-root-{}", std::process::id()));
        let root = fixture.join("root");
        let outside = fixture.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("rust-toolchain"), "nightly").unwrap();
        fs::write(outside.join("payload"), [1; 4096]).unwrap();
        let mut walker = Walker::new(3, 100, 60);
        let (prepared, _) = walker.prepare_roots(&[root.clone().into_os_string()]);
        fs::rename(&root, fixture.join("original")).unwrap();
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        assert!(walker
            .measure_root(&prepared[0])
            .err()
            .unwrap()
            .to_string()
            .contains("Root changed"));
        assert!(
            walker.areas.is_empty()
                && walker.references.is_empty()
                && walker.directories.is_empty()
        );
        fs::remove_file(&root).unwrap();
        fs::rename(&outside, &root).unwrap();
        assert!(walker.measure_root(&prepared[0]).is_err());
        assert!(walker.areas.is_empty() && walker.references.is_empty());
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn process_paths_decode_lsof_escapes_once_and_disclose_ambiguous_encodings() {
        let (path, ambiguous) = decode_process_path(br"/a\\b\nc\td\re\bf\fg\x7f").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"/a\\b\nc\td\re\x08f\x0cg\x7f");
        assert!(!ambiguous);
        let (path, ambiguous) = decode_process_path(br"/literal\\n\\x01").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), br"/literal\n\x01");
        assert!(!ambiguous);
        for input in [
            br"/bad\z".as_slice(),
            br"/bad\x0",
            br"/bad\xgg",
            br"/bad\x00",
            b"/bad\\",
        ] {
            assert!(decode_process_path(input).is_none());
        }
        assert!(decode_process_path(b"/ambiguous^A").unwrap().1);
        assert!(decode_process_path(b"/ambiguous^?").unwrap().1);
        assert!(!decode_process_path(b"/plain^text").unwrap().1);
        let output = b"p1\0n/ambiguous^A\0n/bad\\z\0n/valid\\ttab\0";
        let context = collect_process_paths(output, Instant::now(), 60).unwrap();
        assert_eq!(context.warnings.len(), 1);
        assert!(context.warnings[0].contains("encoding"));
        assert!(context.paths.contains(&PathBuf::from("/valid\ttab")));
        assert!(!context.paths.contains(&PathBuf::from(r"/bad\z")));
    }

    #[test]
    fn raw_process_collection_deduplicates_before_resolution_and_honors_deadline() {
        let mut output = b"p1\0".to_vec();
        for _ in 0..60_000 {
            output.extend_from_slice(b"n/keeper/nonexistent/../file\0");
        }
        let context = collect_process_paths(&output, Instant::now(), 60).unwrap();
        assert_eq!(
            context.paths,
            vec![PathBuf::from("/keeper/nonexistent/../file")]
        );
        assert!(context.warnings.is_empty());
        let context =
            collect_process_paths(&output, Instant::now() - Duration::from_secs(2), 1).unwrap();
        assert!(context.paths.is_empty());
        assert!(context.warnings[0].contains("collection time budget exhausted"));
    }

    #[test]
    fn denied_process_paths_only_cloud_related_areas() {
        use std::os::unix::fs::PermissionsExt;
        let fixture =
            std::env::temp_dir().join(format!("keeper-process-denied-{}", std::process::id()));
        let blocked = fixture.join("blocked");
        let child = blocked.join("child");
        let idle = fixture.join("idle");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir(&idle).unwrap();
        fs::write(blocked.join("open"), "data").unwrap();
        let child_meta = fs::metadata(&child).unwrap();
        let idle_meta = fs::metadata(&idle).unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o0)).unwrap();
        let denied = fs::metadata(blocked.join("open")).is_err();
        let mut context = ProcessIdentities::inspect(&[blocked.join("open")], Instant::now(), 60);
        let child_unknown = context.area_uncertain(&child, (child_meta.dev(), child_meta.ino()));
        let idle_unknown = context.area_uncertain(&idle, (idle_meta.dev(), idle_meta.ino()));
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(fixture).unwrap();
        if denied {
            assert!(context.failed_lookups > 0);
            assert!(child_unknown);
        }
        assert!(!idle_unknown);
        assert!(context.stopped.is_none());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn process_firmlink_targets_mark_both_distinct_parent_directories() {
        let normal = Path::new("/usr/local");
        let alias = Path::new("/System/Volumes/Data/usr/local");
        let id = |path: &Path| fs::metadata(path).map(|m| (m.dev(), m.ino()));
        let (Ok(normal_id), Ok(alias_id)) = (id(normal), id(alias)) else {
            return; // This host has no such firmlink; never create system paths.
        };
        if normal_id != alias_id {
            return;
        }
        let normal_parent = id(normal.parent().unwrap()).unwrap();
        let data_parent = id(alias.parent().unwrap()).unwrap();
        assert_ne!(normal_parent, data_parent);
        for path in [
            normal.to_owned(),
            alias.to_owned(),
            normal.join(format!(
                "keeper-missing-process-path-{}",
                std::process::id()
            )),
        ] {
            let context = ProcessIdentities::inspect(&[path], Instant::now(), 60);
            assert!(context.active.contains(&normal_parent));
            assert!(context.active.contains(&data_parent));
            assert!(context.stopped.is_none());
        }
        // A similarly spelled but physically distinct directory is not an alias.
        let context = ProcessIdentities::inspect(&[PathBuf::from("/usr")], Instant::now(), 60);
        assert!(!context.active.contains(&data_parent));
        let context = ProcessIdentities::inspect(
            &[normal.to_owned()],
            Instant::now() - Duration::from_secs(2),
            1,
        );
        assert!(context.stopped.is_some());
        assert!(context.active.is_empty());
    }

    #[test]
    fn expired_preparation_budget_stops_before_inspecting_roots() {
        let mut walker = Walker::new(0, 100, 1);
        walker.started = Instant::now() - Duration::from_secs(2);
        let (roots, _) = walker.prepare_roots(&["/keeper-deliberately-missing".into()]);
        assert!(roots.is_empty());
        assert_eq!(walker.visited, 0);
        assert_eq!(walker.error_count, 0);
        assert_eq!(walker.roots_not_prepared, 1);
        assert_eq!(walker.stopped, Some("time limit reached"));
    }
}
