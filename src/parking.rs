//! Parking preserves all non-target files in place. Plans are proposals, not deletion authority.
use super::*;
use cap_std::fs::{Dir, MetadataExt as CapMetadataExt};
use sha2::{Digest, Sha256};
use std::fs::{DirBuilder, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
mod workspace;

pub const MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;
pub const MAX_TARGETS: usize = 8;
const MAX_AGE: u64 = 24 * 60 * 60;

fn seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn digest(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("Missing or invalid {field}").into())
}
fn number(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("Missing or invalid {field}").into())
}
fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| "Parking requires UTF-8 paths".into())
}

fn identity(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    Ok(json!({"device": m.dev(), "inode": m.ino()}))
}

fn protected_name(path: &Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    name == ".keeper-keep"
        || name == ".git"
        || name == ".t3"
        || name == ".codex"
        || name == ".env"
        || (name.starts_with(".env.")
            && ![".example", ".sample", ".template"]
                .iter()
                .any(|s| name.ends_with(s)))
        || [".pem", ".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db"]
            .iter()
            .any(|s| name.ends_with(s))
        || ["id_rsa", "id_ed25519", "credentials", ".npmrc"].contains(&name.as_str())
}

// Fingerprint metadata only: never read environment, database or key contents.
fn hash_metadata(
    path: &Path,
    m: &cap_std::fs::Metadata,
    device: u64,
    hash: &mut Sha256,
) -> Result<()> {
    if m.dev() != device {
        return Err("Target crosses a filesystem boundary".into());
    }
    let relative = path.as_os_str().as_bytes();
    hash.update((relative.len() as u64).to_le_bytes());
    hash.update(relative);
    hash.update(format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        m.dev(),
        m.ino(),
        m.mode(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.nlink()
    ));
    Ok(())
}

// Resolve one component at a time and bind traversal to the inspected inode.
// A swap to a symlink or a different directory cannot redirect this handle.
fn open_child(parent: &Dir, name: &Path) -> Result<Dir> {
    let before = parent.symlink_metadata(name)?;
    if !before.is_dir() {
        return Err("Target has a symlink or non-directory component".into());
    }
    let child = parent.open_dir(name)?;
    let after = child.dir_metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("Directory changed while opening it".into());
    }
    Ok(child)
}

fn open_target(project: &Dir, relative: &Path) -> Result<Dir> {
    let mut dir = project.try_clone()?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("Invalid target component".into());
        }
        dir = open_child(&dir, Path::new(component.as_os_str()))?;
    }
    Ok(dir)
}

fn tree_snapshot(
    dir: &Dir,
    path: &Path,
    device: u64,
    hash: &mut Sha256,
    sensitive: &mut Vec<String>,
    dependencies: bool,
) -> Result<()> {
    hash_metadata(path, &dir.dir_metadata()?, device, hash)?;
    let mut names = dir
        .entries()?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    for name in names {
        if !dependencies && recovery_input_name(&name) {
            return Err(
                "Cache contains dependency manifests or workspace recovery inputs; preserve it"
                    .into(),
            );
        }
        let relative = path.join(&name);
        if protected_name(&relative) && sensitive.len() < 5 {
            sensitive.push(path_text(&relative)?.to_owned());
        }
        let m = dir.symlink_metadata(&name)?;
        if m.is_dir() {
            let child = open_child(dir, Path::new(&name))?;
            tree_snapshot(&child, &relative, device, hash, sensitive, dependencies)?;
        } else {
            hash_metadata(&relative, &m, device, hash)?;
        }
    }
    Ok(())
}

fn snapshot(dir: &Dir, dependencies: bool) -> Result<(String, Vec<String>)> {
    let mut hash = Sha256::new();
    let mut sensitive = Vec::new();
    tree_snapshot(
        dir,
        Path::new(""),
        dir.dir_metadata()?.dev(),
        &mut hash,
        &mut sensitive,
        dependencies,
    )?;
    Ok((hex(&hash.finalize()), sensitive))
}

fn bounded_file(path: &Path) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || fs::canonicalize(path)? != path || m.len() > 32 * 1024 * 1024 {
        return Err("Recovery manifest is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("Recovery manifest exceeded size limit".into());
    }
    Ok(bytes)
}

fn regular_evidence(path: &Path, project: &Path) -> Result<(Value, Vec<u8>)> {
    let bytes = bounded_file(path)?;
    Ok((
        json!({"path": path_text(path.strip_prefix(project)?)?, "sha256": digest(&bytes)}),
        bytes,
    ))
}

fn valid_manager_version(version: &str) -> bool {
    let (release, integrity) = version
        .split_once('+')
        .map_or((version, None), |(v, h)| (v, Some(h)));
    if let Some(integrity) = integrity {
        let Some((algorithm, hash)) = integrity.split_once('.') else {
            return false;
        };
        if !["sha1", "sha224", "sha256", "sha384", "sha512"].contains(&algorithm)
            || hash.is_empty()
            || hash.len() > 128
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return false;
        }
    }
    let (base, prerelease) = release
        .split_once('-')
        .map_or((release, None), |(v, p)| (v, Some(p)));
    if let Some(prerelease) = prerelease {
        if prerelease.len() > 64
            || prerelease
                .split('.')
                .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return false;
        }
    }
    let numbers = base.split('.').collect::<Vec<_>>();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn recovery(project: &Path, path: &Path) -> Result<Value> {
    if path.file_name() != Some(OsStr::new("node_modules")) {
        let kind = if path.ends_with(".next/cache") {
            "Next.js build"
        } else if path.ends_with(".turbo/cache") {
            "Turbo build"
        } else if path.ends_with(".pytest_cache") {
            "pytest run"
        } else {
            "execution of the corresponding Python source"
        };
        return Ok(
            json!({"description": format!("Regenerated by the next {kind}; a cold run may take longer"), "automatic": false}),
        );
    }
    let package = path.parent().ok_or("Invalid target")?;
    if let Some(recipe) = workspace::recovery(project, package)? {
        return Ok(recipe);
    }
    dependency_recovery(project, package)
}

fn dependency_recovery(project: &Path, package: &Path) -> Result<Value> {
    if fs::symlink_metadata(package.join("npm-shrinkwrap.json")).is_ok() {
        return Err("npm shrinkwrap overrides package-lock; preserve installation until recovery is verified".into());
    }
    // Ancestor lockfiles alone do not prove workspace membership or regeneration.
    // Keep workspace installations until their ownership can be verified.
    if package.join("package.json").is_file() {
        let mut found = Vec::new();
        for (lock, command) in [
            ("package-lock.json", vec!["npm", "ci"]),
            (
                "pnpm-lock.yaml",
                vec!["pnpm", "install", "--frozen-lockfile"],
            ),
            ("yarn.lock", vec!["yarn", "install", "--frozen-lockfile"]),
            ("bun.lock", vec!["bun", "install", "--frozen-lockfile"]),
            ("bun.lockb", vec!["bun", "install", "--frozen-lockfile"]),
        ] {
            if package.join(lock).exists() {
                found.push((lock, command));
            }
        }
        if found.len() > 1 {
            return Err("Ambiguous dependency lockfiles; preserve installation".into());
        }
        if let Some((lock, command)) = found.first() {
            let (manifest_evidence, manifest_bytes) =
                regular_evidence(&package.join("package.json"), project)?;
            let (lock_evidence, lock_bytes) = regular_evidence(&package.join(lock), project)?;
            let manifest: Value =
                serde_json::from_slice(&manifest_bytes).map_err(|_| "Invalid package manifest")?;
            let manager = manifest
                .get("packageManager")
                .and_then(Value::as_str)
                .unwrap_or("unspecified");
            if manager != "unspecified" {
                let (tool, version) = manager
                    .split_once('@')
                    .ok_or("Unrecognized package-manager hint; preserve installation")?;
                if tool != command[0] || version.len() > 256 || !valid_manager_version(version) {
                    return Err(
                        "Unrecognized or inconsistent package-manager hint; preserve installation"
                            .into(),
                    );
                }
            }
            let mut command = command.clone();
            if command[0] == "yarn"
                && ((manager.starts_with("yarn@") && !manager.starts_with("yarn@1."))
                    || String::from_utf8_lossy(&lock_bytes)
                        .lines()
                        .any(|l| l.starts_with("__metadata:")))
            {
                command = vec!["yarn", "install", "--immutable"];
            }
            let evidence = vec![manifest_evidence, lock_evidence];
            return Ok(
                json!({"cwd": if package == project { "." } else { path_text(package.strip_prefix(project)?)? }, "command": command,
                    "package_manager": manager, "evidence": evidence, "automatic": false,
                    "limitations": "Requires the original registries, credentials and toolchain. Local edits inside dependencies cannot be reconstructed from a lockfile."}),
            );
        }
    }
    Err(
        "No local package manifest and unambiguous lockfile; workspace recovery is not verified"
            .into(),
    )
}

fn git_state(project: &Path) -> Result<Value> {
    let status = g(
        project,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let head = g(project, &["rev-parse", "--verify", "HEAD"])
        .ok()
        .map(|b| String::from_utf8_lossy(&b).trim().to_owned());
    Ok(json!({"head": head,
        "dirty": !status.is_empty(), "status_sha256": digest(&status)}))
}

fn preservation(project: &Path) -> Result<Value> {
    let mut items = Vec::new();
    let mut children = entries(project)?;
    children.sort_by_key(|e| e.file_name());
    for entry in children {
        let m = fs::symlink_metadata(entry.path())?;
        items.push(json!({"path": path_text(Path::new(&entry.file_name()))?,
            "type": if m.is_symlink() { "symlink" } else if m.is_dir() { "directory" } else { "file" },
            "mode": format!("{:04o}", m.mode() & 0o7777), "local_state_hint": protected_name(&entry.path())}));
    }
    Ok(
        json!({"policy": "All files outside exact targets stay in place, including ignored, untracked and modified files. No backup or secret extraction is performed.",
        "top_level_inventory": items, "whole_checkout_removal": false}),
    )
}

pub fn plan(project: &Path, days: u32, only: Option<&Path>) -> Result<Value> {
    if days == 0 {
        return Err("--days must be positive".into());
    }
    let project = fs::canonicalize(project)?;
    let project_dir = Dir::open_ambient_dir(&project, cap_std::ambient_authority())?;
    let opened = opened_paths();
    let report = inspect(&project, days, opened.as_ref().ok().map(Vec::as_slice))?;
    let context = json!({"idle_days": report.idle_days, "linked_worktree": report.worktree,
        "missing_tracked_files": {"count": report.missing_files, "examples": report.missing_examples}});
    let mut targets = Vec::new();
    let mut blocked = Vec::new();
    let mut total = 0u64;
    let mut candidates = report.candidates;
    candidates.sort_by_key(|c| (std::cmp::Reverse(c.bytes), c.path.clone()));
    for candidate in candidates {
        let relative = candidate.path.strip_prefix(&project)?;
        if only.is_some_and(|p| p != relative) {
            continue;
        }
        // Source modifications alone do not make a separate generated cache valuable.
        let mut reasons = candidate
            .blockers
            .into_iter()
            .filter(|r| r != "uncommitted or untracked files")
            .collect::<Vec<_>>();
        let mut fingerprint = None;
        let mut recipe = None;
        if reasons.is_empty() {
            match open_target(&project_dir, relative).and_then(|dir| {
                snapshot(
                    &dir,
                    relative.file_name() == Some(OsStr::new("node_modules")),
                )
            }) {
                Ok((value, sensitive)) => {
                    fingerprint = Some(value);
                    if !sensitive.is_empty() {
                        reasons.push(
                            format!("secret-like or local-data paths inside target (first 5): {}; preserve for review", sensitive.join(", ")),
                        );
                    }
                }
                Err(e) => reasons.push(e.to_string()),
            }
            match recovery(&project, &candidate.path) {
                Ok(value) => recipe = Some(value),
                Err(e) => reasons.push(e.to_string()),
            }
        }
        if targets.len() >= MAX_TARGETS || total.saturating_add(candidate.bytes) > MAX_BYTES {
            reasons.push(
                "exceeds per-run limit (8 directories / 10 GiB); select a smaller target"
                    .to_owned(),
            );
        }
        if reasons.is_empty() {
            total += candidate.bytes;
            targets.push(json!({"path": path_text(relative)?, "bytes": candidate.bytes, "fingerprint": fingerprint, "recovery": recipe}));
        } else {
            blocked.push(
                json!({"path": path_text(relative)?, "bytes": candidate.bytes, "reasons": reasons}),
            );
        }
    }
    let git = git_state(&project)?;
    Ok(
        json!({"schema": 2, "host": host_context()?, "action": "park", "created_at": seconds()?, "expires_after_seconds": MAX_AGE,
        "project": path_text(&project)?, "project_identity": identity(&project)?, "git": git,
        "minimum_idle_days": days, "estimated_bytes": total, "limits": {"max_bytes": MAX_BYTES, "max_targets": MAX_TARGETS},
        "targets": targets, "blocked": blocked, "context": context, "preservation": preservation(&project)?,
        "warning": opened.err().map(|e| e.to_string())}),
    )
}

pub fn write_plan(path: &Path, value: &Value) -> Result<()> {
    let project = Path::new(text(value, "project")?);
    let parent = fs::canonicalize(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    if parent.starts_with(project) {
        return Err("Save plans outside the project being parked".into());
    }
    write_new(
        &parent.join(path.file_name().ok_or("Invalid plan path")?),
        &serde_json::to_vec_pretty(value)?,
    )
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    // Remove only the file this call created if writing or syncing fails.
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        FileSync::directory(path.parent().ok_or("Missing parent")?)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

struct FileSync;
impl FileSync {
    fn directory(path: &Path) -> Result<()> {
        fs::File::open(path)?.sync_all()?;
        Ok(())
    }
}

fn state_dir(project: &Path) -> Result<PathBuf> {
    let path = if let Some(path) = std::env::var_os("KEEPER_STATE_DIR") {
        PathBuf::from(path)
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unavailable")?)
            .join(".local/state/workspace-keeper")
    };
    // Refuse symlinks even when they resolve inside a trusted state directory.
    let absolute = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    if absolute
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("Invalid state directory".into());
    }
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        if let Ok(m) = fs::symlink_metadata(&current) {
            if m.is_symlink() {
                return Err("State directory must not traverse symlinks".into());
            }
        }
    }
    if absolute.starts_with(project) {
        return Err("State directory must be outside the parked project".into());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&absolute)?;
    let path = fs::canonicalize(&absolute)?;
    let m = fs::metadata(&path)?;
    if path.starts_with(project) || m.uid() != current_uid()? || m.mode() & 0o077 != 0 {
        return Err(
            "State directory must be private (0700), owned by you, and outside the project".into(),
        );
    }
    Ok(path)
}

struct Lock(PathBuf);
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn validate(plan: &Value) -> Result<(PathBuf, u32, Vec<Value>)> {
    if plan["schema"] != 2 || plan["action"] != "park" {
        return Err("Unsupported plan".into());
    }
    if plan["host"] != host_context()? {
        return Err("Plan host differs; regenerate the plan on this machine".into());
    }
    let now = seconds()?;
    let created = number(plan, "created_at")?;
    if created > now || now - created > MAX_AGE {
        return Err("Plan expired or has a future timestamp; regenerate it".into());
    }
    let days = u32::try_from(number(plan, "minimum_idle_days")?)?;
    if days == 0 {
        return Err("Invalid idle threshold".into());
    }
    let project = PathBuf::from(text(plan, "project")?);
    if fs::canonicalize(&project)? != project || identity(&project)? != plan["project_identity"] {
        return Err("Project identity changed".into());
    }
    if git_state(&project)? != plan["git"] {
        return Err("Git state changed; regenerate plan".into());
    }
    let targets = plan["targets"].as_array().ok_or("Invalid targets")?.clone();
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err("Plan must contain 1–8 exact targets".into());
    }
    let mut sum = 0u64;
    let mut seen = BTreeSet::new();
    for target in &targets {
        let path = Path::new(text(target, "path")?);
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            || !ARTIFACTS.iter().any(|a| path.ends_with(a))
        {
            return Err("Invalid target path".into());
        }
        for other in &seen {
            if path.starts_with(other) || Path::new(other).starts_with(path) {
                return Err("Duplicate or overlapping targets".into());
            }
        }
        seen.insert(path.to_path_buf());
        sum = sum
            .checked_add(number(target, "bytes")?)
            .ok_or("Byte count overflow")?;
    }
    if sum > MAX_BYTES {
        return Err("Plan exceeds 10 GiB per-run limit".into());
    }
    Ok((project, days, targets))
}

fn fresh_target(project: &Path, days: u32, expected: &Value) -> Result<Value> {
    let fresh = plan(project, days, Some(Path::new(text(expected, "path")?)))?;
    match_target(&fresh, expected)
}

fn match_target(fresh: &Value, expected: &Value) -> Result<Value> {
    let target = fresh["targets"]
        .as_array()
        .and_then(|a| a.iter().find(|t| t["path"] == expected["path"]))
        .ok_or_else(|| {
            format!(
                "Target is absent, already removed, or protected: {}",
                fresh["blocked"]
            )
        })?;
    if target != expected {
        return Err("Target or recovery evidence changed; regenerate plan".into());
    }
    Ok(target.clone())
}

pub fn apply(plan: &Value, yes: bool) -> Result<Value> {
    apply_with_recorder(plan, yes, event)
}

fn apply_with_recorder(
    plan: &Value,
    yes: bool,
    mut record: impl FnMut(&mut fs::File, &Value) -> Result<()>,
) -> Result<Value> {
    if !yes {
        return Err("Apply requires --yes after reviewing the plan".into());
    }
    if current_uid()? == 0 {
        return Err("Run keeper apply without sudo".into());
    }
    let (project, days, targets) = validate(plan)?;
    let state = state_dir(&project)?;
    let lock_path = state.join(format!("{}.lock", digest(project.as_os_str().as_bytes())));
    write_new(&lock_path, format!("pid={}\n", std::process::id()).as_bytes()).map_err(|e| {
        if e.downcast_ref::<std::io::Error>().is_none_or(|e| e.kind() != std::io::ErrorKind::AlreadyExists) {
            return format!("Could not create/write project lock at {}: {e}. Check available space and directory permissions", lock_path.display());
        }
        let mut owner = String::new();
        let _ = fs::File::open(&lock_path).and_then(|f| f.take(64).read_to_string(&mut owner));
        let pid = owner.trim().strip_prefix("pid=").and_then(|p| p.parse::<u32>().ok());
        format!("Cannot acquire project lock {} (recorded pid: {pid:?}; inspect stale locks manually): {e}", lock_path.display())
    })?;
    let _lock = Lock(lock_path);
    // Validate every target before deleting the first, then recheck each immediately before it.
    let only = if targets.len() == 1 {
        Some(Path::new(text(&targets[0], "path")?))
    } else {
        None
    };
    let preflight = self::plan(&project, days, only)?;
    for target in &targets {
        match_target(&preflight, target)?;
    }
    let dir = Dir::open_ambient_dir(&project, cap_std::ambient_authority())?;
    let dm = dir.dir_metadata()?;
    if json!({"device": dm.dev(), "inode": dm.ino()}) != plan["project_identity"] {
        return Err("Project changed while opening it".into());
    }
    let name = format!(
        "receipt-{}-{}-{}.jsonl",
        seconds()?,
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.subsec_nanos()
    );
    let receipt_path = state.join(name);
    let mut receipt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&receipt_path)?;
    record(
        &mut receipt,
        &json!({"event": "started", "project": project, "git": plan["git"], "targets": targets,
        "preservation": "All non-target files remain in place; this receipt is not a backup"}),
    )?;
    FileSync::directory(&state)?;
    let mut removed = Vec::new();
    for target in &targets {
        let mut deletion_started = false;
        let mut removal_completed = false;
        let result = (|| -> Result<()> {
            if identity(&project)? != plan["project_identity"]
                || git_state(&project)? != plan["git"]
            {
                return Err("Project or Git state changed".into());
            }
            fresh_target(&project, days, target)?;
            let relative = Path::new(text(target, "path")?);
            let anchored = open_target(&dir, relative)?;
            let (fingerprint, sensitive) = snapshot(
                &anchored,
                relative.file_name() == Some(OsStr::new("node_modules")),
            )?;
            if fingerprint != text(target, "fingerprint")? || !sensitive.is_empty() {
                return Err("Target changed during checks".into());
            }
            record(
                &mut receipt,
                &json!({"event": "deleting", "target": target}),
            )?;
            // Snapshot and removal use the same handle, never re-resolve ancestors.
            deletion_started = true;
            anchored.remove_open_dir_all()?;
            removal_completed = true;
            removed.push(target.clone());
            record(&mut receipt, &json!({"event": "removed", "target": target}))?;
            Ok(())
        })();
        if let Err(e) = result {
            let _ = record(
                &mut receipt,
                &json!({"event": "failed", "error": e.to_string(), "target": target, "deletion_started": deletion_started, "removal_completed": removal_completed}),
            );
            let outcome = if removal_completed {
                "target was fully deleted, but its receipt record failed"
            } else if deletion_started {
                "the current target may be partially removed"
            } else {
                "the current target was not touched (pre-delete check or receipt write failed)"
            };
            return Err(format!(
                "Stopped after {} completed deletions; {outcome}: {e}. Receipt: {}",
                removed.len(),
                receipt_path.display()
            )
            .into());
        }
    }
    record(
        &mut receipt,
        &json!({"event": "completed", "removed_targets": removed.len()}),
    )
    .map_err(|e| {
        format!(
            "All {} targets were deleted, but the completion record failed: {e}. Receipt: {}",
            removed.len(),
            receipt_path.display()
        )
    })?;
    Ok(
        json!({"action": "park", "project": project, "removed": removed, "receipt": receipt_path,
        "estimated_bytes": targets.iter().filter_map(|t| t["bytes"].as_u64()).sum::<u64>(),
        "local_state": "preserved in place", "recovery": "Use the recorded recipes; Keeper never executes install scripts"}),
    )
}

fn event(file: &mut fs::File, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub fn read_plan(path: &Path) -> Result<Value> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
        return Err("Plan must be a regular file under 8 MiB".into());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn receipt_failures_report_actual_deletions_and_receipt_path() {
        let root = std::env::temp_dir().join(format!("keeper-receipt-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        g(&project, &["init", "-q"]).unwrap();
        g(&project, &["config", "user.email", "test@example.invalid"]).unwrap();
        g(&project, &["config", "user.name", "Test"]).unwrap();
        fs::write(project.join(".gitignore"), "node_modules/\n").unwrap();
        fs::write(project.join("package.json"), "{}").unwrap();
        fs::write(project.join("package-lock.json"), "{}").unwrap();
        g(&project, &["add", "."]).unwrap();
        assert!(Command::new("git")
            .arg("-C")
            .arg(&project)
            .args(["commit", "-qm", "fixture"])
            .env("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
            .status()
            .unwrap()
            .success());
        fn age(path: &Path) {
            if path.is_dir() {
                for e in fs::read_dir(path).unwrap() {
                    age(&e.unwrap().path());
                }
            }
            fs::File::open(path)
                .unwrap()
                .set_times(
                    fs::FileTimes::new()
                        .set_modified(UNIX_EPOCH + Duration::from_secs(1_600_000_000)),
                )
                .unwrap();
        }
        let previous_state = std::env::var_os("KEEPER_STATE_DIR");
        std::env::set_var("KEEPER_STATE_DIR", root.join("state"));
        for failed_event in ["removed", "completed"] {
            fs::create_dir(project.join("node_modules")).unwrap();
            fs::write(project.join("node_modules/generated"), "cache").unwrap();
            age(&project);
            let proposal = plan(&project, 7, None).unwrap();
            let mut failure_record = None;
            let err = apply_with_recorder(&proposal, true, |file, value| {
                if value["event"] == "failed" {
                    failure_record = Some(value.clone());
                }
                if value["event"] == failed_event {
                    return Err("simulated full disk".into());
                }
                event(file, value)
            })
            .unwrap_err()
            .to_string();
            assert!(!project.join("node_modules").exists());
            assert!(
                err.contains("Receipt:") && err.contains("simulated full disk"),
                "{err}"
            );
            if failed_event == "removed" {
                assert!(
                    err.contains("target was fully deleted, but its receipt record failed"),
                    "{err}"
                );
                assert_eq!(failure_record.unwrap()["removal_completed"], true);
            }
            assert!(
                err.contains(if failed_event == "removed" {
                    "1 completed deletions"
                } else {
                    "All 1 targets were deleted"
                }),
                "{err}"
            );
            assert!(!fs::read_dir(root.join("state")).unwrap().any(|e| e
                .unwrap()
                .path()
                .extension()
                .is_some_and(|e| e == "lock")));
        }
        match previous_state {
            Some(value) => std::env::set_var("KEEPER_STATE_DIR", value),
            None => std::env::remove_var("KEEPER_STATE_DIR"),
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn opened_target_cannot_be_redirected_by_parent_swap() {
        let root = std::env::temp_dir().join(format!("keeper-handle-{}", std::process::id()));
        fs::create_dir_all(root.join("packages/web/node_modules")).unwrap();
        fs::create_dir_all(root.join(".t3/precious/node_modules")).unwrap();
        fs::write(root.join(".t3/precious/node_modules/.env"), "unique").unwrap();
        let dir = Dir::open_ambient_dir(&root, cap_std::ambient_authority()).unwrap();
        let target = open_target(&dir, Path::new("packages/web/node_modules")).unwrap();
        let fingerprint = snapshot(&target, false).unwrap().0;
        fs::rename(root.join("packages/web"), root.join("original")).unwrap();
        symlink("../.t3/precious", root.join("packages/web")).unwrap();
        assert!(open_target(&dir, Path::new("packages/web/node_modules")).is_err());
        assert_eq!(snapshot(&target, false).unwrap().0, fingerprint);
        target.remove_open_dir_all().unwrap();
        assert_eq!(
            fs::read_to_string(root.join(".t3/precious/node_modules/.env")).unwrap(),
            "unique"
        );
        assert!(!root.join("original/node_modules").exists());
        fs::remove_dir_all(root).unwrap();
    }
}
