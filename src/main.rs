#![forbid(unsafe_code)]
mod parking;
mod storage;

use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const ARTIFACTS: &[&str] = &[
    "node_modules",
    ".next/cache",
    ".turbo/cache",
    ".pytest_cache",
    "__pycache__",
];
const SKIP: &[&str] = &[
    ".git",
    "node_modules",
    ".next",
    ".turbo",
    ".venv",
    "venv",
    "target",
    "dist",
    "build",
    "Library",
    ".Trash",
    ".cache",
    ".t3",
    ".codex",
    ".pytest_cache",
    "__pycache__",
];
const LOCKS: &[&str] = &[
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
];

fn run(command: &mut Command) -> Result<Output> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or("Missing stdout")?;
    let mut stderr = child.stderr.take().ok_or("Missing stderr")?;
    let out = std::thread::spawn(move || {
        let mut data = Vec::new();
        stdout.read_to_end(&mut data).map(|_| data)
    });
    let err = std::thread::spawn(move || {
        let mut data = Vec::new();
        stderr.read_to_end(&mut data).map(|_| data)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Command exceeded 30 seconds".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Ok(Output {
        status,
        stdout: out.join().map_err(|_| "stdout reader failed")??,
        stderr: err.join().map_err(|_| "stderr reader failed")??,
    })
}

fn git(project: &Path, args: &[&OsStr]) -> Result<Vec<u8>> {
    let output = run(Command::new("git")
        .args(["--no-optional-locks", "--literal-pathspecs", "-C"])
        .arg(project)
        .args(args))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_owned()
            .into());
    }
    Ok(output.stdout)
}

fn g(project: &Path, args: &[&str]) -> Result<Vec<u8>> {
    git(project, &args.iter().map(OsStr::new).collect::<Vec<_>>())
}

fn output_path(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(
        bytes.strip_suffix(b"\n").unwrap_or(bytes),
    ))
}

fn current_uid() -> Result<u32> {
    let uid = run(Command::new("id").arg("-u"))?;
    if !uid.status.success() {
        return Err("Cannot determine current user".into());
    }
    Ok(String::from_utf8_lossy(&uid.stdout).trim().parse()?)
}

fn host_context() -> Result<Value> {
    let output = run(&mut Command::new("hostname"))?;
    if !output.status.success() {
        return Err("Cannot identify the scan host".into());
    }
    let hostname = String::from_utf8(output.stdout)?;
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err("Cannot identify the scan host".into());
    }
    Ok(json!({"hostname": hostname,
        "os": std::env::consts::OS, "architecture": std::env::consts::ARCH}))
}

fn process_args(uid: u32) -> Vec<String> {
    let mut args = vec!["-nP".to_owned(), "-Fpn0".to_owned()];
    // An elevated scan must see the user's processes too, not just root's.
    if uid != 0 {
        args.extend(["-a".to_owned(), "-u".to_owned(), uid.to_string()]);
    }
    args
}

fn decode_process_path(input: &[u8]) -> Option<(PathBuf, bool)> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut ambiguous = false;
    let mut i = 0;
    while i < input.len() {
        let byte = if input[i] == b'\\' {
            i += 1;
            match *input.get(i)? {
                b'\\' => b'\\',
                b'b' => 8,
                b'f' => 12,
                b'r' => b'\r',
                b'n' => b'\n',
                b't' => b'\t',
                b'x' => {
                    let high = (*input.get(i + 1)? as char).to_digit(16)?;
                    let low = (*input.get(i + 2)? as char).to_digit(16)?;
                    i += 2;
                    (high * 16 + low) as u8
                }
                _ => return None,
            }
        } else {
            // lsof prints control bytes as ^A, etc., indistinguishably from
            // literal caret text. Keep possible literal positives, but never
            // infer inactivity from this ambiguous process context.
            if input[i] == b'^'
                && input
                    .get(i + 1)
                    .is_some_and(|b| (b'@'..=b'_').contains(b) || *b == b'?')
            {
                ambiguous = true;
            }
            input[i]
        };
        if byte == 0 {
            return None;
        }
        bytes.push(byte);
        i += 1;
    }
    Some((PathBuf::from(OsStr::from_bytes(&bytes)), ambiguous))
}

fn opened_paths() -> Result<Vec<PathBuf>> {
    // Do not let the inspection child introduce project activity through its cwd.
    let output = run(Command::new("lsof")
        .current_dir("/")
        .args(process_args(current_uid()?)))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("Process inspection incomplete; cleanup blocked".into());
    }
    let mut paths = Vec::new();
    let mut pid = 0;
    for field in output.stdout.split(|c| *c == 0) {
        let field = field.strip_prefix(b"\n").unwrap_or(field);
        if let Some(value) = field.strip_prefix(b"p") {
            pid = String::from_utf8_lossy(value).parse::<u32>()?;
        }
        if field.starts_with(b"n/") && pid != std::process::id() {
            let (path, ambiguous) = decode_process_path(&field[1..])
                .ok_or("Process path encoding unsupported; cleanup blocked")?;
            if ambiguous {
                return Err("Process path encoding ambiguous; cleanup blocked".into());
            }
            paths.push(fs::canonicalize(&path).unwrap_or(path));
        }
    }
    Ok(paths)
}

fn entries(path: &Path) -> Result<Vec<fs::DirEntry>> {
    Ok(fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?)
}

fn skip(name: &OsStr) -> bool {
    SKIP.iter().any(|s| name == OsStr::new(s))
}

fn discover(
    path: &Path,
    depth: usize,
    found: &mut BTreeSet<PathBuf>,
    errors: &mut Vec<Value>,
) -> Result<()> {
    if path.join(".git").exists() {
        found.insert(path.to_path_buf());
        match g(path, &["worktree", "list", "--porcelain", "-z"]) {
            Ok(data) => {
                for field in data.split(|c| *c == 0) {
                    if let Some(name) = field.strip_prefix(b"worktree ") {
                        let candidate = PathBuf::from(OsStr::from_bytes(name));
                        // Git submodules can report their internal gitdir as a worktree.
                        if !candidate.components().any(|c| c.as_os_str() == ".git") {
                            found.insert(candidate);
                        }
                    }
                }
            }
            Err(e) => errors.push(json!({"project": path, "error": e.to_string()})),
        }
    }
    if depth > 0 {
        for entry in fs::read_dir(path)? {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    errors.push(json!({"project": path, "error": e.to_string()}));
                    continue;
                }
            };
            let child = entry.path();
            let result: Result<()> = (|| {
                if entry.file_type()?.is_dir() && !skip(&entry.file_name()) {
                    discover(&child, depth - 1, found, errors)?;
                }
                Ok(())
            })();
            if let Err(e) = result {
                errors.push(json!({"project": child, "error": e.to_string()}));
            }
        }
    }
    Ok(())
}

fn artifacts(
    root: &Path,
    base: &Path,
    found: &mut Vec<(PathBuf, &'static str, PathBuf)>,
) -> Result<()> {
    if base != root && base.join(".git").exists() {
        return Ok(());
    }
    for &name in ARTIFACTS {
        let path = base.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => found.push((path, name, base.to_path_buf())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    for entry in entries(base)? {
        if entry.file_type()?.is_dir() && !skip(&entry.file_name()) {
            artifacts(root, &entry.path(), found)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct Inventory {
    bytes: u64,
    newest: i64,
    unsafe_contents: bool,
    recovery_inputs: bool,
    seen: HashSet<(u64, u64)>,
}

fn recovery_input_name(name: &OsStr) -> bool {
    LOCKS
        .iter()
        .copied()
        .chain([
            "package.json",
            "pnpm-workspace.yaml",
            "npm-shrinkwrap.json",
            ".npmrc",
            "bunfig.toml",
            ".pnpmfile.cjs",
            ".pnpmfile.mjs",
        ])
        .any(|input| name.as_bytes().eq_ignore_ascii_case(input.as_bytes()))
}

fn inventory(path: &Path, device: u64, result: &mut Inventory) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    result.newest = result.newest.max(meta.mtime());
    result.recovery_inputs |= path.file_name().is_some_and(recovery_input_name);
    if meta.dev() != device || path.file_name() == Some(OsStr::new(".git")) {
        result.unsafe_contents = true;
        return Ok(());
    }
    if result.seen.insert((meta.dev(), meta.ino())) {
        result.bytes += meta.blocks() * 512;
    }
    if meta.is_dir() {
        for entry in entries(path)? {
            inventory(&entry.path(), device, result)?;
        }
    }
    Ok(())
}

struct Candidate {
    path: PathBuf,
    bytes: u64,
    blockers: Vec<String>,
}
struct Report {
    project: PathBuf,
    worktree: bool,
    idle_days: f64,
    candidates: Vec<Candidate>,
    missing_files: usize,
    missing_examples: Vec<String>,
}
impl Report {
    fn json(&self) -> Value {
        json!({"project": self.project, "worktree": self.worktree, "idle_days": (self.idle_days * 10.0).round()/10.0,
            "missing_tracked_files": {"count": self.missing_files, "examples": self.missing_examples},
            "candidates": self.candidates.iter().map(|c| json!({"path": c.path, "bytes": c.bytes, "blockers": c.blockers})).collect::<Vec<_>>()})
    }
}

fn inspect(project: &Path, days: u32, opened: Option<&[PathBuf]>) -> Result<Report> {
    let project = fs::canonicalize(project)?;
    if output_path(&g(&project, &["rev-parse", "--show-toplevel"])?) != project {
        return Err("Not a Git project root".into());
    }
    let mut reasons = Vec::new();
    if fs::symlink_metadata(project.join(".keeper-pin")).is_ok() {
        reasons.push("pinned (.keeper-pin)".to_owned());
    }
    if !g(
        &project,
        &["status", "--porcelain", "--untracked-files=all"],
    )?
    .is_empty()
    {
        reasons.push("uncommitted or untracked files".to_owned());
    }
    match opened {
        None => reasons.push("process inspection unavailable".to_owned()),
        Some(paths) if paths.iter().any(|p| p.starts_with(&project)) => {
            reasons.push("running process has files or cwd in project".to_owned())
        }
        _ => (),
    }
    let mut newest = 0;
    let mut missing_files = 0;
    let mut missing_examples = Vec::new();
    for name in g(
        &project,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?
    .split(|c| *c == 0)
    .filter(|n| !n.is_empty())
    {
        match fs::symlink_metadata(project.join(OsStr::from_bytes(name))) {
            Ok(meta) => newest = newest.max(meta.mtime()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing_files += 1;
                if missing_examples.len() < 5 {
                    missing_examples.push(String::from_utf8_lossy(name).into_owned());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    if missing_files > 0 {
        reasons.push("tracked file missing".to_owned());
    }
    let head = run(Command::new("git").arg("-C").arg(&project).args([
        "rev-parse",
        "--verify",
        "--quiet",
        "HEAD",
    ]))?;
    if head.status.success() {
        newest = newest.max(
            String::from_utf8_lossy(&g(&project, &["log", "-1", "--format=%ct"])?)
                .trim()
                .parse::<i64>()?,
        );
    } else {
        reasons.push("no resolvable HEAD commit; preserve unfinished repository".to_owned());
    }
    let log = output_path(&g(&project, &["rev-parse", "--git-path", "logs/HEAD"])?);
    match fs::metadata(project.join(log)) {
        Ok(meta) => newest = newest.max(meta.mtime()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let device = fs::metadata(&project)?.dev();
    let mut paths = Vec::new();
    artifacts(&project, &project, &mut paths)?;
    let mut candidates = Vec::new();
    for (path, kind, package) in paths {
        let mut blockers = reasons.clone();
        let meta = fs::symlink_metadata(&path)?;
        let mut bytes = 0;
        if !meta.is_dir() || fs::canonicalize(&path)? != path {
            blockers.push("symlink or non-directory".to_owned());
        } else if meta.dev() != device {
            blockers.push("different filesystem or mount point".to_owned());
        } else {
            let mut info = Inventory::default();
            inventory(&path, device, &mut info)?;
            bytes = info.bytes;
            newest = newest.max(info.newest);
            if info.unsafe_contents {
                blockers.push("nested Git repository or different filesystem".to_owned());
            }
            if kind != "node_modules" && info.recovery_inputs {
                blockers.push(
                    "Cache contains dependency manifests or workspace recovery inputs; preserve it"
                        .to_owned(),
                );
            }
            let relative = path.strip_prefix(&project)?.as_os_str();
            if !git(
                &project,
                &[
                    OsStr::new("ls-files"),
                    OsStr::new("-z"),
                    OsStr::new("--"),
                    relative,
                ],
            )?
            .is_empty()
            {
                blockers.push("contains tracked files".to_owned());
            }
            let ignored = run(Command::new("git").arg("-C").arg(&project).args([
                OsStr::new("check-ignore"),
                OsStr::new("-q"),
                OsStr::new("--"),
                relative,
            ]))?;
            match ignored.status.code() {
                Some(0) => (),
                Some(1) => blockers.push("not Git-ignored".to_owned()),
                _ => return Err("Git ignore check failed".into()),
            }
            if kind == "node_modules"
                && !package
                    .ancestors()
                    .take_while(|p| p.starts_with(&project))
                    .any(|p| LOCKS.iter().any(|l| p.join(l).is_file()))
            {
                blockers.push("no dependency lockfile".to_owned());
            }
        }
        candidates.push(Candidate {
            path,
            bytes,
            blockers,
        });
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let idle_days = if newest == 0 {
        0.0
    } else {
        (now - newest).max(0) as f64 / 86400.0
    };
    for c in &mut candidates {
        if idle_days < f64::from(days) {
            c.blockers.push(format!("activity within {days} days"));
        }
    }
    Ok(Report {
        worktree: project.join(".git").is_file(),
        project,
        idle_days,
        candidates,
        missing_files,
        missing_examples,
    })
}

fn clean(project: &Path, relative: &Path, days: u32, yes: bool) -> Result<Value> {
    if current_uid()? == 0 {
        return Err("Run keeper clean without sudo; elevated deletion is disabled".into());
    }
    if !yes {
        return Err("Deletion requires --yes; review scan first".into());
    }
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
        || !ARTIFACTS.iter().any(|a| relative.ends_with(a))
    {
        return Err("Only named regenerable cache directories can be cleaned".into());
    }
    let plan = parking::plan(project, days, Some(relative))?;
    if plan["targets"].as_array().is_none_or(|a| a.is_empty()) {
        return Err(format!("Target protected or absent: {}", plan["blocked"]).into());
    }
    parking::apply(&plan, yes)
}

fn main_result() -> Result<bool> {
    let mut positional: Vec<OsString> = Vec::new();
    let (mut days, mut depth, mut json_output, mut yes) = (7u32, 3usize, false, false);
    let mut all = false;
    let mut max_entries = 5_000_000usize;
    let mut max_seconds = 300u64;
    let mut inventory_limits = false;
    let mut output: Option<PathBuf> = None;
    let mut args = std::env::args_os().skip(1);
    let mut literal = false;
    while let Some(arg) = args.next() {
        if literal {
            positional.push(arg);
            continue;
        }
        match arg.to_str() {
            Some("--") => literal = true,
            Some("--help" | "-h") => {
                println!("keeper inventory ROOT... [--depth 3] [--max-entries 5000000] [--max-seconds 300] [--json] [--all]\nkeeper scan ROOT... [--days 7] [--depth 3] [--json] [--all]\nkeeper plan PROJECT [--days 7] [--output PLAN.json]\nkeeper apply PLAN.json --yes\nkeeper clean PROJECT CACHE [--days 7] --yes\n\nInventory measures whole storage areas; sizes are not cleanup approvals.\nInventory --depth controls reported folder detail, not measurement depth.\nPlans expose metadata, never secret values. Parking preserves all non-target files in place.\nLimits: one project, 8 directories, 10 GiB per run; plans expire after 24 hours.\nInventory and scan are read-only. Use --all or --json for full detail. Run without sudo.");
                return Ok(true);
            }
            Some("--days") => {
                days = args
                    .next()
                    .ok_or("--days needs a value")?
                    .to_str()
                    .ok_or("Invalid days")?
                    .parse()?
            }
            Some("--depth") => {
                depth = args
                    .next()
                    .ok_or("--depth needs a value")?
                    .to_str()
                    .ok_or("Invalid depth")?
                    .parse()?
            }
            Some("--json") => json_output = true,
            Some("--max-entries" | "--max-seconds") => {
                let value = args.next().ok_or("Inventory limit needs a value")?;
                let value = value.to_str().ok_or("Invalid inventory limit")?;
                if arg == "--max-entries" {
                    max_entries = value.parse()?;
                } else {
                    max_seconds = value.parse()?;
                }
                inventory_limits = true;
            }
            Some("--output") => {
                output = Some(PathBuf::from(args.next().ok_or("--output needs a path")?))
            }
            Some("--all") => all = true,
            Some("--yes") => yes = true,
            Some(s) if s.starts_with('-') => return Err(format!("Unknown option: {s}").into()),
            _ => positional.push(arg),
        }
    }
    if days == 0 {
        return Err("--days must be at least 1".into());
    }
    if inventory_limits && positional.first().and_then(|s| s.to_str()) != Some("inventory") {
        return Err("--max-entries and --max-seconds apply only to inventory".into());
    }
    match positional.first().and_then(|s| s.to_str()) {
        Some("inventory") if positional.len() > 1 => {
            if yes || output.is_some() {
                return Err("Inventory is read-only; --yes and --output are not supported".into());
            }
            let report = storage::inventory(&positional[1..], depth, max_entries, max_seconds)?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                storage::print(&report, all);
            }
            Ok(report["complete"] == true)
        }
        Some("plan") if positional.len() == 2 => {
            let plan = parking::plan(Path::new(&positional[1]), days, None)?;
            if let Some(path) = output {
                parking::write_plan(&path, &plan)?;
            }
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(true)
        }
        Some("apply") if positional.len() == 2 => {
            let plan = parking::read_plan(Path::new(&positional[1]))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&parking::apply(&plan, yes)?)?
            );
            Ok(true)
        }
        Some("clean") if positional.len() == 3 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&clean(
                    Path::new(&positional[1]),
                    Path::new(&positional[2]),
                    days,
                    yes
                )?)?
            );
            Ok(true)
        }
        Some("scan") if positional.len() > 1 => {
            let mut found = BTreeSet::new();
            let mut errors = Vec::new();
            for root in &positional[1..] {
                let result = fs::canonicalize(root)
                    .map_err(Into::into)
                    .and_then(|p| discover(&p, depth, &mut found, &mut errors));
                if let Err(e) = result {
                    errors.push(json!({"project": root.to_string_lossy(), "error": e.to_string()}));
                }
            }
            let processes = opened_paths();
            let warning = processes.as_ref().err().map(ToString::to_string);
            let mut reports = Vec::new();
            for path in found {
                match inspect(&path, days, processes.as_ref().ok().map(Vec::as_slice)) {
                    Ok(report) => reports.push(report),
                    Err(e) => errors.push(json!({"project": path, "error": e.to_string()})),
                }
            }
            reports.sort_by_key(|r| {
                std::cmp::Reverse(r.candidates.iter().map(|c| c.bytes).sum::<u64>())
            });
            let eligible: u64 = reports
                .iter()
                .flat_map(|r| &r.candidates)
                .filter(|c| c.blockers.is_empty())
                .map(|c| c.bytes)
                .sum();
            let total: u64 = reports
                .iter()
                .flat_map(|r| &r.candidates)
                .map(|c| c.bytes)
                .sum();
            let host = if json_output {
                match host_context() {
                    Ok(host) => host,
                    Err(_) => {
                        errors.push(
                            json!({"scope": "host", "error": "Cannot identify the scan host"}),
                        );
                        Value::Null
                    }
                }
            } else {
                Value::Null
            };
            let complete = errors.is_empty() && warning.is_none();
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"host": host, "projects": reports.iter().map(Report::json).collect::<Vec<_>>(), "eligible_bytes": eligible, "total_cache_bytes": total, "protected_bytes": total - eligible, "complete": complete, "warning": warning, "errors": errors})
                    )?
                );
            } else {
                println!("Workspace Keeper — read-only scan\n{} projects/worktrees inspected. Known caches: {}; eligible: {}; protected: {}.", reports.len(), size(total), size(eligible), size(total - eligible));
                println!("This measures supported project caches, not total disk usage. Discovery depth: {depth}.");
                if !complete {
                    println!("INCOMPLETE: {} paths could not be inspected; totals exclude them. Continue without sudo; accessible paths were still scanned.", errors.len());
                }
                if let Some(w) = warning {
                    println!("Warning: {w}");
                }
                for r in &reports {
                    if !all && !r.candidates.iter().any(|c| c.bytes >= 1024 * 1024) {
                        continue;
                    }
                    println!(
                        "\n{}{} (activity age: {:.1} days)",
                        r.project.display(),
                        if r.worktree { " [linked worktree]" } else { "" },
                        r.idle_days
                    );
                    for c in &r.candidates {
                        if !all && c.bytes < 1024 * 1024 {
                            continue;
                        }
                        println!(
                            "  {}  {}  {}",
                            size(c.bytes),
                            c.path.strip_prefix(&r.project)?.display(),
                            if c.blockers.is_empty() {
                                "eligible for explicit cleanup".to_owned()
                            } else {
                                c.blockers.join("; ")
                            }
                        );
                        if c.blockers.is_empty() {
                            println!(
                                "    keeper clean {} {} --days {days} --yes",
                                quote(&r.project),
                                quote(c.path.strip_prefix(&r.project)?)
                            );
                        }
                    }
                }
                if eligible == 0 {
                    println!("\nNo eligible caches found in inspected projects. Protected caches are not cleanup recommendations.");
                }
                if !all {
                    println!("\nCaches under 1 MiB and projects without visible caches are hidden. Use --all or --json for full detail.");
                }
                for e in &errors {
                    eprintln!("ERROR: {}: {}", e["project"], e["error"]);
                }
            }
            Ok(errors.is_empty())
        }
        _ => Err("Use keeper --help for usage".into()),
    }
}

fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / 1073741824.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / 1048576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}

fn main() {
    match main_result() {
        Ok(true) => (),
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn elevated_scan_checks_all_users() {
        assert!(!process_args(0).contains(&"-u".to_owned()));
        assert!(process_args(501).contains(&"501".to_owned()));
    }
    #[test]
    fn human_sizes_do_not_round_small_caches_to_zero_gib() {
        assert_eq!(size(4096), "4.0 KiB");
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1048576), "1.0 MiB");
    }
}
