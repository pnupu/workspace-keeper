use serde_json::Value;
use std::fs::{self, File, FileTimes};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture {
    root: PathBuf,
    project: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "keeper-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        let f = Self { root, project };
        f.git(&["init", "-q"]);
        // Background maintenance removes transient lock files while age() walks
        // the fixture. Keep these disposable repositories deterministic.
        f.git(&["config", "maintenance.auto", "false"]);
        f.git(&["config", "gc.auto", "0"]);
        f.git(&["config", "user.email", "test@example.invalid"]);
        f.git(&["config", "user.name", "Test"]);
        fs::write(
            f.project.join(".gitignore"),
            "node_modules/\n.next/\n.keeper-pin\n.t3/\n",
        )
        .unwrap();
        fs::write(f.project.join("package-lock.json"), "{}").unwrap();
        fs::write(
            f.project.join("package.json"),
            "{\"name\":\"fixture\",\"private\":true}",
        )
        .unwrap();
        fs::write(f.project.join("source.txt"), "source survives").unwrap();
        f.git(&["add", "."]);
        f.git(&["commit", "-qm", "fixture"]);
        fs::create_dir(f.cache()).unwrap();
        fs::write(f.cache().join("generated"), "cache").unwrap();
        age(&f.project);
        f
    }
    fn cache(&self) -> PathBuf {
        self.project.join("node_modules")
    }
    fn nested_cache(&self) -> PathBuf {
        let package = self.project.join("packages/web");
        let cache = package.join("node_modules");
        fs::create_dir_all(&cache).unwrap();
        fs::write(package.join("package.json"), "{\"name\":\"web\"}").unwrap();
        fs::write(package.join("package-lock.json"), "{}").unwrap();
        fs::write(cache.join("generated"), "cache").unwrap();
        cache
    }
    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.project)
            .args(args)
            .env("GIT_AUTHOR_DATE", "2020-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2020-01-01T00:00:00Z")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    fn scan(&self) -> Value {
        let out = cli(&[
            "scan",
            self.project.to_str().unwrap(),
            "--depth",
            "0",
            "--json",
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(value["warning"].is_null(), "{value}");
        value
    }
    fn clean(&self, path: &str) -> Output {
        cli(&["clean", self.project.to_str().unwrap(), path, "--yes"])
    }
    fn blocked(&self, expected: &str) {
        let out = self.clean("node_modules");
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(expected),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(self.cache().exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn cli(args: &[&str]) -> Output {
    let context = Path::new(args.get(1).copied().unwrap_or("."));
    let state = context
        .parent()
        .unwrap_or(Path::new("."))
        .join("keeper-state");
    Command::new(env!("CARGO_BIN_EXE_keeper"))
        .args(args)
        .env("KEEPER_STATE_DIR", state)
        .output()
        .unwrap()
}
fn age(path: &Path) {
    let meta = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("Cannot age fixture {}: {error}", path.display()));
    if meta.is_symlink() {
        return;
    }
    if meta.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            age(&entry.unwrap().path());
        }
    }
    let old = SystemTime::now() - Duration::from_secs(30 * 86400);
    File::open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(old))
        .unwrap();
}

#[test]
fn scan_and_cleanup_preserve_source() {
    let f = Fixture::new();
    assert!(f.scan()["eligible_bytes"].as_u64().unwrap() > 0);
    let out = f.clean("node_modules");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!f.cache().exists());
    assert_eq!(
        fs::read_to_string(f.project.join("source.txt")).unwrap(),
        "source survives"
    );
}
#[test]
fn dirty_source_is_preserved() {
    let f = Fixture::new();
    fs::write(f.project.join("source.txt"), "valuable edits").unwrap();
    f.blocked("activity within");
}
#[test]
fn untracked_files_protect_project() {
    let f = Fixture::new();
    fs::write(f.project.join("new.txt"), "valuable").unwrap();
    f.blocked("activity within");
}
#[test]
fn pin_protects_project() {
    let f = Fixture::new();
    fs::write(f.project.join(".keeper-pin"), "").unwrap();
    f.blocked("pinned");
}
#[test]
fn recent_source_protects_project() {
    let f = Fixture::new();
    File::open(f.project.join("source.txt"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(SystemTime::now()))
        .unwrap();
    f.blocked("activity within");
}
#[test]
fn recent_cache_protects_project() {
    let f = Fixture::new();
    fs::write(f.cache().join("generated"), "new").unwrap();
    f.blocked("activity within");
}
#[test]
fn recent_checkout_protects_project() {
    let f = Fixture::new();
    File::open(f.project.join(".git/logs/HEAD"))
        .unwrap()
        .set_times(FileTimes::new().set_modified(SystemTime::now()))
        .unwrap();
    f.blocked("activity within");
}
#[test]
fn tracked_cache_is_preserved() {
    let f = Fixture::new();
    f.git(&["add", "-f", "node_modules/generated"]);
    f.blocked("contains tracked files");
}
#[test]
fn missing_lockfile_blocks_dependencies() {
    let f = Fixture::new();
    fs::remove_file(f.project.join("package-lock.json")).unwrap();
    f.blocked("no dependency lockfile");
}
#[test]
fn nested_git_is_preserved() {
    let f = Fixture::new();
    fs::create_dir(f.cache().join(".git")).unwrap();
    age(&f.project);
    f.blocked("nested Git");
}
#[test]
fn symlink_target_is_preserved() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("valuable"), "keep").unwrap();
    fs::remove_dir_all(f.cache()).unwrap();
    symlink(&outside, f.cache()).unwrap();
    f.blocked("symlink");
    assert!(outside.join("valuable").exists());
}
#[test]
fn internal_symlink_is_not_followed() {
    let f = Fixture::new();
    let outside = f.root.join("valuable");
    fs::write(&outside, "keep").unwrap();
    symlink(&outside, f.cache().join("link")).unwrap();
    // Set link mtime without touching its target, using the platform touch tool.
    assert!(Command::new("touch")
        .args(["-h", "-t", "202001010000"])
        .arg(f.cache().join("link"))
        .status()
        .unwrap()
        .success());
    age(&f.project);
    let out = f.clean("node_modules");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(outside.exists());
}
#[test]
fn fresh_checks_protect_changes_after_scan() {
    let f = Fixture::new();
    assert!(f.scan()["eligible_bytes"].as_u64().unwrap() > 0);
    fs::write(f.project.join("source.txt"), "new").unwrap();
    f.blocked("activity within");
}
#[test]
fn nested_package_cache_can_be_cleaned() {
    let f = Fixture::new();
    f.nested_cache();
    age(&f.project);
    assert_eq!(
        f.scan()["projects"][0]["candidates"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(f.clean("packages/web/node_modules").status.success());
    assert!(f.cache().exists());
}
#[test]
fn linked_worktrees_are_discovered() {
    let f = Fixture::new();
    let linked = f.root.join("linked");
    f.git(&[
        "worktree",
        "add",
        "-qb",
        "feature",
        linked.to_str().unwrap(),
    ]);
    let report = f.scan();
    assert_eq!(report["projects"].as_array().unwrap().len(), 2);
    assert!(report["projects"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["worktree"] == true));
}
#[test]
fn application_data_is_excluded() {
    let f = Fixture::new();
    fs::create_dir_all(f.project.join(".t3/session/node_modules")).unwrap();
    assert_eq!(
        f.scan()["projects"][0]["candidates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!f.clean(".t3/session/node_modules").status.success());
}
#[test]
fn refuses_arbitrary_paths_and_missing_confirmation() {
    let f = Fixture::new();
    for path in ["../outside", "/tmp/node_modules", "source.txt"] {
        assert!(!f.clean(path).status.success());
    }
    assert!(
        !cli(&["clean", f.project.to_str().unwrap(), "node_modules"])
            .status
            .success()
    );
    assert!(!cli(&["scan", f.project.to_str().unwrap(), "--days", "0"])
        .status
        .success());
    assert!(f.cache().exists());
}
#[test]
fn actual_open_file_protects_project() {
    let f = Fixture::new();
    let file = File::open(f.project.join("source.txt")).unwrap();
    f.blocked("running process");
    drop(file);
}
#[test]
#[cfg(target_os = "macos")]
fn escaped_project_names_preserve_open_file_cleanup_guards() {
    for (name, reason) in [
        ("back\\slash", "running process"),
        ("new\nline", "running process"),
        ("with\ttab", "running process"),
        ("control\u{1}", "process inspection unavailable"),
    ] {
        let mut f = Fixture::new();
        let renamed = f.root.join(name);
        fs::rename(&f.project, &renamed).unwrap();
        f.project = renamed;
        age(&f.project);
        assert!(f.scan()["eligible_bytes"].as_u64().unwrap() > 0);
        let _held = File::open(f.project.join("source.txt")).unwrap();
        f.blocked(reason);
    }
}

#[test]
fn failed_process_inspection_blocks_cleanup() {
    let f = Fixture::new();
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .args([
            "clean",
            f.project.to_str().unwrap(),
            "node_modules",
            "--yes",
        ])
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(f.cache().exists());
}
#[test]
fn stale_worktree_is_reported_alongside_results() {
    let f = Fixture::new();
    let linked = f.root.join("linked");
    f.git(&[
        "worktree",
        "add",
        "-qb",
        "feature",
        linked.to_str().unwrap(),
    ]);
    fs::remove_dir_all(linked).unwrap();
    let out = cli(&[
        "scan",
        f.project.to_str().unwrap(),
        "--depth",
        "0",
        "--json",
    ]);
    assert!(!out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["projects"].as_array().unwrap().len(), 1);
    assert_eq!(report["errors"].as_array().unwrap().len(), 1);
}

#[test]
fn inaccessible_directory_does_not_abort_siblings() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let denied = f.root.join("denied");
    fs::create_dir(&denied).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    let out = cli(&["scan", f.root.to_str().unwrap(), "--depth", "2", "--json"]);
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o700)).unwrap();
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!out.status.success());
    assert_eq!(report["complete"], false);
    assert_eq!(report["projects"].as_array().unwrap().len(), 1);
    assert_eq!(report["errors"][0]["project"], denied.to_str().unwrap());
}

#[test]
fn unborn_repository_is_reported_and_protected() {
    let f = Fixture::new();
    fs::remove_dir_all(f.project.join(".git")).unwrap();
    f.git(&["init", "-q"]);
    let report = f.scan();
    assert!(report["errors"].as_array().unwrap().is_empty());
    assert!(report["projects"][0]["candidates"][0]["blockers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s.as_str().unwrap().contains("no resolvable HEAD")));
    f.blocked("no resolvable HEAD");
}

#[test]
fn default_output_hides_tiny_caches_but_all_retains_them() {
    let f = Fixture::new();
    let out = cli(&["scan", f.project.to_str().unwrap(), "--depth", "0"]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Known caches:"));
    assert!(!text.contains("node_modules"));
    let out = cli(&["scan", f.project.to_str().unwrap(), "--depth", "0", "--all"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("node_modules"));
    assert!(text.contains("keeper clean"));
    assert!(!text.contains("0.00 GiB"));
}

#[test]
fn submodule_gitdir_is_not_reported_as_worktree() {
    let f = Fixture::new();
    let source = Fixture::new();
    f.git(&[
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        source.project.to_str().unwrap(),
        "external/module",
    ]);
    let out = cli(&[
        "scan",
        f.project.to_str().unwrap(),
        "--depth",
        "3",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["projects"].as_array().unwrap().len(), 2);
    assert!(report["errors"].as_array().unwrap().is_empty());
}

impl Fixture {
    fn workspace(tool: &str) -> Self {
        let f = Self::new();
        let nested = f.nested_cache();
        fs::remove_file(nested.parent().unwrap().join("package-lock.json")).unwrap();
        fs::remove_file(f.project.join("package-lock.json")).unwrap();
        let mut root = serde_json::json!({"name":"fixture","private":true});
        if tool == "pnpm" {
            fs::write(
                f.project.join("pnpm-workspace.yaml"),
                "packages:\n  - 'packages/*'\n",
            )
            .unwrap();
            fs::write(
                f.project.join("pnpm-lock.yaml"),
                "lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\nimporters:\n  .: {}\n  packages/web: {}\n",
            )
            .unwrap();
        } else {
            root["workspaces"] = serde_json::json!(["packages/*"]);
            if tool == "bun" {
                fs::write(f.project.join("bun.lock"), "{\n// Bun text lock\n\"lockfileVersion\": 1,\n\"workspaces\": {\"\": {\"name\":\"fixture\"}, \"packages/web\": {\"name\":\"web\",},},\n\"packages\": {},\n}").unwrap();
            } else {
                fs::write(
                    f.project.join("package-lock.json"),
                    r#"{"lockfileVersion":3,"packages":{"":{"name":"fixture"},"packages/web":{"name":"web"}}}"#,
                )
                .unwrap();
            }
        }
        fs::write(f.project.join("package.json"), root.to_string()).unwrap();
        f.git(&["add", "-A"]);
        f.git(&["commit", "-qm", "workspace fixture"]);
        age(&f.project);
        f
    }
    fn plan(&self) -> (PathBuf, Value) {
        let path = self.root.join("plan.json");
        let out = cli(&[
            "plan",
            self.project.to_str().unwrap(),
            "--output",
            path.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        (path, serde_json::from_slice(&out.stdout).unwrap())
    }
    fn apply(&self, path: &Path) -> Output {
        cli(&["apply", path.to_str().unwrap(), "--yes"])
    }
}

#[test]
fn shared_workspaces_record_root_recipe_and_preserve_non_targets() {
    for tool in ["npm", "bun", "pnpm"] {
        let f = Fixture::workspace(tool);
        fs::write(f.project.join(".env"), "KEEP_SECRET=private").unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
        for target in plan["targets"].as_array().unwrap() {
            let recovery = &target["recovery"];
            assert_eq!(recovery["cwd"], ".");
            assert_eq!(recovery["command"][0], tool);
            assert_eq!(recovery["workspace"]["member_count"], 1);
            assert!(recovery["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["path"] == "packages/web/package.json"));
        }
        let output = f.clean("packages/web/node_modules");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(f.cache().exists());
        assert!(!f.project.join("packages/web/node_modules").exists());
        assert_eq!(
            fs::read_to_string(f.project.join(".env")).unwrap(),
            "KEEP_SECRET=private"
        );
        assert!(!plan.to_string().contains("KEEP_SECRET"));
    }
}

#[test]
fn workspace_membership_and_recovery_changes_invalidate_plan() {
    for change in ["sibling", "declaration", "config", "lock"] {
        let f = Fixture::workspace("bun");
        fs::write(
            f.project.join(".gitignore"),
            "node_modules/\n.npmrc\npackages/ignored/\n",
        )
        .unwrap();
        age(&f.project);
        let (path, _) = f.plan();
        match change {
            "sibling" => {
                fs::create_dir(f.project.join("packages/ignored")).unwrap();
                fs::write(
                    f.project.join("packages/ignored/package.json"),
                    r#"{"name":"new-member"}"#,
                )
                .unwrap();
            }
            "declaration" => fs::write(
                f.project.join("package.json"),
                r#"{"workspaces":["other/*"]}"#,
            )
            .unwrap(),
            "config" => fs::write(
                f.project.join(".npmrc"),
                "//registry.invalid/:_authToken=DO_NOT_PRINT",
            )
            .unwrap(),
            _ => {
                // Same dependency graph, changed lock bytes must still invalidate.
                let lock = f.project.join("bun.lock");
                let original = fs::read_to_string(&lock).unwrap();
                fs::write(lock, format!("{original}\n")).unwrap();
            }
        }
        age(&f.project);
        let out = f.apply(&path);
        assert!(!out.status.success(), "{change}");
        assert!(f.cache().exists());
        assert!(f.project.join("packages/web/node_modules").exists());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("DO_NOT_PRINT"));
    }
}

#[test]
fn workspace_context_refuses_ambiguous_or_unrecoverable_members() {
    for change in [
        "local-lock",
        "shrinkwrap",
        "outside-glob",
        "nested",
        "missing-lock-member",
        "dependency-drift",
        "symlink",
        "local-dependency",
        "unsupported-glob",
    ] {
        let f = Fixture::workspace("npm");
        let member = f.project.join("packages/web");
        match change {
            "local-lock" => fs::write(member.join("bun.lock"), "{}").unwrap(),
            "shrinkwrap" => fs::write(member.join("npm-shrinkwrap.json"), "{}").unwrap(),
            "outside-glob" => fs::write(
                f.project.join("package.json"),
                r#"{"workspaces":["../outside"]}"#,
            )
            .unwrap(),
            "nested" => fs::write(
                member.join("package.json"),
                r#"{"name":"web","workspaces":[]}"#,
            )
            .unwrap(),
            "missing-lock-member" => fs::write(
                f.project.join("package-lock.json"),
                r#"{"packages":{"":{}}}"#,
            )
            .unwrap(),
            "dependency-drift" => fs::write(
                member.join("package.json"),
                r#"{"name":"web","dependencies":{"example":"1.0.0"}}"#,
            )
            .unwrap(),
            "local-dependency" => {
                let value =
                    r#"{"name":"web","dependencies":{"example":"file:../../node_modules/local"}}"#;
                fs::write(member.join("package.json"), value).unwrap();
                fs::write(
                    f.project.join("package-lock.json"),
                    format!(r#"{{"packages":{{"":{{}},"packages/web":{value}}}}}"#),
                )
                .unwrap();
            }
            "unsupported-glob" => fs::write(
                f.project.join("package.json"),
                r#"{"workspaces":["packages/**"]}"#,
            )
            .unwrap(),
            _ => {
                let outside = f.root.join("outside");
                fs::create_dir(&outside).unwrap();
                fs::write(outside.join("package.json"), r#"{"name":"outside"}"#).unwrap();
                symlink(outside, f.project.join("packages/linked")).unwrap();
            }
        }
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(
            plan["targets"].as_array().unwrap().is_empty(),
            "{change}: {plan}"
        );
        assert!(f.cache().exists());
    }
}

#[test]
fn workspace_does_not_claim_an_undeclared_installation() {
    let f = Fixture::workspace("bun");
    let unrelated = f.project.join("unrelated/node_modules");
    fs::create_dir_all(&unrelated).unwrap();
    fs::write(
        unrelated.parent().unwrap().join("package.json"),
        r#"{"name":"unrelated"}"#,
    )
    .unwrap();
    fs::write(unrelated.join("data"), "retain").unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
    assert!(plan["blocked"]
        .to_string()
        .contains("not a declared workspace member"));
    assert!(!f.clean("unrelated/node_modules").status.success());
    assert!(unrelated.exists());
}

#[test]
fn workspace_sensitive_fixtures_remain_protected() {
    let f = Fixture::workspace("bun");
    fs::create_dir_all(f.cache().join("sdk/credentials")).unwrap();
    fs::write(f.cache().join("sdk/credentials/secret"), "PRIVATE_VALUE").unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 1, "{plan}");
    assert_eq!(plan["targets"][0]["path"], "packages/web/node_modules");
    assert!(plan["blocked"].to_string().contains("secret-like"));
    assert!(!plan.to_string().contains("PRIVATE_VALUE"));
    assert!(!f.clean("node_modules").status.success());
}

#[test]
fn many_missing_files_have_one_reason_and_bounded_examples() {
    let f = Fixture::new();
    for n in 0..500 {
        fs::write(f.project.join(format!("missing-{n}")), "tracked").unwrap();
    }
    f.git(&["add", "-A"]);
    f.git(&["commit", "-qm", "many tracked files"]);
    for n in 0..500 {
        fs::remove_file(f.project.join(format!("missing-{n}"))).unwrap();
    }
    age(&f.project);
    let report = f.scan();
    let project = &report["projects"][0];
    assert_eq!(project["missing_tracked_files"]["count"], 500);
    assert_eq!(
        project["missing_tracked_files"]["examples"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(
        project["candidates"][0]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| *r == "tracked file missing")
            .count(),
        1
    );
    let (_, plan) = f.plan();
    assert_eq!(plan["context"]["missing_tracked_files"]["count"], 500);
    assert!(plan.to_string().len() < 6000);
    assert!(plan["targets"].as_array().unwrap().is_empty());
}

#[test]
fn plans_identify_host_and_reject_foreign_host_context() {
    let f = Fixture::new();
    let (path, mut plan) = f.plan();
    assert!(!plan["host"]["hostname"].as_str().unwrap().is_empty());
    assert_eq!(f.scan()["host"], plan["host"]);
    plan["host"]["hostname"] = serde_json::json!("a-different-machine.invalid");
    fs::write(&path, plan.to_string()).unwrap();
    let out = f.apply(&path);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Plan host differs"));
    assert!(f.cache().exists());
}

#[test]
fn all_workspace_dependency_groups_reject_local_inputs() {
    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        for spec in [
            "file:../../node_modules/.inputs/local",
            "../../node_modules/.inputs/local",
            "archive.tgz",
            "/tmp/local",
            "link:../local",
            "git+file:///tmp/local",
        ] {
            let f = Fixture::workspace("npm");
            let mut m = serde_json::json!({"name":"web"});
            m[group] = serde_json::json!({"local-input":spec});
            fs::write(f.project.join("packages/web/package.json"), m.to_string()).unwrap();
            let lock = serde_json::json!({"lockfileVersion":3,"packages":{"":{"name":"fixture"},"packages/web":m}});
            fs::write(f.project.join("package-lock.json"), lock.to_string()).unwrap();
            fs::create_dir_all(f.cache().join(".inputs/local")).unwrap();
            fs::write(
                f.cache().join(".inputs/local/source.js"),
                "unique local dependency",
            )
            .unwrap();
            age(&f.project);
            let (_, plan) = f.plan();
            assert!(
                plan["targets"].as_array().unwrap().is_empty(),
                "{group}/{spec}: {plan}"
            );
            assert!(plan["blocked"].to_string().contains("local"), "{plan}");
            assert!(f.cache().join(".inputs/local/source.js").exists());
        }
    }
}

#[test]
fn workspace_install_scope_settings_and_hooks_are_blocked() {
    for (name, value) in [
        (".npmrc", "recursive-install=false\n"),
        (
            "pnpm-workspace.yaml",
            "packages: ['packages/*']\nrecursiveInstall: false\n",
        ),
        (
            "pnpm-workspace.yaml",
            "packages: ['packages/*']\nunknownSetting: true\n",
        ),
        ("bunfig.toml", "[install]\nproduction = true\n"),
        (".pnpmfile.cjs", "throw Error('must never execute');"),
    ] {
        let f = Fixture::workspace("pnpm");
        fs::write(f.project.join(name), value).unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(
            plan["targets"].as_array().unwrap().is_empty(),
            "{name}: {plan}"
        );
        assert!(f.cache().exists());
    }
}

#[test]
fn workspace_discovery_includes_scanner_excluded_member_names() {
    for prefix in ["", "packages/"] {
        for name in ["build", "dist", "target"] {
            let f = Fixture::workspace("npm");
            if prefix.is_empty() {
                fs::write(
                    f.project.join("package.json"),
                    r#"{"name":"fixture","workspaces":["packages/*","*"]}"#,
                )
                .unwrap();
                age(&f.project);
            }
            let (path, original) = f.plan();
            assert_eq!(
                original["targets"].as_array().unwrap().len(),
                2,
                "{original}"
            );
            let member = format!("{prefix}{name}");
            fs::create_dir_all(f.project.join(&member).join("node_modules")).unwrap();
            let m = serde_json::json!({"name":format!("member-{name}"),"version":"1.0.0"});
            fs::write(f.project.join(&member).join("package.json"), m.to_string()).unwrap();
            age(&f.project);
            assert!(!f.apply(&path).status.success());
            let out = cli(&["plan", f.project.to_str().unwrap()]);
            let stale: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert!(
                stale["targets"].as_array().unwrap().is_empty(),
                "{member}: {stale}"
            );
            assert!(stale["blocked"]
                .to_string()
                .contains("lockfile members differ"));
            let lock_path = f.project.join("package-lock.json");
            let mut lock: Value = serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
            lock["packages"][&member] = m;
            fs::write(lock_path, lock.to_string()).unwrap();
            age(&f.project);
            let out = cli(&["plan", f.project.to_str().unwrap()]);
            let fresh: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert!(!fresh["targets"].as_array().unwrap().is_empty(), "{fresh}");
            for target in fresh["targets"].as_array().unwrap() {
                let recovery = &target["recovery"];
                assert_eq!(recovery["workspace"]["member_count"], 2);
                assert!(recovery["workspace"]["affected_installations"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!(format!("{member}/node_modules"))));
                assert!(recovery["evidence"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|e| e["path"] == format!("{member}/package.json")));
            }
            assert!(f.cache().exists());
        }
    }
}

#[test]
fn hidden_workspace_glob_directories_fail_closed() {
    let f = Fixture::workspace("npm");
    fs::create_dir(f.project.join("packages/.hidden")).unwrap();
    fs::write(
        f.project.join("packages/.hidden/package.json"),
        r#"{"name":"hidden"}"#,
    )
    .unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
    assert!(plan["blocked"].to_string().contains("hidden directory"));
}

#[test]
fn pnpm_importer_metadata_is_protected_on_either_side() {
    for member in [".", "packages/web"] {
        for (field, value) in [
            (
                "dependenciesMeta",
                serde_json::json!({"web":{"injected":true}}),
            ),
            ("publishDirectory", serde_json::json!("dist")),
        ] {
            for in_lock in [false, true] {
                let f = Fixture::workspace("pnpm");
                let (path, _) = f.plan();
                if in_lock {
                    let lock_path = f.project.join("pnpm-lock.yaml");
                    let mut lock: Value =
                        serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
                    lock["importers"][member][field] = value.clone();
                    fs::write(lock_path, lock.to_string()).unwrap();
                } else {
                    let m_path = f.project.join(member).join("package.json");
                    let mut m: Value = serde_json::from_slice(&fs::read(&m_path).unwrap()).unwrap();
                    if field == "publishDirectory" {
                        m["publishConfig"] = serde_json::json!({"directory":value});
                    } else {
                        m[field] = value.clone();
                    }
                    fs::write(m_path, m.to_string()).unwrap();
                }
                age(&f.project);
                assert!(!f.apply(&path).status.success());
                let out = cli(&["plan", f.project.to_str().unwrap()]);
                let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
                assert!(
                    plan["targets"].as_array().unwrap().is_empty(),
                    "{member}/{field}/{in_lock}: {plan}"
                );
                assert!(plan["blocked"]
                    .to_string()
                    .contains("pnpm importer metadata"));
                assert!(f.cache().exists());
            }
        }
    }
}

#[test]
fn pnpm_workspace_recipe_overrides_external_recursive_install_setting() {
    let f = Fixture::workspace("pnpm");
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .args(["plan", f.project.to_str().unwrap()])
        .env("npm_config_recursive_install", "false")
        .output()
        .unwrap();
    assert!(out.status.success());
    let mut plan: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
    for target in plan["targets"].as_array().unwrap() {
        assert_eq!(
            target["recovery"]["command"],
            serde_json::json!([
                "pnpm",
                "install",
                "--frozen-lockfile",
                "--config.recursive-install=true",
                "--filter=./**"
            ])
        );
        assert!(target["recovery"]["limitations"]
            .as_str()
            .unwrap()
            .contains("environment are not captured"));
    }
    plan["targets"][0]["recovery"]["command"]
        .as_array_mut()
        .unwrap()
        .pop();
    let path = f.root.join("edited-plan.json");
    fs::write(&path, plan.to_string()).unwrap();
    assert!(!f.apply(&path).status.success());
    assert!(f.cache().exists());
}

#[test]
fn unnamed_pnpm_members_get_path_based_restore_selection() {
    let f = pnpm_link_fixture();
    fs::write(f.project.join("package.json"), r#"{"private":true}"#).unwrap();
    fs::write(
        f.project.join("packages/web/package.json"),
        r#"{"private":true,"dependencies":{"lib":"workspace:*"}}"#,
    )
    .unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
    for target in plan["targets"].as_array().unwrap() {
        assert!(target["recovery"]["command"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("--filter=./**")));
        assert!(target["recovery"]["workspace"]["affected_installations"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("packages/web/node_modules")));
    }
}

#[test]
fn caches_containing_workspace_members_preserve_manifest_and_source() {
    for cache in [
        "__pycache__",
        ".pytest_cache",
        ".next/cache",
        ".turbo/cache",
    ] {
        let f = Fixture::workspace("npm");
        let member = format!("{cache}/lib");
        fs::create_dir_all(f.project.join(cache)).unwrap();
        fs::rename(f.project.join("packages/web"), f.project.join(&member)).unwrap();
        fs::write(
            f.project.join(&member).join("index.js"),
            "module.exports=42;",
        )
        .unwrap();
        fs::write(
            f.project.join(".gitignore"),
            "node_modules/\n__pycache__/\n.pytest_cache/\n.next/\n.turbo/\n",
        )
        .unwrap();
        fs::write(
            f.project.join("package.json"),
            serde_json::json!({"name":"fixture","workspaces":[member]}).to_string(),
        )
        .unwrap();
        let mut lock = serde_json::json!({"lockfileVersion":3,"packages":{"":{"name":"fixture"}}});
        lock["packages"][&member] = serde_json::json!({"name":"web"});
        fs::write(f.project.join("package-lock.json"), lock.to_string()).unwrap();
        f.git(&["add", "-A"]);
        f.git(&["commit", "-qm", "member inside cache"]);
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(
            plan["targets"].as_array().unwrap().is_empty(),
            "{cache}: {plan}"
        );
        assert!(plan["blocked"]
            .to_string()
            .contains("Cache contains dependency manifests"));
        assert!(!f.clean(cache).status.success());
        assert!(!f.clean("node_modules").status.success());
        assert!(f.project.join(&member).join("package.json").exists());
        assert_eq!(
            fs::read_to_string(f.project.join(&member).join("index.js")).unwrap(),
            "module.exports=42;"
        );
        let scan = f.scan();
        assert!(scan["projects"][0]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["path"] == f.project.join(cache).to_str().unwrap())
            .unwrap()["blockers"]
            .to_string()
            .contains("recovery inputs"));
    }
}

#[test]
fn adding_recovery_inputs_to_cache_invalidates_the_whole_batch() {
    for name in [
        "package.json",
        "PACKAGE.JSON",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
    ] {
        let f = Fixture::new();
        fs::write(
            f.project.join(".gitignore"),
            "node_modules/\n__pycache__/\n",
        )
        .unwrap();
        let cache = f.project.join("__pycache__");
        fs::create_dir(&cache).unwrap();
        fs::write(cache.join("generated"), "cache").unwrap();
        age(&f.project);
        let (path, plan) = f.plan();
        assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
        fs::write(cache.join(name), "UNIQUE_INPUT").unwrap();
        age(&f.project);
        assert!(!f.apply(&path).status.success());
        assert!(f.cache().exists());
        assert!(!f.clean("__pycache__").status.success());
        assert_eq!(
            fs::read_to_string(cache.join(name)).unwrap(),
            "UNIQUE_INPUT"
        );
    }
}

#[test]
fn pnpm_case_aliases_cannot_hide_disposable_intermediaries() {
    for link in [
        "link:../../__PYCACHE__/../packages/lib",
        "link:../../NODE_MODULES/../packages/lib",
        "link:../../.NeXt/CACHE/../../packages/lib",
    ] {
        let f = pnpm_link_fixture();
        fs::create_dir(f.project.join("__pycache__")).unwrap();
        fs::create_dir_all(f.project.join(".next/cache")).unwrap();
        let lock_path = f.project.join("pnpm-lock.yaml");
        let mut lock: Value = serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        lock["importers"]["packages/web"]["dependencies"]["lib"]["version"] = link.into();
        fs::write(lock_path, lock.to_string()).unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(
            !plan["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["path"].as_str().unwrap().ends_with("node_modules")),
            "{link}: {plan}"
        );
        let reasons = plan["blocked"].to_string();
        let expected = if link.contains(".NeXt") {
            if f.project.join(".NeXt").exists() {
                "non-canonical directory spelling"
            } else {
                "Workspace link cannot be recovered"
            }
        } else {
            "disposable installation or cache"
        };
        assert!(reasons.contains(expected), "{link}: {plan}");
        assert!(!f.clean("node_modules").status.success());
        assert!(f.cache().exists());
    }
}

#[test]
fn pnpm_transitive_link_inputs_block_cleanup() {
    for location in ["dependencies", "optionalDependencies", "nestedMetadata"] {
        let f = Fixture::workspace("pnpm");
        let (path, _) = f.plan();
        let lock_path = f.project.join("pnpm-lock.yaml");
        let mut lock: Value = serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        lock["snapshots"] = serde_json::json!({"remote@1.0.0":{location:{"local":"link:node_modules/.inputs/local"}}});
        fs::write(lock_path, lock.to_string()).unwrap();
        fs::create_dir_all(f.cache().join(".inputs/local")).unwrap();
        fs::write(
            f.cache().join(".inputs/local/source.js"),
            "unique local input",
        )
        .unwrap();
        age(&f.project);
        assert!(!f.apply(&path).status.success());
        let out = cli(&["plan", f.project.to_str().unwrap()]);
        let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(
            plan["targets"].as_array().unwrap().is_empty(),
            "{location}: {plan}"
        );
        assert!(plan["blocked"]
            .to_string()
            .contains("local dependency inputs"));
        assert!(!f.clean("node_modules").status.success());
        assert_eq!(
            fs::read_to_string(f.cache().join(".inputs/local/source.js")).unwrap(),
            "unique local input"
        );
    }
}

fn pnpm_link_fixture() -> Fixture {
    let f = Fixture::workspace("pnpm");
    fs::create_dir(f.project.join("packages/lib")).unwrap();
    fs::write(
        f.project.join("packages/lib/package.json"),
        r#"{"name":"lib"}"#,
    )
    .unwrap();
    fs::write(
        f.project.join("packages/lib/index.js"),
        "module.exports=42;",
    )
    .unwrap();
    fs::write(
        f.project.join("packages/web/package.json"),
        r#"{"name":"web","dependencies":{"lib":"workspace:*"}}"#,
    )
    .unwrap();
    let lock_path = f.project.join("pnpm-lock.yaml");
    let mut lock: Value = serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["importers"]["packages/lib"] = serde_json::json!({});
    lock["importers"]["packages/web"]["dependencies"] =
        serde_json::json!({"lib":{"specifier":"workspace:*","version":"link:../lib"}});
    fs::write(lock_path, lock.to_string()).unwrap();
    f.git(&["add", "-A"]);
    f.git(&["commit", "-qm", "workspace link"]);
    age(&f.project);
    f
}

#[test]
fn pnpm_generated_peer_lock_supports_recovery() {
    let f = pnpm_link_fixture();
    fs::write(
        f.project.join("packages/web/package.json"),
        r#"{"name":"web","peerDependencies":{"lib":"workspace:^"}}"#,
    )
    .unwrap();
    // pnpm 9.14.2 generates an ordinary dependency for this auto-installed peer.
    fs::write(
        f.project.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .: {}\n\n  packages/lib: {}\n\n  packages/web:\n    dependencies:\n      lib:\n        specifier: workspace:^\n        version: link:../lib\n",
    )
    .unwrap();
    age(&f.project);
    let (path, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
    let output = f.apply(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(f.project.join("packages/lib/index.js").exists());
    assert!(!f.project.join("packages/web/node_modules").exists());
}

#[test]
fn pnpm_peer_normalization_retains_ordinary_group_precedence_and_drift_checks() {
    for groups in [
        vec!["devDependencies"],
        vec!["dependencies"],
        vec!["optionalDependencies"],
        vec!["devDependencies", "dependencies", "optionalDependencies"],
    ] {
        let f = pnpm_link_fixture();
        let mut manifest =
            serde_json::json!({"name":"web","peerDependencies":{"lib":"workspace:^"}});
        for group in &groups {
            manifest[group] = serde_json::json!({"lib":"workspace:*"});
        }
        fs::write(
            f.project.join("packages/web/package.json"),
            manifest.to_string(),
        )
        .unwrap();
        let lock_path = f.project.join("pnpm-lock.yaml");
        let mut lock: Value = serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        let group = *groups.last().unwrap();
        lock["importers"]["packages/web"] =
            serde_json::json!({group: {"lib":{"specifier":"workspace:*","version":"link:../lib"}}});
        fs::write(&lock_path, lock.to_string()).unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");

        lock["importers"]["packages/web"][group]["lib"]["specifier"] =
            serde_json::json!("workspace:^");
        fs::write(&lock_path, lock.to_string()).unwrap();
        age(&f.project);
        fs::remove_file(f.root.join("plan.json")).unwrap();
        let (_, plan) = f.plan();
        assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
        assert!(plan["blocked"]
            .to_string()
            .contains("manifest and lockfile dependencies differ"));
    }
}

#[test]
fn pnpm_overridden_local_peers_still_block_cleanup() {
    for group in ["dependencies", "devDependencies", "optionalDependencies"] {
        let f = pnpm_link_fixture();
        let manifest = serde_json::json!({"name":"web", "peerDependencies":{"lib":"file:../../node_modules/.inputs/lib"}, group:{"lib":"workspace:*"}});
        fs::write(
            f.project.join("packages/web/package.json"),
            manifest.to_string(),
        )
        .unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
        assert!(plan["blocked"]
            .to_string()
            .contains("local or patched dependencies"));
        assert!(f.cache().exists());
    }
}

#[test]
fn pnpm_importer_links_cannot_traverse_disposable_paths_or_symlinks() {
    for (link, reason) in [
        (
            "link:../../node_modules/lib",
            "disposable installation or cache",
        ),
        (
            "link:../../node_modules/../packages/lib",
            "disposable installation or cache",
        ),
        (
            "link:../../.next/cache/../../packages/lib",
            "disposable installation or cache",
        ),
        ("link:../../shortcut", "symlink or non-directory"),
        (
            "link:../../../project/packages/lib",
            "escapes its workspace root",
        ),
    ] {
        let f = pnpm_link_fixture();
        let (path, initial) = f.plan();
        assert_eq!(initial["targets"].as_array().unwrap().len(), 2, "{initial}");
        symlink("../packages/lib", f.cache().join("lib")).unwrap();
        symlink("packages/lib", f.project.join("shortcut")).unwrap();
        fs::create_dir_all(f.project.join(".next/cache")).unwrap();
        let lock_path = f.project.join("pnpm-lock.yaml");
        let mut lock: Value = serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        lock["importers"]["packages/web"]["dependencies"]["lib"]["version"] = link.into();
        fs::write(lock_path, lock.to_string()).unwrap();
        age(&f.project);
        for p in [f.cache().join("lib"), f.project.join("shortcut")] {
            assert!(Command::new("touch")
                .args(["-h", "-t", "202001010000"])
                .arg(p)
                .status()
                .unwrap()
                .success());
        }
        assert!(!f.apply(&path).status.success());
        let out = cli(&["plan", f.project.to_str().unwrap()]);
        let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(
            !plan["targets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["path"].as_str().unwrap().ends_with("node_modules")),
            "{link}: {plan}"
        );
        assert!(
            plan["blocked"].to_string().contains(reason),
            "{link}: {plan}"
        );
        assert!(!f.clean("node_modules").status.success());
        assert!(f.cache().join("lib/index.js").exists());
    }
}

#[test]
fn validated_importer_link_does_not_exempt_other_local_inputs() {
    let f = pnpm_link_fixture();
    let lock_path = f.project.join("pnpm-lock.yaml");
    let mut lock: Value = serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["importers"]["packages/web"]["dependencies"]["lib"]["extra"] =
        "link:../../node_modules/local".into();
    fs::write(lock_path, lock.to_string()).unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
    assert!(plan["blocked"]
        .to_string()
        .contains("local dependency inputs"));
}

#[test]
fn pnpm_incompatible_lock_settings_and_resolution_metadata_block_recovery() {
    for change in [
        "autoInstallPeers",
        "excludeLinksFromLockfile",
        "unknownSetting",
        "missingSettings",
        "lockfileVersion",
        "overrides",
        "patchedDependencies",
        "packageExtensionsChecksum",
        "pnpmfileChecksum",
        "ignoredOptionalDependencies",
        "catalogs",
    ] {
        let f = Fixture::workspace("pnpm");
        let (plan_path, original) = f.plan();
        assert_eq!(original["targets"].as_array().unwrap().len(), 2);
        let lock_path = f.project.join("pnpm-lock.yaml");
        let mut lock: Value = serde_yaml_ng::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        match change {
            "autoInstallPeers" => lock["settings"][change] = false.into(),
            "excludeLinksFromLockfile" | "unknownSetting" => {
                lock["settings"][change] = true.into();
            }
            "missingSettings" => {
                lock.as_object_mut().unwrap().remove("settings");
            }
            "lockfileVersion" => lock[change] = "6.0".into(),
            _ => lock[change] = serde_json::json!({"stale":"metadata"}),
        }
        fs::write(lock_path, lock.to_string()).unwrap();
        age(&f.project);
        assert!(!f.apply(&plan_path).status.success(), "{change}");
        let out = cli(&["plan", f.project.to_str().unwrap()]);
        assert!(out.status.success());
        let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(
            plan["targets"].as_array().unwrap().is_empty(),
            "{change}: {plan}"
        );
        assert!(
            plan["blocked"].to_string().contains("pnpm lockfile"),
            "{plan}"
        );
        assert!(f.cache().join("generated").exists());
    }
}

#[test]
fn npm_omitted_member_names_allow_inference_but_not_renames() {
    for (member, name, pattern) in [
        ("packages/web", "web", "packages/*"),
        ("packages/@scope/web", "@scope/web", "packages/@scope/*"),
    ] {
        let f = Fixture::workspace("npm");
        if member != "packages/web" {
            fs::create_dir(f.project.join("packages/@scope")).unwrap();
            fs::rename(f.project.join("packages/web"), f.project.join(member)).unwrap();
        }
        fs::write(
            f.project.join("package.json"),
            serde_json::json!({"name":"fixture","workspaces":[pattern]}).to_string(),
        )
        .unwrap();
        let manifest_path = f.project.join(member).join("package.json");
        fs::write(&manifest_path, serde_json::json!({"name":name}).to_string()).unwrap();
        let mut lock = serde_json::json!({"lockfileVersion":3,"packages":{"":{"name":"fixture"}}});
        lock["packages"][member] = serde_json::json!({});
        fs::write(f.project.join("package-lock.json"), lock.to_string()).unwrap();
        f.git(&["add", "-A"]);
        f.git(&["commit", "-qm", "inferred names"]);
        age(&f.project);
        let (plan_path, plan) = f.plan();
        assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
        fs::write(manifest_path, r#"{"name":"renamed"}"#).unwrap();
        age(&f.project);
        assert!(!f.apply(&plan_path).status.success());
        let out = cli(&["plan", f.project.to_str().unwrap()]);
        let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
        assert!(plan["blocked"]
            .to_string()
            .contains("metadata and lockfile differ"));
        assert!(f.cache().exists());
    }
}

#[test]
fn workspace_registry_file_inputs_block_deletion_without_disclosure() {
    for key in [
        "cafile",
        "//registry.invalid/:certfile",
        "//registry.invalid/:keyfile",
    ] {
        let f = Fixture::workspace("npm");
        fs::write(
            f.project.join(".npmrc"),
            format!("{key}=node_modules/PRIVATE_INPUT.crt\n"),
        )
        .unwrap();
        fs::write(f.cache().join("PRIVATE_INPUT.crt"), "UNIQUE_CERTIFICATE").unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
        assert!(plan["blocked"]
            .to_string()
            .contains("Unsupported workspace install configuration"));
        assert!(!plan.to_string().contains("PRIVATE_INPUT"));
        assert!(!plan.to_string().contains("UNIQUE_CERTIFICATE"));
        assert!(!f.clean("node_modules").status.success());
        assert!(f.cache().join("PRIVATE_INPUT.crt").exists());
    }
}

#[test]
fn failed_host_lookup_preserves_scan_results_but_blocks_plans() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let bin = f.root.join("bin");
    fs::create_dir(&bin).unwrap();
    let hostname = bin.join("hostname");
    for script in ["#!/bin/sh\nexit 1\n", "#!/bin/sh\nprintf '\\n'\n"] {
        fs::write(&hostname, script).unwrap();
        fs::set_permissions(&hostname, fs::Permissions::from_mode(0o700)).unwrap();
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
        let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
            .args(["scan", f.project.to_str().unwrap(), "--json"])
            .env("PATH", &path)
            .output()
            .unwrap();
        assert!(!out.status.success());
        let scan: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(scan["complete"], false);
        assert!(scan["host"].is_null());
        assert_eq!(scan["projects"].as_array().unwrap().len(), 1);
        assert_eq!(scan["errors"][0]["scope"], "host");
        let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
            .args(["plan", f.project.to_str().unwrap()])
            .env("PATH", &path)
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(f.cache().exists());
    }
}

#[test]
fn workspace_registry_credentials_are_hashed_without_disclosure() {
    let f = Fixture::workspace("pnpm");
    fs::write(f.project.join(".npmrc"), "registry=https://registry.invalid/\n@scope:registry=https://registry.invalid/\n//registry.invalid/:_authToken=DO_NOT_DISCLOSE\n").unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2, "{plan}");
    assert!(!plan.to_string().contains("DO_NOT_DISCLOSE"));
    assert!(plan["targets"][0]["recovery"]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["path"] == ".npmrc"));
}

#[test]
fn workspace_bun_identity_changes_block_stale_lock_recovery() {
    for change in ["name", "version"] {
        let f = Fixture::workspace("bun");
        let mut m = serde_json::json!({"name":"web"});
        m[change] = serde_json::json!(if change == "name" { "renamed" } else { "2.0.0" });
        fs::write(f.project.join("packages/web/package.json"), m.to_string()).unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
        assert!(plan["blocked"]
            .to_string()
            .contains("metadata and lockfile differ"));
    }
}

#[test]
fn workspace_lockfile_local_sources_are_protected_even_for_registry_specs() {
    for source in [
        "file:node_modules/.inputs/pkg.tgz",
        "node_modules/.inputs/pkg.tgz",
        "git+file:///tmp/local",
    ] {
        let f = Fixture::workspace("npm");
        let lock_path = f.project.join("package-lock.json");
        let mut lock: Value = serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        lock["packages"]["node_modules/example"] =
            serde_json::json!({"version":"1.0.0","resolved":source});
        fs::write(lock_path, lock.to_string()).unwrap();
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(
            plan["targets"].as_array().unwrap().is_empty(),
            "{source}: {plan}"
        );
        assert!(plan["blocked"].to_string().contains("dependency"));
        assert!(f.cache().exists());
    }
}

#[test]
fn npm_workspace_recipe_discloses_replacement_scope_and_unselected_installs() {
    let f = Fixture::workspace("npm");
    let (_, plan) = f.plan();
    for target in plan["targets"].as_array().unwrap() {
        let precondition = target["recovery"]["workspace_selection_precondition"]
            .as_str()
            .unwrap();
        assert!(precondition.contains("npm_config_workspace"));
        assert!(precondition.contains("workspace= selections from user/global"));
        assert!(precondition.contains("skipping workspace members"));
        let scope = &target["recovery"]["workspace"];
        assert_eq!(
            scope["affected_installations"],
            serde_json::json!(["node_modules", "packages/web/node_modules"])
        );
        assert_eq!(scope["requires_separate_recovery_review"], true);
        assert!(scope["recovery_scope"]
            .as_str()
            .unwrap()
            .contains("removes and replaces"));
        assert!(scope["recovery_scope"]
            .as_str()
            .unwrap()
            .contains("protected"));
    }
}

#[test]
fn non_utf8_missing_file_examples_do_not_abort_scan_or_plan() {
    use std::os::unix::ffi::OsStringExt;
    let f = Fixture::new();
    let name = std::ffi::OsString::from_vec(b"bad\xff.txt".to_vec());
    // APFS cannot create this filename, but a cloned Git index can contain it.
    let blob = Command::new("git")
        .arg("-C")
        .arg(&f.project)
        .args(["rev-parse", "HEAD:source.txt"])
        .output()
        .unwrap();
    assert!(blob.status.success());
    let out = Command::new("git")
        .arg("-C")
        .arg(&f.project)
        .args(["update-index", "--add", "--cacheinfo", "100644"])
        .arg(String::from_utf8(blob.stdout).unwrap().trim())
        .arg(name)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    f.git(&["commit", "-qm", "non unicode filename"]);
    age(&f.project);
    let scan = f.scan();
    assert_eq!(scan["projects"][0]["missing_tracked_files"]["count"], 1);
    let (_, plan) = f.plan();
    assert_eq!(plan["context"]["missing_tracked_files"]["count"], 1);
    assert!(plan["targets"].as_array().unwrap().is_empty());
}

#[test]
fn parking_preserves_dirty_source_env_database_and_permissions() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let f = Fixture::new();
    fs::write(f.project.join("source.txt"), "unfinished source").unwrap();
    fs::write(f.project.join(".env.local"), "DO_NOT_LEAK_SUPER_SECRET=123").unwrap();
    fs::write(f.project.join("local.sqlite"), "unique database").unwrap();
    fs::write(f.project.join("untracked-notes.txt"), "unique notes").unwrap();
    fs::set_permissions(
        f.project.join(".env.local"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    age(&f.project);
    let (path, plan) = f.plan();
    assert_eq!(plan["git"]["dirty"], true);
    assert_eq!(plan["targets"].as_array().unwrap().len(), 1);
    let raw = fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("DO_NOT_LEAK"));
    assert!(f.cache().exists());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    let out = f.apply(&path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(!f.cache().exists());
    assert_eq!(
        fs::read_to_string(f.project.join("source.txt")).unwrap(),
        "unfinished source"
    );
    assert_eq!(
        fs::read_to_string(f.project.join(".env.local")).unwrap(),
        "DO_NOT_LEAK_SUPER_SECRET=123"
    );
    assert_eq!(
        fs::metadata(f.project.join(".env.local")).unwrap().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::read_to_string(f.project.join("local.sqlite")).unwrap(),
        "unique database"
    );
    assert!(f.project.join("untracked-notes.txt").exists());
    let receipt = fs::read_to_string(result["receipt"].as_str().unwrap()).unwrap();
    assert!(!receipt.contains("DO_NOT_LEAK"));
    let events: Vec<Value> = receipt
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        events
            .iter()
            .map(|v| v["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["started", "deleting", "removed", "completed"]
    );
    assert_eq!(
        events[0]["targets"][0]["recovery"]["command"],
        serde_json::json!(["npm", "ci"])
    );
}

#[test]
fn sensitive_files_inside_generated_target_block_deletion() {
    let f = Fixture::new();
    fs::write(f.cache().join(".env"), "password=unique").unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 0);
    assert!(plan["blocked"].to_string().contains("secret-like"));
    f.blocked("secret-like");
}

#[test]
fn apply_refuses_changed_cache_even_if_mtime_is_old() {
    let f = Fixture::new();
    let (path, _) = f.plan();
    fs::write(f.cache().join("generated"), "new data").unwrap();
    age(&f.project);
    let out = f.apply(&path);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("changed"));
    assert!(f.cache().exists());
}

#[test]
fn apply_refuses_changed_lockfile_and_new_source_work() {
    let f = Fixture::new();
    let (path, _) = f.plan();
    fs::write(f.project.join("package-lock.json"), "{\"changed\":true}").unwrap();
    age(&f.project);
    assert!(!f.apply(&path).status.success());
    assert!(f.cache().exists());
}

#[test]
fn apply_rejects_tampered_path_limits_and_expiry() {
    let f = Fixture::new();
    let (path, original) = f.plan();
    let mut cases = Vec::new();
    let mut p = original.clone();
    p["targets"][0]["path"] = "../outside/node_modules".into();
    cases.push(p);
    let mut p = original.clone();
    p["targets"][0]["bytes"] = (11u64 * 1024 * 1024 * 1024).into();
    cases.push(p);
    let mut p = original.clone();
    p["created_at"] = 1.into();
    cases.push(p);
    let mut p = original.clone();
    p["targets"]
        .as_array_mut()
        .unwrap()
        .push(original["targets"][0].clone());
    cases.push(p);
    let mut p = original.clone();
    p["targets"][0]["fingerprint"] = "tampered".into();
    cases.push(p);
    for plan in cases {
        fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
        assert!(!f.apply(&path).status.success());
        assert!(f.cache().exists());
    }
}

#[test]
fn apply_refuses_symlink_swap_and_preserves_external_data() {
    let f = Fixture::new();
    let (path, _) = f.plan();
    let original = f.root.join("original-cache");
    fs::rename(f.cache(), &original).unwrap();
    symlink(&original, f.cache()).unwrap();
    assert!(!f.apply(&path).status.success());
    assert!(original.join("generated").exists());
}

#[test]
fn apply_requires_confirmation_and_a_writable_private_receipt_directory() {
    let f = Fixture::new();
    let (path, _) = f.plan();
    assert!(!cli(&["apply", path.to_str().unwrap()]).status.success());
    let invalid = f.root.join("not-a-directory");
    fs::write(&invalid, "keep").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .args(["apply", path.to_str().unwrap(), "--yes"])
        .env("KEEPER_STATE_DIR", &invalid)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(f.cache().exists());
    let inside = f.project.join("state");
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .args(["apply", path.to_str().unwrap(), "--yes"])
        .env("KEEPER_STATE_DIR", &inside)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!inside.exists());
    assert!(f.cache().exists());
}

#[test]
fn plan_never_overwrites_existing_output_or_writes_inside_project() {
    let f = Fixture::new();
    let (path, _) = f.plan();
    fs::write(&path, "keep existing").unwrap();
    assert!(!cli(&[
        "plan",
        f.project.to_str().unwrap(),
        "--output",
        path.to_str().unwrap()
    ])
    .status
    .success());
    assert_eq!(fs::read_to_string(path).unwrap(), "keep existing");
    let inside = f.project.join("plan.json");
    assert!(!cli(&[
        "plan",
        f.project.to_str().unwrap(),
        "--output",
        inside.to_str().unwrap()
    ])
    .status
    .success());
    assert!(!inside.exists());
}

#[test]
fn batch_preflight_leaves_first_target_if_second_has_changed() {
    let f = Fixture::new();
    let second = f.nested_cache();
    age(&f.project);
    let (path, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2);
    fs::write(second.join("new"), "new").unwrap();
    age(&f.project);
    assert!(!f.apply(&path).status.success());
    assert!(f.cache().exists());
    assert!(second.exists());
}

#[test]
fn multiple_targets_are_removed_with_one_receipt() {
    let f = Fixture::new();
    let second = f.nested_cache();
    age(&f.project);
    let (path, plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2);
    let out = f.apply(&path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!f.cache().exists());
    assert!(!second.exists());
}

#[test]
fn ancestor_lockfiles_do_not_authorize_nested_installations() {
    for has_manifest in [false, true] {
        let f = Fixture::new();
        let cache = f.nested_cache();
        fs::remove_file(cache.parent().unwrap().join("package-lock.json")).unwrap();
        if !has_manifest {
            fs::remove_file(cache.parent().unwrap().join("package.json")).unwrap();
        }
        age(&f.project);
        let (_, plan) = f.plan();
        assert!(plan["blocked"]
            .to_string()
            .contains("workspace recovery is not verified"));
        assert!(!f.clean("packages/web/node_modules").status.success());
        assert!(cache.exists());
    }
}

#[test]
fn arbitrary_package_manager_values_are_not_disclosed() {
    let f = Fixture::new();
    fs::write(
        f.project.join("package.json"),
        r#"{"packageManager":"yarn@https://user:SECRET_VALUE@example.invalid/tool"}"#,
    )
    .unwrap();
    age(&f.project);
    let (path, plan) = f.plan();
    assert!(plan["targets"].as_array().unwrap().is_empty());
    assert!(!fs::read_to_string(path).unwrap().contains("SECRET_VALUE"));
    assert!(plan["blocked"].to_string().contains("package-manager hint"));
}

#[test]
fn corepack_integrity_and_prerelease_versions_are_supported() {
    for (manager, lock, flag) in [
        (
            "pnpm@9.15.0+sha512.76e2379760a4",
            "pnpm-lock.yaml",
            "--frozen-lockfile",
        ),
        ("yarn@4.0.0-rc.53", "yarn.lock", "--immutable"),
        (
            "yarn@1.22.22+sha512.abcdef012345",
            "yarn.lock",
            "--frozen-lockfile",
        ),
    ] {
        let f = Fixture::new();
        fs::remove_file(f.project.join("package-lock.json")).unwrap();
        fs::write(f.project.join(lock), "fixture lock").unwrap();
        fs::write(
            f.project.join("package.json"),
            serde_json::json!({"packageManager": manager}).to_string(),
        )
        .unwrap();
        f.git(&["add", "-A"]);
        f.git(&["commit", "-qm", "package manager fixture"]);
        age(&f.project);
        let (_, plan) = f.plan();
        assert_eq!(plan["targets"].as_array().unwrap().len(), 1, "{plan}");
        assert_eq!(plan["targets"][0]["recovery"]["package_manager"], manager);
        assert_eq!(plan["targets"][0]["recovery"]["command"][2], flag);
    }
}

#[test]
fn incomplete_workspace_lock_still_blocks_installations() {
    let f = Fixture::new();
    let nested = f.nested_cache();
    fs::write(
        f.project.join("package.json"),
        r#"{"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    age(&f.project);
    let (_, plan) = f.plan();
    assert!(plan["targets"].as_array().unwrap().is_empty(), "{plan}");
    assert!(plan["blocked"]
        .to_string()
        .contains("Workspace lockfile has no member inventory"));
    assert!(nested.exists());
}

#[test]
fn workspace_added_outside_git_root_after_plan_prevents_deletion() {
    let f = Fixture::new();
    let (path, _) = f.plan();
    fs::write(f.root.join("package.json"), r#"{"workspaces":["project"]}"#).unwrap();
    let out = f.apply(&path);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Workspace recovery is not verified"));
    assert!(f.cache().exists());
}

#[test]
fn ignored_shrinkwrap_ambiguity_and_changes_prevent_deletion() {
    let f = Fixture::new();
    fs::write(
        f.project.join(".gitignore"),
        "node_modules/\nnpm-shrinkwrap.json\n",
    )
    .unwrap();
    age(&f.project);
    let (path, _) = f.plan();
    for value in ["{}", "corrupted shrinkwrap"] {
        fs::write(f.project.join("npm-shrinkwrap.json"), value).unwrap();
        let out = f.apply(&path);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("shrinkwrap overrides"));
        assert!(f.cache().exists());
        let fresh = cli(&["plan", f.project.to_str().unwrap()]);
        assert!(fresh.status.success());
        let proposal: Value = serde_json::from_slice(&fresh.stdout).unwrap();
        assert!(proposal["targets"].as_array().unwrap().is_empty());
        assert!(proposal["blocked"]
            .to_string()
            .contains("shrinkwrap overrides"));
    }
}

#[test]
fn berry_lockfile_uses_immutable_install_and_root_cwd() {
    let f = Fixture::new();
    fs::remove_file(f.project.join("package-lock.json")).unwrap();
    fs::write(f.project.join("yarn.lock"), "__metadata:\n  version: 8\n").unwrap();
    f.git(&["add", "-A"]);
    f.git(&["commit", "-qm", "switch fixture to Yarn"]);
    age(&f.project);
    let (_, plan) = f.plan();
    assert_eq!(
        plan["targets"][0]["recovery"]["command"],
        serde_json::json!(["yarn", "install", "--immutable"])
    );
    assert_eq!(plan["targets"][0]["recovery"]["cwd"], ".");
}

#[test]
fn node_is_never_executed_and_environment_drift_does_not_invalidate_plan() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let (path, _) = f.plan();
    let bin = f.root.join("bin");
    fs::create_dir(&bin).unwrap();
    let marker = f.root.join("node-executed");
    fs::write(
        bin.join("node"),
        format!("#!/bin/sh\ntouch '{}'\necho v999.0.0\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(bin.join("node"), fs::Permissions::from_mode(0o700)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .args(["apply", path.to_str().unwrap(), "--yes"])
        .env("KEEPER_STATE_DIR", f.root.join("keeper-state"))
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!marker.exists());
}

#[test]
fn inspection_child_does_not_block_keeper_running_inside_project() {
    let f = Fixture::new();
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .current_dir(&f.project)
        .args(["plan", "."])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 1, "{plan}");
}

#[test]
fn shared_hardlinks_stop_before_touching_second_target_and_allow_fresh_plan() {
    let f = Fixture::new();
    let second = f.nested_cache();
    fs::remove_file(second.join("generated")).unwrap();
    fs::hard_link(f.cache().join("generated"), second.join("generated")).unwrap();
    age(&f.project);
    let (path, mut plan) = f.plan();
    assert_eq!(plan["targets"].as_array().unwrap().len(), 2);
    plan["targets"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|t| t["path"].as_str().unwrap().to_owned());
    fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let out = f.apply(&path);
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        error.contains("1 completed deletions") && error.contains("target was not touched"),
        "{error}"
    );
    assert!(!f.cache().exists());
    assert_eq!(
        fs::read_to_string(second.join("generated")).unwrap(),
        "cache"
    );
    let receipt = fs::read_dir(f.root.join("keeper-state"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .unwrap();
    let events: Vec<Value> = fs::read_to_string(receipt)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.last().unwrap()["deletion_started"], false);
    assert_eq!(events.last().unwrap()["removal_completed"], false);
    fs::remove_file(path).unwrap();
    let (fresh_path, fresh) = f.plan();
    assert_eq!(fresh["targets"].as_array().unwrap().len(), 1);
    let out = f.apply(&fresh_path);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!second.exists());
}

#[test]
fn stale_lock_reports_its_path_and_pid() {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let (path, _) = f.plan();
    let state = f.root.join("keeper-state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = state.join(format!(
        "{}.lock",
        Sha256::digest(f.project.to_str().unwrap().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    fs::write(&lock, "pid=123456\n").unwrap();
    let out = f.apply(&path);
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        error.contains(lock.to_str().unwrap()) && error.contains("123456"),
        "{error}"
    );
    assert!(f.cache().exists());
    assert!(lock.exists());
}

#[test]
fn lock_write_failure_leaves_no_stale_lock_or_deletions() {
    let f = Fixture::new();
    let (path, _) = f.plan();
    let out = Command::new("/bin/sh")
        .args([
            "-c",
            "trap '' XFSZ; ulimit -f 0; exec \"$1\" apply \"$2\" --yes",
            "keeper-test",
            env!("CARGO_BIN_EXE_keeper"),
            path.to_str().unwrap(),
        ])
        .env("KEEPER_STATE_DIR", f.root.join("keeper-state"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(f.cache().exists());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(
        error.contains("Could not create/write project lock"),
        "{error}"
    );
    assert!(!error.contains("stale"));
    assert!(fs::read_dir(f.root.join("keeper-state"))
        .unwrap()
        .next()
        .is_none());
    assert!(f.apply(&path).status.success());
}

#[test]
fn mid_batch_failure_records_completed_deletion_and_keeps_local_data() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let second = f.nested_cache();
    let protected = second.join("unwritable");
    fs::create_dir(&protected).unwrap();
    fs::write(protected.join("generated"), "cache").unwrap();
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o500)).unwrap();
    // The plan is reviewable and may be reordered within the same limits.
    age(&f.project);
    let (path, mut plan) = f.plan();
    plan["targets"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|t| t["path"].as_str().unwrap().to_owned());
    fs::write(&path, serde_json::to_vec(&plan).unwrap()).unwrap();
    let out = f.apply(&path);
    fs::set_permissions(&protected, fs::Permissions::from_mode(0o700)).unwrap();
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(
        error.contains("1 completed deletions") && error.contains("Receipt:"),
        "{error}"
    );
    assert!(!f.cache().exists());
    assert!(f.project.join("source.txt").exists());
    let receipt = fs::read_dir(f.root.join("keeper-state"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .unwrap();
    let events: Vec<Value> = fs::read_to_string(receipt)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(
        events
            .iter()
            .map(|e| e["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["started", "deleting", "removed", "deleting", "failed"]
    );
}
