use serde_json::Value;
use std::fs;
#[cfg(not(target_os = "macos"))]
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "keeper-inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn write(&self, path: &str, data: impl AsRef<[u8]>) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }
    fn run(&self, args: &[&str]) -> (Output, Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_keeper"))
            .arg("inventory")
            .arg(&self.0)
            .arg("--json")
            .args(args)
            .output()
            .unwrap();
        let report = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
        (output, report)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn area<'a>(report: &'a Value, suffix: &str) -> &'a Value {
    report["areas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| Path::new(a["path"].as_str().unwrap()).ends_with(suffix))
        .unwrap_or_else(|| panic!("Missing {suffix}: {report}"))
}

#[test]
fn inventory_exposes_large_areas_without_authorizing_cleanup_or_reading_secrets() {
    let f = Fixture::new();
    f.write("project/.git/objects/history", vec![1; 8192]);
    f.write("project/.env", "SUPER_SECRET_VALUE");
    f.write("project/target/output", vec![2; 16384]);
    f.write("project/.venv/pyvenv.cfg", "home=/example");
    f.write("project/.venv/lib/library", vec![3; 8192]);
    f.write("Library/pnpm/store/blob", vec![4; 16384]);
    f.write(".codex/state.db", "UNIQUE_AGENT_CONTENT");
    f.write("Library/Containers/com.docker.docker/volume", vec![5; 8192]);
    let (out, report) = f.run(&[]);
    assert!(out.status.success(), "{report}");
    assert_eq!(report["action"], "inventory");
    assert_eq!(report["read_only"], true);
    assert_eq!(report["limits"]["max_entries"], 5_000_000);
    assert_eq!(report["limits"]["max_areas"], 256);
    assert!(report["review_guidance_by_category"]["agent_state"]
        .as_str()
        .unwrap()
        .contains("Preserve"));
    assert!(report["cleanup_eligible_bytes"].is_null());
    for (path, category) in [
        ("project", "project"),
        ("project/.git", "git_history"),
        ("project/target", "build_output"),
        ("project/.venv", "environment"),
        ("Library/pnpm/store", "package_store"),
        (".codex", "agent_state"),
        ("Library/Containers/com.docker.docker", "application_data"),
    ] {
        let row = area(&report, path);
        assert_eq!(row["category"], category);
        assert_eq!(row["cleanup_approved"], false);
        assert!(row["allocated_bytes"].as_u64().unwrap() > 0);
    }
    assert!(!report.to_string().contains("SUPER_SECRET_VALUE"));
    assert!(!report.to_string().contains("UNIQUE_AGENT_CONTENT"));
    assert_eq!(
        fs::read_to_string(f.0.join("project/.env")).unwrap(),
        "SUPER_SECRET_VALUE"
    );
    assert_eq!(
        fs::read_to_string(f.0.join(".codex/state.db")).unwrap(),
        "UNIQUE_AGENT_CONTENT"
    );
}

#[test]
fn inventory_allocation_matches_du_without_following_symlinks_or_counting_hardlinks_twice() {
    let f = Fixture::new();
    let outside = Fixture::new();
    f.write("a/payload", vec![1; 65536]);
    fs::create_dir(f.0.join("b")).unwrap();
    fs::hard_link(f.0.join("a/payload"), f.0.join("b/shared")).unwrap();
    outside.write("secret", vec![1; 1024 * 1024]);
    symlink(&outside.0, f.0.join("escape")).unwrap();
    let (out, report) = f.run(&[f.0.join("a").to_str().unwrap()]);
    assert!(out.status.success(), "{report}");
    assert_eq!(report["roots"].as_array().unwrap().len(), 1);
    assert_eq!(
        report["overlapping_roots_omitted"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(report["symlinks_not_followed"], 1);
    assert_eq!(
        report["repeated_hardlink_bytes_not_counted"],
        fs::metadata(f.0.join("a/payload")).unwrap().blocks() * 512
    );
    let du = Command::new("du").arg("-sk").arg(&f.0).output().unwrap();
    assert!(du.status.success());
    let blocks: u64 = String::from_utf8(du.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(report["observed_allocated_bytes"], blocks * 1024);
    assert!(!report.to_string().contains(outside.0.to_str().unwrap()));
    let human = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .args([
            "inventory",
            f.0.to_str().unwrap(),
            f.0.join("a").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.contains("Root:"));
    assert!(text.contains("Overlapping root omitted (covered on the same filesystem):"));
    assert!(text.contains(f.0.join("a").to_str().unwrap()));
}

#[test]
fn inventory_budgets_return_partial_data_and_a_failure_status() {
    let f = Fixture::new();
    for n in 0..20 {
        f.write(&format!("dir/{n}"), vec![1; 4096]);
    }
    let (out, report) = f.run(&["--max-entries", "3"]);
    assert!(!out.status.success());
    assert_eq!(report["complete"], false);
    assert_eq!(report["stopped_reason"], "entry limit reached");
    assert!(report["entries_visited"].as_u64().unwrap() <= 3);
    assert_eq!(report["roots"][0]["measurement_complete"], false);
    assert_eq!(report["reference_collection_complete"], false);
}

#[test]
fn inventory_failed_opens_consume_the_entry_budget() {
    let f = Fixture::new();
    for n in 0..30 {
        let path = f.0.join(format!("blocked{n}"));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o0)).unwrap();
    }
    let permission_checks_apply = fs::read_dir(f.0.join("blocked0")).is_err();
    let (out, report) = f.run(&["--max-entries", "2"]);
    for n in 0..30 {
        fs::set_permissions(
            f.0.join(format!("blocked{n}")),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    assert!(!out.status.success());
    assert_eq!(report["complete"], false);
    assert_eq!(report["entries_visited"], 2);
    assert_eq!(report["stopped_reason"], "entry limit reached");
    if permission_checks_apply {
        assert_eq!(report["error_count"], 1);
    }
}

#[test]
fn inventory_missing_roots_consume_the_preparation_budget() {
    let f = Fixture::new();
    let roots: Vec<_> = (0..30).map(|n| f.0.join(format!("missing{n}"))).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .arg("inventory")
        .args(&roots)
        .args(["--max-entries", "2", "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["entries_visited"], 2);
    assert_eq!(report["error_count"], 2);
    assert_eq!(report["roots_not_prepared"], 28);
    assert_eq!(report["stopped_reason"], "entry limit reached");
}

#[test]
#[cfg(target_os = "macos")]
fn inventory_firmlink_aliases_and_overlapping_alias_subtrees_count_once() {
    let f = Fixture::new();
    f.write("nested/rust-toolchain", "stable");
    f.write("nested/payload", vec![1; 16384]);
    let alias = Path::new("/System/Volumes/Data").join(f.0.strip_prefix("/").unwrap());
    let actual = fs::metadata(&f.0).unwrap();
    let aliased = fs::metadata(&alias).unwrap();
    assert_eq!((actual.dev(), actual.ino()), (aliased.dev(), aliased.ino()));
    let (out, single) = f.run(&[]);
    assert!(out.status.success());
    for (first, second) in [
        (f.0.clone(), alias.clone()),
        (f.0.clone(), alias.join("nested")),
        (f.0.join("nested"), alias.clone()),
        (alias.clone(), f.0.clone()),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
            .arg("inventory")
            .arg(&first)
            .arg(&second)
            .arg("--json")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            report["observed_allocated_bytes"], single["observed_allocated_bytes"],
            "{report}"
        );
        assert_eq!(report["roots"].as_array().unwrap().len(), 1);
        assert_eq!(
            report["overlapping_roots_omitted"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(report["toolchain_references"].as_array().unwrap().len(), 1);
    }
}

#[test]
#[cfg(target_os = "macos")]
fn inventory_detects_open_files_through_filesystem_aliases() {
    let f = Fixture::new();
    f.write("project/.git/HEAD", "ref: refs/heads/main");
    f.write("project/open-file", "open");
    // The test process holds this file; Keeper excludes only its own PID.
    let _held = fs::File::open(f.0.join("project/open-file")).unwrap();
    let project = f.0.join("project");
    let alias = Path::new("/System/Volumes/Data").join(project.strip_prefix("/").unwrap());
    for roots in [
        vec![project.clone()],
        vec![alias.clone()],
        vec![project.clone(), alias.clone()],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
            .arg("inventory")
            .args(roots)
            .arg("--json")
            .output()
            .unwrap();
        assert!(out.status.success());
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        let row = report["areas"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["category"] == "project")
            .unwrap();
        assert_eq!(row["open_paths_detected"], true, "{report}");
    }
}

#[test]
#[cfg(target_os = "macos")]
fn inventory_decodes_escaped_open_paths_and_preserves_unknown_for_ambiguous_names() {
    let f = Fixture::new();
    let names = [
        "plain",
        "with space",
        "back\\slash",
        "new\nline",
        "with\ttab",
        "with\rcarriage",
        "with\u{8}back",
        "with\u{c}form",
        "literal\\n",
        "withéaccent",
    ];
    let mut held = Vec::new();
    for name in names {
        let path = format!("{name}/open");
        f.write(&path, "open");
        held.push(fs::File::open(f.0.join(path)).unwrap());
    }
    f.write("idle/data", "idle");
    let (out, report) = f.run(&[]);
    assert!(out.status.success(), "{report}");
    for name in names {
        assert_eq!(area(&report, name)["open_paths_detected"], true, "{report}");
    }
    assert_eq!(
        area(&report, "idle")["open_paths_detected"],
        false,
        "{report}"
    );

    f.write("control\u{1}/open", "open");
    let _control = fs::File::open(f.0.join("control\u{1}/open")).unwrap();
    let (out, report) = f.run(&[]);
    assert!(out.status.success(), "{report}");
    assert!(
        area(&report, "control\u{1}")["open_paths_detected"].is_null(),
        "{report}"
    );
    assert!(
        area(&report, "idle")["open_paths_detected"].is_null(),
        "{report}"
    );
    assert!(report["process_inspection_warning"]
        .as_str()
        .unwrap()
        .contains("encoding"));
    assert_eq!(area(&report, "plain")["open_paths_detected"], true);
}

#[test]
fn inventory_deleted_open_file_does_not_hide_unrelated_inactivity() {
    let f = Fixture::new();
    f.write("active/open", "open");
    f.write("idle/data", "idle");
    let _held = fs::File::open(f.0.join("active/open")).unwrap();
    fs::remove_file(f.0.join("active/open")).unwrap();
    let (out, report) = f.run(&[]);
    assert!(out.status.success());
    assert_eq!(
        area(&report, "active")["open_paths_detected"],
        true,
        "{report}"
    );
    assert_eq!(
        area(&report, "idle")["open_paths_detected"],
        false,
        "{report}"
    );
    // Unrelated protected system paths may warn; they must not cloud this area.
}

#[test]
fn inventory_keeps_accessible_roots_when_another_root_is_missing() {
    let f = Fixture::new();
    f.write("data/payload", vec![1; 16384]);
    let (out, report) = f.run(&[f.0.join("missing").to_str().unwrap()]);
    assert!(!out.status.success());
    assert_eq!(report["complete"], false);
    assert_eq!(report["error_count"], 1);
    assert!(report["observed_allocated_bytes"].as_u64().unwrap() >= 16384);
}

#[test]
fn inventory_matches_project_toolchain_references_and_leaves_unsupported_managers_unknown() {
    let f = Fixture::new();
    f.write(
        ".rustup/toolchains/1.86.0-aarch64-apple-darwin/bin/rustc",
        "binary",
    );
    f.write("Applications/Unity/Hub/Editor/2022.2.2f1/editor", "binary");
    f.write(".nvm/versions/node/v24.0.0/bin/node", "binary");
    f.write(
        "project/rust-toolchain.toml",
        "[toolchain]\nchannel = '1.86.0' # pinned\ncomponents = ['clippy']\n",
    );
    f.write(
        "game/ProjectSettings/ProjectVersion.txt",
        "m_EditorVersion: 2022.2.2f1\nm_EditorVersionWithRevision: 2022.2.2f1 (commit)\n",
    );
    f.write("project/node_modules/package/rust-toolchain", "nightly");
    let (out, report) = f.run(&[]);
    assert!(out.status.success(), "{report}");
    for path in [
        ".rustup/toolchains/1.86.0-aarch64-apple-darwin",
        "Applications/Unity/Hub/Editor/2022.2.2f1",
    ] {
        assert_eq!(
            area(&report, path)["referenced_by"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    assert_eq!(
        area(&report, ".nvm/versions/node/v24.0.0")["reference_check"],
        "not_supported"
    );
    assert_eq!(report["toolchain_references"].as_array().unwrap().len(), 2);
    assert_eq!(report["reference_collection_complete"], false);
    assert_eq!(report["reference_excluded_area_count"], 4);
}

#[test]
fn inventory_marks_unreadable_or_invalid_reference_context_without_leaking_values() {
    let f = Fixture::new();
    let outside = Fixture::new();
    outside.write("config", "SECRET_OUTSIDE_VALUE");
    fs::create_dir(f.0.join("linked")).unwrap();
    symlink(outside.0.join("config"), f.0.join("linked/rust-toolchain")).unwrap();
    f.write("bad/rust-toolchain", "SECRET_INSIDE_VALUE");
    f.write(
        "duplicate/rust-toolchain.toml",
        "[toolchain]\nchannel='stable'\nchannel='nightly'\n",
    );
    f.write(
        "invalid/rust-toolchain.toml",
        "[toolchain]\nchannel='stable'garbage\n",
    );
    f.write(
        "malformed/rust-toolchain.toml",
        "[toolchain]\nchannel='1.86.0'\nthis is not toml\n",
    );
    f.write(
        "unknown/rust-toolchain.toml",
        "[toolchain]\nchannel='stable'\nunknown = true\n",
    );
    f.write(
        "broken-array/rust-toolchain.toml",
        "[toolchain]\nchannel='stable'\ncomponents=['clippy' 'rustfmt']\n",
    );
    fs::create_dir_all(f.0.join("directory/rust-toolchain.toml")).unwrap();
    let (out, report) = f.run(&[]);
    assert!(out.status.success());
    assert_eq!(report["complete"], true);
    assert_eq!(report["reference_collection_complete"], false);
    assert_eq!(report["toolchain_references"].as_array().unwrap().len(), 8);
    assert!(report["toolchain_references"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["version"].is_null()));
    assert!(!report.to_string().contains("SECRET_"));
}

#[test]
fn inventory_discovers_projects_in_agent_and_build_directories() {
    let f = Fixture::new();
    for parent in [
        ".t3/worktrees",
        "build",
        "out",
        "dist",
        "artifacts",
        "target",
    ] {
        f.write(&format!("{parent}/app/.git/HEAD"), "ref: refs/heads/main");
        f.write(&format!("{parent}/app/rust-toolchain"), "nightly");
    }
    let (out, report) = f.run(&[]);
    assert!(out.status.success());
    assert_eq!(report["toolchain_references"].as_array().unwrap().len(), 6);
    for parent in [
        ".t3/worktrees",
        "build",
        "out",
        "dist",
        "artifacts",
        "target",
    ] {
        assert_eq!(
            area(&report, &format!("{parent}/app"))["category"],
            "project"
        );
    }
    // Git internals are deliberately excluded, and that is disclosed.
    assert_eq!(report["reference_excluded_area_count"], 6);
    assert_eq!(
        report["reference_excluded_area_examples"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(report["reference_collection_complete"], false);
}

#[test]
fn inventory_preserves_installed_applications_and_application_support() {
    let f = Fixture::new();
    f.write(
        "Applications/Editor.app/Contents/Info.plist",
        "bundle metadata",
    );
    f.write(
        "Applications/Editor.app/Contents/Resources/app/out/code.js",
        "code",
    );
    f.write(
        "Library/Application Support/Chrome/Extensions/plugin/dist/code.js",
        "code",
    );
    let (out, report) = f.run(&["--depth", "10"]);
    assert!(out.status.success());
    assert_eq!(
        area(&report, "Editor.app")["category"],
        "installed_application"
    );
    assert_eq!(
        area(&report, "Application Support/Chrome")["category"],
        "application_data"
    );
    assert!(report["areas"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["category"] != "build_output"));
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .arg("inventory")
        .arg(f.0.join("Applications/Editor.app/Contents/Resources/app/out"))
        .arg("--json")
        .output()
        .unwrap();
    assert!(out.status.success());
    let nested: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(nested["areas"][0]["category"], "installed_application");
}

#[test]
fn inventory_app_suffix_without_bundle_structure_keeps_project_and_data_context() {
    let f = Fixture::new();
    f.write("ws/pasture.app/.git/HEAD", "ref: refs/heads/main");
    f.write("ws/pasture.app/target/output", vec![1; 16384]);
    f.write("ws/pasture.app/rust-toolchain", "stable");
    f.write("Library/Application Support/com.example.app/state", "state");
    f.write("Library/Caches/com.example.app/cache", "cache");
    f.write("Library/WebKit/com.example.app/data", "data");
    // Symlinked bundle metadata must not turn a source directory into an app.
    f.write("pretend.app/source", "source");
    f.write("elsewhere/Info.plist", "metadata");
    symlink(f.0.join("elsewhere"), f.0.join("pretend.app/Contents")).unwrap();
    let (out, report) = f.run(&["--depth", "10"]);
    assert!(out.status.success());
    for (path, category) in [
        ("ws/pasture.app", "project"),
        ("ws/pasture.app/.git", "git_history"),
        ("ws/pasture.app/target", "build_output"),
        (
            "Library/Application Support/com.example.app",
            "application_data",
        ),
        ("Library/Caches/com.example.app", "application_cache"),
        ("Library/WebKit/com.example.app", "other"),
        ("pretend.app", "other"),
    ] {
        assert_eq!(area(&report, path)["category"], category);
    }
    assert_eq!(report["toolchain_references"].as_array().unwrap().len(), 1);
    assert!(report["areas"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["category"] != "installed_application"));
}

#[test]
fn inventory_matches_rust_channels_dates_and_hosts_separately() {
    let f = Fixture::new();
    for version in [
        "nightly-aarch64-apple-darwin",
        "nightly-x86_64-unknown-linux-gnu",
        "nightly-2025-01-01-aarch64-apple-darwin",
        "nightly-2026-10-01-x86_64-apple-darwin",
        "1.86.0-aarch64-apple-darwin",
    ] {
        f.write(&format!(".rustup/toolchains/{version}/bin/rustc"), "binary");
    }
    f.write("rolling/rust-toolchain", "nightly");
    f.write("dated/rust-toolchain", "nightly-2025-01-01");
    f.write("pinned/rust-toolchain", "1.86.0");
    let (out, report) = f.run(&[]);
    assert!(out.status.success());
    for (version, reference) in [
        ("nightly-aarch64-apple-darwin", "rolling"),
        ("nightly-x86_64-unknown-linux-gnu", "rolling"),
        ("nightly-2025-01-01-aarch64-apple-darwin", "dated"),
        ("1.86.0-aarch64-apple-darwin", "pinned"),
    ] {
        let row = area(&report, version);
        assert_eq!(row["reference_count"], 1);
        assert_eq!(
            row["referenced_by"][0],
            f.0.join(reference).join("rust-toolchain").to_str().unwrap()
        );
    }
    assert_eq!(
        area(&report, "nightly-2026-10-01-x86_64-apple-darwin")["reference_count"],
        0
    );
}

#[test]
fn inventory_cross_reference_examples_remain_bounded() {
    let f = Fixture::new();
    for n in 0..100 {
        let mut state = (n as u32) + 1;
        // Pseudorandom bytes keep the fixture size stable on compressed filesystems.
        let payload: Vec<u8> = (0..64 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect();
        f.write(
            &format!("host{n}/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc"),
            payload,
        );
    }
    for n in 0..400 {
        f.write(&format!("project{n}/rust-toolchain"), "stable");
    }
    // One generic host row per toolchain leaves room for every toolchain, while
    // the smaller project rows exercise eviction alongside reference bounding.
    let (out, report) = f.run(&["--depth", "1"]);
    assert!(out.status.success());
    assert_eq!(report["areas"].as_array().unwrap().len(), 256);
    assert!(report["areas_omitted"].as_u64().unwrap() > 0);
    let rows: Vec<_> = report["areas"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["category"] == "toolchain")
        .collect();
    assert_eq!(rows.len(), 100);
    for row in rows {
        assert_eq!(row["reference_count"], 400);
        assert_eq!(row["referenced_by"].as_array().unwrap().len(), 5);
    }
    assert!(out.stdout.len() < 1_000_000, "{} bytes", out.stdout.len());
}

#[test]
#[cfg(not(target_os = "macos"))]
fn inventory_handles_non_utf8_paths_and_does_not_guess_process_activity() {
    let f = Fixture::new();
    let name = std::ffi::OsString::from_vec(b"odd\xff".to_vec());
    fs::create_dir(f.0.join(&name)).unwrap();
    fs::write(f.0.join(name).join("file"), "data").unwrap();
    let (out, report) = f.run(&[]);
    assert!(out.status.success(), "{report}");
    let row = &report["areas"][0];
    assert_eq!(row["path_utf8"], false);
    assert!(row["open_paths_detected"].is_null());
}

#[test]
fn inventory_reports_cannot_be_applied_and_mutation_flags_are_refused() {
    let f = Fixture::new();
    f.write("project/source", "preserve");
    let (_, report) = f.run(&[]);
    let report_file = f.0.join("report.json");
    fs::write(&report_file, report.to_string()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
        .arg("apply")
        .arg(&report_file)
        .arg("--yes")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        fs::read_to_string(f.0.join("project/source")).unwrap(),
        "preserve"
    );
    for arg in ["--yes", "--max-entries=3"] {
        let out = Command::new(env!("CARGO_BIN_EXE_keeper"))
            .arg("inventory")
            .arg(&f.0)
            .arg(arg)
            .output()
            .unwrap();
        assert!(!out.status.success());
    }
}
