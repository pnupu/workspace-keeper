//! Conservative ownership and recovery evidence for shared workspace installations.
use super::*;
use std::collections::BTreeMap;

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn disposable_path(path: &Path) -> bool {
    path.ancestors().any(|ancestor| {
        ARTIFACTS.iter().any(|artifact| {
            let mut actual = ancestor.components().rev();
            Path::new(artifact).components().rev().all(|expected| {
                actual.next().is_some_and(|component| {
                    component
                        .as_os_str()
                        .as_bytes()
                        .eq_ignore_ascii_case(expected.as_os_str().as_bytes())
                })
            })
        })
    })
}

fn manifest(path: &Path) -> Result<Value> {
    let value: Value = serde_json::from_slice(&bounded_file(path)?)
        .map_err(|_| "Invalid workspace package manifest")?;
    if !value.is_object() {
        return Err("Invalid workspace package manifest".into());
    }
    Ok(value)
}

// Support literal paths and whole-component '*' only. Reject more expressive
// globs instead of interpreting them differently from a package manager.
fn patterns(value: &Value) -> Result<Vec<Vec<&str>>> {
    let list = value
        .as_array()
        .ok_or("Unsupported workspace declaration")?;
    if list.is_empty() || list.len() > 256 {
        return Err("Workspace declaration must contain 1–256 patterns".into());
    }
    list.iter()
        .map(|v| {
            let parts: Vec<_> = v.as_str().ok_or("Invalid workspace pattern")?.split('/').collect();
            if parts.len() > 16 || parts.iter().any(|p| {
                p.is_empty() || p.starts_with('.') || *p == "node_modules"
                    || (*p != "*" && !p.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c)))
            }) {
                return Err("Unsupported workspace pattern; only literal paths and single-directory * are verified".into());
            }
            Ok(parts)
        })
        .collect()
}

fn expand(
    base: &Path,
    parts: &[&str],
    members: &mut BTreeSet<PathBuf>,
    visited: &mut usize,
) -> Result<()> {
    *visited += 1;
    if *visited > 4096 || members.len() > 256 {
        return Err("Workspace discovery exceeds bounded limits".into());
    }
    if !present(base)? {
        return Ok(());
    }
    let m = fs::symlink_metadata(base)?;
    if !m.is_dir() || fs::canonicalize(base)? != base {
        return Err("Workspace member path must be a real directory without symlinks".into());
    }
    if present(&base.join(".git"))? {
        return Err("Workspace crosses a nested Git repository".into());
    }
    if parts.is_empty() {
        if present(&base.join("package.json"))? {
            members.insert(base.to_path_buf());
            if members.len() > 256 {
                return Err("Workspace discovery exceeds bounded limits".into());
            }
        }
    } else if parts[0] == "*" {
        expand_glob(base, &parts[1..], members, visited)?;
    } else {
        expand(&base.join(parts[0]), &parts[1..], members, visited)?;
    }
    Ok(())
}

fn expand_glob(
    base: &Path,
    rest: &[&str],
    members: &mut BTreeSet<PathBuf>,
    visited: &mut usize,
) -> Result<()> {
    for entry in entries(base)? {
        let name = entry.file_name();
        // Package managers exclude these trees. Scanner exclusions such as
        // build/dist/target are valid workspace names and must be inspected.
        if name == OsStr::new(".git") || name == OsStr::new("node_modules") {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_dir() || kind.is_symlink() {
            // Hidden-member glob semantics differ between managers. Refuse
            // this context rather than silently omit a possible member.
            if name.as_bytes().starts_with(b".") {
                return Err(
                    "Workspace glob matches a hidden directory; recovery is not verified".into(),
                );
            }
            expand(&entry.path(), rest, members, visited)?;
        }
    }
    Ok(())
}

// Bun text locks are JSON with trailing commas and // comments. Preserve
// strings byte-for-byte; invalid or unsupported syntax fails closed.
fn bun_lock(bytes: &[u8]) -> Result<Value> {
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < out.len() {
        match out[i] {
            b'"' => {
                i += 1;
                while i < out.len() {
                    match out[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'/' if out.get(i + 1) == Some(&b'/') => {
                while i < out.len() && out[i] != b'\n' {
                    out[i] = b' ';
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    i = 0;
    while i < out.len() {
        match out[i] {
            b'"' => {
                i += 1;
                while i < out.len() {
                    match out[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b',' => {
                let next = out[i + 1..].iter().find(|b| !b.is_ascii_whitespace());
                if matches!(next, Some(b'}' | b']')) {
                    out[i] = b' ';
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    serde_json::from_slice(&out).map_err(|_| "Invalid or unsupported Bun workspace lockfile".into())
}

fn dependency_specs(value: &Value, pnpm_lock: bool) -> Result<BTreeMap<String, String>> {
    if !value.is_object() {
        return Err("Invalid workspace lockfile member".into());
    }
    let mut specs = BTreeMap::new();
    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(v) = value.get(group) {
            let deps = v.as_object().ok_or("Invalid workspace dependencies")?;
            for (name, spec) in deps {
                let spec = if pnpm_lock { &spec["specifier"] } else { spec };
                let spec = spec
                    .as_str()
                    .ok_or("Invalid workspace dependency specifier")?;
                if !remote_or_workspace_spec(spec) {
                    return Err(
                        "Workspace has local or patched dependencies; recovery is not verified"
                            .into(),
                    );
                }
                // Keep groups separate: moving between prod/dev changes install behavior.
                specs.insert(format!("{group}/{name}"), spec.to_owned());
            }
        }
    }
    Ok(specs)
}

fn pnpm_manifest_specs(specs: BTreeMap<String, String>) -> BTreeMap<String, String> {
    // With autoInstallPeers=true, peers absent from all ordinary groups are
    // installed as dependencies. Ordinary groups take precedence in this order.
    // Validate every original spec before calling this, including overridden peers.
    let mut effective = BTreeMap::new();
    for group in [
        "peerDependencies",
        "devDependencies",
        "dependencies",
        "optionalDependencies",
    ] {
        let prefix = format!("{group}/");
        for (key, spec) in &specs {
            if let Some(name) = key.strip_prefix(&prefix) {
                let installed_group = if group == "peerDependencies" {
                    "dependencies"
                } else {
                    group
                };
                effective.insert(name, (installed_group, spec));
            }
        }
    }
    effective
        .into_iter()
        .map(|(name, (group, spec))| (format!("{group}/{name}"), spec.clone()))
        .collect()
}

fn remote_or_workspace_spec(spec: &str) -> bool {
    if let Some(spec) = spec.strip_prefix("workspace:") {
        return ["*", "^", "~"].contains(&spec);
    }
    if let Some(alias) = spec.strip_prefix("npm:") {
        return alias.rsplit_once('@').is_some_and(|(name, version)| {
            !name.is_empty()
                && registry_spec(version)
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"@/_-.".contains(&c))
        });
    }
    [
        "https://",
        "http://",
        "git+https://",
        "git+ssh://",
        "ssh://",
        "git://",
        "github:",
        "gitlab:",
        "bitbucket:",
    ]
    .iter()
    .any(|p| spec.starts_with(p))
        || registry_spec(spec)
}

fn registry_spec(spec: &str) -> bool {
    !spec.is_empty()
        && !spec.starts_with('.')
        && !spec.ends_with(".tgz")
        && !spec.ends_with(".tar.gz")
        && !spec.ends_with(".tar")
        && spec
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._+*^~<>=| ".contains(&c))
}

fn registry_config(bytes: &[u8]) -> Result<()> {
    let config =
        std::str::from_utf8(bytes).map_err(|_| "Invalid workspace registry configuration")?;
    for line in config.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let (key, _) = line
            .split_once('=')
            .ok_or("Unsupported workspace install configuration")?;
        let key = key.trim().to_ascii_lowercase();
        let scope_registry = key.starts_with('@')
            && key.ends_with(":registry")
            && key[..key.len() - 9]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"@_.-".contains(&c));
        let auth = key.starts_with("//")
            && [
                ":_authtoken",
                ":_auth",
                ":_password",
                ":username",
                ":email",
                ":always-auth",
            ]
            .iter()
            .any(|suffix| key.ends_with(suffix));
        if ![
            "registry",
            "always-auth",
            "strict-ssl",
            "_auth",
            "_authtoken",
            "_password",
            "username",
            "email",
        ]
        .contains(&key.as_str())
            && !scope_registry
            && !auth
        {
            return Err("Unsupported workspace install configuration; only registry/auth settings are verified".into());
        }
    }
    Ok(())
}

// Recovery supports the shared v9 format with default resolution settings.
// Unknown top-level metadata may carry stale overrides, patches or hook hashes
// that make a frozen install fail even when every importer still matches.
fn pnpm_lock_settings(lock: &Value) -> Result<()> {
    let fields = lock.as_object().ok_or("Invalid pnpm workspace lockfile")?;
    if !(lock["lockfileVersion"] == "9.0" || lock["lockfileVersion"] == 9)
        || fields.keys().any(|k| {
            ![
                "lockfileVersion",
                "settings",
                "importers",
                "packages",
                "snapshots",
            ]
            .contains(&k.as_str())
        })
    {
        return Err("Unsupported pnpm lockfile format or custom resolution metadata".into());
    }
    let settings = lock["settings"]
        .as_object()
        .ok_or("Missing pnpm lockfile settings; recovery is not verified")?;
    if lock["settings"]["autoInstallPeers"] != true
        || lock["settings"]["excludeLinksFromLockfile"] != false
        || settings
            .keys()
            .any(|k| !["autoInstallPeers", "excludeLinksFromLockfile"].contains(&k.as_str()))
    {
        return Err("Unsupported pnpm lockfile settings; recovery is not verified".into());
    }
    Ok(())
}

fn npm_inferred_name(member: &str) -> &str {
    let Some((parent, name)) = member.rsplit_once('/') else {
        return member;
    };
    let scope = parent.rsplit('/').next().unwrap_or(parent);
    if scope.starts_with('@') {
        &member[member.len() - scope.len() - name.len() - 1..]
    } else {
        name
    }
}

// Lockfiles can refer to local inputs even when package.json uses a registry
// version. Those inputs must never be assumed to survive removal of an install.
fn reject_local_lock_sources(value: &Value, members: &BTreeSet<String>) -> Result<()> {
    match value {
        Value::String(s) => {
            let s = s.to_ascii_lowercase();
            if ["file:", "git+file:", "portal:", "patch:", "link:"]
                .iter()
                .any(|p| s.starts_with(p) || s.contains(&format!("@{p}")))
            {
                return Err(
                    "Lockfile contains local dependency inputs; preserve installation".into(),
                );
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_local_lock_sources(item, members)?;
            }
        }
        Value::Object(items) => {
            if items.get("type").is_some_and(|v| v == "directory") {
                return Err(
                    "Lockfile contains local dependency inputs; preserve installation".into(),
                );
            }
            for (key, v) in items {
                if ["resolved", "tarball"].contains(&key.as_str()) {
                    if let Some(s) = v.as_str() {
                        let workspace_link =
                            items.get("link").is_some_and(|v| v == true) && members.contains(s);
                        let remote = [
                            "https://",
                            "http://",
                            "git+https://",
                            "git+ssh://",
                            "git://",
                            "ssh://",
                        ]
                        .iter()
                        .any(|p| s.starts_with(p));
                        if !workspace_link && !remote {
                            return Err("Lockfile contains an unverified dependency source; preserve installation".into());
                        }
                    }
                }
                reject_local_lock_sources(&Value::String(key.clone()), members)?;
                reject_local_lock_sources(v, members)?;
            }
        }
        _ => (),
    }
    Ok(())
}

fn pnpm_importer_sources(
    importer: &Value,
    base: &Path,
    root: &Path,
    members: &BTreeSet<PathBuf>,
    member_names: &BTreeSet<String>,
) -> Result<()> {
    // Only an importer's dependency version may link directly to a workspace
    // member. Every other link, including transitive snapshot inputs, is refused.
    let mut remaining = importer.clone();
    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(deps) = remaining[group].as_object_mut() {
            for dependency in deps.values_mut() {
                if let Some(link) = dependency["version"]
                    .as_str()
                    .and_then(|s| s.strip_prefix("link:"))
                {
                    let relative = Path::new(link);
                    if link.is_empty() || relative.is_absolute() {
                        return Err("Workspace link must be relative to its importer".into());
                    }
                    let mut destination = base.to_path_buf();
                    for component in relative.components() {
                        match component {
                            Component::CurDir => (),
                            Component::ParentDir if destination != root => {
                                destination.pop();
                            }
                            Component::Normal(name) => {
                                destination.push(name);
                                if disposable_path(destination.strip_prefix(root)?) {
                                    return Err("Workspace link traverses a disposable installation or cache".into());
                                }
                                let metadata = fs::symlink_metadata(&destination)
                                    .map_err(|_| "Workspace link cannot be recovered")?;
                                if !metadata.is_dir() || metadata.is_symlink() {
                                    return Err(
                                        "Workspace link traverses a symlink or non-directory"
                                            .into(),
                                    );
                                }
                                // A case-insensitive filesystem can resolve a
                                // different spelling, then hide it with '..'.
                                if !entries(destination.parent().ok_or("Invalid link path")?)?
                                    .iter()
                                    .any(|entry| entry.file_name() == name)
                                {
                                    return Err(
                                        "Workspace link uses non-canonical directory spelling"
                                            .into(),
                                    );
                                }
                            }
                            _ => return Err("Workspace link escapes its workspace root".into()),
                        }
                    }
                    if destination != root && !members.contains(&destination) {
                        return Err("Workspace lock links to an undeclared local dependency; preserve installation".into());
                    }
                    // This specific field has been validated with its importer
                    // base. All remaining fields still go through the denylist.
                    dependency
                        .as_object_mut()
                        .ok_or("Invalid importer dependency")?
                        .remove("version");
                }
            }
        }
    }
    reject_local_lock_sources(&remaining, member_names)
}

pub(super) fn recovery(project: &Path, package: &Path) -> Result<Option<Value>> {
    let mut owners = Vec::new();
    // Always inspect above the Git root too: an enclosing workspace can affect
    // a package even if it has a separate local lockfile.
    for ancestor in package.ancestors() {
        let pnpm = present(&ancestor.join("pnpm-workspace.yaml"))?;
        let has_manifest = present(&ancestor.join("package.json"))?;
        let workspace = has_manifest
            && manifest(&ancestor.join("package.json"))?
                .get("workspaces")
                .is_some();
        if pnpm || workspace {
            owners.push(ancestor);
        }
    }
    if owners.is_empty() {
        return Ok(None);
    }
    if owners.len() != 1 || !owners[0].starts_with(project) {
        return Err(
            "Workspace recovery is not verified across enclosing or nested workspace roots".into(),
        );
    }
    let root = owners[0];
    if disposable_path(root.strip_prefix(project)?) {
        return Err(
            "Workspace recovery inputs are inside a disposable installation or cache".into(),
        );
    }
    let root_manifest = manifest(&root.join("package.json"))?;
    let mut recipe = dependency_recovery(project, root)?;
    // Command comes only from our fixed recovery recipes, never a manifest.
    let tool = recipe["command"][0]
        .as_str()
        .ok_or("Missing recovery command")?
        .to_owned();
    if !["npm", "bun", "pnpm"].contains(&tool.as_str()) {
        return Err(
            "Workspace recovery currently supports npm, Bun text locks and pnpm shared locks"
                .into(),
        );
    }
    let mut evidence = recipe["evidence"]
        .as_array()
        .ok_or("Missing recovery evidence")?
        .clone();
    let pnpm_config = root.join("pnpm-workspace.yaml");
    let declaration = if tool == "pnpm" {
        let (ev, bytes) = regular_evidence(&pnpm_config, project)?;
        let config: Value = serde_yaml_ng::from_slice(&bytes)
            .map_err(|_| "Invalid pnpm workspace configuration")?;
        if config
            .as_object()
            .ok_or("Invalid pnpm workspace configuration")?
            .iter()
            .any(|(k, v)| k != "packages" && !(k == "sharedWorkspaceLockfile" && v == true))
        {
            return Err("Custom pnpm workspace recovery is not verified".into());
        }
        evidence.push(ev);
        config["packages"].clone()
    } else {
        if present(&pnpm_config)? {
            return Err("Mixed workspace declarations; preserve installation".into());
        }
        let declaration = &root_manifest["workspaces"];
        if declaration
            .as_object()
            .is_some_and(|o| o.keys().any(|k| k != "packages"))
        {
            return Err("Custom workspace declaration recovery is not verified".into());
        }
        declaration.get("packages").unwrap_or(declaration).clone()
    };
    let patterns = patterns(&declaration)?;
    let mut members = BTreeSet::new();
    let mut visited = 0;
    for pattern in patterns {
        // The workspace root may be the Git root; expansion starts below it.
        if pattern[0] == "*" {
            expand_glob(root, &pattern[1..], &mut members, &mut visited)?;
        } else {
            expand(
                &root.join(pattern[0]),
                &pattern[1..],
                &mut members,
                &mut visited,
            )?;
        }
    }
    if members
        .iter()
        .any(|member| member.strip_prefix(project).is_ok_and(disposable_path))
    {
        return Err(
            "Workspace recovery inputs are inside a disposable installation or cache".into(),
        );
    }
    if package != root && !members.contains(package) {
        return Err("Installation is not a declared workspace member; preserve it".into());
    }
    let lock_path = PathBuf::from(text(&evidence[1], "path")?);
    let bytes = bounded_file(&project.join(&lock_path))?;
    let lock: Value = match tool.as_str() {
        "npm" => serde_json::from_slice(&bytes).map_err(|_| "Invalid npm workspace lockfile")?,
        "pnpm" => {
            serde_yaml_ng::from_slice(&bytes).map_err(|_| "Invalid pnpm workspace lockfile")?
        }
        _ if lock_path.ends_with("bun.lock") => bun_lock(&bytes)?,
        _ => {
            return Err("Bun binary workspace locks are not verified; preserve installation".into())
        }
    };
    if tool == "pnpm" {
        pnpm_lock_settings(&lock)?;
    }
    let key = match tool.as_str() {
        "npm" => "packages",
        "pnpm" => "importers",
        _ => "workspaces",
    };
    let locked = lock[key]
        .as_object()
        .ok_or("Workspace lockfile has no member inventory")?;
    let root_key = if tool == "pnpm" { "." } else { "" };
    let mut expected = BTreeSet::from([root_key.to_owned()]);
    let mut manifests = vec![(root_key.to_owned(), root_manifest)];
    for member in &members {
        // A member-level lock or workspace changes ownership; do not guess.
        for ancestor in member.ancestors().take_while(|p| *p != root) {
            if present(&ancestor.join("pnpm-workspace.yaml"))?
                || present(&ancestor.join("npm-shrinkwrap.json"))?
                || LOCKS
                    .iter()
                    .map(|l| present(&ancestor.join(l)))
                    .collect::<Result<Vec<_>>>()?
                    .contains(&true)
            {
                return Err(
                    "Workspace recovery is not verified with member or intervening lockfiles"
                        .into(),
                );
            }
            if ancestor != member && present(&ancestor.join("package.json"))? {
                return Err(
                    "Workspace recovery is not verified with intervening package manifests".into(),
                );
            }
        }
        let m = manifest(&member.join("package.json"))?;
        if m.get("workspaces").is_some() || m.get("packageManager").is_some() {
            return Err("Nested workspace or member package-manager hints are not verified".into());
        }
        let name = path_text(member.strip_prefix(root)?)?.to_owned();
        expected.insert(name.clone());
        manifests.push((name, m));
        evidence.push(regular_evidence(&member.join("package.json"), project)?.0);
    }
    let actual: BTreeSet<_> = locked
        .keys()
        .filter(|k| tool != "npm" || !k.split('/').any(|c| c == "node_modules"))
        .cloned()
        .collect();
    if actual != expected {
        return Err(
            "Workspace declaration and lockfile members differ; preserve installation".into(),
        );
    }
    if tool == "pnpm" {
        for (field, value) in lock.as_object().ok_or("Invalid pnpm lockfile")? {
            if field != "importers" {
                reject_local_lock_sources(value, &expected)?;
            }
        }
    } else {
        reject_local_lock_sources(&lock, &expected)?;
    }
    let mut names = BTreeSet::new();
    for (_, m) in &manifests {
        if let Some(name) = m.get("name") {
            if !names.insert(
                name.as_str()
                    .filter(|n| !n.is_empty())
                    .ok_or("Invalid workspace package name")?,
            ) {
                return Err("Duplicate workspace package names; preserve installation".into());
            }
        }
    }
    for (member, m) in &manifests {
        if [
            "patchedDependencies",
            "pnpm",
            "overrides",
            "resolutions",
            "catalog",
            "catalogs",
            "bundledDependencies",
            "bundleDependencies",
            "peerDependenciesMeta",
        ]
        .iter()
        .any(|k| m.get(k).is_some())
        {
            return Err(
                "Custom dependency resolution in workspace manifest is not verified".into(),
            );
        }
        if tool != "pnpm" {
            for field in ["name", "version"] {
                // npm omits a member name when it matches the directory name,
                // including @scope/name. Root and Bun names remain explicit.
                let inferred_name_matches = tool == "npm"
                    && field == "name"
                    && !member.is_empty()
                    && locked[member].get(field).is_none()
                    && m[field].as_str() == Some(npm_inferred_name(member));
                if m.get(field) != locked[member].get(field) && !inferred_name_matches {
                    return Err(
                        "Workspace member metadata and lockfile differ; preserve installation"
                            .into(),
                    );
                }
            }
        }
        let specs = dependency_specs(m, false)?;
        for (name, spec) in &specs {
            if spec.starts_with("workspace:")
                && !names.contains(name.split_once('/').ok_or("Invalid dependency")?.1)
            {
                return Err(
                    "Workspace dependency has no declared package; preserve installation".into(),
                );
            }
        }
        let specs = if tool == "pnpm" {
            pnpm_manifest_specs(specs)
        } else {
            specs
        };
        if specs != dependency_specs(&locked[member], tool == "pnpm")? {
            return Err(
                "Workspace manifest and lockfile dependencies differ; preserve installation".into(),
            );
        }
        if tool == "pnpm" {
            if m.get("dependenciesMeta").is_some()
                || m["publishConfig"].get("directory").is_some()
                || locked[member].get("dependenciesMeta").is_some()
                || locked[member].get("publishDirectory").is_some()
            {
                return Err(
                    "Custom pnpm importer metadata is not verified; preserve installation".into(),
                );
            }
            let base = if member == "." {
                root.to_path_buf()
            } else {
                root.join(member)
            };
            pnpm_importer_sources(&locked[member], &base, root, &members, &expected)?;
        }
    }
    // Only registry/auth configuration is accepted. Hashing arbitrary install
    // settings or hooks would not prove that a root command restores members.
    for directory in std::iter::once(root).chain(members.iter().map(PathBuf::as_path)) {
        for name in [".npmrc", "bunfig.toml", ".pnpmfile.cjs", ".pnpmfile.mjs"] {
            let config = directory.join(name);
            if present(&config)? {
                if name != ".npmrc" {
                    return Err(
                        "Custom workspace install configuration or hooks are not verified".into(),
                    );
                }
                let (ev, bytes) = regular_evidence(&config, project)?;
                registry_config(&bytes)?;
                evidence.push(ev);
            }
        }
    }
    let installations = std::iter::once(root)
        .chain(members.iter().map(PathBuf::as_path))
        .map(|p| path_text(p.join("node_modules").strip_prefix(project)?).map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    recipe["evidence"] = json!(evidence);
    if tool == "pnpm" {
        // Override recursion and selection settings that can otherwise make a
        // root command succeed without restoring all workspace members.
        recipe["command"] = json!([
            "pnpm",
            "install",
            "--frozen-lockfile",
            "--config.recursive-install=true",
            "--filter=./**"
        ]);
    }
    recipe["limitations"] = json!("Requires the original registries, credentials and compatible toolchain. Host/user package-manager configuration and environment are not captured or validated; review them before restoring. A successful install does not prove the original layout: verify the affected projects' imports and builds afterward. Local edits inside dependencies cannot be reconstructed from a lockfile.");
    if tool == "npm" {
        recipe["workspace_selection_precondition"] = json!("Before running npm ci, unset npm_config_workspace / NPM_CONFIG_WORKSPACE in the environment and remove workspace= selections from user/global npm config. The command does not override these settings and can exit successfully while skipping workspace members. Review other host configuration too; Keeper does not isolate it.");
    }
    recipe["workspace"] = json!({"root": root.strip_prefix(project)?.to_str().filter(|p| !p.is_empty()).unwrap_or("."),
    "member_count": members.len(), "affected_installations": installations,
    "requires_separate_recovery_review": true,
    "recovery_scope": if tool == "npm" {
        "npm ci removes and replaces existing node_modules across the entire workspace, including unselected or protected installations. Review every listed installation and preserve unique files before manually restoring."
    } else {
        "Reinstalls the entire workspace and may replace or remove packages in unselected or protected installations. Review every listed installation and preserve unique files before manually restoring."
    }});
    Ok(Some(recipe))
}
