# Workspace Keeper

A native Rust CLI for project-aware storage management. Git and `lsof` are
required. Validated on macOS; the Unix implementation has not been exercised on
Linux here. No Python or Node runtime is required to run Keeper.

```sh
git clone https://github.com/pnupu/workspace-keeper.git
cd workspace-keeper
cargo install --path . --locked
keeper scan ~
```

## Find the large storage areas

```sh
keeper inventory ~ /Applications
keeper inventory ~ /Applications --json
keeper inventory ~/audits --max-entries 500000 --max-seconds 120
```

`inventory` measures whole directory trees, including areas the cache scanner
does not cover: Git history and complete checkouts, build output, virtual
environments, shared package stores, toolchain versions, application caches,
Docker data and agent state. It ranks directory footprints by allocated size
and supplies ownership/recovery questions for an agent to investigate. Directory
names and layouts are classification hints, not proof that contents are disposable.
Only the explicitly supplied roots are traversed; include `/Applications` to
inspect system-wide editor installations. No package managers or cleanup commands
are executed, and an inventory report cannot be passed to `keeper apply`.

The JSON includes bounded Unity and Rust toolchain declarations found outside
classified caches/installations, matching installed versions, open-path activity,
and the latest observed filesystem modification time. It never infers that an
unreferenced toolchain is unused: another project, environment override or
unsupported declaration may need it. Node version references are not supported.
Unreadable, symlinked, oversized or unsupported declarations make reference
context incomplete without exposing their values. Rust TOML support is deliberately
limited to one `[toolchain]` table with single-line quoted `channel`/`profile` and
string arrays for `components`/`targets`; escapes, multiline values and other
constructs are reported as unsupported. Build and agent directories are searched
for nested projects and declarations. Installed applications, toolchains,
dependencies, stores, Git internals and classified caches are measured but not
searched for declarations; excluded-area counts and examples make that gap explicit
and set `reference_collection_complete` to false. Git marker detection does not
check remote availability, unpublished commits or unique ignored/untracked data;
whole-checkout retirement still needs those checks and preservation first.

Installed `.app` bundles (with a regular `Contents/Info.plist` inside a real
`Contents` directory) and code under `Library/Application Support` are not
labelled as build output. A `.app` suffix alone does not establish a bundle.
A Git marker at the current user's home does not turn
the whole home into a checkout-retirement suggestion, including filesystem aliases
of that home directory. Home protection and open-path activity matching use
directory device/inode identities. On macOS, process directories with a verified
Data-volume alias also mark that alias's containing directories as active; the
parents on the two spellings can be physically different. Alias resolution uses
the same process-context time and path limits.

Nested rows overlap and must not be added together. Overlapping input roots are
collapsed only when the parent can reach the child on the same filesystem;
explicit roots across mount boundaries are retained. Directory identities detect
filesystem aliases, including macOS Data-volume paths and overlapping alias
subtrees. Both retained and collapsed roots appear in human output. Root
identities are retained from preparation and rechecked before traversal;
a replaced root is refused. Observed hard links and physical directories count
once across roots, assigned to the
first visited path; repeated alias subtrees contribute zero on later visits and
are reported with a count and bounded examples. APFS clones/compression can
change the actual capacity reclaimed.
An explicit root recognized as an alias during traversal has
`already_counted_as_alias: true` and a human-readable label. Its hierarchy and
storage belong to the earlier traversal; scan that root alone for its own depth
hierarchy.
Concurrent filesystem changes mean this is an inventory, not a snapshot. Secret,
database and source contents are not read; only bounded regular toolchain
declarations are parsed. Agent state and application data receive preservation
guidance. Non-UTF-8 paths use display-only lossy text and unknown process activity.

Default limits are five million entries, 300 seconds, traversal depth 64, the
largest 256 area summaries, 4,096 toolchain references and 100 error examples.
Recovery guidance is stored once per category to keep agent context compact.
Each toolchain area lists at most five `referenced_by` examples, with
`reference_count` giving the total among the collected declarations. Rolling Rust
channels and dated nightlies are matched separately, allowing host suffixes.
The time budget is checked between entries; individual filesystem/process calls
can exceed it. Each root attempt consumes the entry budget before normalization,
including missing roots. Root overlap detection uses an identity index with
cached ancestry and cooperative time checks; `roots_not_prepared` reports budget
omissions. Each descendant entry also consumes the budget before metadata or
opening can fail, including unreadable directories. `--depth`
controls the reported folder hierarchy (default 3), not
measurement depth. Classified areas can appear below that level. Human output
shows the largest 25 areas of at least 1 MiB; `--all` shows all retained areas.
Summary truncation is reported separately from incomplete traversal. Symlinks
are counted but never followed below a root, and other filesystems are skipped.
An unreadable path or exhausted traversal budget produces partial JSON and exit
status 1; accessible results remain available. `complete` describes measurement;
process warnings and `reference_collection_complete` describe context separately.
Process paths are deduplicated before filesystem resolution. Collection and
identity resolution each have a 50,000 unique-path cap and use the remaining time
budget. Filename backslash and hexadecimal escapes from `lsof` are decoded once.
Ambiguous caret notation for control characters or unsupported escapes preserve
known positives but make negative activity unknown, with a warning.
The cleanup activity guard uses the same decoder and blocks cleanup when a
process path has ambiguous or unsupported encoding.
Deleted-but-open paths use surviving directory ancestors, so they do not
make unrelated activity unknown. Other lookup failures, the path cap and the
time limit have distinct warnings. A lookup denied by permissions only makes
potentially related areas unknown, using the nearest resolved directory's
identity; unrelated areas can still report false. Exhausted collection or
resolution budgets preserve known activity but leave other results unknown
(`null`). Failure to resolve a potential macOS Data-volume alias also leaves
negative activity unknown. These are activity observations, not proof that an
area is idle.

Inventory sizes are not cleanup estimates: `cleanup_eligible_bytes` is null and
every area's `cleanup_approved` is false. Use `keeper plan PROJECT` for exact
supported cleanup targets and recovery evidence. Existing cleanup limits and
preservation rules still apply.

## Plan a project parking operation

```sh
keeper plan /path/to/project --days 7 --output /tmp/project-parking.json
# Review the JSON: exact targets, blockers, preservation policy, recovery recipes.
keeper apply /tmp/project-parking.json --yes
```

`plan` only inspects the project and optionally creates a private JSON file.
Choose an output path outside the project. Existing output files are never
overwritten. Without `--output`, the JSON is printed to stdout for an agent to
consume. Treat it as local metadata: it contains paths, filenames, sizes, Git
state, and validated package-manager hints. It does not include environment values, database
contents, source diffs, or key contents.

Parking leaves **every file outside the exact selected directories in place**:
source changes, Git history, `.env` files, keys, certificates, local databases,
agent state, unknown files, permissions, and symlinks. There is no whole-checkout
removal or backup/restore feature. The receipt is an audit record, not a backup.
Encrypted preservation and verified restore must precede future checkout
retirement; this version does not claim to make unique data recoverable.

A dirty repository does not automatically block parking. Recent tracked or
untracked source activity still does. An old source edit can remain untouched
while a separate generated cache is removed. A clean Git status does not make
ignored files disposable.

Supported targets remain `node_modules`, `.next/cache`, `.turbo/cache`,
`.pytest_cache`, and `__pycache__`. They must be ignored by Git and contain no
tracked files, nested Git repositories, or other filesystem. Candidate paths
must resolve to real directories without symlink ancestors. Inside a target,
secret-like filenames (including `.env`, private-key formats and database
extensions) and `.keeper-keep` block deletion. This conservative filename check
can protect package test fixtures too; the first five matching paths are reported.
It is not a general secret detector.
Unknown files outside targets are always retained. Locally patched or renamed
files inside a generated tree cannot reliably be identified as unique: preserve
such work before approving that tree.

Standalone dependency targets need a package manifest and an unambiguous
lockfile directly beside the installation. Shared npm, Bun text-lock and pnpm
workspaces can use their root lockfile when the declaration, lockfile member
inventory and dependency specifications agree. Keeper records the root install
command and hashes every member manifest and supported local install config.
The recovery command affects the **whole workspace**, including dependencies
outside the selected cleanup target. In particular, `npm ci` removes and replaces
existing root and member `node_modules`, even installations Keeper left protected
or unselected. Other managers can also replace or remove packages. Recipes list
all affected installations and require a separate recovery review: preserve any
unique files in those installations before running the command. Keeper's own
deletion remains confined to the exact targets; it never runs recovery commands.

Workspace patterns currently support literal relative paths and whole-directory
`*` components such as `packages/*`. Names such as `build`, `dist` and `target`
are included in workspace ownership checks even though the general scanner skips
those trees. Globs matching hidden directories (apart from excluded `.git`) are
not supported. More complex globs, enclosing workspaces
outside the Git project, nested workspaces, symlinked members, member lockfiles,
local dependency paths (including peer dependencies and lockfile inputs), custom
resolution settings, npm shrinkwrap, Yarn workspaces and Bun binary
workspace locks remain protected. Discovery is bounded to 256 members and 4,096
visited directories. An ancestor lockfile alone never establishes ownership.
Sensitive filenames inside dependency fixtures still block deletion; this release
does not verify package contents against a registry or bypass that protection.
Only registry/auth settings without file inputs in local `.npmrc` files are
accepted; `cafile`, `certfile` and `keyfile` remain blocked. pnpm workspace
configuration is limited to `packages` and an optional true
`sharedWorkspaceLockfile`; other install settings, Bun config files and pnpm
hooks stay blocked. Unknown settings are preserved rather than guessed.
pnpm workspace locks must use format 9 with `autoInstallPeers: true` and
`excludeLinksFromLockfile: false`, no other lock settings, and no custom resolution
metadata. A stale override or hook checksum also blocks recovery approval.
pnpm importer `dependenciesMeta` and `publishConfig.directory`/`publishDirectory`
are not supported and remain protected.
pnpm importer links must resolve lexically to a declared member without traversing
symlinks, case aliases, installations or caches. Transitive `link:` inputs remain protected.
Workspace roots or members beneath removable installations/caches are not supported.
Non-dependency caches containing package manifests, locks or workspace configuration
are protected even when a dependency installation is not selected for cleanup.

pnpm workspace recipes include `--config.recursive-install=true --filter='./**'` to
override recursion and project-selection settings, including unnamed members.
These flags are specific
overrides, not isolation from all host configuration.
Before running an npm workspace recipe, unset `npm_config_workspace` /
`NPM_CONFIG_WORKSPACE` and remove `workspace=` selections from user/global npm
config. `npm ci` does not override them and can succeed while skipping members;
the recipe records this precondition explicitly.
Host/user package-manager configuration and environment are otherwise not captured
or validated. Review them before restoring and verify the affected projects'
imports and builds afterward; a successful exit does not prove the original layout.

The plan records hashes, an install command and a validated package-manager hint.
Reinstallation still depends on registry access, credentials,
original toolchains and package availability. Cache recipes describe the next
build/test operation that regenerates them. Keeper never executes restore
commands, install scripts, or agent-supplied shell code.

## Execution boundaries

- One project, at most eight directories and 10 GiB of estimated allocated bytes
  per run. These limits are enforced independently of editable plan fields.
- Plans expire after 24 hours. Changed project identity, Git state, directory
  metadata, or dependency recovery evidence requires a new plan.
- Plans use schema 2 and include hostname, OS and architecture. Applying a plan
  with different host metadata is refused. This is an accidental-use check, not
  a globally unique machine identity. Regenerate plans made by older versions.
- Every target is checked before the first deletion, and each is checked again
  immediately before deletion. Existing pins and detected active processes block
  execution. Same-project Keeper runs are serialized with a private lock.
- Directory components are checked individually. The final fingerprint and
  removal use the same open directory handle, so ancestor swaps cannot redirect
  deletion to another tree. Symlink destinations are not cleanup targets.
- A private, fsynced receipt is created before deletion. Each target gets
  `deleting` and `removed` records. A failure stops the batch and reports its
  receipt. Previously completed deletions are not rolled back. After a crash,
  an unmatched `deleting` entry means the outcome needs inspection.
- There is no force bypass, recursive repository deletion, or automatic backup
  expiry. Root cleanup is refused. Never run cleanup alongside agents/builds or
  another cleaner: activity checks cannot prevent new work starting afterward.

Receipts live in `~/.local/state/workspace-keeper/` with mode 0600; the state
directory must be owned by you and mode 0700. `KEEPER_STATE_DIR` can select
another private, canonical directory outside the project. Symlinked state paths
are rejected. A lock left by a crashed run must be inspected before manual
removal; Keeper does not guess whether its owner is still active.
Lock errors include the lock path and recorded process ID. A completely full
disk can prevent durable receipts; free a little space elsewhere before retrying.

The existing single-target command uses the same bounded executor and receipts:

```sh
keeper clean /path/to/project node_modules --yes
```

It creates and immediately applies a plan for that exact target. For agent-driven
work, prefer the explicit `plan` / `apply` sequence so the decision is reviewable.
To exclude a project, create `.keeper-pin` in its root. To preserve a particular
cache, put `.keeper-keep` inside it.

## Scan work folders

```sh
keeper scan ~/work ~/audits --days 7
keeper scan ~ --json
keeper scan ~ --all
```

Run without `sudo`. Inaccessible folders are reported individually and discovery
continues elsewhere. The report is incomplete when a path cannot be inspected;
zero eligible bytes never means zero reclaimable disk space. Discovery depth is
three directory levels by default (`--depth` changes it). Registered linked
worktrees outside the roots are included. Stale registrations are reported, not
pruned; empty repositories are protected. Elevated scans check all users'
processes rather than root alone.

The scan is an initial inventory. Its conservative eligibility checks can differ
from a parking plan: plans permit older dirty source, and add recovery evidence
and sensitive-file checks. The plan and fresh executor checks decide what can
actually be removed.

JSON scans and plans identify their host. If host lookup fails, JSON scans retain
their results with `host: null` and an incomplete-report error; plans are refused.
Missing tracked files are summarized
once per project with a count and at most five example paths (lossy text for
non-UTF-8 filenames); candidate blockers
contain one missing-file reason, regardless of how many files are missing.
Plans retain this summary under `context`. File contents and credential values
are never printed.

Text output hides caches below 1 MiB and projects without larger caches;
`--all` and `--json` retain all entries. A scan exits with code 1 on per-project
errors and includes successful results too. Sizes are estimates: shared objects,
hard links, APFS clones and concurrent changes affect actual free-space gains.
This is not a total disk-usage inventory.

Targets sharing hard links need separate runs. Removing one changes the other
target's link counts and change times, so a batch can stop safely after the first
deletion. Create a fresh plan for the remaining target; Keeper retains these
fingerprint checks to detect unexpected changes.

Workspace recovery follows the documented root-install behavior of
[npm](https://docs.npmjs.com/cli/v11/using-npm/workspaces/),
[Bun](https://bun.com/docs/pm/workspaces) and
[pnpm](https://pnpm.io/workspaces). Install commands remain manual and require
the original toolchain, configuration and registry access.

## Verify

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --test-threads=1
```

Tests exercise the actual CLI in temporary repositories, including preservation
of dirty source, private environment files, databases and symlink destinations;
changed/edited/expired plans; batch preflight; receipts; recovery instructions;
permissions; process inspection; linked worktrees and incomplete scans.
