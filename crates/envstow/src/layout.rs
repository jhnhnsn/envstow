//! envstow file & key layout — where the identity, recipients, and encrypted store live,
//! and how they are located, read, and written.
//!
//! Locations
//! ---------
//!   * Identity (PRIVATE key): `$ENVSTOW_IDENTITY`, else `~/.config/envstow/identity.txt`
//!     (`%APPDATA%\envstow\identity.txt` on Windows). Contains one `AGE-SECRET-KEY-...` line.
//!     Never committed; created mode 0600 on Unix.
//!   * Recipients (PUBLIC keys): `<store root>/recipients`. One `age1...` per line;
//!     `#` comments and optional trailing `# Name` allowed. Shared across all profiles of a
//!     store, but NOT across stores — each store has its own collaborators.
//!   * Encrypted stores: `<store root>/<profile>.enc`, one per profile. The default
//!     profile is `default.enc`. Each file is an `envstow-format: <n>` header line
//!     followed by the age payload; the decrypted plaintext is dotenv. The header is checked
//!     before decryption so a store from a newer envstow reports that plainly instead of
//!     failing as a decryption error — see [`FORMAT_VERSION`].
//!
//! Where the store root comes from
//! -------------------------------
//! Two kinds of store, resolved by [`resolve_root`]:
//!
//!   * **Local** — `.envstow/` beside your code, found by walking up from the CWD. This is
//!     envstow's original and still default model: the store is committed with the repo, so it
//!     travels to collaborators the same way the code does.
//!   * **Central** — `~/.config/envstow/stores/<name>/`, addressed by NAME rather than path.
//!     For work where a committed store is wrong or impossible: a public repo whose owner does
//!     not want a permanent ciphertext record in it, or collaborators sharing a synced folder
//!     rather than a git remote.
//!
//! `.envstow` is a file OR a directory
//! -----------------------------------
//! A repo that uses a central store still needs to say so, or every command needs a flag. It
//! does that with a `.envstow` FILE (rather than a directory) containing `store: <name>`.
//! Same name, and the filesystem type discriminates — this is exactly what git does for
//! worktrees and submodules, where `.git` is a file holding `gitdir: <path>`.
//!
//! Using one name for both cases is what keeps the model small: a path is a file or a
//! directory, never both, so "this repo has a local store AND a pointer to a central one" is
//! unrepresentable rather than an ambiguity to resolve. The alternative — a pointer at
//! `.envstow/store`, beside the stores — would have needed a rule for that collision, and any
//! rule that silently picks a winner picks the wrong store some of the time. In a secrets tool
//! that is the failure worth designing out.
//!
//! The pointer holds a NAME, not a path, which is what makes it safe to commit: it resolves
//! under each collaborator's own home directory, leaks nothing beyond the fact that envstow is
//! in use, and doesn't break when someone's layout differs.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// A repo's envstow entry: a directory holding a local store, or a file pointing at a central
/// one. See the module docs for why one name covers both.
pub const ENVSTOW_DIR: &str = ".envstow";
/// The name of the default (unnamed) profile.
pub const DEFAULT_PROFILE: &str = "default";
/// The recipients file's basename, resolved against whatever store root is in effect.
pub const RECIPIENTS_NAME: &str = "recipients";

/// Central stores live under this directory, beside — deliberately NOT inside — the directory
/// holding the identity key.
///
/// Colocating stores with `identity.txt` would make one directory sufficient to decrypt
/// everything in it: an over-broad backup, a synced config dir, or a dotfiles repo that
/// symlinks `~/.config` would carry both halves at once. Today each half is useless alone —
/// the key decrypts nothing by itself, the ciphertext opens for no one without it. The
/// `stores/` subdirectory keeps that true while still putting everything envstow owns in one
/// findable place.
pub const STORES_SUBDIR: &str = "stores";

/// The pointer file's field prefix: `store: <name>`.
///
/// A prefixed key rather than a bare name, mirroring git's `gitdir:`. A bare value would leave
/// nowhere to add a second field later, and would make an empty or truncated file
/// indistinguishable from a missing one — the prefix turns both into a clear parse error.
const POINTER_PREFIX: &str = "store:";

/// Where to send someone whose envstow is too old to read a store.
pub const REPO_URL: &str = "https://github.com/jhnhnsn/envstow";

/// The on-disk store format this binary reads and writes.
///
/// This versions the *file layout*, not the tool — bump it only when the bytes change shape in a
/// way an older binary would misread (a new envelope, a different payload encoding, a header
/// field). Ordinary releases leave it alone: 0.1.6 → 0.1.7 added a command and did NOT touch the
/// format. Bumping it on every release would cry wolf and train people to ignore the warning.
///
/// When you DO bump it, both guards below start firing for anyone on an older binary — a read
/// gets [`LayoutError::FormatTooNew`], a write gets [`LayoutError::FormatWouldDowngrade`] — each
/// naming the version and pointing at [`REPO_URL`]. Add a note to CHANGELOG.md saying the format
/// moved and that everyone sharing a store must update.
///
/// History:
///   * 1 — headerless: the file is a bare age payload. Everything envstow wrote before 0.1.9.
///   * 2 — the `envstow-format:` header, added in 0.1.9. This bump is the one break the scheme
///     couldn't avoid: a binary with no header code (≤ 0.1.8) sees the header as a corrupt age
///     envelope and reports "decryption failed: Header is invalid". That's precisely the
///     cryptic failure the header exists to prevent — but it can only be prevented for versions
///     that already know to look for it. From 2 onward, an old binary gets a real explanation.
pub const FORMAT_VERSION: u32 = 2;

/// The header line prefixed to every store: `envstow-format: <n>\n`, before the age payload.
///
/// It lives OUTSIDE the ciphertext deliberately. A version sealed inside the encrypted payload is
/// unreadable until after decryption — useless for catching an envelope change, which is exactly
/// the case that would otherwise surface as the maximally-confusing "No matching keys found"
/// (indistinguishable from "you were removed as a recipient"). age itself does the same thing
/// with its own `age-encryption.org/v1` line. The version is public metadata, not a secret.
const FORMAT_PREFIX: &str = "envstow-format: ";

/// Split a store file's bytes into `(format, ciphertext)`.
///
/// A store with no header is format 1: every store written before 0.1.9 starts directly with
/// age's own `age-encryption.org/v1` line. Reading those still works — this binary upgrades them
/// to format 2 the next time anything writes. (The reverse isn't true: a ≤0.1.8 binary can't read
/// what we write. See [`FORMAT_VERSION`].)
fn split_format_header(bytes: &[u8]) -> Result<(u32, &[u8]), LayoutError> {
    let Some(rest) = bytes.strip_prefix(FORMAT_PREFIX.as_bytes()) else {
        return Ok((1, bytes));
    };
    let Some(nl) = rest.iter().position(|b| *b == b'\n') else {
        return Err(LayoutError::BadFormatHeader);
    };
    let digits = std::str::from_utf8(&rest[..nl])
        .map_err(|_| LayoutError::BadFormatHeader)?
        .trim();
    let version: u32 = digits.parse().map_err(|_| LayoutError::BadFormatHeader)?;
    Ok((version, &rest[nl + 1..]))
}

/// Validate a profile name: non-empty, and only chars safe as a filename component (so it can't
/// escape the `.envstow/` dir or collide with the `.enc` suffix). `recipients` is reserved.
pub fn valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name != "recipients"
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Validate a central store name. Same rules as a profile name — it becomes a single directory
/// component under `stores/`, so it must not be able to escape it (`..`, `/`) or be empty.
pub fn valid_store_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Where a store root came from. Carried alongside the resolved path so commands can *say*
/// which store they acted on and why — a silently-relocated secret store is a bad thing to
/// have to debug, and "did it use the store I meant?" should never need guessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreSource {
    /// `--store-dir <path>` or `$ENVSTOW_STORE_DIR`.
    ExplicitDir,
    /// `--store <name>` or `$ENVSTOW_STORE` → a central store.
    NamedFlag(String),
    /// A committed `.envstow` pointer file naming a central store.
    Pointer { name: String, from: PathBuf },
    /// A `.envstow/` directory found by walking up from the CWD — the original model.
    LocalDir,
}

impl StoreSource {
    /// A short human phrase for status output, mirroring `profile`'s "from $ENVSTOW_PROFILE".
    pub fn describe(&self) -> String {
        match self {
            StoreSource::ExplicitDir => "from --store-dir".to_string(),
            StoreSource::NamedFlag(n) => format!("central store '{n}'"),
            StoreSource::Pointer { name, from } => {
                format!("central store '{name}', via {}", from.display())
            }
            StoreSource::LocalDir => "local .envstow/ directory".to_string(),
        }
    }
}

/// How the caller asked for a store, before it is resolved to a path. Built by the CLI layer
/// from flags and environment; [`resolve_root`] turns it into a real directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StoreSelector {
    /// No explicit selection — walk up from the CWD and use whatever is found.
    #[default]
    Discover,
    /// An explicit central store name.
    Named(String),
    /// An explicit directory, used as the store root verbatim.
    Dir(PathBuf),
}

/// The root directory of the central stores area: `~/.config/envstow/stores/`.
///
/// Derived from the identity path's parent so the two always agree about where envstow's
/// config lives, including under `$XDG_CONFIG_HOME` or `%APPDATA%`. `$ENVSTOW_IDENTITY` is a
/// deliberate exception: it relocates only the key, not the stores, since the whole point of
/// keeping them apart is that they need not travel together.
pub fn central_stores_dir() -> PathBuf {
    config_dir().join(STORES_SUBDIR)
}

/// The path of a central store by name.
pub fn central_store_path(name: &str) -> PathBuf {
    central_stores_dir().join(name)
}

/// List the central store names that exist, sorted. A directory counts as a store only if it
/// has a `recipients` file — a half-created or stray directory is not offered as a choice.
pub fn list_central_stores() -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = fs::read_dir(central_stores_dir()) {
        for e in entries.flatten() {
            if e.path().join(RECIPIENTS_NAME).is_file() {
                names.push(e.file_name().to_string_lossy().into_owned());
            }
        }
    }
    names.sort();
    names
}

/// Parse a `.envstow` pointer file's contents into the central store name it names.
///
/// Accepts blank lines and `#` comments so the file can carry a note explaining itself to
/// whoever finds it in a clone. Anything else — no `store:` line, an empty value, an invalid
/// name — is an error rather than a fallback: a pointer we can't read must not silently
/// degrade into "no store here", which would send the caller to some other store entirely.
fn parse_pointer(text: &str) -> Result<String, LayoutError> {
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some(value) = t.strip_prefix(POINTER_PREFIX) else {
            return Err(LayoutError::BadPointer(format!(
                "expected a `{POINTER_PREFIX} <name>` line, found `{t}`"
            )));
        };
        let name = value.trim();
        if name.is_empty() {
            return Err(LayoutError::BadPointer(format!(
                "`{POINTER_PREFIX}` has no store name after it"
            )));
        }
        if !valid_store_name(name) {
            return Err(LayoutError::BadPointer(format!(
                "invalid store name '{name}' (use letters, digits, - or _)"
            )));
        }
        return Ok(name.to_string());
    }
    Err(LayoutError::BadPointer(format!(
        "no `{POINTER_PREFIX} <name>` line found"
    )))
}

/// The store name a pointer file's text names, or `None` if it isn't a readable pointer.
///
/// The lossy counterpart to [`parse_pointer`], for callers that are *asking whether* a pointer
/// names something rather than resolving through one. `init` uses it to notice that a repo
/// already points at the store being created; a malformed pointer is simply "not that store"
/// there, since the resolving path will report it properly the moment anything reads a secret.
pub fn parse_pointer_name(text: &str) -> Option<String> {
    parse_pointer(text).ok()
}

/// Render a pointer file's contents, with a comment explaining it to whoever finds it.
pub fn render_pointer(name: &str) -> String {
    format!(
        "# envstow: this project's secrets live in a central store, NOT in this repo.\n\
         # Each collaborator keeps their own copy at ~/.config/envstow/stores/{name}/.\n\
         # This file names it; it contains no secrets and is safe to commit.\n\
         {POINTER_PREFIX} {name}\n"
    )
}

/// Walk up from the CWD looking for a `.envstow` entry, and resolve it to a store root.
///
/// One probe per level, then branch on what was found:
///   * a directory → a local store, rooted there (envstow's original behavior, unchanged);
///   * a file      → a pointer naming a central store.
///
/// Nearest wins, so a nested project overrides an outer one, matching how the walk has always
/// behaved and how git resolves `.git`.
fn discover_root() -> Result<(PathBuf, StoreSource), LayoutError> {
    let mut dir = env::current_dir().map_err(|e| LayoutError::Io(e.to_string()))?;
    loop {
        let cand = dir.join(ENVSTOW_DIR);
        match fs::metadata(&cand) {
            Ok(meta) if meta.is_dir() => {
                // A directory without `recipients` is not a store — it's an unrelated directory
                // that happens to share the name, or a half-finished init. Keep walking rather
                // than claiming this level, so an outer real store still wins.
                if cand.join(RECIPIENTS_NAME).is_file() {
                    return Ok((cand, StoreSource::LocalDir));
                }
            }
            Ok(_) => {
                let text = fs::read_to_string(&cand).map_err(|e| LayoutError::Io(e.to_string()))?;
                let name = parse_pointer(&text)?;
                let root = central_store_path(&name);
                if !root.join(RECIPIENTS_NAME).is_file() {
                    return Err(LayoutError::PointerDangling {
                        name,
                        from: cand,
                        expected: root,
                    });
                }
                return Ok((
                    root,
                    StoreSource::Pointer {
                        name,
                        from: cand.clone(),
                    },
                ));
            }
            Err(_) => {}
        }
        if !dir.pop() {
            return Err(LayoutError::NoRecipientsFile);
        }
    }
}

/// Resolve a [`StoreSelector`] to a concrete store root plus the reason it was chosen.
///
/// An explicit selection never falls back to the walk. If you named a store and it isn't there,
/// that is an error — quietly walking instead could hand you a different store than the one you
/// asked for, and in the case this feature exists for (keeping secrets OUT of a public repo)
/// the store it would find is precisely the one you were avoiding.
pub fn resolve_root(sel: &StoreSelector) -> Result<(PathBuf, StoreSource), LayoutError> {
    match sel {
        StoreSelector::Dir(path) => {
            if !path.join(RECIPIENTS_NAME).is_file() {
                return Err(LayoutError::NoStoreAtDir(path.clone()));
            }
            Ok((path.clone(), StoreSource::ExplicitDir))
        }
        StoreSelector::Named(name) => {
            if !valid_store_name(name) {
                return Err(LayoutError::BadStoreName(name.clone()));
            }
            let root = central_store_path(name);
            if !root.join(RECIPIENTS_NAME).is_file() {
                return Err(LayoutError::NoSuchStore {
                    name: name.clone(),
                    known: list_central_stores(),
                });
            }
            Ok((root, StoreSource::NamedFlag(name.clone())))
        }
        StoreSelector::Discover => discover_root(),
    }
}

/// A parsed recipient entry: the `age1...` key plus an optional human label from a trailing
/// `# Name` comment. The label is cosmetic — matching/removal can use either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    pub key: String,
    pub label: Option<String>,
}

#[derive(Debug)]
pub enum LayoutError {
    NoRecipientsFile,
    NoStore(PathBuf),
    Io(String),
    NoIdentity(PathBuf),
    Empty(&'static str),
    /// The store is a newer format than this binary can read.
    FormatTooNew {
        found: u32,
    },
    /// The store is a newer format than this binary writes; writing would downgrade it.
    FormatWouldDowngrade {
        found: u32,
    },
    /// The header is present but unparseable — a truncated or corrupted file.
    BadFormatHeader,
    /// A `.envstow` pointer file exists but can't be read as one.
    BadPointer(String),
    /// A pointer names a central store that isn't on this machine.
    PointerDangling {
        name: String,
        from: PathBuf,
        expected: PathBuf,
    },
    /// `--store <name>` named a central store that doesn't exist.
    NoSuchStore {
        name: String,
        known: Vec<String>,
    },
    /// `--store-dir <path>` pointed somewhere that isn't a store.
    NoStoreAtDir(PathBuf),
    /// A store name that can't be a directory component.
    BadStoreName(String),
}

impl std::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LayoutError::NoRecipientsFile => {
                let known = list_central_stores();
                write!(
                    f,
                    "no `{ENVSTOW_DIR}` found in this directory or any parent \
                     (run `envstow init` first)"
                )?;
                if !known.is_empty() {
                    // They have central stores — most likely they meant one of them and are
                    // simply outside a repo that points at it. Naming them turns a dead end
                    // into a next step.
                    write!(
                        f,
                        "\n\x20  Central stores on this machine: {}\n\
                         \x20  Use one with `envstow --store <name> ...`",
                        known.join(", ")
                    )?;
                }
                Ok(())
            }
            LayoutError::NoStore(p) => {
                write!(f, "no store file at {}", p.display())
            }
            LayoutError::Io(e) => write!(f, "{e}"),
            LayoutError::NoIdentity(p) => write!(
                f,
                "no identity (private key) at {} — run `envstow init` or set $ENVSTOW_IDENTITY",
                p.display()
            ),
            LayoutError::Empty(what) => write!(f, "{what} is empty"),
            LayoutError::FormatTooNew { found } => write!(
                f,
                "this store uses format {found}, but your envstow only understands format \
                 {FORMAT_VERSION}.\n\
                 A teammate wrote it with a newer envstow. Update yours to read it:\n\
                 \x20  {REPO_URL}"
            ),
            LayoutError::FormatWouldDowngrade { found } => write!(
                f,
                "refusing to write — this store is format {found} and your envstow writes format \
                 {FORMAT_VERSION}.\n\
                 Writing would downgrade it and break it for teammates on a newer envstow. \
                 Update yours first:\n\
                 \x20  {REPO_URL}"
            ),
            LayoutError::BadFormatHeader => write!(
                f,
                "the store's `{}` header is malformed — the file looks truncated or corrupted. \
                 Restore it from a backup, or from git history if the store is committed \
                 (`git checkout -- {ENVSTOW_DIR}`).",
                FORMAT_PREFIX.trim_end()
            ),
            LayoutError::BadPointer(why) => write!(
                f,
                "the `{ENVSTOW_DIR}` file is not a valid store pointer: {why}.\n\
                 \x20  A pointer file contains one line: `{POINTER_PREFIX} <name>`.\n\
                 \x20  (A `{ENVSTOW_DIR}` DIRECTORY holds a store directly; a FILE points at a \
                 central one.)"
            ),
            // The error a new collaborator meets first — any command hits it, not just `init`.
            // "Create it" alone is a trap: for the likeliest reader (just cloned, wants the
            // team's secrets) creating an empty store is exactly the wrong move, so each intent
            // gets named and pointed at its own command.
            LayoutError::PointerDangling {
                name,
                from,
                expected,
            } => write!(
                f,
                "{} says this project's secrets live in the central store '{name}',\n\
                 \x20 but that store isn't on this machine (looked in {}).\n\
                 \n\
                 \x20  If you're trying to GET THIS PROJECT'S SECRETS (most likely — you \
                 cloned it):\n\
                 \x20    envstow init --store {name}   …prints the steps to join\n\
                 \x20  If you're trying to USE A DIFFERENT STORE you already have:\n\
                 \x20    envstow store   …lists them\n\
                 \x20  If this project's secrets should live IN THE REPO instead:\n\
                 \x20    rm {} && envstow init",
                from.display(),
                expected.display(),
                from.display()
            ),
            LayoutError::NoSuchStore { name, known } => {
                write!(f, "no central store named '{name}'.")?;
                if known.is_empty() {
                    write!(
                        f,
                        "\n\x20  There are no central stores yet — create one with \
                         `envstow init --store {name}`."
                    )
                } else {
                    write!(f, "\n\x20  Known stores: {}", known.join(", "))
                }
            }
            LayoutError::NoStoreAtDir(p) => write!(
                f,
                "no `{RECIPIENTS_NAME}` file in {} — that directory isn't an envstow store.\n\
                 \x20  Create one there with `envstow init --store-dir {}`.",
                p.display(),
                p.display()
            ),
            LayoutError::BadStoreName(n) => {
                write!(f, "invalid store name '{n}' (use letters, digits, - or _)")
            }
        }
    }
}

impl std::error::Error for LayoutError {}

/// Resolved paths for a store: the recipients file and the encrypted store beside it, plus
/// where the store root came from so commands can report it.
pub struct Paths {
    pub recipients: PathBuf,
    pub store: PathBuf,
    pub source: StoreSource,
}

/// Resolve the store root for `sel` and derive the paths for `profile` inside it. Does not
/// require the profile's store file to exist yet (init and `profile create` create it).
/// All profiles of a store share its one `recipients` file.
pub fn locate_in(sel: &StoreSelector, profile: &str) -> Result<Paths, LayoutError> {
    let (root, source) = resolve_root(sel)?;
    Ok(Paths {
        recipients: root.join(RECIPIENTS_NAME),
        store: root.join(format!("{profile}.enc")),
        source,
    })
}

/// [`locate_in`] with the default selector — walk up from the CWD. Kept for the call sites that
/// have no selector of their own.
pub fn locate(profile: &str) -> Result<Paths, LayoutError> {
    locate_in(&StoreSelector::Discover, profile)
}

/// The store root, for enumerating profiles.
pub fn store_root(sel: &StoreSelector) -> Result<PathBuf, LayoutError> {
    resolve_root(sel).map(|(root, _)| root)
}

/// The store root discovered by walking up from the CWD.
pub fn repo_root() -> Result<PathBuf, LayoutError> {
    store_root(&StoreSelector::Discover)
}

/// List the profile names present in a store root (from `<root>/*.enc`). Each `<name>.enc` is
/// the profile `<name>` (so `default.enc` → `default`). Sorted and de-duplicated.
pub fn list_profiles(root: &Path) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries.flatten() {
            let fname = e.file_name();
            let fname = fname.to_string_lossy();
            if let Some(stem) = fname.strip_suffix(".enc") {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// envstow's per-user config directory: `~/.config/envstow` (`%APPDATA%\envstow` on Windows).
/// Holds the identity key and, under `stores/`, any central stores.
pub fn config_dir() -> PathBuf {
    let base = if cfg!(windows) {
        env::var_os("APPDATA").map(PathBuf::from)
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join("envstow")
}

/// Path to the identity (private key) file: `$ENVSTOW_IDENTITY` or the per-user config path.
pub fn identity_path() -> PathBuf {
    if let Some(p) = env::var_os("ENVSTOW_IDENTITY") {
        return PathBuf::from(p);
    }
    config_dir().join("identity.txt")
}

/// Warn (once per invocation, to stderr) if the identity private key is readable by group or
/// other. envstow creates it `0600`, but permissions drift — a copy, a restore from backup, or a
/// loose umask can leave the key world-readable, and anyone who can read it decrypts every store
/// you can. We warn rather than refuse (unlike `ssh`) so a permission slip can't lock you out of
/// your own secrets; the message says exactly how to fix it. Never prints key contents.
#[cfg(unix)]
fn warn_if_identity_perms_loose(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mode = meta.permissions().mode();
        // Any group/other bit set (0o077) means someone besides the owner can read it.
        if mode & 0o077 != 0 {
            eprintln!(
                "⚠️  envstow: your identity key is readable by others (mode {:o}) — {}\n\
                 \x20  Anyone who can read it can decrypt every store you have access to. Fix it:\n\
                 \x20    chmod 600 {}",
                mode & 0o777,
                path.display(),
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_identity_perms_loose(_path: &Path) {
    // Windows: the key lives under %APPDATA%, which is already per-user; no POSIX mode to check.
}

/// Read the identity secret string (`AGE-SECRET-KEY-...`) from the identity file.
pub fn read_identity_secret() -> Result<String, LayoutError> {
    let path = identity_path();
    warn_if_identity_perms_loose(&path);
    let raw = fs::read_to_string(&path).map_err(|_| LayoutError::NoIdentity(path.clone()))?;
    // The file may be an age-keygen-style file with `# ` comment lines; take the first
    // AGE-SECRET-KEY line, else the first non-comment non-blank line.
    for line in raw.lines() {
        let t = line.trim();
        if t.starts_with("AGE-SECRET-KEY-") {
            return Ok(t.to_string());
        }
    }
    for line in raw.lines() {
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('#') {
            return Ok(t.to_string());
        }
    }
    Err(LayoutError::Empty("identity file"))
}

/// Write a new identity file with the given secret string, creating parent dirs. On Unix the
/// file is created mode 0600. Refuses to overwrite an existing identity.
pub fn write_new_identity(secret: &str) -> Result<PathBuf, LayoutError> {
    let path = identity_path();
    if path.exists() {
        return Err(LayoutError::Io(format!(
            "identity already exists at {} — refusing to overwrite",
            path.display()
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| LayoutError::Io(e.to_string()))?;
    }
    let contents = format!("# envstow age identity — PRIVATE. Never commit or share.\n{secret}\n");
    fs::write(&path, contents).map_err(|e| LayoutError::Io(e.to_string()))?;
    set_owner_only(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), LayoutError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| LayoutError::Io(e.to_string()))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), LayoutError> {
    // Windows ACLs are not adjusted here; APPDATA is already per-user.
    Ok(())
}

/// Parse the recipients file text into ordered [`Recipient`] entries.
///
/// Format: one recipient per line, `age1...` optionally followed by `# Label`. Blank lines and
/// full-line `#` comments are ignored. Any line whose first token isn't `age1...` is skipped
/// (keeps the file forgiving of stray notes).
pub fn parse_recipients(text: &str) -> Vec<Recipient> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        // Split off an inline `# label` comment.
        let (keypart, labelpart) = match t.split_once('#') {
            Some((k, l)) => (k.trim(), Some(l.trim().to_string())),
            None => (t, None),
        };
        let key = keypart.split_whitespace().next().unwrap_or("");
        if !key.starts_with("age1") {
            continue;
        }
        out.push(Recipient {
            key: key.to_string(),
            label: labelpart.filter(|s| !s.is_empty()),
        });
    }
    out
}

/// Render recipients back to file text, preserving labels as trailing `# Label` comments.
pub fn render_recipients(recipients: &[Recipient]) -> String {
    let mut s = String::from(
        "# envstow recipients — age PUBLIC keys that can decrypt the store.\n\
         # One `age1...` per line; add a `# Name` label if you like.\n\
         # After editing, run `envstow reencrypt` (or add/remove-recipient) to re-key the store.\n",
    );
    for r in recipients {
        match &r.label {
            Some(l) => s.push_str(&format!("{}  # {}\n", r.key, l)),
            None => s.push_str(&format!("{}\n", r.key)),
        }
    }
    s
}

/// Read + parse the recipients file at `path`.
pub fn read_recipients(path: &Path) -> Result<Vec<Recipient>, LayoutError> {
    let text = fs::read_to_string(path).map_err(|e| LayoutError::Io(e.to_string()))?;
    Ok(parse_recipients(&text))
}

/// Read the encrypted store, verifying the format header and stripping it.
///
/// Returns the age ciphertext alone, so callers hand `crypto::decrypt` exactly what it expects.
/// The format check runs BEFORE any crypto, so a store from a newer envstow fails with a clear
/// "update your envstow" rather than a decryption error that reads like a permissions problem.
pub fn read_store(path: &Path) -> Result<Vec<u8>, LayoutError> {
    if !path.is_file() {
        return Err(LayoutError::NoStore(path.to_path_buf()));
    }
    let bytes = fs::read(path).map_err(|e| LayoutError::Io(e.to_string()))?;
    let (version, ciphertext) = split_format_header(&bytes)?;
    if version > FORMAT_VERSION {
        return Err(LayoutError::FormatTooNew { found: version });
    }
    Ok(ciphertext.to_vec())
}

/// Read just the format version of an existing store, without reading it as a store. Used by the
/// write guard, which must inspect a file it may be about to refuse. A store that doesn't exist
/// yet (init, `profile create`) has no format to conflict with.
fn store_format(path: &Path) -> Result<Option<u32>, LayoutError> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|e| LayoutError::Io(e.to_string()))?;
    let (version, _) = split_format_header(&bytes)?;
    Ok(Some(version))
}

/// Write the encrypted store with this binary's format header, creating `.envstow/` if needed.
///
/// Refuses to overwrite a store written in a NEWER format: an old binary re-encrypting a newer
/// store would silently downgrade it and break every teammate who has already updated. The read
/// guard alone can't catch this — by the time anyone reads it, the damage is committed.
pub fn write_store(path: &Path, ciphertext: &[u8]) -> Result<(), LayoutError> {
    if let Some(found) = store_format(path)? {
        if found > FORMAT_VERSION {
            return Err(LayoutError::FormatWouldDowngrade { found });
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| LayoutError::Io(e.to_string()))?;
    }
    let mut out = format!("{FORMAT_PREFIX}{FORMAT_VERSION}\n").into_bytes();
    out.extend_from_slice(ciphertext);
    fs::write(path, out).map_err(|e| LayoutError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_labeled_recipients() {
        let text = "# header comment\n\
                    age1aaa   # Alice\n\
                    age1bbb\n\
                    \n\
                    age1ccc # CI runner\n\
                    not-a-key should be skipped\n";
        let r = parse_recipients(text);
        assert_eq!(
            r,
            vec![
                Recipient {
                    key: "age1aaa".into(),
                    label: Some("Alice".into())
                },
                Recipient {
                    key: "age1bbb".into(),
                    label: None
                },
                Recipient {
                    key: "age1ccc".into(),
                    label: Some("CI runner".into())
                },
            ]
        );
    }

    #[test]
    fn render_then_parse_roundtrips() {
        let recips = vec![
            Recipient {
                key: "age1aaa".into(),
                label: Some("Alice".into()),
            },
            Recipient {
                key: "age1bbb".into(),
                label: None,
            },
        ];
        let text = render_recipients(&recips);
        assert_eq!(parse_recipients(&text), recips);
    }

    #[test]
    fn identity_path_respects_env_override() {
        // Save/restore so we don't disturb other tests' environment assumptions.
        let prev = env::var_os("ENVSTOW_IDENTITY");
        env::set_var("ENVSTOW_IDENTITY", "/tmp/custom-identity.txt");
        assert_eq!(identity_path(), PathBuf::from("/tmp/custom-identity.txt"));
        match prev {
            Some(v) => env::set_var("ENVSTOW_IDENTITY", v),
            None => env::remove_var("ENVSTOW_IDENTITY"),
        }
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        assert!(parse_recipients("\n\n#only comments\n#age1notreal\n").is_empty());
    }

    #[test]
    fn headerless_store_is_format_1() {
        // Every store written before the header existed begins with age's own line. These must
        // keep working untouched — that's what makes the header a silent, migration-free rollout.
        let legacy = b"age-encryption.org/v1\n-----> X25519 abc\npayload";
        let (version, ciphertext) = split_format_header(legacy).unwrap();
        assert_eq!(version, 1, "absent header means format 1");
        assert_eq!(
            ciphertext, legacy,
            "ciphertext must be passed through whole"
        );
    }

    #[test]
    fn header_is_split_from_the_ciphertext() {
        let stored = b"envstow-format: 1\nage-encryption.org/v1\npayload";
        let (version, ciphertext) = split_format_header(stored).unwrap();
        assert_eq!(version, 1);
        assert_eq!(
            ciphertext, b"age-encryption.org/v1\npayload",
            "the age payload must come back byte-exact, header removed"
        );
    }

    #[test]
    fn a_newer_format_is_reported_not_guessed_at() {
        let future = b"envstow-format: 7\nage-encryption.org/v1\npayload";
        let (version, _) = split_format_header(future).unwrap();
        assert_eq!(
            version, 7,
            "parse must report the real version, not clamp it"
        );
        assert!(version > FORMAT_VERSION, "7 is newer than we understand");
    }

    #[test]
    fn malformed_headers_are_rejected() {
        // Truncated (no newline) and non-numeric versions are corruption, not a format we can
        // reason about — better to say so than to guess.
        for bad in [
            &b"envstow-format: 1"[..],
            &b"envstow-format: abc\npayload"[..],
            &b"envstow-format: \npayload"[..],
        ] {
            assert!(
                matches!(split_format_header(bad), Err(LayoutError::BadFormatHeader)),
                "should reject malformed header: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn write_store_refuses_to_downgrade_a_newer_store() {
        // No CLI path reaches this today — set/delete both decrypt first, so the READ guard
        // fires before this one. It's a backstop: it makes downgrade-safety a property of the
        // layout layer, so a future command that writes without reading first can't silently
        // break a newer teammate's store. Tested here because only a unit test can reach it.
        let dir = env::temp_dir().join(format!("envstow-fmt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let store = dir.join("future.enc");
        fs::write(&store, b"envstow-format: 42\nage-encryption.org/v1\n").unwrap();

        let err = write_store(&store, b"age-encryption.org/v1\nnew").unwrap_err();
        assert!(
            matches!(err, LayoutError::FormatWouldDowngrade { found: 42 }),
            "should refuse, got {err:?}"
        );
        assert_eq!(
            fs::read(&store).unwrap(),
            b"envstow-format: 42\nage-encryption.org/v1\n",
            "the refused write must leave the file untouched"
        );

        // A store at our own format is fine to overwrite, and gets the header back.
        let ours = dir.join("ours.enc");
        fs::write(&ours, format!("{FORMAT_PREFIX}{FORMAT_VERSION}\nold")).unwrap();
        write_store(&ours, b"age-encryption.org/v1\nnew").unwrap();
        assert_eq!(
            fs::read(&ours).unwrap(),
            format!("{FORMAT_PREFIX}{FORMAT_VERSION}\nage-encryption.org/v1\nnew").into_bytes()
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pointer_parses_a_name_ignoring_comments_and_blanks() {
        // The rendered file leads with explanatory comments — parsing must see past them, or
        // the very file envstow writes wouldn't read back.
        let text = render_pointer("acme");
        assert_eq!(parse_pointer(&text).unwrap(), "acme");
        assert_eq!(parse_pointer("store: acme\n").unwrap(), "acme");
        assert_eq!(parse_pointer("\n#note\nstore:  acme  \n").unwrap(), "acme");
    }

    #[test]
    fn a_pointer_we_cannot_read_is_an_error_not_a_shrug() {
        // Every one of these must FAIL rather than resolve to "no store here". Falling through
        // would send the caller to whatever the walk finds next — for the public-repo case,
        // precisely the store they moved their secrets out of.
        for bad in [
            "",                     // empty file
            "\n\n",                 // only blanks
            "# just a comment\n",   // no field
            "acme\n",               // bare name, no `store:` key
            "store:\n",             // key with no value
            "store: ../../etc\n",   // path traversal in a name
            "store: has spaces\n",  // not a valid directory component
            "gitdir: /somewhere\n", // right shape, wrong tool
        ] {
            assert!(
                matches!(parse_pointer(bad), Err(LayoutError::BadPointer(_))),
                "should reject pointer {bad:?}"
            );
        }
    }

    #[test]
    fn store_names_cannot_escape_the_stores_directory() {
        // A name becomes one directory component under `stores/`. Anything that could climb out
        // of it, or name a different file, must be refused before it reaches the filesystem.
        assert!(valid_store_name("acme"));
        assert!(valid_store_name("my-store_2"));
        for bad in ["", "..", "a/b", "../etc", "a b", ".hidden", "a.enc"] {
            assert!(!valid_store_name(bad), "should reject store name {bad:?}");
        }
    }

    #[test]
    fn stores_live_beside_the_identity_not_with_it() {
        // The separation is deliberate (see STORES_SUBDIR): one directory must not be enough to
        // both decrypt and hold the ciphertext. If someone "simplifies" this later, this fails.
        let ident = config_dir().join("identity.txt");
        let stores = central_stores_dir();
        assert_ne!(
            stores,
            ident.parent().unwrap(),
            "central stores must NOT sit in the same directory as the identity key"
        );
        assert!(
            stores.starts_with(config_dir()),
            "but they should still live under the one envstow config dir"
        );
    }

    #[test]
    fn an_explicit_selection_never_falls_back_to_the_walk() {
        // The safety property of resolve_root: naming a store that isn't there is an error, not
        // an invitation to go looking. Silently walking could hand back a DIFFERENT store than
        // the one asked for.
        let missing = env::temp_dir().join("envstow-definitely-not-a-store");
        let err = resolve_root(&StoreSelector::Dir(missing.clone())).unwrap_err();
        assert!(
            matches!(err, LayoutError::NoStoreAtDir(_)),
            "a --store-dir with no recipients must fail, got {err:?}"
        );

        let err = resolve_root(&StoreSelector::Named("nope-not-real-store".into())).unwrap_err();
        assert!(
            matches!(err, LayoutError::NoSuchStore { .. }),
            "an unknown --store must fail, got {err:?}"
        );
    }

    #[test]
    fn store_errors_say_what_to_do_next() {
        // These messages ARE the feature for anyone who mistypes a store name or clones a repo
        // whose central store they don't have yet.
        let dangling = LayoutError::PointerDangling {
            name: "acme".into(),
            from: PathBuf::from("/repo/.envstow"),
            expected: PathBuf::from("/home/u/.config/envstow/stores/acme"),
        }
        .to_string();
        assert!(dangling.contains("acme"), "names the store");
        assert!(dangling.contains("/repo/.envstow"), "names the pointer");
        // This is the first error a new collaborator meets, from ANY command — so it routes by
        // what they were trying to do rather than stating the problem and stopping.
        assert!(
            dangling.matches("If you're trying to").count() >= 2,
            "must offer more than one intent: {dangling}"
        );
        assert!(
            dangling.contains("envstow init --store acme"),
            "tells them how to create it: {dangling}"
        );

        let unknown = LayoutError::NoSuchStore {
            name: "typo".into(),
            known: vec!["acme".into(), "side".into()],
        }
        .to_string();
        assert!(
            unknown.contains("acme, side"),
            "lists what DOES exist, so a typo is obvious: {unknown}"
        );

        let bad = LayoutError::BadPointer("no `store:` line found".into()).to_string();
        assert!(
            bad.contains("store: <name>"),
            "shows the expected format: {bad}"
        );
        assert!(
            bad.contains("DIRECTORY") && bad.contains("FILE"),
            "explains the file-vs-directory distinction: {bad}"
        );
    }

    #[test]
    fn format_errors_name_the_version_and_the_repo() {
        // The message IS the feature: it must say what to do, not just what went wrong.
        let too_new = LayoutError::FormatTooNew { found: 2 }.to_string();
        assert!(too_new.contains("format 2"), "names the found version");
        assert!(too_new.contains(REPO_URL), "points at the repo: {too_new}");

        let downgrade = LayoutError::FormatWouldDowngrade { found: 2 }.to_string();
        assert!(
            downgrade.contains("refusing to write"),
            "leads with refusal"
        );
        assert!(downgrade.contains(REPO_URL), "points at the repo");
    }
}
