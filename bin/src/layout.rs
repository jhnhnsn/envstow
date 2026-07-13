//! envseal file & key layout — where the identity, recipients, and encrypted store live,
//! and how they are located, read, and written.
//!
//! Locations
//! ---------
//!   * Identity (PRIVATE key): `$ENVSEAL_IDENTITY`, else `~/.config/envseal/identity.txt`
//!     (`%APPDATA%\envseal\identity.txt` on Windows). Contains one `AGE-SECRET-KEY-...` line.
//!     Never committed; created mode 0600 on Unix.
//!   * Recipients (PUBLIC keys): `recipients` at the repo root. Committed. One `age1...` per
//!     line; `#` comments and optional trailing `# Name` allowed. This is the recipient set
//!     the store is encrypted to.
//!   * Encrypted store: `secrets/secrets.enc` (age binary), beside the `recipients` file.
//!     Committed. Plaintext payload is dotenv.
//!
//! The repo root is whatever directory (walking up from the CWD) contains a `recipients`
//! file — that anchors both the store and any relative operations.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub const RECIPIENTS_FILE: &str = "recipients";
pub const STORE_FILE: &str = "secrets/secrets.enc";

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
    NoStore,
    Io(String),
    NoIdentity(PathBuf),
    Empty(&'static str),
}

impl std::fmt::Display for LayoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LayoutError::NoRecipientsFile => write!(
                f,
                "no `{RECIPIENTS_FILE}` file found in this directory or any parent \
                 (run `envseal init` first)"
            ),
            LayoutError::NoStore => {
                write!(f, "no `{STORE_FILE}` found next to `{RECIPIENTS_FILE}`")
            }
            LayoutError::Io(e) => write!(f, "{e}"),
            LayoutError::NoIdentity(p) => write!(
                f,
                "no identity (private key) at {} — run `envseal init` or set $ENVSEAL_IDENTITY",
                p.display()
            ),
            LayoutError::Empty(what) => write!(f, "{what} is empty"),
        }
    }
}

impl std::error::Error for LayoutError {}

/// Resolved paths for a repo: the recipients file and the encrypted store beside it.
pub struct Paths {
    pub recipients: PathBuf,
    pub store: PathBuf,
}

/// Walk up from the CWD to find the `recipients` file that anchors the repo; derive the store
/// path beside it. Does not require the store to exist yet (init creates it).
pub fn locate() -> Result<Paths, LayoutError> {
    let mut dir = env::current_dir().map_err(|e| LayoutError::Io(e.to_string()))?;
    loop {
        let cand = dir.join(RECIPIENTS_FILE);
        if cand.is_file() {
            return Ok(Paths {
                store: dir.join(STORE_FILE),
                recipients: cand,
            });
        }
        if !dir.pop() {
            return Err(LayoutError::NoRecipientsFile);
        }
    }
}

/// Path to the identity (private key) file: `$ENVSEAL_IDENTITY` or the per-user config path.
pub fn identity_path() -> PathBuf {
    if let Some(p) = env::var_os("ENVSEAL_IDENTITY") {
        return PathBuf::from(p);
    }
    let base = if cfg!(windows) {
        env::var_os("APPDATA").map(PathBuf::from)
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.unwrap_or_else(|| PathBuf::from("."))
        .join("envseal")
        .join("identity.txt")
}

/// Read the identity secret string (`AGE-SECRET-KEY-...`) from the identity file.
pub fn read_identity_secret() -> Result<String, LayoutError> {
    let path = identity_path();
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
    let contents = format!("# envseal age identity — PRIVATE. Never commit or share.\n{secret}\n");
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
        "# envseal recipients — age PUBLIC keys that can decrypt the store.\n\
         # One `age1...` per line; add a `# Name` label if you like.\n\
         # After editing, run `envseal reencrypt` (or add/remove-recipient) to re-key the store.\n",
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

/// Read the raw encrypted store bytes.
pub fn read_store(path: &Path) -> Result<Vec<u8>, LayoutError> {
    if !path.is_file() {
        return Err(LayoutError::NoStore);
    }
    fs::read(path).map_err(|e| LayoutError::Io(e.to_string()))
}

/// Write the encrypted store bytes, creating the `secrets/` dir if needed.
pub fn write_store(path: &Path, ciphertext: &[u8]) -> Result<(), LayoutError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| LayoutError::Io(e.to_string()))?;
    }
    fs::write(path, ciphertext).map_err(|e| LayoutError::Io(e.to_string()))
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
        let prev = env::var_os("ENVSEAL_IDENTITY");
        env::set_var("ENVSEAL_IDENTITY", "/tmp/custom-identity.txt");
        assert_eq!(identity_path(), PathBuf::from("/tmp/custom-identity.txt"));
        match prev {
            Some(v) => env::set_var("ENVSEAL_IDENTITY", v),
            None => env::remove_var("ENVSEAL_IDENTITY"),
        }
    }

    #[test]
    fn skips_blank_and_comment_lines() {
        assert!(parse_recipients("\n\n#only comments\n#age1notreal\n").is_empty());
    }
}
