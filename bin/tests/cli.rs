//! End-to-end integration tests driving the real `envseal` binary in isolated temp dirs.
//!
//! These exercise the full lifecycle — init, set, list, unlock round-trip, get masking,
//! edit, and multi-recipient add/remove — against the compiled binary, so they catch
//! regressions the in-crate unit tests can't (argument parsing, file layout, process spawn,
//! the crypto round-trip through the actual store on disk).
//!
//! Isolation: each test gets a unique temp directory and its own `ENVSEAL_IDENTITY`, so they
//! never touch the developer's real `~/.config/envseal`. No `sops`/`age` CLIs are required —
//! all crypto is compiled into the binary.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_envseal");

/// A disposable repo dir + identity path. Removed on drop.
struct Repo {
    dir: PathBuf,
    identity: PathBuf,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl Repo {
    /// Create a fresh, unique temp repo. Uniqueness comes from pid + an atomic counter, so
    /// parallel test threads never collide (we can't use timestamps — but pid+counter is
    /// enough for a single test process).
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("envseal-it-{}-{}-{}", tag, std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp repo");
        let identity = dir.join("identity.txt");
        Repo { dir, identity }
    }

    /// Run `envseal <args...>` in this repo with this identity, feeding `stdin_data` to stdin.
    fn run(&self, args: &[&str], stdin_data: &str) -> Output {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Command::new(BIN)
            .args(args)
            .current_dir(&self.dir)
            .env("ENVSEAL_IDENTITY", &self.identity)
            // Ensure a deterministic non-agent, non-tty context unless a test overrides it.
            .env_remove("CLAUDECODE")
            .env_remove("CLAUDE_CODE_ENTRYPOINT")
            .env_remove("ENVSEAL_AGENT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn envseal");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin_data.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait envseal");
        Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Run with an extra env var set (e.g. ENVSEAL_AGENT=1 or EDITOR).
    fn run_env(&self, args: &[&str], stdin_data: &str, key: &str, val: &str) -> Output {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Command::new(BIN)
            .args(args)
            .current_dir(&self.dir)
            .env("ENVSEAL_IDENTITY", &self.identity)
            .env_remove("CLAUDECODE")
            .env_remove("CLAUDE_CODE_ENTRYPOINT")
            .env_remove("ENVSEAL_AGENT")
            .env(key, val)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn envseal");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin_data.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait envseal");
        Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn store(&self) -> PathBuf {
        self.dir.join("secrets").join("secrets.enc")
    }
    fn recipients(&self) -> PathBuf {
        self.dir.join("recipients")
    }
    fn public_key(&self) -> String {
        // The recipients file lists our key; grab the first age1 token.
        let text = std::fs::read_to_string(self.recipients()).unwrap();
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find_map(|l| {
                l.split_whitespace()
                    .next()
                    .filter(|t| t.starts_with("age1"))
            })
            .expect("a public key in recipients")
            .to_string()
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Assert the store on disk is age ciphertext, never the given plaintext.
fn store_is_encrypted(path: &Path, plaintext_needle: &str) {
    let bytes = std::fs::read(path).expect("read store");
    let as_text = String::from_utf8_lossy(&bytes);
    assert!(
        as_text.starts_with("age-encryption.org/") || bytes.starts_with(b"age"),
        "store should be an age file, got {:?}...",
        &as_text.chars().take(30).collect::<String>()
    );
    assert!(
        !as_text.contains(plaintext_needle),
        "plaintext must NOT appear in the encrypted store"
    );
}

#[test]
fn init_creates_identity_recipients_and_store() {
    let repo = Repo::new("init");
    let out = repo.run(&["init"], "");
    assert_eq!(out.code, 0, "init failed: {}", out.stderr);
    assert!(repo.identity.is_file(), "identity file created");
    assert!(repo.recipients().is_file(), "recipients file created");
    assert!(repo.store().is_file(), "store created");
    assert!(repo.public_key().starts_with("age1"));

    // init is idempotent.
    let again = repo.run(&["init"], "");
    assert_eq!(again.code, 0, "re-init failed: {}", again.stderr);
}

#[test]
fn pubkey_prints_the_public_key_matching_recipients() {
    let repo = Repo::new("pubkey");
    assert_eq!(repo.run(&["init"], "").code, 0);

    let out = repo.run(&["pubkey"], "");
    assert_eq!(out.code, 0, "pubkey failed: {}", out.stderr);
    let printed = out.stdout.trim();
    assert!(
        printed.starts_with("age1"),
        "should print an age public key, got {printed:?}"
    );
    // It must match the key `init` wrote into the recipients file.
    assert_eq!(
        printed,
        repo.public_key(),
        "pubkey must match the recipients entry"
    );
}

#[test]
fn set_list_and_unlock_roundtrip() {
    let repo = Repo::new("roundtrip");
    assert_eq!(repo.run(&["init"], "").code, 0);

    // set two secrets via stdin.
    assert_eq!(repo.run(&["set", "AI_API_KEY"], "sk-fake-abc123").code, 0);
    assert_eq!(
        repo.run(&["set", "DATABASE_URL"], "postgres://u:p@h/db?x=1")
            .code,
        0
    );

    // The on-disk store is encrypted and does not contain the plaintext.
    store_is_encrypted(&repo.store(), "sk-fake-abc123");

    // list shows names, never values.
    let list = repo.run(&["list"], "");
    assert_eq!(list.code, 0);
    assert!(list.stdout.contains("AI_API_KEY"));
    assert!(list.stdout.contains("DATABASE_URL"));
    assert!(!list.stdout.contains("sk-fake"));

    // unlock -- <cmd> sets the vars; the child confirms exact round-trip WITHOUT printing them.
    let check = repo.run(
        &[
            "unlock",
            "--",
            "sh",
            "-c",
            "test \"$AI_API_KEY\" = sk-fake-abc123 && test \"$DATABASE_URL\" = 'postgres://u:p@h/db?x=1' && echo OK",
        ],
        "",
    );
    assert_eq!(check.code, 0, "unlock child failed: {}", check.stderr);
    assert!(
        check.stdout.contains("OK"),
        "round-trip mismatch: {:?}",
        check.stdout
    );
}

#[test]
fn get_masks_under_agent_but_reveals_with_show() {
    let repo = Repo::new("get");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOKEN"], "topsecretvalue").code, 0);

    // Under an agent, bare `get` masks.
    let masked = repo.run_env(&["get", "TOKEN"], "", "ENVSEAL_AGENT", "1");
    assert_eq!(masked.code, 0);
    assert!(
        !masked.stdout.contains("topsecretvalue"),
        "must not reveal under agent"
    );
    assert!(masked.stdout.contains("•"), "should print a mask");

    // --show overrides even under an agent.
    let shown = repo.run_env(&["get", "TOKEN", "--show"], "", "ENVSEAL_AGENT", "1");
    assert_eq!(shown.code, 0);
    assert_eq!(shown.stdout.trim(), "topsecretvalue", "--show must reveal");

    // Piped + not under agent (the $(...) case) reveals.
    let piped = repo.run(&["get", "TOKEN"], "");
    assert_eq!(piped.stdout.trim(), "topsecretvalue");

    // Unknown name → exit 1.
    assert_eq!(repo.run(&["get", "NOPE"], "").code, 1);
}

#[test]
fn edit_updates_the_store() {
    let repo = Repo::new("edit");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "EXISTING"], "keepme").code, 0);

    // A fake editor that appends a new secret line to the file it's given.
    let editor = repo.dir.join("fake_editor.sh");
    std::fs::write(&editor, "#!/bin/sh\nprintf 'NEW=addedvalue\\n' >> \"$1\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = repo.run_env(&["edit"], "", "EDITOR", editor.to_str().unwrap());
    assert_eq!(out.code, 0, "edit failed: {}", out.stderr);

    // Both the preserved and the new secret round-trip.
    let check = repo.run(
        &[
            "unlock",
            "--",
            "sh",
            "-c",
            "test \"$EXISTING\" = keepme && test \"$NEW\" = addedvalue && echo OK",
        ],
        "",
    );
    assert!(
        check.stdout.contains("OK"),
        "edit round-trip failed: {} {}",
        check.stdout,
        check.stderr
    );

    // The edit temp file must not be left behind.
    assert!(
        !repo.dir.join(".envseal-edit.tmp").exists(),
        "edit temp file should be shredded/removed"
    );
}

#[test]
fn add_and_remove_recipient_controls_access() {
    // Owner repo.
    let owner = Repo::new("owner");
    assert_eq!(owner.run(&["init"], "").code, 0);
    assert_eq!(owner.run(&["set", "SECRET"], "sharedvalue").code, 0);

    // A collaborator with their own identity + repo (just to generate a keypair).
    let collab = Repo::new("collab");
    assert_eq!(collab.run(&["init"], "").code, 0);
    let collab_pub = collab.public_key();

    // Owner adds the collaborator and re-encrypts.
    let add = owner.run(&["add-recipient", &collab_pub, "alice"], "");
    assert_eq!(add.code, 0, "add-recipient failed: {}", add.stderr);

    // The collaborator can now decrypt the OWNER's store using THEIR identity.
    let as_collab = Command::new(BIN)
        .args([
            "unlock",
            "--",
            "sh",
            "-c",
            "test \"$SECRET\" = sharedvalue && echo OK",
        ])
        .current_dir(&owner.dir) // owner's store + recipients
        .env("ENVSEAL_IDENTITY", &collab.identity) // but collaborator's key
        .env_remove("CLAUDECODE")
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&as_collab.stdout).contains("OK"),
        "collaborator should decrypt after add: {}",
        String::from_utf8_lossy(&as_collab.stderr)
    );

    // Owner removes the collaborator.
    let rm = owner.run(&["remove-recipient", "alice"], "");
    assert_eq!(rm.code, 0, "remove-recipient failed: {}", rm.stderr);
    assert!(
        rm.stderr.to_lowercase().contains("rotate"),
        "should warn about rotation"
    );

    // Now the collaborator can NO LONGER decrypt.
    let after = Command::new(BIN)
        .args(["unlock", "--", "true"])
        .current_dir(&owner.dir)
        .env("ENVSEAL_IDENTITY", &collab.identity)
        .env_remove("CLAUDECODE")
        .output()
        .unwrap();
    assert_ne!(
        after.status.code(),
        Some(0),
        "collaborator must be locked out after removal"
    );

    // Refuse to remove the last recipient.
    let last = owner.run(&["remove-recipient", &owner.public_key()], "");
    assert_ne!(last.code, 0, "must refuse removing the last recipient");
}
