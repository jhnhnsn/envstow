//! End-to-end integration tests driving the real `envstow` binary in isolated temp dirs.
//!
//! These exercise the full lifecycle — init, set, list, unlock round-trip, get masking,
//! env/refresh eval payloads, and multi-recipient add/remove — against the compiled binary, so they catch
//! regressions the in-crate unit tests can't (argument parsing, file layout, process spawn,
//! the crypto round-trip through the actual store on disk).
//!
//! Isolation: each test gets a unique temp directory and its own `ENVSTOW_IDENTITY`, so they
//! never touch the developer's real `~/.config/envstow`. No `sops`/`age` CLIs are required —
//! all crypto is compiled into the binary.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_envstow");

/// Every agent-detection marker envstow knows about. Tests must clear ALL of them to simulate a
/// clean non-agent shell — the test process itself may run under an agent that sets some of them
/// (e.g. AI_AGENT), which would otherwise make "not under agent" cases mask unexpectedly.
const AGENT_MARKERS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CURSOR_TRACE_ID",
    "CURSOR_AGENT",
    "AIDER_MODEL",
    "AIDER_CHAT",
    "WINDSURF",
    "WINDSURF_AGENT",
    "AI_AGENT",
    "AGENT",
    "ENVSTOW_AGENT",
];

/// Strip all agent markers from a Command so the child sees a non-agent environment.
fn clear_agent_markers(cmd: &mut Command) {
    for m in AGENT_MARKERS {
        cmd.env_remove(m);
    }
}

/// A disposable repo dir + identity path. Removed on drop.
struct Repo {
    dir: PathBuf,
    identity: PathBuf,
    /// A private config dir for this test. Central stores resolve under it, so a test that
    /// creates one can never touch the developer's real `~/.config/envstow/stores/`.
    config: PathBuf,
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

impl Repo {
    /// Create a fresh, unique temp repo. Uniqueness comes from pid + an atomic counter, so
    /// parallel test threads never collide (we can't use timestamps — but pid+counter is
    /// enough for a single test process).
    fn new(tag: &str) -> Repo {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("envstow-it-{}-{}-{}", tag, std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp repo");
        let identity = dir.join("identity.txt");
        let config = dir.join("config");
        Repo {
            dir,
            identity,
            config,
        }
    }

    /// The path a central store called `name` resolves to for THIS test.
    fn central_store(&self, name: &str) -> PathBuf {
        self.config.join("envstow").join("stores").join(name)
    }

    /// This repo's `.envstow` entry — a directory for a local store, a file for a pointer.
    fn entry(&self) -> PathBuf {
        self.dir.join(".envstow")
    }

    /// Run `envstow <args...>` in this repo with this identity, feeding `stdin_data` to stdin.
    fn run(&self, args: &[&str], stdin_data: &str) -> Output {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .current_dir(&self.dir)
            .env("ENVSTOW_IDENTITY", &self.identity)
            // Central stores resolve under the config dir; pin it into this test's temp dir so
            // nothing here can reach (or create) a store in the developer's real ~/.config.
            .env("XDG_CONFIG_HOME", &self.config)
            .env("APPDATA", &self.config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Ensure a deterministic non-agent, non-tty context unless a test overrides it.
        clear_agent_markers(&mut cmd);
        let mut child = cmd.spawn().expect("spawn envstow");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin_data.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait envstow");
        Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// Run with an extra env var set (e.g. ENVSTOW_AGENT=1 or EDITOR).
    fn run_env(&self, args: &[&str], stdin_data: &str, key: &str, val: &str) -> Output {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .current_dir(&self.dir)
            .env("ENVSTOW_IDENTITY", &self.identity)
            // Central stores resolve under the config dir; pin it into this test's temp dir so
            // nothing here can reach (or create) a store in the developer's real ~/.config.
            .env("XDG_CONFIG_HOME", &self.config)
            .env("APPDATA", &self.config)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        clear_agent_markers(&mut cmd);
        cmd.env(key, val); // test-specified var wins (set AFTER clearing)
        let mut child = cmd.spawn().expect("spawn envstow");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin_data.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait envstow");
        Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn store(&self) -> PathBuf {
        self.dir.join(".envstow").join("default.enc")
    }
    fn recipients(&self) -> PathBuf {
        self.dir.join(".envstow").join("recipients")
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

/// Write a fake clipboard tool onto a private dir that echoes `contents`, named for whatever the
/// host platform's real paste command is. Returns the dir to prepend to PATH, so `set --clipboard`
/// finds this instead of the developer's actual clipboard — tests must never read or depend on it.
#[cfg(unix)]
fn write_fake_clipboard(dir: &Path, contents: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin_dir = dir.join("fakebin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    // Match the first command envstow tries on this platform.
    let name = if cfg!(target_os = "macos") {
        "pbpaste"
    } else {
        "wl-paste"
    };
    let tool = bin_dir.join(name);
    // `cat <<'EOF'` keeps the value out of argv and preserves it byte-for-byte.
    std::fs::write(
        &tool,
        format!("#!/bin/sh\ncat <<'ENVSTOW_EOF'\n{contents}\nENVSTOW_EOF\n"),
    )
    .unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin_dir
}

/// Assert the store on disk is age ciphertext behind envstow's format header, never the given
/// plaintext. The header is a plaintext line before the age payload — everything after it must
/// still be a real age file.
fn store_is_encrypted(path: &Path, plaintext_needle: &str) {
    let bytes = std::fs::read(path).expect("read store");
    let as_text = String::from_utf8_lossy(&bytes);
    let payload = as_text
        .split_once('\n')
        .map(|(_header, rest)| rest)
        .unwrap_or(&as_text);
    assert!(
        payload.starts_with("age-encryption.org/"),
        "store should be an age file behind the format header, got {:?}...",
        as_text.chars().take(40).collect::<String>()
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
fn init_installs_agent_skill_into_the_repo() {
    let repo = Repo::new("initskill");
    // Non-TTY (piped) init installs the skill without prompting.
    let out = repo.run(&["init"], "");
    assert_eq!(out.code, 0, "init failed: {}", out.stderr);

    let skill = repo.dir.join(".claude/skills/envstow/SKILL.md");
    assert!(
        skill.is_file(),
        "init should write the agent skill into the repo"
    );
    let content = std::fs::read_to_string(&skill).unwrap();
    assert!(
        content.contains("name: envstow"),
        "skill has valid frontmatter"
    );
    assert!(
        out.stderr.contains("agent skill"),
        "init should announce the skill install: {}",
        out.stderr
    );
}

#[test]
fn init_no_skill_flag_skips_the_skill() {
    let repo = Repo::new("noskill");
    let out = repo.run(&["init", "--no-skill"], "");
    assert_eq!(out.code, 0, "init --no-skill failed: {}", out.stderr);
    assert!(
        !repo.dir.join(".claude/skills/envstow/SKILL.md").exists(),
        "--no-skill must not write the skill"
    );
}

#[test]
fn profiles_are_isolated() {
    let repo = Repo::new("profiles");
    assert_eq!(repo.run(&["init", "--no-skill"], "").code, 0);

    // Default profile stores one value.
    assert_eq!(repo.run(&["set", "SHARED"], "default-val").code, 0);

    // Create a named profile and store a DIFFERENT value under the same key.
    let created = repo.run(&["profile", "create", "prod"], "");
    assert_eq!(created.code, 0, "profile create failed: {}", created.stderr);
    assert_eq!(
        repo.run(&["--profile", "prod", "set", "SHARED"], "prod-val")
            .code,
        0
    );

    // Each profile reads back its OWN value (isolation).
    let d = repo.run(&["run", "--", "sh", "-c", "printf '%s' \"$SHARED\""], "");
    assert_eq!(d.stdout, "default-val", "default profile value");
    let p = repo.run(
        &[
            "--profile",
            "prod",
            "run",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$SHARED\"",
        ],
        "",
    );
    assert_eq!(p.stdout, "prod-val", "prod profile value");

    // Both flag positions work: post-command --profile too.
    let p2 = repo.run(
        &[
            "run",
            "--profile",
            "prod",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$SHARED\"",
        ],
        "",
    );
    assert_eq!(p2.stdout, "prod-val", "post-command --profile");

    // `profiles` lists both.
    let list = repo.run(&["profiles"], "");
    assert!(
        list.stdout.contains("default"),
        "lists default: {}",
        list.stdout
    );
    assert!(list.stdout.contains("prod"), "lists prod: {}", list.stdout);
}

#[test]
fn unknown_profile_errors_helpfully() {
    let repo = Repo::new("badprofile");
    assert_eq!(repo.run(&["init", "--no-skill"], "").code, 0);
    // Using a profile that was never created should fail with a helpful message, not silently.
    let out = repo.run(&["--profile", "nope", "list"], "");
    assert_ne!(out.code, 0, "unknown profile should fail");
    assert!(
        out.stderr.contains("no such profile") && out.stderr.contains("profile create"),
        "should suggest creating it: {}",
        out.stderr
    );
}

#[test]
fn version_flag_prints_crate_version() {
    let repo = Repo::new("version");
    let expected = format!("envstow {}", env!("CARGO_PKG_VERSION"));
    // All three spellings work and print the same thing, without needing a repo/identity.
    for form in ["--version", "-V", "version"] {
        let out = repo.run(&[form], "");
        assert_eq!(out.code, 0, "`{form}` should exit 0: {}", out.stderr);
        assert_eq!(out.stdout.trim(), expected, "`{form}` output");
    }
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
fn multiline_value_roundtrips() {
    let repo = Repo::new("multiline");
    assert_eq!(repo.run(&["init"], "").code, 0);

    // A multi-line secret (like a PEM key) piped into `set`.
    let pem = "-----BEGIN KEY-----\nline1\nline2\n-----END KEY-----";
    assert_eq!(
        repo.run(&["set", "TLS_KEY"], pem).code,
        0,
        "set multi-line failed"
    );

    // It must come back byte-for-byte through unlock. Write it to a file and compare, so no
    // value is echoed; base64 the file contents for an exact, newline-safe comparison.
    let script = "printf '%s' \"$TLS_KEY\" | base64 | tr -d '\\n'";
    let out = repo.run(&["run", "--", "sh", "-c", script], "");
    let got_b64 = out.stdout.trim();
    use base64::Engine;
    let expected_b64 = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
    assert_eq!(
        got_b64, expected_b64,
        "multi-line value did not round-trip exactly"
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
            "run",
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
    let masked = repo.run_env(&["get", "TOKEN"], "", "ENVSTOW_AGENT", "1");
    assert_eq!(masked.code, 0);
    assert!(
        !masked.stdout.contains("topsecretvalue"),
        "must not reveal under agent"
    );
    assert!(masked.stdout.contains("•"), "should print a mask");

    // --show overrides even under an agent.
    let shown = repo.run_env(&["get", "TOKEN", "--show"], "", "ENVSTOW_AGENT", "1");
    assert_eq!(shown.code, 0);
    assert_eq!(shown.stdout.trim(), "topsecretvalue", "--show must reveal");

    // Piped + not under agent (the $(...) case) reveals.
    let piped = repo.run(&["get", "TOKEN"], "");
    assert_eq!(piped.stdout.trim(), "topsecretvalue");

    // Unknown name → exit 1.
    assert_eq!(repo.run(&["get", "NOPE"], "").code, 1);
}

#[cfg(unix)]
#[test]
fn set_clipboard_stores_the_clipboard_contents() {
    let repo = Repo::new("clip");
    assert_eq!(repo.run(&["init"], "").code, 0);

    let bin_dir = write_fake_clipboard(&repo.dir, "sk-clip-abc123");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = repo.run_env(&["set", "CLIP_TOKEN", "--clipboard"], "", "PATH", &path);
    assert_eq!(out.code, 0, "set --clipboard failed: {}", out.stderr);

    // The value never appears in our output — only a masked confirmation.
    assert!(
        !out.stderr.contains("sk-clip-abc123") && !out.stdout.contains("sk-clip-abc123"),
        "clipboard value must not be printed: {} {}",
        out.stdout,
        out.stderr
    );

    // It round-trips exactly, with the tool's trailing newline stripped.
    let check = repo.run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "test \"$CLIP_TOKEN\" = sk-clip-abc123 && echo OK",
        ],
        "",
    );
    assert!(
        check.stdout.contains("OK"),
        "clipboard value did not round-trip: {} {}",
        check.stdout,
        check.stderr
    );
    store_is_encrypted(&repo.store(), "sk-clip-abc123");
}

#[cfg(unix)]
#[test]
fn set_clipboard_errors_when_no_tool_is_available() {
    let repo = Repo::new("cliperr");
    assert_eq!(repo.run(&["init"], "").code, 0);

    // An empty PATH means no paste tool exists — must fail loudly, not store an empty value.
    let out = repo.run_env(&["set", "NOPE", "--clipboard"], "", "PATH", "");
    assert_ne!(out.code, 0, "should fail with no clipboard tool");
    assert!(
        out.stderr.contains("no clipboard tool found"),
        "should name the problem and suggest piping: {}",
        out.stderr
    );
    assert!(
        !repo.run(&["list"], "").stdout.contains("NOPE"),
        "must not create the secret when the clipboard read fails"
    );
}

/// Write a fake `curl` that reports `tag_url` as the `/releases/latest` redirect target, so update
/// tests never touch the network. Returns the dir to prepend to PATH.
#[cfg(unix)]
fn write_fake_curl(dir: &Path, tag_url: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin_dir = dir.join("curlbin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let tool = bin_dir.join("curl");
    // envstow calls curl with -w '%{url_effective}' and expects the resolved URL on stdout.
    std::fs::write(&tool, format!("#!/bin/sh\nprintf '%s' '{tag_url}'\n")).unwrap();
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin_dir
}

#[cfg(unix)]
#[test]
fn upgrade_check_reports_a_newer_version_without_installing() {
    let repo = Repo::new("updchk");
    // Pretend GitHub's latest is an absurdly high version so this test survives real releases.
    let bin_dir = write_fake_curl(
        &repo.dir,
        "https://github.com/jhnhnsn/envstow/releases/tag/v99.0.0",
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = repo.run_env(&["upgrade", "--check"], "", "PATH", &path);
    assert_eq!(out.code, 0, "--check should succeed: {}", out.stderr);
    assert!(
        out.stderr.contains("99.0.0") && out.stderr.contains("is available"),
        "should report the newer version: {}",
        out.stderr
    );
    // --check must never install: no installer run, no confirmation prompt.
    assert!(
        !out.stderr.contains("running the official installer"),
        "--check must not install: {}",
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn upgrade_says_nothing_to_do_when_current() {
    let repo = Repo::new("updcur");
    // Report our own version as latest.
    let tag = format!(
        "https://github.com/jhnhnsn/envstow/releases/tag/v{}",
        env!("CARGO_PKG_VERSION")
    );
    let bin_dir = write_fake_curl(&repo.dir, &tag);
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = repo.run_env(&["upgrade"], "", "PATH", &path);
    assert_eq!(out.code, 0);
    assert!(
        out.stderr.contains("up to date"),
        "should report up-to-date: {}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("running the official installer"),
        "must not install when already current: {}",
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn upgrade_refuses_when_not_installed_by_our_installer() {
    // No cargo-dist receipt (ENVSTOW_IDENTITY points into a temp dir with no receipt beside it),
    // so this stands in for a Homebrew/AUR/cargo-install copy: envstow must NOT overwrite it.
    let repo = Repo::new("updpkg");
    let bin_dir = write_fake_curl(
        &repo.dir,
        "https://github.com/jhnhnsn/envstow/releases/tag/v99.0.0",
    );
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let out = repo.run_env(&["upgrade"], "", "PATH", &path);
    assert_ne!(out.code, 0, "should refuse without a receipt");
    assert!(
        out.stderr
            .contains("wasn't installed by the envstow installer"),
        "should explain why it refused: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains("brew upgrade") || out.stderr.contains("package manager"),
        "should point at the right updater: {}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("running the official installer"),
        "must not run the installer: {}",
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn upgrade_refuses_to_run_non_interactively_without_yes() {
    // Replacing the running binary by piping a remote script to sh is not something to do by
    // default in CI. A non-TTY caller must opt in explicitly.
    let repo = Repo::new("updci");
    let bin_dir = write_fake_curl(
        &repo.dir,
        "https://github.com/jhnhnsn/envstow/releases/tag/v99.0.0",
    );
    // A cargo-dist receipt beside the identity, so this gets PAST the receipt guard and reaches
    // the confirmation — which is what we're actually testing.
    std::fs::write(
        repo.identity.parent().unwrap().join("envstow-receipt.json"),
        r#"{"provider": {"source": "cargo-dist", "version": "0.32.0"}}"#,
    )
    .unwrap();
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // Repo::run pipes stdin, so this is the non-TTY case.
    let out = repo.run_env(&["upgrade"], "", "PATH", &path);
    assert_ne!(out.code, 0, "should refuse without --yes");
    assert!(
        out.stderr.contains("--yes"),
        "should name the flag that unblocks it: {}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("running the official installer"),
        "must not install: {}",
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn update_still_works_as_an_alias_for_upgrade() {
    // `update` was the real name in 0.1.12 only. It stays as an undocumented alias so anyone who
    // read that changelog isn't broken by the rename.
    let repo = Repo::new("updalias");
    let tag = format!(
        "https://github.com/jhnhnsn/envstow/releases/tag/v{}",
        env!("CARGO_PKG_VERSION")
    );
    let bin_dir = write_fake_curl(&repo.dir, &tag);
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let aliased = repo.run_env(&["update", "--check"], "", "PATH", &path);
    let canonical = repo.run_env(&["upgrade", "--check"], "", "PATH", &path);
    assert_eq!(aliased.code, 0, "alias should work: {}", aliased.stderr);
    assert_eq!(
        aliased.stderr, canonical.stderr,
        "`update` must behave identically to `upgrade`"
    );
}

#[test]
fn upgrade_rejects_unknown_flags() {
    let repo = Repo::new("updflag");
    let out = repo.run(&["upgrade", "--yolo"], "");
    assert_eq!(out.code, 2, "unknown flag should be a usage error");
    assert!(
        out.stderr.contains("usage"),
        "should print usage: {}",
        out.stderr
    );
}

/// Drive `envstow scan-leak` with a piped payload and a set of env vars (name -> value).
/// Returns the exit code and stderr. `ENVSTOW_LOADED` is set to the given names.
fn scan_leak(env: &[(&str, &str)], payload: &str) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut cmd = Command::new(BIN);
    cmd.args(["scan-leak"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    clear_agent_markers(&mut cmd);
    let loaded = env.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(",");
    cmd.env("ENVSTOW_LOADED", loaded);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn envstow");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("wait envstow");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[test]
fn scan_leak_blocks_a_leak_and_allows_a_name_reference() {
    let secret = "sk-fake-9d4f2a7c1e8b";
    // A leaked value -> exit 2 (block), the offending NAME reported, the VALUE never printed.
    let out = scan_leak(
        &[("FAKE_TOKEN", secret)],
        &format!(r#"{{"tool_response":{{"stdout":"the token is {secret} here"}}}}"#),
    );
    assert_eq!(out.code, 2, "a leak must block (exit 2): {}", out.stderr);
    assert!(out.stderr.contains("BLOCKED by envstow"), "{}", out.stderr);
    assert!(
        out.stderr.contains("$FAKE_TOKEN"),
        "names the var: {}",
        out.stderr
    );
    assert!(
        !out.stderr.contains(secret) && !out.stdout.contains(secret),
        "must never print the value: {} {}",
        out.stdout,
        out.stderr
    );

    // A NAME reference (not the value) -> exit 0 (allow).
    let ok = scan_leak(
        &[("FAKE_TOKEN", secret)],
        r#"{"tool_response":{"stdout":"deploy with $FAKE_TOKEN"}}"#,
    );
    assert_eq!(ok.code, 0, "a name reference must pass: {}", ok.stderr);
}

#[test]
fn scan_leak_catches_non_conventional_and_multiline_and_ignores_low_entropy() {
    // DATABASE_URL (no *_KEY/*_TOKEN name) is caught via ENVSTOW_LOADED.
    let dburl = "postgres://admin:hunter2SECRETval@db/main";
    let out = scan_leak(
        &[("DATABASE_URL", dburl)],
        &format!(r#"{{"tool_response":{{"stdout":"connecting to {dburl}"}}}}"#),
    );
    assert_eq!(out.code, 2, "DATABASE_URL leak must block: {}", out.stderr);

    // A multi-line value leaking just its middle line -> block.
    let mid = scan_leak(
        &[(
            "TLS_KEY",
            "-----BEGIN-----\nMIISECRETMIDDLExyz0000\n-----END-----",
        )],
        r#"{"tool_response":{"stdout":"exfiltrated: MIISECRETMIDDLExyz0000"}}"#,
    );
    assert_eq!(
        mid.code, 2,
        "multi-line middle leak must block: {}",
        mid.stderr
    );

    // A low-entropy value (digit run) appearing in output -> allow (no false positive).
    let low = scan_leak(
        &[("PIN", "12345678")],
        r#"{"tool_response":{"stdout":"finished, 12345678 lines"}}"#,
    );
    assert_eq!(
        low.code, 0,
        "low-entropy value must not over-block: {}",
        low.stderr
    );
}

#[test]
fn status_reports_locked_unlocked_profile_and_names() {
    use std::process::Stdio;
    let run = |envs: &[(&str, &str)]| -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(["status"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        clear_agent_markers(&mut cmd);
        // Start from a clean slate for the markers status reads.
        for k in ["ENVSTOW_UNLOCKED", "ENVSTOW_PROFILE", "ENVSTOW_LOADED"] {
            cmd.env_remove(k);
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        Output {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    };

    // Outside an unlock: locked.
    let locked = run(&[]);
    assert_eq!(locked.code, 0);
    assert!(
        locked.stdout.contains("locked"),
        "should report locked: {}",
        locked.stdout
    );
    assert!(
        !locked.stdout.contains("unlocked"),
        "not unlocked: {}",
        locked.stdout
    );

    // Unlocked with a profile and loaded names: reports both, names only.
    let unlocked = run(&[
        ("ENVSTOW_UNLOCKED", "1"),
        ("ENVSTOW_PROFILE", "prod"),
        ("ENVSTOW_LOADED", "DB_URL,API_KEY"),
    ]);
    assert_eq!(unlocked.code, 0);
    assert!(unlocked.stdout.contains("unlocked"), "{}", unlocked.stdout);
    assert!(
        unlocked.stdout.contains("prod"),
        "profile: {}",
        unlocked.stdout
    );
    assert!(
        unlocked.stdout.contains("DB_URL") && unlocked.stdout.contains("API_KEY"),
        "names: {}",
        unlocked.stdout
    );

    // Unlocked, no explicit profile -> default.
    let dflt = run(&[("ENVSTOW_UNLOCKED", "1"), ("ENVSTOW_LOADED", "X")]);
    assert!(
        dflt.stdout.contains("default"),
        "default profile: {}",
        dflt.stdout
    );
}

#[test]
fn scan_leak_rejects_arguments() {
    // It reads stdin; a positional arg is a usage error (exit 2, names the mistake).
    let mut cmd = Command::new(BIN);
    let out = cmd
        .args(["scan-leak", "somefile"])
        .stdin(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("stdin"));
}

#[cfg(unix)]
#[test]
fn refresh_unsets_a_deleted_secret_via_eval() {
    let repo = Repo::new("refresh");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "DOOMED"], "doomedval").code, 0);
    assert_eq!(repo.run(&["set", "KEEPER"], "keeperval").code, 0);

    // The whole point: inside an unlocked shell, delete a secret, then `eval $(envstow refresh)`
    // must clear it from THIS shell — the thing exit+unlock otherwise requires.
    let bin = BIN;
    let script = format!(
        r#"
        test -n "$DOOMED" || {{ echo "SETUP-FAIL: DOOMED not set"; exit 1; }}
        {bin} delete DOOMED --force >/dev/null 2>&1
        # Still set: the store changed, this process's env did not.
        test -n "$DOOMED" || {{ echo "FAIL: expected DOOMED still set pre-refresh"; exit 1; }}
        eval "$({bin} refresh 2>/dev/null)"
        # Now gone, and the surviving secret is untouched.
        test -z "$DOOMED" || {{ echo "FAIL: DOOMED survived refresh"; exit 1; }}
        test -n "$KEEPER" || {{ echo "FAIL: refresh clobbered KEEPER"; exit 1; }}
        echo REFRESH-OK
        "#
    );
    let out = repo.run(&["run", "--", "sh", "-c", &script], "");
    assert!(
        out.stdout.contains("REFRESH-OK"),
        "refresh should unset the deleted secret in-place: {} {}",
        out.stdout,
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn refresh_never_emits_a_value() {
    // stdout is eval'd by the user's shell — it must contain ONLY `unset` lines, never a value,
    // or `eval` would both leak and execute it.
    let repo = Repo::new("refreshsafe");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "GONE"], "goneval").code, 0);
    assert_eq!(repo.run(&["set", "STAYS"], "staysval").code, 0);

    let bin = BIN;
    // Delete one and CHANGE another, then capture exactly what refresh writes to stdout.
    let script = format!(
        r#"
        {bin} delete GONE --force >/dev/null 2>&1
        printf 'newvalue' | {bin} set STAYS >/dev/null 2>&1
        {bin} refresh 2>/dev/null
        "#
    );
    let out = repo.run(&["run", "--", "sh", "-c", &script], "");
    assert!(
        !out.stdout.contains("goneval")
            && !out.stdout.contains("staysval")
            && !out.stdout.contains("newvalue"),
        "stdout must never carry a value: {:?}",
        out.stdout
    );
    for line in out.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("unset "),
            "every eval line must be an unset, got {line:?}"
        );
    }
    assert!(
        out.stdout.contains("unset GONE"),
        "should unset the deleted one: {:?}",
        out.stdout
    );
    assert!(
        !out.stdout.contains("unset STAYS"),
        "must not unset a secret that's still in the store: {:?}",
        out.stdout
    );
}

#[cfg(unix)]
#[test]
fn refresh_only_touches_names_envstow_set() {
    // A same-named var from your shell rc must never be unset — envstow only owns what it set.
    let repo = Repo::new("refreshown");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "MINE"], "mineval").code, 0);

    let bin = BIN;
    // NOT_MINE looks like a stale secret (set in the env, absent from the store) but envstow
    // never set it, so it must not appear in the eval payload.
    let script = format!(
        r#"
        export NOT_MINE=from-the-shell-rc
        {bin} delete MINE --force >/dev/null 2>&1
        {bin} refresh 2>/dev/null
        "#
    );
    let out = repo.run(&["run", "--", "sh", "-c", &script], "");
    assert!(
        !out.stdout.contains("NOT_MINE"),
        "must not unset a var envstow didn't set: {:?}",
        out.stdout
    );
    assert!(
        out.stdout.contains("unset MINE"),
        "should still unset its own: {:?}",
        out.stdout
    );
}

#[test]
fn refresh_outside_an_unlocked_shell_is_refused() {
    let repo = Repo::new("refreshbare");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "X"], "v").code, 0);

    let out = repo.run(&["refresh"], "");
    assert_ne!(out.code, 0, "should refuse outside an unlock");
    assert!(
        out.stderr.contains("not inside"),
        "should explain why: {}",
        out.stderr
    );
    assert!(
        out.stdout.trim().is_empty(),
        "must emit no eval payload: {:?}",
        out.stdout
    );
}

#[test]
fn unlock_warns_when_it_shadows_a_different_value() {
    let repo = Repo::new("shadow");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "DATABASE_URL"], "inner-value").code, 0);
    assert_eq!(repo.run(&["set", "ONLY_HERE"], "uncontested").code, 0);

    // Simulate an outer unlock (or a shell rc) having already set the same name differently.
    let out = repo.run_env(&["run", "--", "true"], "", "DATABASE_URL", "outer-value");
    assert_eq!(out.code, 0, "unlock should still succeed: {}", out.stderr);
    assert!(
        out.stderr.contains("already set with a different value"),
        "should warn about the shadow: {}",
        out.stderr
    );
    assert!(
        out.stderr.contains("DATABASE_URL"),
        "should name the shadowed var: {}",
        out.stderr
    );
    // Only the contested name is listed in the warning — the tail after "wins inside:" is the
    // shadowed list, and an uncontested name must not appear there.
    let shadowed_list = out
        .stderr
        .split("wins inside:")
        .nth(1)
        .expect("warning should have a shadowed list");
    assert!(
        !shadowed_list.contains("ONLY_HERE"),
        "must not list an uncontested name as shadowed: {shadowed_list}"
    );
    // Neither value may be printed — not the outer one, not ours.
    assert!(
        !out.stderr.contains("inner-value") && !out.stderr.contains("outer-value"),
        "must never print either value: {}",
        out.stderr
    );

    // Warning only: the store's value still wins inside the child.
    let check = repo.run_env(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "test \"$DATABASE_URL\" = inner-value && echo OK",
        ],
        "",
        "DATABASE_URL",
        "outer-value",
    );
    assert!(
        check.stdout.contains("OK"),
        "the store's value must shadow the outer one: {} {}",
        check.stdout,
        check.stderr
    );
}

#[test]
fn unlock_is_quiet_when_the_value_is_unchanged() {
    // Re-unlocking the same store (or any name that happens to already hold the same value) is
    // not a shadow — warning there would fire on every name and train people to ignore it.
    let repo = Repo::new("noshadow");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOKEN"], "samevalue").code, 0);

    let out = repo.run_env(&["run", "--", "true"], "", "TOKEN", "samevalue");
    assert_eq!(out.code, 0);
    assert!(
        !out.stderr.contains("already set"),
        "an identical value is not a shadow: {}",
        out.stderr
    );
}

#[test]
fn store_carries_a_format_header() {
    let repo = Repo::new("fmthdr");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOKEN"], "headervalue").code, 0);

    let bytes = std::fs::read(repo.store()).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.starts_with("envstow-format: 2\n"),
        "store should lead with the format header, got {:?}...",
        text.chars().take(30).collect::<String>()
    );
    // The header is metadata, not a leak: the value is still encrypted behind it.
    assert!(
        !text.contains("headervalue"),
        "header must not disturb encryption"
    );
}

#[test]
fn headerless_store_still_reads() {
    // A store written by envstow <= 0.1.8 has no header. Simulate one by stripping the header
    // from a fresh store, then confirm this binary still reads it. Old stores stay readable;
    // only the reverse (a pre-0.1.9 binary reading what we write) is the break.
    let repo = Repo::new("legacy");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "OLD"], "legacyvalue").code, 0);

    let bytes = std::fs::read(repo.store()).unwrap();
    let nl = bytes.iter().position(|b| *b == b'\n').unwrap();
    std::fs::write(repo.store(), &bytes[nl + 1..]).unwrap();
    assert!(
        String::from_utf8_lossy(&std::fs::read(repo.store()).unwrap())
            .starts_with("age-encryption.org/"),
        "test setup: should now look like a pre-header store"
    );

    let check = repo.run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "test \"$OLD\" = legacyvalue && echo OK",
        ],
        "",
    );
    assert!(
        check.stdout.contains("OK"),
        "a headerless (pre-0.1.9) store must still decrypt: {} {}",
        check.stdout,
        check.stderr
    );

    // …and writing it back upgrades it to a headered store, silently.
    assert_eq!(repo.run(&["set", "NEW"], "another").code, 0);
    assert!(
        String::from_utf8_lossy(&std::fs::read(repo.store()).unwrap())
            .starts_with("envstow-format: 2\n"),
        "a write should upgrade a format-1 store to a headered format-2 one"
    );
}

#[test]
fn a_newer_format_store_is_refused_with_an_upgrade_hint() {
    let repo = Repo::new("fmtnew");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOKEN"], "futurevalue").code, 0);

    // Forge a store from a hypothetical future envstow by bumping only the header.
    let bytes = std::fs::read(repo.store()).unwrap();
    let nl = bytes.iter().position(|b| *b == b'\n').unwrap();
    let mut forged = b"envstow-format: 99\n".to_vec();
    forged.extend_from_slice(&bytes[nl + 1..]);
    std::fs::write(repo.store(), &forged).unwrap();

    // Reading says what's wrong and where to go — NOT "decryption failed".
    let read = repo.run(&["list"], "");
    assert_ne!(read.code, 0, "must refuse to read a newer format");
    assert!(
        read.stderr.contains("format 99") && read.stderr.contains("github.com/jhnhnsn/envstow"),
        "read error should name the version and the repo: {}",
        read.stderr
    );
    assert!(
        !read.stderr.contains("No matching keys"),
        "must NOT surface the misleading decryption error: {}",
        read.stderr
    );

    // Writing is refused too, leaving the newer store intact. In practice `set` trips the READ
    // guard first (it decrypts before re-encrypting), so that's the message here; layout's write
    // guard is the backstop beneath it, covered directly in its own unit test.
    let write = repo.run(&["set", "CLOBBER"], "nope");
    assert_ne!(write.code, 0, "must not touch a newer store");
    assert!(
        write.stderr.contains("format 99") && write.stderr.contains("github.com/jhnhnsn/envstow"),
        "write path should also explain and point at the repo: {}",
        write.stderr
    );
    assert_eq!(
        std::fs::read(repo.store()).unwrap(),
        forged,
        "the newer store must be left untouched"
    );
}

#[test]
fn set_delete_nudge_only_inside_an_unlocked_shell() {
    let repo = Repo::new("nudge");
    assert_eq!(repo.run(&["init"], "").code, 0);

    // Outside an unlocked shell: no nudge on either mutation.
    let s = repo.run(&["set", "TOK"], "value1");
    assert!(
        !s.stderr.contains("unlocked shell"),
        "set outside unlock must not nudge: {}",
        s.stderr
    );

    // Inside an unlocked shell (ENVSTOW_UNLOCKED=1): each mutation nudges to reset the shell.
    let s2 = repo.run_env(&["set", "TOK"], "value2", "ENVSTOW_UNLOCKED", "1");
    assert!(
        s2.stderr.contains("unlocked shell") && s2.stderr.contains("envstow unlock"),
        "set inside unlock should nudge: {}",
        s2.stderr
    );
    // The nudge is advisory: stderr only, never stdout, exit unchanged.
    assert_eq!(s2.code, 0);
    assert!(
        !s2.stdout.contains("unlocked shell"),
        "nudge must not touch stdout: {:?}",
        s2.stdout
    );

    let d = repo.run_env(&["delete", "TOK", "--force"], "", "ENVSTOW_UNLOCKED", "1");
    assert!(
        d.stderr.contains("unlocked shell"),
        "delete inside unlock should nudge: {}",
        d.stderr
    );
}

#[test]
fn edit_is_removed_with_a_helpful_tombstone() {
    // `edit` was removed (it parked the whole store's plaintext on disk for an editor session).
    // Anyone who still types it gets pointed at set/delete, not a bare "unknown command".
    let repo = Repo::new("editgone");
    assert_eq!(repo.run(&["init"], "").code, 0);
    let out = repo.run_env(&["edit"], "", "EDITOR", "cat");
    assert_ne!(out.code, 0, "edit must no longer run");
    assert!(
        out.stderr.contains("removed") && out.stderr.contains("envstow set"),
        "tombstone should explain and redirect: {}",
        out.stderr
    );
    assert!(out.stdout.is_empty(), "edit must not decrypt anything");
}

#[test]
fn delete_removes_only_the_named_secret() {
    let repo = Repo::new("delete");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "DOOMED"], "deleteme").code, 0);
    assert_eq!(repo.run(&["set", "KEEPER"], "keepme").code, 0);

    let out = repo.run(&["delete", "DOOMED"], "");
    assert_eq!(out.code, 0, "delete failed: {}", out.stderr);
    assert!(
        out.stderr.to_lowercase().contains("rotate"),
        "should warn about rotation: {}",
        out.stderr
    );

    // The name is gone from list, the neighbour survives.
    let list = repo.run(&["list"], "");
    assert!(!list.stdout.contains("DOOMED"), "deleted name still listed");
    assert!(list.stdout.contains("KEEPER"), "neighbour must survive");

    // The store still decrypts and the survivor round-trips unchanged.
    let check = repo.run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "test \"$KEEPER\" = keepme && test -z \"$DOOMED\" && echo OK",
        ],
        "",
    );
    assert!(
        check.stdout.contains("OK"),
        "post-delete store wrong: {} {}",
        check.stdout,
        check.stderr
    );

    // The deleted value is no longer in the re-encrypted store.
    store_is_encrypted(&repo.store(), "deleteme");

    // get on the deleted name fails; deleting an unknown name fails.
    assert_eq!(repo.run(&["get", "DOOMED"], "").code, 1);
    assert_eq!(repo.run(&["delete", "NOPE"], "").code, 1);
}

#[test]
fn delete_is_scoped_to_one_profile() {
    let repo = Repo::new("delprofile");
    assert_eq!(repo.run(&["init", "--no-skill"], "").code, 0);
    assert_eq!(repo.run(&["set", "SHARED"], "default-val").code, 0);
    assert_eq!(repo.run(&["profile", "create", "prod"], "").code, 0);
    assert_eq!(
        repo.run(&["--profile", "prod", "set", "SHARED"], "prod-val")
            .code,
        0
    );

    // Deleting from prod must leave the same name in default untouched.
    assert_eq!(
        repo.run(&["--profile", "prod", "delete", "SHARED"], "")
            .code,
        0
    );
    assert!(!repo
        .run(&["--profile", "prod", "list"], "")
        .stdout
        .contains("SHARED"));

    let d = repo.run(&["run", "--", "sh", "-c", "printf '%s' \"$SHARED\""], "");
    assert_eq!(d.stdout, "default-val", "default profile must be untouched");
}

#[cfg(unix)]
#[test]
fn a_world_readable_identity_key_warns() {
    use std::os::unix::fs::PermissionsExt;
    let repo = Repo::new("keyperms");
    assert_eq!(repo.run(&["init", "--no-skill"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOK"], "sk-value-abc123").code, 0);

    // init makes the key 0600; simulate drift to group/other-readable.
    std::fs::set_permissions(&repo.identity, std::fs::Permissions::from_mode(0o644)).unwrap();

    let out = repo.run(&["list"], "");
    assert_eq!(out.code, 0, "should still work, just warn: {}", out.stderr);
    assert!(
        out.stderr.contains("readable by others") && out.stderr.contains("chmod 600"),
        "a loose-perms identity should warn with the fix: {}",
        out.stderr
    );

    // The warning must go to stderr only — a `$(envstow get ...)` capture must stay clean.
    assert!(
        !out.stdout.contains("readable by others"),
        "warning must not pollute stdout: {:?}",
        out.stdout
    );

    // A correctly-locked key is silent.
    std::fs::set_permissions(&repo.identity, std::fs::Permissions::from_mode(0o600)).unwrap();
    let quiet = repo.run(&["list"], "");
    assert!(
        !quiet.stderr.contains("readable by others"),
        "0600 key must not warn: {}",
        quiet.stderr
    );
}

#[test]
fn a_newcomer_is_told_how_to_get_access_not_just_that_it_failed() {
    // The most common first-run failure: installed envstow, cloned the repo, nobody's added you.
    // age says "No matching keys found", which reads like a bug — especially since `init` has
    // just reported adding your key to `recipients`. Both messages must name the real next step.
    let owner = Repo::new("newcomer-owner");
    assert_eq!(owner.run(&["init", "--no-skill"], "").code, 0);
    assert_eq!(owner.run(&["set", "SECRET"], "ownersvalue").code, 0);

    // A newcomer with their own identity, running init INSIDE the owner's repo (what ONBOARDING
    // currently tells people to do) — this appends their key to recipients but grants nothing.
    let newcomer_id = owner.dir.join("newcomer-identity.txt");
    let init = Command::new(BIN)
        .args(["init", "--no-skill"])
        .current_dir(&owner.dir)
        .env("ENVSTOW_IDENTITY", &newcomer_id)
        .output()
        .unwrap();
    let init_err = String::from_utf8_lossy(&init.stderr);
    // init must NOT claim they're ready — they can't decrypt yet.
    assert!(
        !init_err.contains("Ready."),
        "init must not say Ready when joining someone else's store: {init_err}"
    );
    assert!(
        init_err.contains("add-recipient"),
        "init should name the command that grants access: {init_err}"
    );

    // Now the decryption failure itself must explain, not just fail. Note `init`-in-the-repo has
    // just APPENDED their key to recipients, so they're in the listed-but-not-yet-re-encrypted
    // case — the honest fix is a recipient running `reencrypt`, and that's what it must say.
    let unlock = Command::new(BIN)
        .args(["run", "--", "true"])
        .current_dir(&owner.dir)
        .env("ENVSTOW_IDENTITY", &newcomer_id)
        .output()
        .unwrap();
    assert_ne!(unlock.status.code(), Some(0), "should fail");
    let err = String::from_utf8_lossy(&unlock.stderr);
    assert!(
        err.contains("reencrypt"),
        "should name the command that fixes it: {err}"
    );
    assert!(
        err.contains("input to") && err.contains("not an access list"),
        "should correct the mental model that recipients == access: {err}"
    );
    assert!(
        !err.contains("No matching keys"),
        "should replace the cryptic age error, not append to it: {err}"
    );
}

#[test]
fn a_key_that_was_never_added_is_told_to_send_its_pubkey() {
    // The other newcomer path: they generated an identity WITHOUT running init in the repo (or
    // ran it elsewhere), so their key was never appended to recipients. Here the fix is
    // `add-recipient`, and they need their public key printed so they can send it.
    let owner = Repo::new("never-owner");
    assert_eq!(owner.run(&["init", "--no-skill"], "").code, 0);
    assert_eq!(owner.run(&["set", "SECRET"], "ownersvalue").code, 0);

    let stranger = Repo::new("never-stranger");
    assert_eq!(stranger.run(&["init", "--no-skill"], "").code, 0);

    let out = Command::new(BIN)
        .args(["list"])
        .current_dir(&owner.dir) // owner's store + recipients (stranger is absent from it)
        .env("ENVSTOW_IDENTITY", &stranger.identity)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0), "can't decrypt");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("add-recipient"),
        "should name the command that grants access: {err}"
    );
    assert!(
        err.contains(&stranger.public_key()),
        "should print THEIR public key so they can send it: {err}"
    );
    assert!(
        !err.contains("No matching keys"),
        "should explain, not surface the raw age error: {err}"
    );
}

#[test]
fn a_listed_but_not_yet_reencrypted_key_gets_a_different_hint() {
    // Distinct case: your key IS in recipients (someone committed it, or you added it yourself),
    // but nobody has re-encrypted, so the ciphertext still doesn't include you. The fix is
    // `reencrypt`, not `add-recipient` — the message must say so.
    let owner = Repo::new("stale-owner");
    assert_eq!(owner.run(&["init", "--no-skill"], "").code, 0);
    assert_eq!(owner.run(&["set", "SECRET"], "ownersvalue").code, 0);

    // Generate a second identity elsewhere, then hand-add its key to recipients WITHOUT
    // re-encrypting — exactly what `init`-in-the-repo does.
    let other = Repo::new("stale-other");
    assert_eq!(other.run(&["init", "--no-skill"], "").code, 0);
    let other_pub = other.public_key();
    let mut recips = std::fs::read_to_string(owner.recipients()).unwrap();
    recips.push_str(&format!("{other_pub}  # pending\n"));
    std::fs::write(owner.recipients(), recips).unwrap();

    let out = Command::new(BIN)
        .args(["list"])
        .current_dir(&owner.dir)
        .env("ENVSTOW_IDENTITY", &other.identity)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(0), "still can't decrypt");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("reencrypt"),
        "listed-but-stale should point at reencrypt: {err}"
    );
    assert!(
        !err.contains("No matching keys"),
        "should explain, not surface the raw age error: {err}"
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
    let mut as_collab_cmd = Command::new(BIN);
    as_collab_cmd
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "test \"$SECRET\" = sharedvalue && echo OK",
        ])
        .current_dir(&owner.dir) // owner's store + recipients
        .env("ENVSTOW_IDENTITY", &collab.identity); // but collaborator's key
    clear_agent_markers(&mut as_collab_cmd);
    let as_collab = as_collab_cmd.output().unwrap();
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
    let mut after_cmd = Command::new(BIN);
    after_cmd
        .args(["run", "--", "true"])
        .current_dir(&owner.dir)
        .env("ENVSTOW_IDENTITY", &collab.identity);
    clear_agent_markers(&mut after_cmd);
    let after = after_cmd.output().unwrap();
    assert_ne!(
        after.status.code(),
        Some(0),
        "collaborator must be locked out after removal"
    );

    // Refuse to remove the last recipient.
    let last = owner.run(&["remove-recipient", &owner.public_key()], "");
    assert_ne!(last.code, 0, "must refuse removing the last recipient");
}

// ---------------------------------------------------------------------------------------------
// `env` — the eval-able current-shell loader
// ---------------------------------------------------------------------------------------------

#[cfg(unix)] // drives the round-trip through `sh -c`, like the refresh tests above
#[test]
fn env_emits_only_shell_code_and_loads_via_eval() {
    let repo = Repo::new("envcmd");
    assert_eq!(repo.run(&["init"], "").code, 0);
    // A hostile value: embedded single quote, `;`, and a command substitution. If quoting is
    // wrong, the eval either breaks or EXECUTES it.
    let hostile = "it's;$(echo pwned)";
    assert_eq!(repo.run(&["set", "STAYS"], hostile).code, 0);

    // Piped + non-agent (the harness default): stdout must be shell code only.
    let out = repo.run(&["env"], "");
    assert_eq!(out.code, 0, "env should succeed: {}", out.stderr);
    for line in out.stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with("export ") || line.starts_with("unset "),
            "every eval line must be an export or unset, got {line:?}"
        );
    }
    assert!(
        out.stdout.contains("export ENVSTOW_UNLOCKED=1")
            && out.stdout.contains("export ENVSTOW_LOADED="),
        "must emit the session markers: {:?}",
        out.stdout
    );

    // Round-trip: a shell that evals the output holds the exact value — unexecuted.
    let bin = BIN;
    let script = format!(
        r#"
        unset STAYS
        eval "$({bin} env 2>/dev/null)"
        printf '%s' "$STAYS"
        "#
    );
    let evaled = repo.run(&["run", "--", "sh", "-c", &script], "");
    assert_eq!(
        evaled.stdout, hostile,
        "eval must reproduce the value byte-for-byte, not execute it"
    );
    assert!(
        !evaled.stdout.contains("pwned\n"),
        "the $() must never run: {:?}",
        evaled.stdout
    );
}

#[cfg(unix)]
#[test]
fn env_syncs_a_changed_store_where_refresh_cannot() {
    // The scenario the nudge points at: set/delete inside an unlocked shell, then
    // eval "$(envstow env)" resets this shell's values — updated AND deleted both handled.
    let repo = Repo::new("envsync");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "GONE"], "goneval").code, 0);
    assert_eq!(repo.run(&["set", "STAYS"], "oldval").code, 0);

    let bin = BIN;
    let script = format!(
        r#"
        {bin} delete GONE --force >/dev/null 2>&1
        printf 'newval' | {bin} set STAYS >/dev/null 2>&1
        eval "$({bin} env 2>/dev/null)"
        printf 'STAYS=%s GONE=%s' "$STAYS" "${{GONE:-unset}}"
        "#
    );
    let out = repo.run(&["run", "--", "sh", "-c", &script], "");
    assert_eq!(
        out.stdout, "STAYS=newval GONE=unset",
        "env must update changed values and unset deleted ones: {:?} / {}",
        out.stdout, out.stderr
    );
}

#[test]
fn env_refuses_under_agent() {
    let repo = Repo::new("envagent");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOK"], "secretval").code, 0);

    let out = repo.run_env(&["env"], "", "CLAUDECODE", "1");
    assert_ne!(out.code, 0, "env must refuse under an agent");
    assert!(
        out.stdout.is_empty(),
        "not one byte on stdout under an agent: {:?}",
        out.stdout
    );
    assert!(
        !out.stderr.contains("secretval") && out.stderr.contains("run --only"),
        "stderr should redirect the agent to run --only, without the value: {}",
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn env_off_unsets_names_without_needing_values() {
    let repo = Repo::new("envoff");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOK"], "secretval").code, 0);

    let bin = BIN;
    let script = format!(
        r#"
        eval "$({bin} env --off 2>/dev/null)"
        printf 'TOK=%s UNLOCKED=%s' "${{TOK:-unset}}" "${{ENVSTOW_UNLOCKED:-unset}}"
        "#
    );
    let out = repo.run(&["run", "--", "sh", "-c", &script], "");
    assert_eq!(
        out.stdout, "TOK=unset UNLOCKED=unset",
        "--off must clear the secrets and the markers: {:?} / {}",
        out.stdout, out.stderr
    );

    // --off prints names only, so it is allowed even under an agent.
    let agent = repo.run_env(&["env", "--off"], "", "CLAUDECODE", "1");
    assert_eq!(
        agent.code, 0,
        "--off is name-only, agent-safe: {}",
        agent.stderr
    );
    assert!(!agent.stdout.contains("secretval") && !agent.stderr.contains("secretval"));
}

// ---------------------------------------------------------------------------------------------
// `run` — the one-shot verb, with `--only` least-privilege scoping
// ---------------------------------------------------------------------------------------------

#[cfg(unix)] // drives the child through `sh -c`, like the unlock/refresh tests
#[test]
fn run_only_scopes_the_env_to_the_named_secrets() {
    let repo = Repo::new("runonly");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "WANTED_A"], "aval").code, 0);
    assert_eq!(repo.run(&["set", "WANTED_B"], "bval").code, 0);
    assert_eq!(repo.run(&["set", "EXCLUDED"], "secretval").code, 0);

    // Comma list and repeated flag together; the child sees exactly the two named secrets,
    // and ENVSTOW_LOADED reflects the scope (so status / the leak guard see the truth).
    let out = repo.run(
        &[
            "run", "--only", "WANTED_A", "--only=WANTED_B", "--", "sh", "-c",
            r#"printf 'A=%s B=%s EXCL=%s LOADED=%s' "$WANTED_A" "$WANTED_B" "${EXCLUDED:-unset}" "$ENVSTOW_LOADED""#,
        ],
        "",
    );
    assert_eq!(out.code, 0, "run failed: {}", out.stderr);
    assert_eq!(
        out.stdout, "A=aval B=bval EXCL=unset LOADED=WANTED_A,WANTED_B",
        "scope must be exactly the named secrets: {:?} / {}",
        out.stdout, out.stderr
    );
    assert!(
        !out.stderr.contains("EXCLUDED"),
        "the loaded-names banner must not name unscoped secrets: {}",
        out.stderr
    );
}

#[cfg(unix)]
#[test]
fn run_without_only_matches_unlock_dashdash() {
    let repo = Repo::new("runall");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOK"], "tokval").code, 0);

    // `--` is optional: the first non-flag token starts the command.
    let out = repo.run(&["run", "sh", "-c", r#"printf '%s' "$TOK""#], "");
    assert_eq!(out.code, 0, "run failed: {}", out.stderr);
    assert_eq!(out.stdout, "tokval");
}

#[test]
fn run_rejects_unknown_names_before_spawning() {
    let repo = Repo::new("runtypo");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "SENTRY_DSN"], "dsnval").code, 0);

    // A typo'd name must refuse with a suggestion, and the command must never run.
    let out = repo.run(
        &["run", "--only", "SENTRY_DNS", "--", "sh", "-c", "echo RAN"],
        "",
    );
    assert_ne!(out.code, 0, "unknown name must be a hard error");
    assert!(
        out.stderr.contains("SENTRY_DNS") && out.stderr.contains("did you mean SENTRY_DSN"),
        "should name the miss and suggest the fix: {}",
        out.stderr
    );
    assert!(
        !out.stdout.contains("RAN"),
        "child must not spawn on a bad --only: {:?}",
        out.stdout
    );
}

#[test]
fn unlock_with_a_command_redirects_to_run() {
    // The one-shot form moved to `run` — `unlock` is subshell-only. Old muscle memory gets a
    // pointer, and the command must NOT execute.
    let repo = Repo::new("unlocksplit");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "TOK"], "tokval").code, 0);

    for form in [
        vec!["unlock", "--", "sh", "-c", "echo RAN"],
        vec!["unlock", "sh", "-c", "echo RAN"],
    ] {
        let out = repo.run(&form, "");
        assert_ne!(out.code, 0, "unlock with args must refuse: {form:?}");
        assert!(
            out.stderr.contains("envstow run"),
            "should redirect to run: {}",
            out.stderr
        );
        assert!(
            !out.stdout.contains("RAN"),
            "the command must not execute: {:?}",
            out.stdout
        );
    }
}

#[test]
fn run_requires_a_command() {
    let repo = Repo::new("runbare");
    assert_eq!(repo.run(&["init"], "").code, 0);
    let out = repo.run(&["run"], "");
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("usage") && out.stderr.contains("unlock"),
        "bare run should show usage and point subshell-seekers at unlock: {}",
        out.stderr
    );

    let flags_only = repo.run(&["run", "--only", "X"], "");
    assert_ne!(
        flags_only.code, 0,
        "flags without a command are not a command"
    );
}

// ---------------------------------------------------------------------------
// store resolution: local vs central, and the `.envstow` file-or-directory rule
// ---------------------------------------------------------------------------

#[test]
fn init_with_a_store_name_keeps_everything_out_of_the_repo() {
    // The public-repo case: nothing encrypted may enter the working tree. What lands in the
    // repo is a pointer FILE naming the store; the ciphertext and recipients live centrally.
    let repo = Repo::new("central-init");
    let out = repo.run(&["init", "--store", "acme", "--no-skill"], "");
    assert_eq!(out.code, 0, "init --store failed: {}", out.stderr);

    let entry = repo.entry();
    assert!(
        entry.is_file(),
        "`.envstow` in the repo must be a FILE (a pointer), not a store dir"
    );
    let text = std::fs::read_to_string(&entry).unwrap();
    assert!(
        text.contains("store: acme"),
        "pointer names the store: {text}"
    );
    assert!(
        !text.contains("age1"),
        "a pointer must not contain key material: {text}"
    );

    // The store itself is central, and complete.
    let central = repo.central_store("acme");
    assert!(
        central.join("recipients").is_file(),
        "central recipients created"
    );
    assert!(
        central.join("default.enc").is_file(),
        "central store created"
    );

    // Nothing encrypted anywhere in the repo — the whole point.
    for e in std::fs::read_dir(&repo.dir).unwrap().flatten() {
        assert_ne!(
            e.path().extension().and_then(|s| s.to_str()),
            Some("enc"),
            "no ciphertext may be written into the repo: {:?}",
            e.path()
        );
    }
}

#[test]
fn a_pointer_file_resolves_with_no_flag_at_all() {
    // The reason the pointer exists: after init, ordinary commands in this repo just work.
    // If this needed `--store` every time, forgetting it would fall through to the walk.
    let repo = Repo::new("central-use");
    assert_eq!(
        repo.run(&["init", "--store", "acme", "--no-skill"], "")
            .code,
        0
    );

    assert_eq!(repo.run(&["set", "TOKEN"], "s3cr3t").code, 0);
    let listed = repo.run(&["list"], "");
    assert!(
        listed.stdout.contains("TOKEN"),
        "set/list via pointer: {}",
        listed.stdout
    );

    // And the value round-trips through the child environment.
    let got = repo.run(&["run", "--", "sh", "-c", "printf '%s' \"$TOKEN\""], "");
    assert_eq!(
        got.stdout, "s3cr3t",
        "value round-trips via the central store"
    );

    // A subdirectory still resolves — the walk finds the pointer above it.
    let sub = repo.dir.join("nested/deep");
    std::fs::create_dir_all(&sub).unwrap();
    let mut cmd = Command::new(BIN);
    cmd.args(["list"])
        .current_dir(&sub)
        .env("ENVSTOW_IDENTITY", &repo.identity)
        .env("XDG_CONFIG_HOME", &repo.config)
        .env("APPDATA", &repo.config);
    clear_agent_markers(&mut cmd);
    let out = cmd.output().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("TOKEN"),
        "the walk must find a pointer from a subdirectory too"
    );
}

#[test]
fn a_dangling_pointer_fails_loudly_instead_of_finding_another_store() {
    // Clone a repo whose central store you don't have. The failure must NAME the store and say
    // how to get one — never silently resolve elsewhere, which for this feature's whole purpose
    // would mean falling back to a store the user meant to avoid.
    let repo = Repo::new("dangling");
    std::fs::write(repo.entry(), "store: notmine\n").unwrap();

    let out = repo.run(&["list"], "");
    assert_ne!(out.code, 0, "a dangling pointer must fail");
    assert!(
        out.stderr.contains("notmine") && out.stderr.contains("init --store notmine"),
        "must name the store and the fix: {}",
        out.stderr
    );
}

#[test]
fn a_malformed_pointer_is_an_error_not_a_fallthrough() {
    let repo = Repo::new("badpointer");
    std::fs::write(repo.entry(), "this is not a pointer\n").unwrap();

    let out = repo.run(&["list"], "");
    assert_ne!(out.code, 0, "an unreadable pointer must fail");
    assert!(
        out.stderr.contains("store: <name>"),
        "must show the expected format: {}",
        out.stderr
    );
}

#[test]
fn a_local_store_still_works_exactly_as_before() {
    // The backward-compatibility guarantee: plain `init` is untouched by any of this.
    let repo = Repo::new("local-still");
    assert_eq!(repo.run(&["init", "--no-skill"], "").code, 0);
    assert!(repo.entry().is_dir(), "plain init still makes a DIRECTORY");
    assert!(repo.store().is_file(), "…containing the store");
    assert_eq!(repo.run(&["set", "K"], "v").code, 0);
    assert!(repo.run(&["list"], "").stdout.contains("K"));
}

#[test]
fn init_refuses_to_clobber_a_pointer_with_a_local_store() {
    // `.envstow` is a file OR a directory, never both. A plain `init` on top of a pointer must
    // refuse: the pointer may name the only copy of someone's secrets.
    let repo = Repo::new("clobber");
    assert_eq!(
        repo.run(&["init", "--store", "acme", "--no-skill"], "")
            .code,
        0
    );

    let out = repo.run(&["init", "--no-skill"], "");
    assert_ne!(out.code, 0, "plain init over a pointer must refuse");
    assert!(
        out.stderr.contains("pointer"),
        "must explain why: {}",
        out.stderr
    );
    assert!(repo.entry().is_file(), "the pointer must survive untouched");
}

#[test]
fn stores_have_separate_recipients_and_separate_secrets() {
    // The axis `--store` adds that `--profile` never had: profiles share one recipients file,
    // stores do not. Two stores must be fully independent.
    let repo = Repo::new("two-stores");
    assert_eq!(
        repo.run(&["init", "--store", "one", "--no-skill"], "").code,
        0
    );
    // Second init in a fresh dir so the pointer doesn't collide; same identity + config.
    let other = repo.dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let mut cmd = Command::new(BIN);
    cmd.args(["init", "--store", "two", "--no-skill"])
        .current_dir(&other)
        .env("ENVSTOW_IDENTITY", &repo.identity)
        .env("XDG_CONFIG_HOME", &repo.config)
        .env("APPDATA", &repo.config);
    clear_agent_markers(&mut cmd);
    assert!(cmd.output().unwrap().status.success(), "second store init");

    assert_eq!(repo.run(&["--store", "one", "set", "A"], "one-val").code, 0);
    assert_eq!(repo.run(&["--store", "two", "set", "B"], "two-val").code, 0);

    let one = repo.run(&["--store", "one", "list"], "").stdout;
    let two = repo.run(&["--store", "two", "list"], "").stdout;
    assert!(
        one.contains('A') && !one.contains('B'),
        "store one sees only its own: {one}"
    );
    assert!(
        two.contains('B') && !two.contains('A'),
        "store two sees only its own: {two}"
    );

    // Separate recipients files, not a shared one.
    assert!(repo.central_store("one").join("recipients").is_file());
    assert!(repo.central_store("two").join("recipients").is_file());
}

#[test]
fn an_unknown_store_name_lists_the_real_ones() {
    let repo = Repo::new("typo");
    assert_eq!(
        repo.run(&["init", "--store", "acme", "--no-skill"], "")
            .code,
        0
    );

    let out = repo.run(&["--store", "acmee", "list"], "");
    assert_ne!(out.code, 0, "a typo'd store must not silently resolve");
    assert!(
        out.stderr.contains("acme"),
        "must list what does exist so the typo is obvious: {}",
        out.stderr
    );
}

#[test]
fn store_command_reports_which_store_is_in_effect_and_why() {
    // With four ways to select a store, "am I writing where I think?" must be answerable.
    let repo = Repo::new("store-cmd");
    assert_eq!(
        repo.run(&["init", "--store", "acme", "--no-skill"], "")
            .code,
        0
    );

    let out = repo.run(&["store"], "");
    assert_eq!(out.code, 0, "store command failed: {}", out.stderr);
    let all = format!("{}{}", out.stdout, out.stderr);
    assert!(all.contains("acme"), "names the store: {all}");
    assert!(
        all.contains("via") || all.contains(".envstow"),
        "says WHY it resolved that way: {all}"
    );
}

#[test]
fn store_and_store_dir_together_is_refused() {
    // Passing both is a mistake about which store you're touching — stop rather than pick.
    let repo = Repo::new("bothflags");
    let out = repo.run(&["--store", "a", "--store-dir", "/tmp/x", "list"], "");
    assert_ne!(out.code, 0);
    assert!(
        out.stderr.contains("not both"),
        "must say only one may be given: {}",
        out.stderr
    );
}

#[test]
fn store_dir_points_at_an_arbitrary_directory() {
    // The shared-folder case (Drive/Dropbox/Syncthing): a store that is neither in the repo nor
    // in the central area, reached by path.
    let repo = Repo::new("storedir");
    let shared = repo.dir.join("Synced Folder");
    let shared_s = shared.to_string_lossy().to_string();

    let out = repo.run(&["init", "--store-dir", &shared_s, "--no-skill"], "");
    assert_eq!(out.code, 0, "init --store-dir failed: {}", out.stderr);
    assert!(
        shared.join("default.enc").is_file(),
        "store created in the given dir"
    );
    assert!(
        !repo.entry().exists(),
        "a PATH must not be committed as a pointer — it wouldn't resolve on another machine"
    );

    assert_eq!(
        repo.run(&["--store-dir", &shared_s, "set", "S"], "v").code,
        0
    );
    assert!(repo
        .run(&["--store-dir", &shared_s, "list"], "")
        .stdout
        .contains('S'));
}

#[test]
fn init_refuses_to_fork_a_store_this_repo_already_points_at() {
    // Joining a colleague's central-store project. The local flow catches this for free — a
    // clone brings `recipients` along, so init sees other keys and says "you're joining." A
    // central store isn't cloned, so without this guard init happily makes a SECOND empty store
    // with the same name: two stores, no sync, and nothing to tell you they diverged.
    let repo = Repo::new("fork-guard");
    assert_eq!(
        repo.run(&["init", "--store", "acme", "--no-skill"], "")
            .code,
        0
    );
    assert_eq!(repo.run(&["set", "SHARED"], "alice-val").code, 0);

    // A second machine: same repo (same pointer), different identity AND config dir.
    let other_cfg = repo.dir.join("other-cfg");
    let other_id = repo.dir.join("other-id.txt");
    let mut cmd = Command::new(BIN);
    cmd.args(["init", "--store", "acme", "--no-skill"])
        .current_dir(&repo.dir)
        .env("ENVSTOW_IDENTITY", &other_id)
        .env("XDG_CONFIG_HOME", &other_cfg)
        .env("APPDATA", &other_cfg);
    clear_agent_markers(&mut cmd);
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "must refuse, got: {err}");
    assert!(
        err.contains("already points at the central store 'acme'"),
        "must name the store and the situation: {err}"
    );
    assert!(
        err.contains("add-recipient"),
        "must show how to actually join: {err}"
    );
    assert!(
        !other_cfg.join("envstow/stores/acme/default.enc").is_file(),
        "the divergent store must NOT have been created"
    );

    // The original store is untouched, and its owner can still re-init idempotently.
    assert!(repo.run(&["list"], "").stdout.contains("SHARED"));
    assert_eq!(
        repo.run(&["init", "--store", "acme", "--no-skill"], "")
            .code,
        0,
        "the owner (who HAS the store) must still be able to re-run init"
    );

    // A differently-named store here is a deliberate act, not a fork — still allowed.
    let mut cmd = Command::new(BIN);
    cmd.args(["init", "--store", "unrelated", "--no-skill"])
        .current_dir(&repo.dir)
        .env("ENVSTOW_IDENTITY", &other_id)
        .env("XDG_CONFIG_HOME", &other_cfg)
        .env("APPDATA", &other_cfg);
    clear_agent_markers(&mut cmd);
    assert!(
        cmd.output().unwrap().status.success(),
        "a different store name is not a fork"
    );
}

#[test]
fn plain_init_over_a_pointer_advises_by_whether_the_store_is_here() {
    // Cloning a repo that carries a committed pointer and reflexively running `envstow init` is
    // the likeliest way to meet this error, and in that case the store is NOT on the machine —
    // so "add secrets with `envstow set`" would send the user straight into a second failure.
    // The advice has to split on whether the named store actually exists.
    let repo = Repo::new("ptr-init");
    std::fs::write(repo.entry(), "store: acme\n").unwrap();

    let absent = repo.run(&["init", "--no-skill"], "");
    assert_ne!(absent.code, 0, "must refuse to clobber the pointer");
    assert!(
        absent.stderr.contains("init --store acme"),
        "with the store absent, must point at the join command: {}",
        absent.stderr
    );
    assert!(
        !absent.stderr.contains("Add secrets with"),
        "must NOT suggest `set`, which cannot work without the store: {}",
        absent.stderr
    );

    // Now actually acquire the store the pointer names, and the advice should flip. Created from
    // a directory WITHOUT that pointer — from inside this repo, the fork guard would (rightly)
    // refuse, since a pointer plus a missing store means "join", not "create".
    let elsewhere = repo.dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let mut cmd = Command::new(BIN);
    cmd.args(["init", "--store", "acme", "--no-skill"])
        .current_dir(&elsewhere)
        .env("ENVSTOW_IDENTITY", &repo.identity)
        .env("XDG_CONFIG_HOME", &repo.config)
        .env("APPDATA", &repo.config);
    clear_agent_markers(&mut cmd);
    assert!(cmd.output().unwrap().status.success(), "create the store");
    let present = repo.run(&["init", "--no-skill"], "");
    assert_ne!(present.code, 0, "still refuses — there's nothing to init");
    assert!(
        present.stderr.contains("envstow set"),
        "with the store present, `set` IS the right next step: {}",
        present.stderr
    );

    // An unreadable pointer shouldn't guess a store name.
    std::fs::write(repo.entry(), "garbage\n").unwrap();
    let bad = repo.run(&["init", "--no-skill"], "");
    assert_ne!(bad.code, 0);
    assert!(
        bad.stderr.contains("isn't a readable pointer"),
        "must say the file is unreadable rather than invent a name: {}",
        bad.stderr
    );

    // The escape hatch every branch advertises must actually work.
    std::fs::remove_file(repo.entry()).unwrap();
    assert_eq!(
        repo.run(&["init", "--no-skill"], "").code,
        0,
        "deleting the pointer must allow a local store"
    );
    assert!(repo.entry().is_dir(), "…and that store is a directory");
}
