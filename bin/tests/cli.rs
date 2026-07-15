//! End-to-end integration tests driving the real `envstow` binary in isolated temp dirs.
//!
//! These exercise the full lifecycle — init, set, list, unlock round-trip, get masking,
//! edit, and multi-recipient add/remove — against the compiled binary, so they catch
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
        Repo { dir, identity }
    }

    /// Run `envstow <args...>` in this repo with this identity, feeding `stdin_data` to stdin.
    fn run(&self, args: &[&str], stdin_data: &str) -> Output {
        use std::io::Write;
        use std::process::Stdio;
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .current_dir(&self.dir)
            .env("ENVSTOW_IDENTITY", &self.identity)
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

/// Write a directly-executable "editor" that appends `NEW=addedvalue` to the file it's given.
/// A `.bat` on Windows, a `chmod +x` POSIX script elsewhere. Returns its path.
fn write_fake_editor(dir: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let editor = dir.join("fake_editor.bat");
        // %~1 is the first arg; append a line. Echo is fine — the file is dotenv text.
        std::fs::write(&editor, "@echo NEW=addedvalue>>%~1\r\n").unwrap();
        editor
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let editor = dir.join("fake_editor.sh");
        std::fs::write(&editor, "#!/bin/sh\nprintf 'NEW=addedvalue\\n' >> \"$1\"\n").unwrap();
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).unwrap();
        editor
    }
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
    let d = repo.run(&["unlock", "--", "sh", "-c", "printf '%s' \"$SHARED\""], "");
    assert_eq!(d.stdout, "default-val", "default profile value");
    let p = repo.run(
        &[
            "--profile",
            "prod",
            "unlock",
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
            "unlock",
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
    let out = repo.run(&["unlock", "--", "sh", "-c", script], "");
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
            "unlock",
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
    let out = repo.run(&["unlock", "--", "sh", "-c", &script], "");
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
    let out = repo.run(&["unlock", "--", "sh", "-c", &script], "");
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
    let out = repo.run(&["unlock", "--", "sh", "-c", &script], "");
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
    let out = repo.run_env(&["unlock", "--", "true"], "", "DATABASE_URL", "outer-value");
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
            "unlock",
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

    let out = repo.run_env(&["unlock", "--", "true"], "", "TOKEN", "samevalue");
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
            "unlock",
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
            "unlock",
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

    let d = repo.run(&["unlock", "--", "sh", "-c", "printf '%s' \"$SHARED\""], "");
    assert_eq!(d.stdout, "default-val", "default profile must be untouched");
}

#[test]
fn edit_updates_the_store() {
    let repo = Repo::new("edit");
    assert_eq!(repo.run(&["init"], "").code, 0);
    assert_eq!(repo.run(&["set", "EXISTING"], "keepme").code, 0);

    // A fake editor that appends a new secret line to the file it's given. Written per-OS so
    // it's directly executable: a .bat on Windows, a chmod +x shell script elsewhere.
    let editor = write_fake_editor(&repo.dir);

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
        !repo.dir.join(".envstow-edit.tmp").exists(),
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
    let mut as_collab_cmd = Command::new(BIN);
    as_collab_cmd
        .args([
            "unlock",
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
        .args(["unlock", "--", "true"])
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
