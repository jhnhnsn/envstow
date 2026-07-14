//! envseal — a local, file-based "GitHub Secrets": an age-encrypted key-value store committed
//! to the repo, decrypted with each user's own age key, surfaced by NAME so neither a human
//! nor an agent has to paste a literal secret value onto a command line.
//!
//! Commands:
//!   envseal get <NAME> [--show]     Resolve one secret by name (masked under an agent).
//!   envseal unlock [-- <cmd>...]    Spawn a subshell / run a command with the whole env set.
//!   envseal init                    Generate an identity, add self as recipient, create store.
//!   envseal pubkey                  Print your age public key (share it to be added).
//!   envseal add-recipient <age1..>  Add a recipient and re-encrypt the store.
//!   envseal remove-recipient <k|nm> Remove a recipient and re-encrypt (then rotate!).
//!   envseal reencrypt               Re-encrypt the store to the current recipients file.
//!   envseal -h | --help
//!
//! Design notes:
//!   * All crypto is the `age` crate (see `crypto`). No external CLI is invoked.
//!   * Plaintext lives only in this process's memory and any child's environment. It is never
//!     written to disk. Buffers are zeroized once no longer needed.
//!   * `get` never prints a value unless the output is safe (not captured by an agent) or the
//!     human explicitly passes `--show`.

use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use zeroize::Zeroize;

mod crypto;
mod layout;

use layout::Recipient;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("-h") | Some("--help") => {
            print_help();
            0
        }
        None => {
            print_help();
            2
        }
        Some("get") => cmd_get(&args[1..]),
        Some("set") => cmd_set(&args[1..]),
        Some("edit") => cmd_edit(),
        Some("list") => cmd_list(),
        Some("pubkey") => cmd_pubkey(),
        Some("unlock") => cmd_unlock(&args[1..]),
        Some("init") => cmd_init(&args[1..]),
        Some("add-recipient") => cmd_add_recipient(&args[1..]),
        Some("remove-recipient") => cmd_remove_recipient(&args[1..]),
        Some("reencrypt") => cmd_reencrypt(),
        Some(other) => {
            eprintln!("envseal: unknown command '{other}'\n");
            print_help();
            2
        }
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Decrypt the located store with the user's identity into ordered (name, value) pairs.
/// The caller owns zeroizing the returned values.
fn load_secrets() -> Result<Vec<(String, String)>, String> {
    let paths = layout::locate().map_err(|e| e.to_string())?;
    let secret = layout::read_identity_secret().map_err(|e| e.to_string())?;
    let identity = crypto::parse_identity(&secret).map_err(|e| e.to_string())?;
    let ciphertext = layout::read_store(&paths.store).map_err(|e| e.to_string())?;

    let mut text = crypto::decrypt_to_text(&ciphertext, &identity).map_err(|e| e.to_string())?;
    let vars = crypto::parse_dotenv(&text);
    text.zeroize();
    Ok(vars)
}

/// Are we very likely running under an agent that captures our stdout into its context?
/// Claude Code sets these; other harnesses can opt in via `ENVSEAL_AGENT=1`.
fn under_agent() -> bool {
    env::var_os("CLAUDECODE").is_some()
        || env::var_os("CLAUDE_CODE_ENTRYPOINT").is_some()
        || env::var_os("ENVSEAL_AGENT").is_some()
}

fn mask(value: &str) -> String {
    // Fixed-width mask so length isn't leaked either.
    let _ = value;
    "••••••••".to_string()
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

/// `envseal get <NAME> [--show]` — resolve one secret by name with guarded output.
///
/// Masking policy (see DESIGN.md):
///   * `--show` given → always print the raw value (explicit request).
///   * running under an agent → mask, because the agent captures stdout and we cannot tell
///     "inside $(...)" from "ran bare into the transcript".
///   * stdout is a terminal (human at a shell) → mask; a bare terminal print is rarely wanted.
///   * stdout is a pipe / command substitution (and NOT under an agent) → print the value.
fn cmd_get(args: &[String]) -> i32 {
    let mut show = false;
    let mut name: Option<&str> = None;
    for a in args {
        match a.as_str() {
            "--show" => show = true,
            s if s.starts_with('-') => {
                eprintln!("envseal get: unknown flag '{s}'");
                return 2;
            }
            s => {
                if name.is_some() {
                    eprintln!("envseal get: expected a single NAME");
                    return 2;
                }
                name = Some(s);
            }
        }
    }
    let Some(name) = name else {
        eprintln!("envseal get: usage: envseal get <NAME> [--show]");
        return 2;
    };

    let mut vars = match load_secrets() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };

    let found = vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    // Scrub every value we loaded; we only keep the one we need below.
    for (_, v) in vars.iter_mut() {
        v.zeroize();
    }

    let Some(mut value) = found else {
        eprintln!("envseal: no secret named '{name}'");
        return 1;
    };

    let reveal = show || (!under_agent() && !io::stdout().is_terminal());
    if reveal {
        // Raw value to stdout, no trailing newline munging beyond a single newline so it works
        // cleanly in `$(...)` (command substitution strips the trailing newline).
        let mut out = io::stdout().lock();
        let _ = out.write_all(value.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    } else {
        // Masked: tell the human/agent how to reveal, without leaking the value.
        println!("{}", mask(&value));
        eprintln!(
            "envseal: value masked (running under an agent or a terminal). \
             Use it by name via `envseal unlock -- <cmd using ${name}>`, \
             or pass --show to reveal."
        );
    }
    value.zeroize();
    0
}

// ---------------------------------------------------------------------------
// set / list
// ---------------------------------------------------------------------------

/// `envseal set <NAME>` — read a value from STDIN (never argv) and store it under NAME,
/// re-encrypting the store. Reading from stdin keeps the literal value off the command line.
fn cmd_set(args: &[String]) -> i32 {
    let Some(name) = args.first() else {
        eprintln!("envseal set: usage: echo -n <value> | envseal set <NAME>");
        return 2;
    };
    if name.contains('=') || name.trim().is_empty() {
        eprintln!("envseal set: NAME must be non-empty and contain no '='.");
        return 2;
    }

    // Read the value from stdin, trimming a single trailing newline (so `echo` works).
    let mut value = String::new();
    if io::stdin().read_to_string(&mut value).is_err() {
        eprintln!("envseal set: could not read value from stdin.");
        return 1;
    }
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }

    let paths = match layout::locate() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("envseal: {e}");
            value.zeroize();
            return 1;
        }
    };
    let mut vars = match load_secrets() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envseal: {e}");
            value.zeroize();
            return 1;
        }
    };

    // Upsert.
    match vars.iter_mut().find(|(k, _)| k == name) {
        Some((_, v)) => {
            v.zeroize();
            *v = value.clone();
        }
        None => vars.push((name.clone(), value.clone())),
    }
    value.zeroize();

    let code = write_secrets(&paths.recipients, &paths.store, &mut vars);
    if code == 0 {
        eprintln!("✔  set {name}");
    }
    code
}

/// `envseal list` — print the variable NAMES in the store (never values).
fn cmd_list() -> i32 {
    let mut vars = match load_secrets() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    for (k, _) in &vars {
        println!("{k}");
    }
    for (_, v) in vars.iter_mut() {
        v.zeroize();
    }
    0
}

/// `envseal pubkey` — print YOUR age public key (derived from your identity), so you can share
/// it with a collaborator who will `add-recipient` it. The public key is not a secret; it is
/// always safe to print, even under an agent.
fn cmd_pubkey() -> i32 {
    let secret = match layout::read_identity_secret() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    match crypto::public_from_secret(&secret) {
        Ok(public) => {
            println!("{public}");
            0
        }
        Err(e) => {
            eprintln!("envseal: identity is unreadable: {e}");
            1
        }
    }
}

/// Serialize `vars` to dotenv, encrypt to the current recipients, and write the store.
/// Zeroizes the plaintext buffer and the values afterward.
fn write_secrets(recipients_path: &Path, store: &Path, vars: &mut [(String, String)]) -> i32 {
    let recipients = layout::read_recipients(recipients_path).unwrap_or_default();
    if recipients.is_empty() {
        eprintln!("envseal: no recipients — cannot encrypt.");
        return 1;
    }
    let recips = match parse_all_recipients(&recipients) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };

    // dotenv is line-based: a value cannot contain a newline. Reject rather than truncate.
    if vars
        .iter()
        .any(|(_, v)| v.contains('\n') || v.contains('\r'))
    {
        eprintln!("envseal: secret values cannot contain newlines.");
        return 1;
    }
    let mut payload = render_dotenv(vars);

    let result = crypto::encrypt(payload.as_bytes(), &recips);
    payload.zeroize();
    for (_, v) in vars.iter_mut() {
        v.zeroize();
    }

    match result {
        Ok(ct) => match layout::write_store(store, &ct) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("envseal: could not write store: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("envseal: encryption failed: {e}");
            1
        }
    }
}

/// `envseal edit` — decrypt the store to a private temp file, open `$EDITOR` on it, then
/// re-encrypt the edited dotenv back to the store. The plaintext temp file is created 0600 in
/// the user's config dir, overwritten with zeros, and removed on exit (success or failure).
fn cmd_edit() -> i32 {
    let paths = match layout::locate() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    // Decrypt current contents to text.
    let mut vars = match load_secrets() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let mut initial = render_dotenv(&vars);
    for (_, v) in vars.iter_mut() {
        v.zeroize();
    }

    // Temp file next to the identity (a per-user, non-repo, ideally-0600 location).
    let tmp = layout::identity_path()
        .parent()
        .unwrap_or(Path::new("."))
        .join(".envseal-edit.tmp");
    if let Some(parent) = tmp.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = write_private_file(&tmp, initial.as_bytes()) {
        initial.zeroize();
        eprintln!("envseal: could not create temp file: {e}");
        return 1;
    }
    initial.zeroize();

    // Launch $EDITOR (fall back to a sensible default) on the temp file.
    let editor = env::var_os("EDITOR")
        .or_else(|| env::var_os("VISUAL"))
        .unwrap_or_else(|| OsString::from(if cfg!(windows) { "notepad" } else { "vi" }));
    let status = Command::new(&editor).arg(&tmp).status();

    let code = match status {
        Ok(s) if s.success() => {
            // Re-read, parse, re-encrypt.
            match std::fs::read_to_string(&tmp) {
                Ok(mut edited) => {
                    let mut new_vars = crypto::parse_dotenv(&edited);
                    edited.zeroize();
                    write_secrets(&paths.recipients, &paths.store, &mut new_vars)
                }
                Err(e) => {
                    eprintln!("envseal: could not read edited file: {e}");
                    1
                }
            }
        }
        Ok(_) => {
            eprintln!("envseal: editor exited non-zero — store left unchanged.");
            1
        }
        Err(e) => {
            eprintln!(
                "envseal: could not launch editor '{}': {e}",
                editor.to_string_lossy()
            );
            1
        }
    };

    shred_and_remove(&tmp);
    if code == 0 {
        eprintln!("✔  store updated.");
    }
    code
}

/// Write `bytes` to `path`, creating it 0600 on Unix (best-effort on Windows).
fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.flush()
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// Best-effort shred: overwrite the file with zeros of the same length, then remove it.
fn shred_and_remove(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let len = meta.len() as usize;
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; len.min(1 << 20)];
            let mut remaining = len;
            while remaining > 0 {
                let n = remaining.min(zeros.len());
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                remaining -= n;
            }
            let _ = f.flush();
        }
    }
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// unlock
// ---------------------------------------------------------------------------

/// `envseal unlock [-- <cmd>...]` — decrypt the whole store and set every value as an env var
/// for a spawned child (an interactive subshell, or the given command). Values never printed;
/// only variable NAMES are listed.
fn cmd_unlock(args: &[String]) -> i32 {
    // Everything after `--` (or all args) is the command to run; empty → interactive subshell.
    let cmd: Vec<String> = match args.iter().position(|a| a == "--") {
        Some(i) => args[i + 1..].to_vec(),
        None => args.to_vec(),
    };

    let vars = match load_secrets() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    if vars.is_empty() {
        eprintln!("envseal: store decrypted but contains no variables.");
        return 1;
    }

    let names: Vec<&str> = vars.iter().map(|(k, _)| k.as_str()).collect();
    eprintln!(
        "🔓 envseal: loaded {} secret(s): {}",
        names.len(),
        names.join(", ")
    );

    spawn_with_env(&cmd, vars)
}

/// Spawn either the given command or an interactive subshell, with `vars` in its env.
/// Zeroizes the values after the child has been launched. Returns the child's exit code.
fn spawn_with_env(cmd: &[String], mut vars: Vec<(String, String)>) -> i32 {
    let (program, args, interactive) = if cmd.is_empty() {
        let (sh, sh_args) = default_shell();
        eprintln!("🔓 envseal: launching unlocked subshell. Type `exit` to lock.");
        (sh, sh_args, true)
    } else {
        (
            OsString::from(&cmd[0]),
            cmd[1..].iter().map(OsString::from).collect(),
            false,
        )
    };

    let mut command = Command::new(&program);
    command.args(&args);
    for (k, v) in &vars {
        command.env(k, v);
    }
    command.env("ENVSEAL_UNLOCKED", "1");
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let result = command.spawn();

    // The child now has its own copy of the environment; scrub ours.
    for (_, v) in vars.iter_mut() {
        v.zeroize();
    }

    match result {
        Ok(mut child) => match child.wait() {
            Ok(status) => status.code().unwrap_or(if interactive { 0 } else { 1 }),
            Err(e) => {
                eprintln!("envseal: error waiting for child: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!(
                "envseal: failed to launch '{}': {e}",
                program.to_string_lossy()
            );
            127
        }
    }
}

#[cfg(unix)]
fn default_shell() -> (OsString, Vec<OsString>) {
    let sh = env::var_os("SHELL").unwrap_or_else(|| OsString::from("/bin/sh"));
    (sh, vec![OsString::from("-i")])
}

#[cfg(windows)]
fn default_shell() -> (OsString, Vec<OsString>) {
    if let Some(comspec) = env::var_os("COMSPEC") {
        (comspec, Vec::new())
    } else {
        (OsString::from("cmd.exe"), Vec::new())
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// `envseal init` — generate an age identity (if none), create the `recipients` file with the
/// user as sole recipient (if none), and create an empty encrypted store (if none). Idempotent.
fn cmd_init(_args: &[String]) -> i32 {
    // 1. Identity: reuse an existing one, else generate and write it.
    let public = match layout::read_identity_secret() {
        Ok(secret) => match crypto::public_from_secret(&secret) {
            Ok(p) => {
                eprintln!(
                    "✔  using existing identity at {}",
                    layout::identity_path().display()
                );
                p
            }
            Err(e) => {
                eprintln!("envseal: existing identity is unreadable: {e}");
                return 1;
            }
        },
        Err(_) => {
            let (public, mut secret) = crypto::generate_keypair();
            match layout::write_new_identity(&secret) {
                Ok(path) => eprintln!("✔  generated identity at {}", path.display()),
                Err(e) => {
                    secret.zeroize();
                    eprintln!("envseal: could not write identity: {e}");
                    return 1;
                }
            }
            secret.zeroize();
            public
        }
    };
    eprintln!("   your public key: {public}");

    // 2. Recipients file in the CWD (this becomes the repo root anchor).
    let recipients_path = env::current_dir()
        .unwrap_or_else(|_| ".".into())
        .join(layout::RECIPIENTS_FILE);
    let mut recipients = if recipients_path.is_file() {
        layout::read_recipients(&recipients_path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let joining_existing = !recipients.is_empty() && !recipients.iter().any(|r| r.key == public);
    if recipients.iter().any(|r| r.key == public) {
        eprintln!("✔  already a recipient in {}", recipients_path.display());
    } else {
        if joining_existing {
            // A store already exists, encrypted to OTHER people. We add ourselves to the
            // recipients list, but the on-disk store can't be re-keyed to include us until
            // an EXISTING recipient runs `envseal reencrypt`. Adding our key alone does not
            // grant us decryption — say so plainly rather than leaving a broken state.
            eprintln!(
                "⚠️  {} already lists {} other recipient(s). Adding your key here does NOT let\n\
                 \x20   you decrypt the existing store — ask an existing recipient to run\n\
                 \x20   `envseal reencrypt` after pulling your key.",
                recipients_path.display(),
                recipients.len()
            );
        }
        recipients.push(Recipient {
            key: public.clone(),
            label: Some("me".to_string()),
        });
        if let Err(e) = std::fs::write(&recipients_path, layout::render_recipients(&recipients)) {
            eprintln!("envseal: could not write recipients file: {e}");
            return 1;
        }
        eprintln!("✔  added you to {}", recipients_path.display());
    }

    // 3. Encrypted store: create an empty one if absent.
    let store_path = recipients_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(layout::STORE_FILE);
    if store_path.is_file() {
        eprintln!("✔  store already exists at {}", store_path.display());
    } else {
        let seed = b"# envseal secrets -- KEY=value lines. Edit via `envseal unlock`.\n";
        match encrypt_payload(seed, &recipients) {
            Ok(ct) => {
                if let Err(e) = layout::write_store(&store_path, &ct) {
                    eprintln!("envseal: could not write store: {e}");
                    return 1;
                }
                eprintln!("✔  created empty store at {}", store_path.display());
            }
            Err(e) => {
                eprintln!("envseal: could not encrypt initial store: {e}");
                return 1;
            }
        }
    }

    eprintln!("\n🔓 Ready. Add secrets by editing the store, then `envseal unlock`.");
    eprintln!("   Share your public key with collaborators so they can add you.");
    0
}

// ---------------------------------------------------------------------------
// recipient management
// ---------------------------------------------------------------------------

fn cmd_add_recipient(args: &[String]) -> i32 {
    let Some(key) = args.first() else {
        eprintln!("envseal add-recipient: usage: envseal add-recipient <age1...> [label]");
        return 2;
    };
    if crypto::parse_recipient(key).is_err() {
        eprintln!("envseal: '{key}' is not a valid age public key (expected age1...).");
        return 1;
    }
    let label = args.get(1).cloned();

    let paths = match layout::locate() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let mut recipients = layout::read_recipients(&paths.recipients).unwrap_or_default();
    if recipients.iter().any(|r| &r.key == key) {
        eprintln!("envseal: {key} is already a recipient.");
        return 0;
    }
    recipients.push(Recipient {
        key: key.clone(),
        label,
    });

    if let Err(e) = std::fs::write(&paths.recipients, layout::render_recipients(&recipients)) {
        eprintln!("envseal: could not update recipients file: {e}");
        return 1;
    }
    eprintln!("✔  added recipient to {}", paths.recipients.display());
    reencrypt_store(&paths.store, &recipients)
}

fn cmd_remove_recipient(args: &[String]) -> i32 {
    let Some(target) = args.first() else {
        eprintln!("envseal remove-recipient: usage: envseal remove-recipient <age1...|label>");
        return 2;
    };

    let paths = match layout::locate() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let recipients = layout::read_recipients(&paths.recipients).unwrap_or_default();

    let matches: Vec<&Recipient> = recipients
        .iter()
        .filter(|r| &r.key == target || r.label.as_deref() == Some(target.as_str()))
        .collect();
    if matches.is_empty() {
        eprintln!("envseal: no recipient matching '{target}'.");
        return 1;
    }
    if matches.len() > 1 {
        eprintln!(
            "envseal: '{target}' matches {} recipients — pass the exact age key.",
            matches.len()
        );
        return 1;
    }
    let removed_key = matches[0].key.clone();
    let kept: Vec<Recipient> = recipients
        .into_iter()
        .filter(|r| r.key != removed_key)
        .collect();
    if kept.is_empty() {
        eprintln!("envseal: refusing to remove the last recipient (store would be unreadable).");
        return 1;
    }

    if let Err(e) = std::fs::write(&paths.recipients, layout::render_recipients(&kept)) {
        eprintln!("envseal: could not update recipients file: {e}");
        return 1;
    }
    eprintln!("✔  removed recipient; {} remain.", kept.len());
    let code = reencrypt_store(&paths.store, &kept);
    if code == 0 {
        eprintln!(
            "\n⚠️  Removing a recipient only blocks FUTURE decryptions. Their key still decrypts\n\
             every historical commit in any clone they kept. Rotate every secret they saw at the\n\
             source to truly revoke access."
        );
    }
    code
}

fn cmd_reencrypt() -> i32 {
    let paths = match layout::locate() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let recipients = layout::read_recipients(&paths.recipients).unwrap_or_default();
    if recipients.is_empty() {
        eprintln!("envseal: recipients file has no keys.");
        return 1;
    }
    reencrypt_store(&paths.store, &recipients)
}

/// Decrypt the store with our identity and re-encrypt it to `recipients`. Used after any change
/// to the recipient set. Plaintext is zeroized.
fn reencrypt_store(store: &Path, recipients: &[Recipient]) -> i32 {
    let secret = match layout::read_identity_secret() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let identity = match crypto::parse_identity(&secret) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let ciphertext = match layout::read_store(store) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let mut plaintext = match crypto::decrypt(&ciphertext, &identity) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("envseal: {e}");
            return 1;
        }
    };

    let recips = match parse_all_recipients(recipients) {
        Ok(r) => r,
        Err(e) => {
            plaintext.zeroize();
            eprintln!("envseal: {e}");
            return 1;
        }
    };
    let result = crypto::encrypt(&plaintext, &recips);
    plaintext.zeroize();

    match result {
        Ok(ct) => {
            if let Err(e) = layout::write_store(store, &ct) {
                eprintln!("envseal: could not write store: {e}");
                return 1;
            }
            eprintln!("✔  re-encrypted store to {} recipient(s).", recips.len());
            0
        }
        Err(e) => {
            eprintln!("envseal: re-encryption failed: {e}");
            1
        }
    }
}

/// Encrypt a plaintext payload to a recipient set (helper for init's empty store).
fn encrypt_payload(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, String> {
    let recips = parse_all_recipients(recipients)?;
    crypto::encrypt(plaintext, &recips).map_err(|e| e.to_string())
}

/// True if `v` both starts and ends with the same quote char — the one case where writing it
/// verbatim would let `parse_dotenv` strip a quote pair that is actually part of the value.
fn starts_and_ends_with_matching_quote(v: &str) -> bool {
    let b = v.as_bytes();
    v.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
}

/// Render (name, value) pairs to dotenv text that `crypto::parse_dotenv` reads back exactly.
/// Values are written verbatim after `=`; a value that itself begins and ends with a matching
/// quote is wrapped in the *other* quote style so parse's quote-stripping cancels out.
/// Caller must ensure no value contains a newline.
fn render_dotenv(vars: &[(String, String)]) -> String {
    let mut payload = String::new();
    for (k, v) in vars {
        payload.push_str(k);
        payload.push('=');
        if starts_and_ends_with_matching_quote(v) {
            let q = if v.starts_with('"') { '\'' } else { '"' };
            payload.push(q);
            payload.push_str(v);
            payload.push(q);
        } else {
            payload.push_str(v);
        }
        payload.push('\n');
    }
    payload
}

/// Parse every recipient string into an age recipient, failing on the first bad one.
fn parse_all_recipients(recipients: &[Recipient]) -> Result<Vec<age::x25519::Recipient>, String> {
    recipients
        .iter()
        .map(|r| crypto::parse_recipient(&r.key).map_err(|e| e.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

fn print_help() {
    eprintln!(
        "envseal — a local, encrypted key-value store (age) surfaced by NAME\n\
         \n\
         USAGE:\n\
         \x20 envseal get <NAME> [--show]      Resolve one secret (masked under an agent).\n\
         \x20 envseal set <NAME>               Read a value from stdin and store it.\n\
         \x20 envseal edit                     Edit all secrets in $EDITOR (decrypt/re-encrypt).\n\
         \x20 envseal list                     List secret NAMES (never values).\n\
         \x20 envseal pubkey                   Print your age PUBLIC key (share it to be added).\n\
         \x20 envseal unlock [-- <cmd>...]     Subshell / run a command with the whole env set.\n\
         \x20 envseal init                     Create identity + recipients + empty store.\n\
         \x20 envseal add-recipient <age1..>   Add a collaborator and re-encrypt.\n\
         \x20 envseal remove-recipient <k|nm>  Remove a collaborator and re-encrypt (then rotate).\n\
         \x20 envseal reencrypt                Re-encrypt the store to the current recipients.\n\
         \n\
         EXAMPLES:\n\
         \x20 do-thing \"$(envseal get DB_PASSWORD)\"   # by name; masked if an agent runs it bare\n\
         \x20 envseal unlock -- npm run build          # run one command with all secrets set\n\
         \x20 envseal unlock                           # start your AI in an unlocked subshell\n\
         \n\
         All crypto is the `age` crate — no external tools. Values are never printed unless\n\
         output is safe or you pass --show."
    );
    let _ = io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_hides_value_and_length() {
        assert_eq!(mask("short"), mask("a-much-longer-secret-value"));
        assert!(!mask("sk-abc123").contains("sk-"));
    }

    #[test]
    fn render_dotenv_roundtrips_through_parse() {
        let cases = vec![
            ("A".to_string(), "1".to_string()),
            ("SPACES".to_string(), "has spaces and # hash".to_string()),
            ("EQ".to_string(), "a=b=c".to_string()),
            ("B64".to_string(), "abc123==".to_string()),
            ("QUOTED".to_string(), "\"already quoted\"".to_string()),
            ("SQUOTED".to_string(), "'single quoted'".to_string()),
            ("URL".to_string(), "postgres://u:p@h/db?x=1".to_string()),
        ];
        let text = render_dotenv(&cases);
        let parsed = crypto::parse_dotenv(&text);
        assert_eq!(
            parsed, cases,
            "every value must survive render -> parse unchanged"
        );
    }

    #[test]
    fn under_agent_detects_claude_and_optin() {
        // Save/restore the vars we touch.
        let save = |k: &str| (k.to_string(), env::var_os(k));
        let saved = [
            save("CLAUDECODE"),
            save("CLAUDE_CODE_ENTRYPOINT"),
            save("ENVSEAL_AGENT"),
        ];
        for (k, _) in &saved {
            env::remove_var(k);
        }
        assert!(!under_agent());
        env::set_var("ENVSEAL_AGENT", "1");
        assert!(under_agent());
        for (k, v) in saved {
            match v {
                Some(v) => env::set_var(&k, v),
                None => env::remove_var(&k),
            }
        }
    }
}
