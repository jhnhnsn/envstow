//! envstow — an age-encrypted key-value store committed to the repo, decrypted with each user's
//! own age key, surfaced by NAME so neither a human nor an agent has to paste a literal secret
//! value onto a command line.
//!
//! Commands:
//!   envstow get <NAME> [--show]     Resolve one secret by name (masked under an agent).
//!   envstow set <NAME> [--clipboard] Store a value from stdin, or the OS clipboard.
//!   envstow delete <NAME>           Remove one secret and re-encrypt (then rotate!).
//!   envstow unlock [-- <cmd>...]    Spawn a subshell / run a command with the whole env set.
//!   envstow refresh                 Emit `unset` lines for secrets that left the store (eval it).
//!   envstow upgrade [--check|--yes] Check for / install a newer envstow.
//!   envstow init                    Generate an identity, add self as recipient, create store.
//!   envstow pubkey                  Print your age public key (share it to be added).
//!   envstow add-recipient <age1..>  Add a recipient and re-encrypt the store.
//!   envstow remove-recipient <k|nm> Remove a recipient and re-encrypt (then rotate!).
//!   envstow reencrypt               Re-encrypt the store to the current recipients file.
//!   envstow --version               Print the version.
//!   envstow -h | --help
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
mod error;
mod layout;
mod secrets;

use error::AppError;
use layout::Recipient;
use secrets::Secrets;

/// A command's result: `Ok(())` on success, or an [`AppError`] carrying the message and exit code.
type Cmd = Result<(), AppError>;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    // Allow `--profile <name>` (or `--profile=<name>`) as a GLOBAL flag before the subcommand,
    // e.g. `envstow --profile prod set X`. We lift it into ENVSTOW_PROFILE so the per-command
    // resolve_profile() picks it up, then drop it from args so dispatch sees the subcommand.
    if let Some(first) = args.first() {
        if first == "--profile" {
            if args.len() >= 2 {
                env::set_var("ENVSTOW_PROFILE", &args[1]);
                args.drain(0..2);
            }
        } else if let Some(name) = first.strip_prefix("--profile=") {
            env::set_var("ENVSTOW_PROFILE", name);
            args.remove(0);
        }
    }
    // Commands that print their own output and always succeed (help/version) short-circuit here;
    // everything else returns `Cmd`, and its error is turned into a message + exit code in ONE
    // place below rather than at every failure site.
    let result: Cmd = match args.first().map(String::as_str) {
        Some("-h") | Some("--help") => {
            print_help();
            Ok(())
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("envstow {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        None => {
            print_help();
            // No subcommand is a usage error (exit 2), but help was already printed, so carry an
            // empty message that main suppresses.
            Err(AppError::usage(""))
        }
        Some("get") => cmd_get(&args[1..]),
        Some("set") => cmd_set(&args[1..]),
        Some("delete") => cmd_delete(&args[1..]),
        Some("edit") => cmd_edit(&args[1..]),
        Some("list") => cmd_list(&args[1..]),
        Some("pubkey") => cmd_pubkey(),
        Some("unlock") => cmd_unlock(&args[1..]),
        Some("refresh") => cmd_refresh(&args[1..]),
        // `upgrade` is the canonical name (deno upgrade, rustup self update): "upgrade" means
        // the program itself, while "update" tends to mean the things a program manages (npm
        // update, brew upgrade, rustup update). envstow manages secrets, so `update` is kept
        // free for that sense — and accepted here as an undocumented alias for anyone who used
        // it in 0.1.12, the one release where it was the real name.
        Some("upgrade") | Some("update") => cmd_upgrade(&args[1..]),
        Some("init") => cmd_init(&args[1..]),
        Some("add-recipient") => cmd_add_recipient(&args[1..]),
        Some("remove-recipient") => cmd_remove_recipient(&args[1..]),
        Some("reencrypt") => cmd_reencrypt(&args[1..]),
        Some("profile") => cmd_profile(&args[1..]),
        Some("profiles") => cmd_profiles(),
        Some(other) => {
            eprintln!("envstow: unknown command '{other}'\n");
            print_help();
            Err(AppError::usage(""))
        }
    };

    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            // Some paths (help, unknown command) already printed and carry an empty message.
            if !e.to_string().is_empty() {
                eprintln!("envstow: {e}");
            }
            e.code()
        }
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Resolve which profile to use and return `(profile, remaining_args)` with any `--profile
/// <name>` (or `--profile=<name>`) removed from the args. Precedence: `--profile` flag >
/// `ENVSTOW_PROFILE` env var > `default`. Returns an error string on a bad/missing name.
fn resolve_profile(args: &[String]) -> Result<(String, Vec<String>), AppError> {
    let mut profile: Option<String> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--profile" {
            let Some(name) = args.get(i + 1) else {
                return Err(AppError::usage("--profile requires a name"));
            };
            profile = Some(name.clone());
            i += 2;
        } else if let Some(name) = a.strip_prefix("--profile=") {
            profile = Some(name.to_string());
            i += 1;
        } else {
            rest.push(a.clone());
            i += 1;
        }
    }
    let profile = profile
        .or_else(|| env::var("ENVSTOW_PROFILE").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| layout::DEFAULT_PROFILE.to_string());
    if !layout::valid_profile_name(&profile) {
        return Err(AppError::usage(format!(
            "invalid profile name '{profile}' (use letters, digits, - or _)"
        )));
    }
    Ok((profile, rest))
}

/// A parsed `[flags] [<NAME>]` command line, shared by `get`/`set`/`delete` — the three commands
/// with the same shape.
struct ParsedArgs<'a> {
    /// Canonical names of the boolean flags that were present.
    flags: Vec<&'static str>,
    /// The single positional argument (a secret NAME), if given.
    positional: Option<&'a str>,
}

impl ParsedArgs<'_> {
    fn has(&self, flag: &'static str) -> bool {
        self.flags.contains(&flag)
    }
}

/// Parse `[flags] [<NAME>]`. `known` maps each accepted flag spelling to a canonical name (so
/// aliases like `-c`/`--clipboard` collapse to one). An unknown `-flag`, or more than one
/// positional, is a usage error naming the offender.
fn parse_simple<'a>(
    args: &'a [String],
    known: &[(&str, &'static str)],
) -> Result<ParsedArgs<'a>, AppError> {
    let mut flags = Vec::new();
    let mut positional = None;
    for a in args {
        let s = a.as_str();
        if let Some((_, canon)) = known.iter().find(|(spelling, _)| *spelling == s) {
            if !flags.contains(canon) {
                flags.push(*canon);
            }
        } else if s.starts_with('-') {
            return Err(AppError::usage(format!("unknown flag '{s}'")));
        } else if positional.is_some() {
            return Err(AppError::usage("expected a single NAME"));
        } else {
            positional = Some(s);
        }
    }
    Ok(ParsedArgs { flags, positional })
}

/// Decrypt the located store for `profile` with the user's identity into a [`Secrets`] (whose
/// values are zeroized on drop).
fn load_secrets(profile: &str) -> Result<Secrets, AppError> {
    let paths = layout::locate(profile)?;
    let secret = layout::read_identity_secret()?;
    let identity = crypto::parse_identity(&secret)?;
    // A missing store for a NAMED profile means the profile doesn't exist — point the user at
    // `profile create` rather than the generic "no store" error (guards against typos too).
    if !paths.store.is_file() && profile != layout::DEFAULT_PROFILE {
        return Err(AppError::msg(format!(
            "no such profile '{profile}'. Create it with `envstow profile create {profile}`"
        )));
    }
    let ciphertext = layout::read_store(&paths.store)?;

    let mut text = crypto::decrypt_to_text(&ciphertext, &identity).map_err(|e| {
        AppError::msg(explain_decrypt_failure(
            e.to_string(),
            &secret,
            &paths.recipients,
        ))
    })?;
    let parsed = crypto::parse_dotenv(&text);
    text.zeroize();
    // Decode any base64-marked (multi-line) values back to their originals.
    let mut vars = Vec::with_capacity(parsed.len());
    for (k, v) in parsed {
        let decoded = crypto::decode_value(&v)?;
        vars.push((k, decoded));
    }
    Ok(Secrets::from_pairs(vars))
}

/// Turn age's `No matching keys found` into an error that says what to actually do.
///
/// That one message covers several very different situations, and the most common — "you've
/// installed envstow and cloned the repo, but nobody has added you yet" — is the one it explains
/// worst. It reads as though something is broken, especially right after `init` has cheerfully
/// reported adding your key to `recipients`. (It did; but `recipients` is an INPUT to encryption,
/// not an access list. Your key only grants decryption once an existing recipient re-encrypts.)
///
/// We can tell the cases apart without any crypto: compare our public key against the recipients
/// file. If we're absent, we were never added. If we're present but decryption still failed, the
/// store is stale — encrypted before our key was listed, and someone needs to `reencrypt`.
fn explain_decrypt_failure(original: String, secret: &str, recipients_path: &Path) -> String {
    // Only reinterpret the "your key doesn't open this" case; other failures (corrupt file, bad
    // format) should keep their own message.
    if !original.contains("No matching keys") {
        return original;
    }
    let Ok(public) = crypto::public_from_secret(secret) else {
        return original;
    };
    let listed = layout::read_recipients(recipients_path)
        .map(|rs| rs.iter().any(|r| r.key == public))
        .unwrap_or(false);

    if listed {
        format!(
            "your key is listed in `{}`, but the store wasn't encrypted to it yet.\n\
             \x20  The store is re-keyed only when someone runs a re-encrypt. Ask an existing \
             recipient to:\n\
             \x20    git pull && envstow reencrypt && git add .envstow && git commit && git push\n\
             \x20  (Adding a key to `recipients` alone does not grant access — that file is an \
             input to\n\
             \x20   encryption, not an access list.)",
            recipients_path.display()
        )
    } else {
        format!(
            "your key isn't a recipient of this store, so you can't decrypt it yet.\n\
             \x20  Your public key:\n\
             \x20    {public}\n\
             \x20  Send it to someone who already has access and ask them to run:\n\
             \x20    envstow add-recipient {public} <your-name>\n\
             \x20  …then `git pull` once they've pushed."
        )
    }
}

/// Environment markers set by AI coding agents that capture command output into their context.
/// If any is present, `get` masks its value so plaintext can't land in the agent's transcript.
/// This is a best-effort allowlist across known tools plus a generic opt-in — an agent that
/// sets none of these is still expected to use `unlock -- <cmd>` (secrets by name), which never
/// exposes a value regardless of detection.
const AGENT_ENV_MARKERS: &[&str] = &[
    // Claude Code
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    // Cursor
    "CURSOR_TRACE_ID",
    "CURSOR_AGENT",
    // Aider
    "AIDER_MODEL",
    "AIDER_CHAT",
    // Windsurf
    "WINDSURF",
    "WINDSURF_AGENT",
    // Generic / cross-tool conventions + explicit opt-in
    "AI_AGENT",
    "AGENT",
    "ENVSTOW_AGENT",
];

/// Are we very likely running under an agent that captures our stdout into its context?
fn under_agent() -> bool {
    AGENT_ENV_MARKERS.iter().any(|m| env::var_os(m).is_some())
}

fn mask(value: &str) -> String {
    // Fixed-width mask so length isn't leaked either.
    let _ = value;
    "••••••••".to_string()
}

/// A masked preview for confirming a freshly-set value: the first few characters followed by a
/// fixed run of dots — enough to recognize a paste, without showing the secret or its length.
/// Short values (≤5 chars) are fully masked so a whole short secret is never revealed.
fn masked_preview(value: &str) -> String {
    const SHOWN: usize = 5;
    const DOTS: &str = "••••••••";
    // Count by chars (not bytes) so multibyte values aren't split mid-codepoint.
    let char_count = value.chars().count();
    if char_count <= SHOWN {
        return DOTS.to_string();
    }
    let head: String = value.chars().take(SHOWN).collect();
    format!("{head}{DOTS}")
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

/// `envstow get <NAME> [--show]` — resolve one secret by name with guarded output.
///
/// Masking policy (see DESIGN.md):
///   * `--show` given → always print the raw value (explicit request).
///   * running under an agent → mask, because the agent captures stdout and we cannot tell
///     "inside $(...)" from "ran bare into the transcript".
///   * stdout is a terminal (human at a shell) → mask; a bare terminal print is rarely wanted.
///   * stdout is a pipe / command substitution (and NOT under an agent) → print the value.
fn cmd_get(args: &[String]) -> Cmd {
    let (profile, args) = resolve_profile(args)?;
    let parsed = parse_simple(&args, &[("--show", "show")])?;
    let show = parsed.has("show");
    let Some(name) = parsed.positional else {
        return Err(AppError::usage(
            "usage: envstow get <NAME> [--profile P] [--show]",
        ));
    };

    let secrets = load_secrets(&profile)?;

    // `secrets` (and thus every value, including the one we print below) is zeroized when it drops
    // at the end of this function — no manual scrubbing needed.
    let Some(value) = secrets.get(name) else {
        return Err(AppError::msg(format!("no secret named '{name}'")));
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
        println!("{}", mask(value));
        eprintln!(
            "envstow: value masked (running under an agent or a terminal). \
             Use it by name via `envstow unlock -- <cmd using ${name}>`, \
             or pass --show to reveal."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// set / list
// ---------------------------------------------------------------------------

/// `envstow set <NAME>` — read a value from STDIN (never argv) and store it under NAME,
/// re-encrypting the store. Reading from stdin keeps the literal value off the command line.
/// `--clipboard` reads the OS clipboard instead of stdin (same guarantee: never in argv).
fn cmd_set(args: &[String]) -> Cmd {
    let (profile, args) = resolve_profile(args)?;
    let parsed = parse_simple(&args, &[("--clipboard", "clipboard"), ("-c", "clipboard")])?;
    let from_clipboard = parsed.has("clipboard");
    let Some(name) = parsed.positional else {
        return Err(AppError::usage(
            "usage: envstow set <NAME> [--profile P] [--clipboard]   (then type the value + \
             Enter, or pipe it: `printf '%s' value | envstow set <NAME>`)",
        ));
    };
    if name.contains('=') || name.trim().is_empty() {
        return Err(AppError::usage(
            "NAME must be non-empty and contain no '='.",
        ));
    }
    let name = name.to_string();
    let name = &name;

    // Read the value. Three modes, none of which put it in argv:
    //   * --clipboard: shell out to the platform's paste tool (see read_clipboard).
    //   * interactive TTY (you typing): prompt, then read ONE line — finishes on Enter.
    //   * piped (`printf … | envstow set`): read ALL of stdin, so multi-line values survive.
    let mut value = String::new();
    if from_clipboard {
        value = read_clipboard()?;
    } else {
        let read = if io::stdin().is_terminal() {
            eprint!("Enter value for {name} (press Enter to finish): ");
            let _ = io::stderr().flush();
            io::stdin().read_line(&mut value)
        } else {
            io::stdin().read_to_string(&mut value)
        };
        if read.is_err() {
            return Err(AppError::msg("could not read value from stdin."));
        }
    }
    if from_clipboard && value.is_empty() {
        return Err(AppError::msg("the clipboard is empty — nothing to store."));
    }
    // Trim a single trailing newline (the Enter keystroke, or a trailing newline from `echo`).
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }

    // From here `value` holds plaintext. On the two fallible steps before it's moved into the
    // store, scrub it explicitly on failure (a bare `?` would skip that).
    let paths = match layout::locate(&profile) {
        Ok(p) => p,
        Err(e) => {
            value.zeroize();
            return Err(e.into());
        }
    };
    let mut secrets = match load_secrets(&profile) {
        Ok(v) => v,
        Err(e) => {
            value.zeroize();
            return Err(e);
        }
    };

    // Compute a masked preview (first few chars + asterisks) so a HUMAN can sanity-check the
    // paste. Under an agent, even the first few chars shouldn't reach the transcript, so mask
    // fully. Preview never holds more than the first 5 chars of the value.
    let preview = if under_agent() {
        mask(&value)
    } else {
        masked_preview(&value)
    };

    // Hand the value to the store (upsert scrubs any prior value it replaces). `value` is moved
    // in, so nothing left here to zeroize; `secrets` scrubs everything on drop.
    secrets.upsert(name, value);

    write_secrets(&paths.recipients, &paths.store, &secrets)?;
    eprintln!("✔  set {name} ({preview})");
    nudge_if_unlocked_shell();
    Ok(())
}

/// The platform's clipboard-paste commands, tried in order until one runs. Each writes the
/// clipboard to stdout, so we capture it and never let it touch a shell or the command line.
///
/// These are the OS's own tools, not a dependency envstow ships — consistent with `age` being
/// compiled in rather than shelled out to. On Linux the display server isn't knowable at compile
/// time (a binary built anywhere may run under Wayland or X11), so we probe both at runtime and
/// let the first one that exists win.
#[cfg(target_os = "macos")]
const CLIPBOARD_CMDS: &[(&str, &[&str])] = &[("pbpaste", &[])];

#[cfg(all(unix, not(target_os = "macos")))]
const CLIPBOARD_CMDS: &[(&str, &[&str])] = &[
    ("wl-paste", &["--no-newline"]),
    ("xclip", &["-selection", "clipboard", "-o"]),
    ("xsel", &["--clipboard", "--output"]),
];

#[cfg(windows)]
const CLIPBOARD_CMDS: &[(&str, &[&str])] =
    &[("powershell", &["-NoProfile", "-Command", "Get-Clipboard"])];

/// Read the OS clipboard as text. Returns a human-actionable error naming the tool to install if
/// none of the platform's paste commands are present.
fn read_clipboard() -> Result<String, String> {
    let mut missing = Vec::new();
    for (program, args) in CLIPBOARD_CMDS {
        let output = Command::new(program).args(*args).output();
        match output {
            Ok(out) if out.status.success() => {
                let mut text = String::from_utf8(out.stdout).map_err(|_| {
                    format!("clipboard contents are not valid UTF-8 (via {program})")
                })?;
                // Strip ONE trailing newline: some tools (pbpaste on a copied line, Get-Clipboard)
                // append one that isn't part of the value. `set` trims stdin the same way.
                if text.ends_with('\n') {
                    text.pop();
                    if text.ends_with('\r') {
                        text.pop();
                    }
                }
                return Ok(text);
            }
            Ok(out) => {
                // The tool exists but failed (e.g. xclip with no X display). Surface its own
                // complaint — it explains the problem better than we can.
                let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(if err.is_empty() {
                    format!("{program} failed to read the clipboard")
                } else {
                    format!("{program}: {err}")
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(*program),
            Err(e) => return Err(format!("could not run {program}: {e}")),
        }
    }
    Err(format!(
        "no clipboard tool found (tried: {}). Install one, or pipe the value instead: \
         `<paste-command> | envstow set <NAME>`",
        missing.join(", ")
    ))
}

/// `envstow delete <NAME>` — remove one secret from the store and re-encrypt.
///
/// Deleting a name only removes it going FORWARD. The value stays readable in every historical
/// commit of the store to anyone who is (or was) a recipient, so a deleted secret is not a
/// revoked one — hence the rotate reminder, mirroring `remove-recipient`.
fn cmd_delete(args: &[String]) -> Cmd {
    let (profile, args) = resolve_profile(args)?;
    let parsed = parse_simple(&args, &[("--force", "force"), ("-f", "force")])?;
    let force = parsed.has("force");
    let Some(name) = parsed.positional else {
        return Err(AppError::usage(
            "usage: envstow delete <NAME> [--profile P] [--force]",
        ));
    };

    let paths = layout::locate(&profile)?;
    let mut secrets = load_secrets(&profile)?;

    if !secrets.contains(name) {
        return Err(AppError::msg(format!("no secret named '{name}'")));
    }

    // Confirm on a TTY: deleting is destructive and the value is unrecoverable from the store
    // once re-encrypted (only git history keeps it). Non-interactive callers are unblocked by
    // --force, and a piped stdin (CI) proceeds without prompting, matching `init`'s convention.
    if !force && io::stdin().is_terminal() {
        eprint!("Delete '{name}' from profile '{profile}'? [y/N] ");
        let _ = io::stderr().flush();
        let mut input = String::new();
        let confirmed = io::stdin().read_line(&mut input).is_ok()
            && matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes");
        if !confirmed {
            return Err(AppError::msg("aborted — store left unchanged."));
        }
    }

    // Drop the entry (its value is zeroized as it leaves the store).
    secrets.remove(name);

    write_secrets(&paths.recipients, &paths.store, &secrets)?;
    eprintln!("✔  deleted {name}");
    eprintln!(
        "\n⚠️  Deleting only removes it going forward. The value is still readable in this\n\
         \x20   store's git history by anyone who is (or was) a recipient. Rotate it at the\n\
         \x20   source if it should no longer be valid."
    );
    nudge_if_unlocked_shell();
    Ok(())
}

/// `envstow list` — print the variable NAMES in the store (never values).
fn cmd_list(args: &[String]) -> Cmd {
    let (profile, _args) = resolve_profile(args)?;
    let secrets = load_secrets(&profile)?;
    for name in secrets.names() {
        println!("{name}");
    }
    Ok(())
}

/// `envstow pubkey` — print YOUR age public key (derived from your identity), so you can share
/// it with a collaborator who will `add-recipient` it. The public key is not a secret; it is
/// always safe to print, even under an agent.
fn cmd_pubkey() -> Cmd {
    let secret = layout::read_identity_secret()?;
    let public = crypto::public_from_secret(&secret)
        .map_err(|e| AppError::msg(format!("identity is unreadable: {e}")))?;
    println!("{public}");
    Ok(())
}

/// Serialize `secrets` to dotenv, encrypt to the current recipients, and write the store.
/// Zeroizes the plaintext payload buffer; the caller's `Secrets` scrubs its own values on drop.
fn write_secrets(recipients_path: &Path, store: &Path, secrets: &Secrets) -> Cmd {
    let recipients = layout::read_recipients(recipients_path).unwrap_or_default();
    if recipients.is_empty() {
        return Err(AppError::msg("no recipients — cannot encrypt."));
    }
    let recips = parse_all_recipients(&recipients)?;

    // Multi-line values are stored base64-encoded (see crypto::encode_value), so the dotenv
    // store stays one line per key. render_dotenv applies the encoding.
    let mut payload = render_dotenv(secrets.pairs());
    let result = crypto::encrypt(payload.as_bytes(), &recips);
    payload.zeroize();
    let ct = result?; // CryptoError -> "encryption failed: {e}"

    layout::write_store(store, &ct)
        .map_err(|e| AppError::msg(format!("could not write store: {e}")))
}

/// `envstow edit` — decrypt the store to a private temp file, open `$EDITOR` on it, then
/// re-encrypt the edited dotenv back to the store. The plaintext temp file is created 0600 in
/// the user's config dir, overwritten with zeros, and removed on exit (success or failure).
fn cmd_edit(args: &[String]) -> Cmd {
    let (profile, _args) = resolve_profile(args)?;
    let paths = layout::locate(&profile)?;
    // Decrypt current contents to text.
    let secrets = load_secrets(&profile)?;
    let mut initial = render_dotenv(secrets.pairs());
    drop(secrets); // scrub the decrypted values now; the plaintext lives on only in `initial`

    // Temp file next to the identity (a per-user, non-repo, ideally-0600 location).
    let tmp = layout::identity_path()
        .parent()
        .unwrap_or(Path::new("."))
        .join(".envstow-edit.tmp");
    if let Some(parent) = tmp.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = write_private_file(&tmp, initial.as_bytes()) {
        initial.zeroize();
        return Err(AppError::msg(format!("could not create temp file: {e}")));
    }
    initial.zeroize();

    // Launch $EDITOR (fall back to a sensible default) on the temp file.
    let editor = env::var_os("EDITOR")
        .or_else(|| env::var_os("VISUAL"))
        .unwrap_or_else(|| OsString::from(if cfg!(windows) { "notepad" } else { "vi" }));
    let status = Command::new(&editor).arg(&tmp).status();

    // Re-encrypt on a clean editor exit; the temp file is shredded either way (below).
    let result: Cmd = match status {
        Ok(s) if s.success() => match std::fs::read_to_string(&tmp) {
            Ok(mut edited) => {
                let new_secrets = Secrets::from_pairs(crypto::parse_dotenv(&edited));
                edited.zeroize();
                write_secrets(&paths.recipients, &paths.store, &new_secrets)
            }
            Err(e) => Err(AppError::msg(format!("could not read edited file: {e}"))),
        },
        Ok(_) => Err(AppError::msg(
            "editor exited non-zero — store left unchanged.",
        )),
        Err(e) => Err(AppError::msg(format!(
            "could not launch editor '{}': {e}",
            editor.to_string_lossy()
        ))),
    };

    shred_and_remove(&tmp);
    result?;
    eprintln!("✔  store updated.");
    nudge_if_unlocked_shell();
    Ok(())
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

/// `envstow unlock [-- <cmd>...]` — decrypt the whole store and set every value as an env var
/// for a spawned child (an interactive subshell, or the given command). Values never printed;
/// only variable NAMES are listed.
fn cmd_unlock(args: &[String]) -> Cmd {
    let (profile, args) = resolve_profile(args)?;
    // Everything after `--` (or all args) is the command to run; empty → interactive subshell.
    let cmd: Vec<String> = match args.iter().position(|a| a == "--") {
        Some(i) => args[i + 1..].to_vec(),
        None => args.to_vec(),
    };

    let secrets = load_secrets(&profile)?;
    if secrets.is_empty() {
        return Err(AppError::msg("store decrypted but contains no variables."));
    }

    let names: Vec<&str> = secrets.names().collect();
    eprintln!(
        "🔓 envstow: loaded {} secret(s) from {}: {}",
        names.len(),
        profile,
        names.join(", ")
    );
    warn_on_shadowed(&secrets);

    spawn_with_env(&cmd, secrets)
}

/// Warn about secrets whose names are ALREADY set in our environment with a different value —
/// the child will see ours, shadowing whatever was there.
///
/// This is the nested-unlock case: unlock in FolderA, cd to FolderB, unlock again. The child gets
/// the UNION of both (env vars are inherited and `Command::env` only adds), with the inner store
/// winning on any shared name. That layering is usually what you want — a subproject adding its
/// own vars on top of shared ones — so this warns rather than blocks.
///
/// Deliberately vague about the source: all we can see is that the name was already set. It might
/// be an outer envstow, your shell rc, or CI. Saying "was already set" is the honest limit of
/// what we know, and it's why identical values are skipped — re-unlocking the same store would
/// otherwise warn about every name, which is noise, not signal.
///
/// Never prints either value, and never reveals which is which — only that they differ.
fn warn_on_shadowed(secrets: &Secrets) {
    let shadowed: Vec<&str> = secrets
        .iter()
        .filter(|(k, v)| {
            // Compare against the inherited value, if any. Only a DIFFERENT value is a real
            // shadow worth reporting.
            env::var_os(k).is_some_and(|existing| existing.to_string_lossy() != *v)
        })
        .map(|(k, _)| k)
        .collect();
    if shadowed.is_empty() {
        return;
    }
    let (count, verb) = if shadowed.len() == 1 {
        ("1 name".to_string(), "was")
    } else {
        (format!("{} names", shadowed.len()), "were")
    };
    eprintln!(
        "⚠️  envstow: {count} {verb} already set with a different value — this store's value wins \
         inside:\n\
         \x20  {}",
        shadowed.join(", ")
    );
}

/// After a `set`/`delete`/`edit` that changed the store, nudge the user IF they ran it from
/// inside an `envstow unlock` shell — that shell holds a copy of the OLD values (a running
/// process's environment can't be changed from outside), so it's now stale. The fix is uniform
/// for every kind of change: exit and unlock again. stderr only; never alters stdout or the exit
/// code. Silent outside an unlocked shell, where there's no stale state to warn about.
fn nudge_if_unlocked_shell() {
    if env::var_os("ENVSTOW_UNLOCKED").is_none() {
        return;
    }
    eprintln!(
        "\nℹ️  envstow: you're in an unlocked shell — it still holds the previous values.\n\
         \x20  Run `exit` then `envstow unlock` to pick up this change."
    );
}

/// Env var listing the NAMES envstow set in this environment, comma-separated. Names only —
/// never values. Lets `refresh` unset exactly what envstow owns and nothing else.
const LOADED_MARKER: &str = "ENVSTOW_LOADED";

/// Is `name` a plain shell identifier — `[A-Za-z_][A-Za-z0-9_]*`? Anything else is unsafe to
/// interpolate into shell code that will be `eval`ed.
fn is_shell_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Build the `ENVSTOW_LOADED` value for a child: the names we're about to set, unioned with any
/// an outer unlock already recorded (nested unlocks stack, so the outer names are still live).
fn loaded_marker(secrets: &Secrets) -> String {
    let mut names: Vec<String> = env::var(LOADED_MARKER)
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    for k in secrets.names() {
        if !names.iter().any(|n| n == k) {
            names.push(k.to_string());
        }
    }
    names.join(",")
}

/// The names envstow recorded setting in this environment, per `ENVSTOW_LOADED`.
fn loaded_names() -> Vec<String> {
    env::var(LOADED_MARKER)
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `envstow refresh` — emit shell code to unset secrets this environment has but the store no
/// longer does. Meant to be evaluated by your shell: `eval "$(envstow refresh)"`.
///
/// Why this exists: a child process cannot modify its parent's environment, so nothing envstow
/// runs can clear a stale variable from your shell. `eval` sidesteps that by having YOUR shell
/// execute what we print. The classic form of this trick (ssh-agent, direnv) prints `export
/// NAME=value` — which for envstow would mean dumping every secret in plaintext to stdout, the
/// one thing this tool exists to prevent. So we print ONLY `unset` lines.
///
/// That makes this deliberately one-directional:
///   * a DELETED secret is unset here — nothing about a value is revealed by unsetting its name;
///   * a CHANGED or ADDED secret is NOT updated — that would require printing the new value.
///
/// For those, exit and unlock again. `refresh` reports them so you know.
///
/// Only names in `ENVSTOW_LOADED` are considered, so a `DATABASE_URL` from your shell rc is never
/// touched — envstow only unsets what it set.
fn cmd_refresh(args: &[String]) -> Cmd {
    let (profile, args) = resolve_profile(args)?;
    if let Some(a) = args.first() {
        return Err(AppError::usage(format!("unexpected argument '{a}'")));
    }
    if env::var_os("ENVSTOW_UNLOCKED").is_none() {
        return Err(AppError::msg(
            "not inside an `envstow unlock` shell — nothing to refresh.\n\
             \x20  (refresh clears secrets this shell still holds after they left the store.)",
        ));
    }

    let secrets = load_secrets(&profile)?;

    // Stale = envstow set it here, and the store no longer has it. Note we compare against the
    // names WE recorded, not the whole environment, so we never unset someone else's var.
    let in_store: Vec<&str> = secrets.names().collect();
    let stale: Vec<String> = loaded_names()
        .into_iter()
        .filter(|n| !in_store.contains(&n.as_str()) && env::var_os(n).is_some())
        .collect();

    // Changed = still in the store, but this shell holds a different value. We can't fix these
    // without printing the new value, so we only report the count.
    let changed = secrets
        .iter()
        .filter(|(k, v)| env::var_os(k).is_some_and(|existing| existing.to_string_lossy() != *v))
        .count();

    // `secrets` scrubs its values on drop at the end of the function.

    // stdout is the eval payload — shell code ONLY, so a stray word can't be executed.
    //
    // Every name here is interpolated into code the user's shell will EVALUATE, so it must be a
    // plain identifier. A store is trusted input, but "trusted" is not a property to bet a shell
    // injection on: a name like `FOO; rm -rf ~` would otherwise run. Anything that isn't
    // [A-Za-z_][A-Za-z0-9_]* is skipped and reported, never emitted.
    let (safe, unsafe_): (Vec<&String>, Vec<&String>) =
        stale.iter().partition(|n| is_shell_identifier(n));
    let mut out = io::stdout().lock();
    for name in &safe {
        let _ = writeln!(out, "unset {name}");
    }
    let _ = out.flush();
    if !unsafe_.is_empty() {
        eprintln!(
            "envstow: refusing to emit {} name(s) that aren't plain identifiers (would be unsafe \
             to eval). Run `exit` then `envstow unlock` instead.",
            unsafe_.len()
        );
    }

    // Everything human-facing goes to stderr, where `eval "$(...)"` won't swallow or run it.
    if safe.is_empty() {
        eprintln!("envstow: nothing to unset — no secret in this shell has left the store.");
    } else {
        eprintln!(
            "🔄 envstow: unset {} secret(s) no longer in the store: {}",
            safe.len(),
            safe.iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if changed > 0 {
        eprintln!(
            "⚠️  envstow: {changed} secret(s) in this shell have a different value in the store. \
             refresh can't update them without printing values — run `exit` then `envstow unlock`."
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// update
// ---------------------------------------------------------------------------

/// The published shell installer, i.e. the command the README tells you to run. `upgrade` re-runs
/// it so you don't have to remember it — that IS the feature.
///
/// POSIX-only: Windows installs via the PowerShell installer and takes a different branch in
/// `cmd_upgrade`, so this would be dead code there (and `-D warnings` in CI rightly fails on it).
#[cfg(not(windows))]
const INSTALLER_URL: &str =
    "https://github.com/jhnhnsn/envstow/releases/latest/download/envstow-installer.sh";

/// `/releases/latest` 302s to `/releases/tag/vX.Y.Z`, so the redirect target names the newest
/// version. That's the whole version check: no JSON to parse (no serde), no API token, and it
/// isn't subject to the API's unauthenticated rate limit.
const LATEST_URL: &str = "https://github.com/jhnhnsn/envstow/releases/latest";

/// Ask GitHub for the latest released version by following the `/releases/latest` redirect and
/// reading the tag off the final URL. Shells out to `curl` rather than linking an HTTP stack:
/// envstow is a secrets tool with three dependencies on purpose, and a self-updater is
/// convenience, not function — not worth tripling the code running beside your decrypted keys.
/// `curl` is already how the README says to install, so it's a dependency we already require.
fn latest_version() -> Result<String, String> {
    let out = Command::new("curl")
        .args([
            "-sSL",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "15",
            "-o",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
            "-w",
            "%{url_effective}",
            LATEST_URL,
        ])
        .output()
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => "curl not found — install it, or update manually:\n\
                 \x20  curl --proto '=https' --tlsv1.2 -LsSf <installer> | sh"
                .to_string(),
            _ => format!("could not run curl: {e}"),
        })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() {
            "could not reach GitHub to check for updates".to_string()
        } else {
            format!("could not check for updates: {err}")
        });
    }
    let url = String::from_utf8_lossy(&out.stdout);
    // …/releases/tag/v0.1.11 → 0.1.11
    let tag = url
        .rsplit('/')
        .next()
        .filter(|t| !t.is_empty() && *t != "latest")
        .ok_or_else(|| format!("unexpected release URL: {url}"))?;
    Ok(tag.trim_start_matches('v').to_string())
}

/// Compare dotted numeric versions (0.1.9 < 0.1.11 — string compare would get this backwards).
/// Non-numeric or extra components fall back to comparing what parses; unknown shapes sort equal
/// so we never claim an update exists on a version we can't read.
fn version_is_newer(candidate: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split(['.', '-', '+'])
            .map_while(|p| p.parse::<u64>().ok())
            .collect()
    };
    let (c, u) = (parse(candidate), parse(current));
    if c.is_empty() || u.is_empty() {
        return false;
    }
    for i in 0..c.len().max(u.len()) {
        let (a, b) = (
            c.get(i).copied().unwrap_or(0),
            u.get(i).copied().unwrap_or(0),
        );
        if a != b {
            return a > b;
        }
    }
    false
}

/// How this envstow was installed, from the cargo-dist receipt beside the identity config.
/// `None` means no receipt — a package manager, `cargo install`, or a hand-placed binary.
fn install_receipt() -> Option<String> {
    let path = layout::identity_path()
        .parent()?
        .join("envstow-receipt.json");
    let text = std::fs::read_to_string(path).ok()?;
    // Deliberately not parsing JSON — that would mean a serde dependency for one field. We only
    // need to know whether OUR installer wrote this, which this substring answers.
    if text.contains("\"source\": \"cargo-dist\"") || text.contains("\"source\":\"cargo-dist\"") {
        Some("cargo-dist".to_string())
    } else {
        Some("unknown".to_string())
    }
}

/// `envstow upgrade [--check]` — check for a newer release, and install it by re-running the
/// published installer.
///
/// Refuses to self-update an install we didn't perform: overwriting a Homebrew/AUR-managed binary
/// desynchronizes it from the package manager's database (`brew doctor` complains; pacman
/// considers it hostile), or drops a second envstow on PATH that may shadow the managed one.
/// When there's no cargo-dist receipt, we say who should do the updating instead.
fn cmd_upgrade(args: &[String]) -> Cmd {
    let mut check_only = false;
    let mut yes = false;
    for a in args {
        match a.as_str() {
            "--check" => check_only = true,
            "--yes" | "-y" => yes = true,
            s => {
                return Err(AppError::usage(format!(
                    "unknown argument '{s}'\nusage: envstow upgrade [--check] [--yes]"
                )));
            }
        }
    }

    let current = env!("CARGO_PKG_VERSION");
    let latest = latest_version()?;

    if !version_is_newer(&latest, current) {
        eprintln!("✔  envstow {current} is up to date (latest: {latest}).");
        return Ok(());
    }
    eprintln!("⬆️  envstow {latest} is available (you have {current}).");
    eprintln!("   {}/releases/tag/v{latest}", layout::REPO_URL);

    if check_only {
        return Ok(());
    }

    // Only self-update an install we own.
    if install_receipt().as_deref() != Some("cargo-dist") {
        return Err(AppError::msg(format!(
            "this copy wasn't installed by the envstow installer, so `update` won't touch it\n\
             \x20  (no cargo-dist receipt at {}).\n\
             \x20  Update it with whatever installed it — e.g. `brew upgrade envstow`, your \
             distro's\n\
             \x20  package manager, or `cargo install --path crates/envstow` from a fresh checkout.",
            layout::identity_path()
                .parent()
                .unwrap_or(Path::new("."))
                .join("envstow-receipt.json")
                .display()
        )));
    }

    // Confirm before replacing the binary. Unlike `init`'s skill prompt, a non-interactive run
    // does NOT proceed by default: this downloads and executes a remote script over the running
    // executable, and a CI job that silently swapped its own envstow out from under itself would
    // be a nasty surprise. Non-TTY callers must opt in with --yes.
    if !yes {
        if !io::stdin().is_terminal() {
            return Err(AppError::msg(
                "refusing to update non-interactively — pass `--yes` to confirm:\n\
                 \x20  envstow upgrade --yes",
            ));
        }
        eprint!("Download and install envstow {latest}? [Y/n] ");
        let _ = io::stderr().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let ans = input.trim().to_ascii_lowercase();
            if ans == "n" || ans == "no" {
                eprintln!("   skipped.");
                return Ok(());
            }
        }
    }

    // Windows installs via the PowerShell installer; there's no `sh` to pipe through, so we print
    // the command instead of running it.
    #[cfg(windows)]
    {
        eprintln!(
            "\nenvstow: run the PowerShell installer to upgrade:\n\
             \x20  powershell -c \"irm https://github.com/jhnhnsn/envstow/releases/latest/download/envstow-installer.ps1 | iex\""
        );
        Ok(())
    }

    #[cfg(not(windows))]
    {
        eprintln!("   running the official installer…");
        // Exactly the pipeline the README documents — same URL, same TLS pinning. We're only
        // saving you from having to remember it.
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "curl --proto '=https' --tlsv1.2 -LsSf {INSTALLER_URL} | sh"
            ))
            .status()
            .map_err(|e| AppError::msg(format!("could not run the installer: {e}")))?;
        if status.success() {
            eprintln!("✔  updated to envstow {latest}. Open a new shell (or `hash -r`) to use it.");
            Ok(())
        } else {
            Err(AppError::msg(format!(
                "the installer exited with {}. Try it by hand:\n\
                 \x20  curl --proto '=https' --tlsv1.2 -LsSf {INSTALLER_URL} | sh",
                status.code().unwrap_or(-1)
            )))
        }
    }
}

/// Spawn either the given command or an interactive subshell, with the secrets in its env.
/// `secrets` scrubs its values on drop, after the child has its own copy. Returns the exit code.
fn spawn_with_env(cmd: &[String], secrets: Secrets) -> Cmd {
    let (program, args, interactive) = if cmd.is_empty() {
        let (sh, sh_args) = default_shell();
        eprintln!("🔓 envstow: launching unlocked subshell. Type `exit` to lock.");
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
    for (k, v) in secrets.iter() {
        command.env(k, v);
    }
    command.env("ENVSTOW_UNLOCKED", "1");
    // Record WHICH names we set, so `refresh` can tell an envstow secret from a same-named var
    // that came from your shell rc or CI — and only ever unset the ones we own. Names only; a
    // name is not a secret (`list` prints them). Nested unlocks union with the outer set, so an
    // inner refresh still knows about the outer store's names.
    command.env("ENVSTOW_LOADED", loaded_marker(&secrets));
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // The child inherits a copy of our env at spawn; our `secrets` scrubs on drop (function end).
    match command.spawn() {
        Ok(mut child) => match child.wait() {
            Ok(status) => {
                // Propagate the child's own exit code as ours, silently — it already printed
                // whatever it printed. A child killed by a signal (no code) is 0 for an
                // interactive subshell (you `exit`ed), 1 otherwise.
                let code = status.code().unwrap_or(if interactive { 0 } else { 1 });
                if code == 0 {
                    Ok(())
                } else {
                    Err(AppError::silent(code))
                }
            }
            Err(e) => Err(AppError::msg(format!("error waiting for child: {e}"))),
        },
        Err(e) => Err(AppError::msg(format!(
            "failed to launch '{}': {e}",
            program.to_string_lossy()
        ))
        .with_code(127)),
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

/// `envstow init` — generate an age identity (if none), create the `recipients` file with the
/// user as sole recipient (if none), and create an empty encrypted store (if none). Idempotent.
/// Also offers to add the Claude Code agent skill to this repo (`--no-skill` to skip).
fn cmd_init(args: &[String]) -> Cmd {
    let skip_skill = args.iter().any(|a| a == "--no-skill");

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
                return Err(AppError::msg(format!(
                    "existing identity is unreadable: {e}"
                )));
            }
        },
        Err(_) => {
            let (public, mut secret) = crypto::generate_keypair();
            match layout::write_new_identity(&secret) {
                Ok(path) => eprintln!("✔  generated identity at {}", path.display()),
                Err(e) => {
                    secret.zeroize();
                    return Err(AppError::msg(format!("could not write identity: {e}")));
                }
            }
            secret.zeroize();
            public
        }
    };
    eprintln!("   your public key: {public}");

    // 2. Recipients file under .envstow/ in the CWD (this becomes the repo root anchor).
    let root = env::current_dir().unwrap_or_else(|_| ".".into());
    // Ensure the .envstow/ dir exists before we write into it.
    if let Err(e) = std::fs::create_dir_all(root.join(layout::ENVSTOW_DIR)) {
        return Err(AppError::msg(format!(
            "could not create {}: {e}",
            layout::ENVSTOW_DIR
        )));
    }
    let recipients_path = root.join(layout::RECIPIENTS_FILE);
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
            // an EXISTING recipient runs `envstow reencrypt`. Adding our key alone does not
            // grant us decryption — say so plainly rather than leaving a broken state.
            eprintln!(
                "⚠️  {} already lists {} other recipient(s). Adding your key here does NOT let\n\
                 \x20   you decrypt the existing store — ask an existing recipient to run\n\
                 \x20   `envstow reencrypt` after pulling your key.",
                recipients_path.display(),
                recipients.len()
            );
        }
        recipients.push(Recipient {
            key: public.clone(),
            label: Some("me".to_string()),
        });
        if let Err(e) = std::fs::write(&recipients_path, layout::render_recipients(&recipients)) {
            return Err(AppError::msg(format!(
                "could not write recipients file: {e}"
            )));
        }
        eprintln!("✔  added you to {}", recipients_path.display());
    }

    // 3. Encrypted store: create an empty one if absent (the default profile → .envstow/default.enc).
    let store_path = root.join(layout::STORE_FILE);
    if store_path.is_file() {
        eprintln!("✔  store already exists at {}", store_path.display());
    } else {
        let seed = b"# envstow secrets -- KEY=value lines. Edit via `envstow unlock`.\n";
        match encrypt_payload(seed, &recipients) {
            Ok(ct) => {
                if let Err(e) = layout::write_store(&store_path, &ct) {
                    return Err(AppError::msg(format!("could not write store: {e}")));
                }
                eprintln!("✔  created empty store at {}", store_path.display());
            }
            Err(e) => {
                return Err(AppError::msg(format!(
                    "could not encrypt initial store: {e}"
                )));
            }
        }
    }

    // 4. Offer to add the Claude Code agent skill to THIS repo (so it commits + travels to
    //    teammates). Prompts [Y/n]; --no-skill skips; non-interactive defaults to yes.
    if !skip_skill {
        let repo_root = root.as_path();
        maybe_install_skill(repo_root);
    }

    // Don't claim "Ready" when we just told them they can't decrypt yet. Someone joining a repo
    // whose store belongs to other people is NOT ready — they're waiting on a recipient. Saying
    // otherwise (right after two green checkmarks) is what makes the later "No matching keys"
    // look like a bug rather than the expected next step.
    if joining_existing {
        eprintln!(
            "\n⏳ Almost there — you can't decrypt this store yet. Send your public key to \
             someone\n\
             \x20  who already has access:\n\
             \x20    {public}\n\
             \x20  They run:  envstow add-recipient {public} <your-name>\n\
             \x20  Then `git pull` and you're in."
        );
    } else {
        eprintln!("\n🔓 Ready. Add secrets by editing the store, then `envstow unlock`.");
        eprintln!("   Share your public key with collaborators so they can add you.");
    }
    Ok(())
}

/// The agent skill content, embedded at compile time so the binary can write it into any repo
/// (a consuming repo has no copy of the source file). Kept in sync with `agent/envstow-skill.md`.
const AGENT_SKILL: &str = include_str!("../../../agent/envstow-skill.md");

/// Offer to write the Claude Code agent skill into `<repo>/.claude/skills/envstow/SKILL.md`.
/// Prompts `[Y/n]` on a TTY (default yes); on a non-TTY (CI) it installs without prompting.
/// Writing it into the repo means it gets committed and travels to teammates who clone.
fn maybe_install_skill(repo_root: &Path) {
    let dest = repo_root
        .join(".claude")
        .join("skills")
        .join("envstow")
        .join("SKILL.md");

    let existed = dest.is_file();
    let prompt = if existed {
        "Update the Claude Code agent skill in this repo? [Y/n] "
    } else {
        "Add the Claude Code agent skill to this repo (so your agent uses secrets safely)? [Y/n] "
    };

    if io::stdin().is_terminal() {
        eprint!("{prompt}");
        let _ = io::stderr().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let ans = input.trim().to_ascii_lowercase();
            if ans == "n" || ans == "no" {
                eprintln!("   skipped. (Install later: see GUARDRAILS.md)");
                return;
            }
        }
    }

    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("envstow: could not create {}: {e}", parent.display());
            return;
        }
    }
    match std::fs::write(&dest, AGENT_SKILL) {
        Ok(()) => {
            let verb = if existed { "updated" } else { "added" };
            eprintln!("✔  {verb} agent skill at {}", dest.display());
            eprintln!("   commit `.claude/skills/envstow/` so teammates get it on clone.");
        }
        Err(e) => eprintln!("envstow: could not write agent skill: {e}"),
    }
}

// ---------------------------------------------------------------------------
// recipient management
// ---------------------------------------------------------------------------

fn cmd_add_recipient(args: &[String]) -> Cmd {
    let (profile, args) = resolve_profile(args)?;
    let Some(key) = args.first() else {
        return Err(AppError::usage(
            "usage: envstow add-recipient <age1...> [label] [--profile P]",
        ));
    };
    if crypto::parse_recipient(key).is_err() {
        return Err(AppError::msg(format!(
            "'{key}' is not a valid age public key (expected age1...)."
        )));
    }
    let label = args.get(1).cloned();

    let paths = layout::locate(&profile)?;
    let mut recipients = layout::read_recipients(&paths.recipients).unwrap_or_default();
    if recipients.iter().any(|r| &r.key == key) {
        // Already present is not an error — nothing to do.
        eprintln!("envstow: {key} is already a recipient.");
        return Ok(());
    }
    recipients.push(Recipient {
        key: key.clone(),
        label,
    });

    if let Err(e) = std::fs::write(&paths.recipients, layout::render_recipients(&recipients)) {
        return Err(AppError::msg(format!(
            "could not update recipients file: {e}"
        )));
    }
    eprintln!("✔  added recipient to {}", paths.recipients.display());
    reencrypt_store(&paths.store, &recipients)
}

fn cmd_remove_recipient(args: &[String]) -> Cmd {
    let (profile, args) = resolve_profile(args)?;
    let Some(target) = args.first() else {
        return Err(AppError::usage(
            "usage: envstow remove-recipient <age1...|label> [--profile P]",
        ));
    };

    let paths = layout::locate(&profile)?;
    let recipients = layout::read_recipients(&paths.recipients).unwrap_or_default();

    let matches: Vec<&Recipient> = recipients
        .iter()
        .filter(|r| &r.key == target || r.label.as_deref() == Some(target.as_str()))
        .collect();
    if matches.is_empty() {
        return Err(AppError::msg(format!("no recipient matching '{target}'.")));
    }
    if matches.len() > 1 {
        return Err(AppError::msg(format!(
            "'{target}' matches {} recipients — pass the exact age key.",
            matches.len()
        )));
    }
    let removed_key = matches[0].key.clone();
    let kept: Vec<Recipient> = recipients
        .into_iter()
        .filter(|r| r.key != removed_key)
        .collect();
    if kept.is_empty() {
        return Err(AppError::msg(
            "refusing to remove the last recipient (store would be unreadable).",
        ));
    }

    if let Err(e) = std::fs::write(&paths.recipients, layout::render_recipients(&kept)) {
        return Err(AppError::msg(format!(
            "could not update recipients file: {e}"
        )));
    }
    eprintln!("✔  removed recipient; {} remain.", kept.len());
    reencrypt_store(&paths.store, &kept)?;
    eprintln!(
        "\n⚠️  Removing a recipient only blocks FUTURE decryptions. Their key still decrypts\n\
         every historical commit in any clone they kept. Rotate every secret they saw at the\n\
         source to truly revoke access."
    );
    Ok(())
}

fn cmd_reencrypt(args: &[String]) -> Cmd {
    let (profile, _args) = resolve_profile(args)?;
    let paths = layout::locate(&profile)?;
    let recipients = layout::read_recipients(&paths.recipients).unwrap_or_default();
    if recipients.is_empty() {
        return Err(AppError::msg("recipients file has no keys."));
    }
    reencrypt_store(&paths.store, &recipients)
}

// ---------------------------------------------------------------------------
// profiles
// ---------------------------------------------------------------------------

/// `envstow profile [create <name>]` — show the current profile (and available ones), or create
/// a new one. The current profile is resolved from ENVSTOW_PROFILE (or `default`).
fn cmd_profile(args: &[String]) -> Cmd {
    // Subcommand: `profile create <name>`
    if args.first().map(String::as_str) == Some("create") {
        let Some(name) = args.get(1) else {
            return Err(AppError::usage("usage: envstow profile create <name>"));
        };
        return profile_create(name);
    }
    if !args.is_empty() {
        return Err(AppError::usage("usage: envstow profile [create <name>]"));
    }

    // Show current + available.
    let current = env::var("ENVSTOW_PROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| layout::DEFAULT_PROFILE.to_string());
    let source = if env::var("ENVSTOW_PROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some()
    {
        "from $ENVSTOW_PROFILE"
    } else {
        "default"
    };
    println!("current profile: {current} ({source})");

    match layout::repo_root() {
        Ok(root) => {
            let profiles = layout::list_profiles(&root);
            if profiles.is_empty() {
                eprintln!("   (no stores yet — run `envstow init`)");
            } else {
                eprintln!("available: {}", profiles.join(", "));
            }
        }
        Err(_) => eprintln!("   (not inside an envstow repo)"),
    }
    Ok(())
}

/// `envstow profiles` — list the profiles that exist in this repo.
fn cmd_profiles() -> Cmd {
    let root = layout::repo_root()?;
    for p in layout::list_profiles(&root) {
        println!("{p}");
    }
    Ok(())
}

/// Create an empty store for a new profile (encrypted to the current recipients).
fn profile_create(name: &str) -> Cmd {
    if !layout::valid_profile_name(name) {
        return Err(AppError::usage(format!(
            "invalid profile name '{name}' (use letters, digits, - or _)"
        )));
    }
    if name == layout::DEFAULT_PROFILE {
        return Err(AppError::msg(format!(
            "'{name}' is the default profile — it already exists after `init`."
        )));
    }
    let paths = layout::locate(name)?;
    if paths.store.is_file() {
        return Err(AppError::msg(format!(
            "profile '{name}' already exists at {}",
            paths.store.display()
        )));
    }
    let recipients = layout::read_recipients(&paths.recipients).unwrap_or_default();
    if recipients.is_empty() {
        return Err(AppError::msg(
            "recipients file has no keys — run `envstow init` first.",
        ));
    }
    let seed = format!("# envstow profile '{name}' -- KEY=value lines.\n");
    let ct = encrypt_payload(seed.as_bytes(), &recipients)
        .map_err(|e| AppError::msg(format!("could not create profile store: {e}")))?;
    layout::write_store(&paths.store, &ct)
        .map_err(|e| AppError::msg(format!("could not write store: {e}")))?;
    eprintln!("✔  created profile '{name}' at {}", paths.store.display());
    eprintln!(
        "   use it with:  envstow --profile {name} set <NAME>   (or export ENVSTOW_PROFILE={name})"
    );
    Ok(())
}

/// Decrypt the store with our identity and re-encrypt it to `recipients`. Used after any change
/// to the recipient set. Plaintext is zeroized.
fn reencrypt_store(store: &Path, recipients: &[Recipient]) -> Cmd {
    let secret = layout::read_identity_secret()?;
    let identity = crypto::parse_identity(&secret)?;
    let ciphertext = layout::read_store(store)?;
    let mut plaintext = crypto::decrypt(&ciphertext, &identity)?;

    let recips = match parse_all_recipients(recipients) {
        Ok(r) => r,
        Err(e) => {
            plaintext.zeroize();
            return Err(AppError::msg(e));
        }
    };
    let result = crypto::encrypt(&plaintext, &recips);
    plaintext.zeroize();
    let ct = result.map_err(|e| AppError::msg(format!("re-encryption failed: {e}")))?;

    layout::write_store(store, &ct)
        .map_err(|e| AppError::msg(format!("could not write store: {e}")))?;
    eprintln!("✔  re-encrypted store to {} recipient(s).", recips.len());
    Ok(())
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
        // Encode multi-line values (base64 behind a marker); single-line values pass through.
        let encoded = crypto::encode_value(v);
        payload.push_str(k);
        payload.push('=');
        if starts_and_ends_with_matching_quote(&encoded) {
            let q = if encoded.starts_with('"') { '\'' } else { '"' };
            payload.push(q);
            payload.push_str(&encoded);
            payload.push(q);
        } else {
            payload.push_str(&encoded);
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
        "envstow — a local, encrypted key-value store (age) surfaced by NAME\n\
         \n\
         USAGE:\n\
         \x20 envstow get <NAME> [--show]      Resolve one secret (masked under an agent).\n\
         \x20 envstow set <NAME> [--clipboard] Read a value from stdin (or clipboard) and store it.\n\
         \x20 envstow delete <NAME>            Remove one secret and re-encrypt (then rotate).\n\
         \x20 envstow edit                     Edit all secrets in $EDITOR (decrypt/re-encrypt).\n\
         \x20 envstow list                     List secret NAMES (never values).\n\
         \x20 envstow pubkey                   Print your age PUBLIC key (share it to be added).\n\
         \x20 envstow unlock [-- <cmd>...]     Subshell / run a command with the whole env set.\n\
         \x20 envstow refresh                  Unset secrets that left the store: eval \"$(envstow refresh)\".\n\
         \x20 envstow init [--no-skill]        Create identity + recipients + store; add agent skill.\n\
         \x20 envstow add-recipient <age1..>   Add a collaborator and re-encrypt.\n\
         \x20 envstow remove-recipient <k|nm>  Remove a collaborator and re-encrypt (then rotate).\n\
         \x20 envstow reencrypt                Re-encrypt the store to the current recipients.\n\
         \x20 envstow profile [create <name>]  Show the current profile, or create a new one.\n\
         \x20 envstow profiles                 List available profiles.\n\
         \x20 envstow upgrade [--check|--yes]  Upgrade envstow to the latest release.\n\
         \n\
         Profiles: add `--profile <name>` to any command to use a separate secret set\n\
         (e.g. dev/staging/prod), or set $ENVSTOW_PROFILE. Default is `default`.\n\
         \x20 envstow --version                Print the envstow version.\n\
         \n\
         EXAMPLES:\n\
         \x20 envstow set MY_TOKEN --clipboard         # store a secret straight from the clipboard\n\
         \x20 do-thing \"$(envstow get DB_PASSWORD)\"   # by name; masked if an agent runs it bare\n\
         \x20 envstow unlock -- npm run build          # run one command with all secrets set\n\
         \x20 envstow unlock                           # start your AI in an unlocked subshell\n\
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
    fn version_compare_is_numeric_not_lexical() {
        // The bug this exists to prevent: "0.1.9" > "0.1.11" as strings, so a lexical compare
        // would tell everyone on 0.1.11 to "update" to 0.1.9, forever.
        assert!(version_is_newer("0.1.11", "0.1.9"), "0.1.11 > 0.1.9");
        assert!(!version_is_newer("0.1.9", "0.1.11"), "0.1.9 is not newer");

        assert!(version_is_newer("0.2.0", "0.1.11"));
        assert!(version_is_newer("1.0.0", "0.99.99"));
        assert!(!version_is_newer("0.1.11", "0.1.11"), "equal is not newer");
        assert!(!version_is_newer("0.1.10", "0.1.11"));

        // Differing component counts: missing parts are zero.
        assert!(version_is_newer("0.2", "0.1.11"));
        assert!(!version_is_newer("0.1", "0.1.0"), "0.1 == 0.1.0");
        assert!(version_is_newer("0.1.1", "0.1"));

        // Pre-release / build suffixes: compare the numeric lead, don't panic.
        assert!(version_is_newer("0.2.0-beta.1", "0.1.11"));

        // Unparseable input must never claim an update — better silent than wrong.
        assert!(!version_is_newer("garbage", "0.1.11"));
        assert!(!version_is_newer("0.1.12", "garbage"));
        assert!(!version_is_newer("", "0.1.11"));
    }

    #[test]
    fn shell_identifiers_gate_what_can_be_evaled() {
        // These are interpolated into code the user's shell will eval. Anything that could break
        // out of `unset <name>` must be rejected — a store is trusted input, but not THAT trusted.
        for ok in ["FOO", "_x", "A1", "DATABASE_URL", "a_b_c9"] {
            assert!(is_shell_identifier(ok), "{ok} should be a valid identifier");
        }
        for bad in [
            "",
            "1FOO",          // leading digit
            "FOO; rm -rf ~", // command injection
            "FOO BAR",
            "FOO$(id)",
            "FOO`id`",
            "FOO&&id",
            "FOO\nid",
            "FOO'",
            "FÖO", // non-ASCII
        ] {
            assert!(
                !is_shell_identifier(bad),
                "{bad:?} must NOT be treated as a safe identifier"
            );
        }
    }

    #[test]
    fn loaded_marker_unions_with_an_outer_unlock() {
        let prev = env::var_os(LOADED_MARKER);
        // Nested unlock: the outer store's names are still live in the environment, so the inner
        // marker must keep them — otherwise a refresh inside the inner shell would forget them.
        env::set_var(LOADED_MARKER, "OUTER_A,SHARED");
        let inner = Secrets::from_pairs(vec![
            ("SHARED".to_string(), "v".to_string()),
            ("INNER_B".to_string(), "v".to_string()),
        ]);
        let marker = loaded_marker(&inner);
        let names: Vec<&str> = marker.split(',').collect();
        assert!(names.contains(&"OUTER_A"), "keeps outer names: {marker}");
        assert!(names.contains(&"INNER_B"), "adds inner names: {marker}");
        assert_eq!(
            names.iter().filter(|n| **n == "SHARED").count(),
            1,
            "no duplicate for a name in both: {marker}"
        );

        env::remove_var(LOADED_MARKER);
        assert_eq!(
            loaded_marker(&inner),
            "SHARED,INNER_B",
            "with no outer marker, just our own names"
        );

        match prev {
            Some(v) => env::set_var(LOADED_MARKER, v),
            None => env::remove_var(LOADED_MARKER),
        }
    }

    #[test]
    fn mask_hides_value_and_length() {
        assert_eq!(mask("short"), mask("a-much-longer-secret-value"));
        assert!(!mask("sk-abc123").contains("sk-"));
    }

    #[test]
    fn masked_preview_shows_first_five_then_dots() {
        let p = masked_preview("sk-proj-abc123def456");
        assert!(p.starts_with("sk-pr"), "should show first 5 chars: {p}");
        assert!(!p.contains("abc123"), "must not reveal the rest: {p}");
        assert!(p.contains('•'), "should be masked after the prefix");
    }

    #[test]
    fn masked_preview_fully_masks_short_values() {
        // ≤5 chars: never reveal any of a short secret.
        for v in ["", "a", "abcd", "exact"] {
            assert!(
                !masked_preview(v).chars().any(|c| c != '•'),
                "short value {v:?} should be all dots, got {}",
                masked_preview(v)
            );
        }
    }

    #[test]
    fn masked_preview_counts_chars_not_bytes() {
        // Multibyte: 5 CHARS shown, no split codepoint (would panic if byte-sliced).
        let p = masked_preview("café☕secret-tail");
        assert!(p.starts_with("café☕"), "5 chars incl. multibyte: {p}");
        assert!(!p.contains("secret"), "rest hidden: {p}");
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
    fn under_agent_detects_every_known_marker() {
        // Save every marker we might touch, clear them all, restore at the end. env::set_var is
        // process-global, so we snapshot the full set to avoid disturbing other tests.
        let saved: Vec<(String, Option<std::ffi::OsString>)> = AGENT_ENV_MARKERS
            .iter()
            .map(|m| (m.to_string(), env::var_os(m)))
            .collect();
        for (k, _) in &saved {
            env::remove_var(k);
        }

        // With all markers cleared, not under an agent.
        assert!(!under_agent(), "no markers → not under agent");

        // Each marker independently triggers detection (Claude, Cursor, Aider, Windsurf, opt-in).
        for marker in AGENT_ENV_MARKERS {
            env::set_var(marker, "1");
            assert!(under_agent(), "{marker} should be detected as an agent");
            env::remove_var(marker);
        }

        // Restore original environment.
        for (k, v) in saved {
            match v {
                Some(v) => env::set_var(&k, v),
                None => env::remove_var(&k),
            }
        }
    }
}
