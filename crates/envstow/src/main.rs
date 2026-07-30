//! envstow — an age-encrypted key-value store committed to the repo, decrypted with each user's
//! own age key, surfaced by NAME so neither a human nor an agent has to paste a literal secret
//! value onto a command line.
//!
//! Commands:
//!   envstow get <NAME> [--show]     Resolve one secret by name (masked under an agent).
//!   envstow set <NAME> [--clipboard] Store a value from stdin, or the OS clipboard.
//!   envstow delete <NAME>           Remove one secret and re-encrypt (then rotate!).
//!   envstow unlock                  Interactive subshell with the whole env set; `exit` locks.
//!   envstow run [--only A,B] -- <c> Run one command with all — or only the named — secrets.
//!   envstow env [--off]             Emit eval-able exports/unsets for the CURRENT shell (guarded).
//!   envstow refresh                 Emit `unset` lines for secrets that left the store (eval it).
//!   envstow shell-init              Print the optional shell wrapper to source from your rc.
//!   envstow status                  Show unlock state, profile, and loaded secret NAMES.
//!   envstow upgrade [--check|--yes] Check for / install a newer envstow.
//!   envstow scan-leak               PostToolUse hook: block tool output containing a live value.
//!   envstow init [--store <name>]   Generate an identity, add self as recipient, create store.
//!   envstow store                   Show which store is in effect (and why); list central ones.
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
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::Command;

use zeroize::Zeroize;

mod agent;
mod cli;
mod crypto;
mod error;
mod layout;
mod leakscan;
mod secrets;
mod selfupdate;
mod session;
mod store;

use agent::{mask, masked_preview, under_agent};
use cli::{parse_simple, resolve_target};
use error::AppError;
use layout::Recipient;
use store::{encrypt_payload, load_secrets_in, reencrypt_store, write_secrets};

/// A command's result: `Ok(())` on success, or an [`AppError`] carrying the message and exit code.
type Cmd = Result<(), AppError>;

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    // Allow `--profile <name>` (or `--profile=<name>`) as a GLOBAL flag before the subcommand,
    // e.g. `envstow --profile prod set X`. We lift it into ENVSTOW_PROFILE so the per-command
    // resolve_profile() picks it up, then drop it from args so dispatch sees the subcommand.
    // Also accept `--store` / `--store-dir` here, same treatment: lifted into the environment
    // so the per-command resolve_store() sees them wherever they were written. Looping lets
    // them combine, e.g. `envstow --store acme --profile prod get X`.
    while let Some(first) = args.first().cloned() {
        let lift = |var: &str, args: &mut Vec<String>| {
            if args.len() >= 2 {
                env::set_var(var, &args[1]);
                args.drain(0..2);
                true
            } else {
                false
            }
        };
        let consumed = match first.as_str() {
            "--profile" => lift("ENVSTOW_PROFILE", &mut args),
            "--store" => lift("ENVSTOW_STORE", &mut args),
            "--store-dir" => lift("ENVSTOW_STORE_DIR", &mut args),
            _ => {
                if let Some(v) = first.strip_prefix("--profile=") {
                    env::set_var("ENVSTOW_PROFILE", v);
                    args.remove(0);
                    true
                } else if let Some(v) = first.strip_prefix("--store=") {
                    env::set_var("ENVSTOW_STORE", v);
                    args.remove(0);
                    true
                } else if let Some(v) = first.strip_prefix("--store-dir=") {
                    env::set_var("ENVSTOW_STORE_DIR", v);
                    args.remove(0);
                    true
                } else {
                    false
                }
            }
        };
        if !consumed {
            break;
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
        // Removed in 0.1.21: `edit` was the one command that parked the whole store's plaintext
        // on disk for an editor session (editor swap/undo files outlive any shred, and it had no
        // agent guard). A tombstone beats "unknown command" for anyone who used it.
        Some("edit") => Err(AppError::msg(
            "`edit` was removed — it wrote the whole store's plaintext to a temp file for your \
             editor,\n  which editors copy into swap/undo files envstow can't clean up.\n  \
             Use `envstow set <NAME>` to add or change (pipe for multi-line values) and \
             `envstow delete <NAME>` to remove.",
        )),
        Some("list") => cmd_list(&args[1..]),
        Some("pubkey") => cmd_pubkey(),
        Some("unlock") => session::cmd_unlock(&args[1..]),
        Some("run") => session::cmd_run(&args[1..]),
        Some("env") => session::cmd_env(&args[1..]),
        Some("refresh") => session::cmd_refresh(&args[1..]),
        Some("status") => session::cmd_status(&args[1..]),
        Some("shell-init") => session::cmd_shell_init(&args[1..]),
        Some("scan-leak") => leakscan::cmd_scan_leak(&args[1..]),
        // `upgrade` is the canonical name (deno upgrade, rustup self update): "upgrade" means
        // the program itself, while "update" tends to mean the things a program manages (npm
        // update, brew upgrade, rustup update). envstow manages secrets, so `update` is kept
        // free for that sense — and accepted here as an undocumented alias for anyone who used
        // it in 0.1.12, the one release where it was the real name.
        Some("upgrade") | Some("update") => selfupdate::cmd_upgrade(&args[1..]),
        Some("init") => cmd_init(&args[1..]),
        Some("add-recipient") => cmd_add_recipient(&args[1..]),
        Some("remove-recipient") => cmd_remove_recipient(&args[1..]),
        Some("reencrypt") => cmd_reencrypt(&args[1..]),
        Some("store") => cmd_store(&args[1..]),
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
    let (sel, profile, args) = resolve_target(args)?;
    let parsed = parse_simple(&args, &[("--show", "show")])?;
    let show = parsed.has("show");
    let Some(name) = parsed.positional else {
        return Err(AppError::usage(
            "usage: envstow get <NAME> [--profile P] [--show]",
        ));
    };

    let secrets = load_secrets_in(&sel, &profile)?;

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
             Use it by name via `envstow run --only {name} -- <cmd using ${name}>`, \
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
    let (sel, profile, args) = resolve_target(args)?;
    let parsed = parse_simple(
        &args,
        // `--export` is an internal flag used by the shell wrapper `unlock` installs: after
        // storing, it prints `export NAME=<value>` to stdout so the CALLER's shell can `eval` it
        // and the value goes live in that shell. Not documented in the usage string.
        &[
            ("--clipboard", "clipboard"),
            ("-c", "clipboard"),
            ("--export", "export"),
        ],
    )?;
    let from_clipboard = parsed.has("clipboard");
    let want_export = parsed.has("export");
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
    let paths = match layout::locate_in(&sel, &profile) {
        Ok(p) => p,
        Err(e) => {
            value.zeroize();
            return Err(e.into());
        }
    };
    let mut secrets = match load_secrets_in(&sel, &profile) {
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

    // If asked to export (and it's safe to — never emit a value under an agent, whose stdout is
    // the transcript), build the `export NAME=<value>` line now, before `value` is moved into the
    // store. The value is shell-single-quoted so ANY content (spaces, `;`, `$()`, newlines) is
    // inert when the caller's shell eval's it — the injection-safety counterpart to refresh's
    // identifier check, but for a value.
    let mut export_line = if want_export && !under_agent() {
        Some(format!(
            "export {name}={}",
            session::shell_single_quote(&value)
        ))
    } else {
        None
    };

    // Hand the value to the store (upsert scrubs any prior value it replaces). `value` is moved
    // in, so nothing left here to zeroize; `secrets` scrubs everything on drop.
    secrets.upsert(name, value);

    if let Err(e) = write_secrets(&paths.recipients, &paths.store, &secrets) {
        if let Some(mut line) = export_line {
            line.zeroize();
        }
        return Err(e);
    }
    eprintln!("set {name} ({preview})");

    if let Some(mut line) = export_line.take() {
        // The caller's shell captures this via `$(…)` and eval's it — the value becomes live in
        // that shell without ever being displayed. Zeroize our copy right after writing it.
        {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
        line.zeroize();
    } else {
        // Couldn't make it live (no --export, or under an agent) — nudge to re-unlock if we're in
        // an unlocked shell holding now-stale values.
        session::nudge_if_unlocked_shell();
    }
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
    let (sel, profile, args) = resolve_target(args)?;
    let parsed = parse_simple(&args, &[("--force", "force"), ("-f", "force")])?;
    let force = parsed.has("force");
    let Some(name) = parsed.positional else {
        return Err(AppError::usage(
            "usage: envstow delete <NAME> [--profile P] [--force]",
        ));
    };

    let paths = layout::locate_in(&sel, &profile)?;
    let mut secrets = load_secrets_in(&sel, &profile)?;

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
    eprintln!("deleted {name}");
    eprintln!(
        "\n⚠️  Deleting only removes it going forward. The value is still readable in this\n\
         \x20   store's git history by anyone who is (or was) a recipient. Rotate it at the\n\
         \x20   source if it should no longer be valid."
    );
    session::nudge_if_unlocked_shell();
    Ok(())
}

/// `envstow list` — print the variable NAMES in the store (never values).
fn cmd_list(args: &[String]) -> Cmd {
    let (sel, profile, _args) = resolve_target(args)?;
    let secrets = load_secrets_in(&sel, &profile)?;
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

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// `envstow init` — generate an age identity (if none), create the `recipients` file with the
/// user as sole recipient (if none), and create an empty encrypted store (if none). Idempotent.
/// Also offers to add the Claude Code agent skill to this repo (`--no-skill` to skip).
///
/// Three shapes, by where the store should live:
///   * `envstow init` — a local `.envstow/` store beside the code, committed with it.
///   * `envstow init --store <name>` — a central store at `~/.config/envstow/stores/<name>/`,
///     plus a `.envstow` POINTER file in the CWD naming it. Nothing encrypted ever enters the
///     working tree. This is the shape for a public repo, or for a store shared by some means
///     other than git.
///   * `envstow init --store-dir <path>` — a store at an arbitrary directory (a synced folder,
///     say). No pointer is written: a path is machine-specific, so committing one would break
///     for everyone else. Reach it with `--store-dir` or `$ENVSTOW_STORE_DIR`.
fn cmd_init(args: &[String]) -> Cmd {
    let skip_skill = args.iter().any(|a| a == "--no-skill");
    let (sel, _rest) = cli::resolve_store(args)?;

    // 1. Identity: reuse an existing one, else generate and write it.
    let public = match layout::read_identity_secret() {
        Ok(secret) => match crypto::public_from_secret(&secret) {
            Ok(p) => {
                eprintln!(
                    "using existing identity at {}",
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
                Ok(path) => eprintln!("generated identity at {}", path.display()),
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

    // 2. Decide where the store itself lives, and create that directory.
    let cwd = env::current_dir().unwrap_or_else(|_| ".".into());
    let store_root = match &sel {
        layout::StoreSelector::Named(name) => layout::central_store_path(name),
        layout::StoreSelector::Dir(path) => path.clone(),
        layout::StoreSelector::Discover => cwd.join(layout::ENVSTOW_DIR),
    };
    // A local store must not collide with a pointer file of the same name — `.envstow` is one
    // or the other. Refuse rather than clobber: the pointer names a store that may hold the
    // only copy of someone's secrets.
    if matches!(sel, layout::StoreSelector::Discover) && store_root.is_file() {
        return Err(AppError::msg(format!(
            "{} is a pointer FILE naming a central store, not a local store directory.\n\
             \x20  This repo already uses a central store — add secrets with `envstow set`, \
             or remove\n\
             \x20  the pointer file first if you really want a local store here.",
            store_root.display()
        )));
    }

    // `init --store <name>` in a repo that ALREADY points at that store, on a machine that
    // doesn't have it: this is someone joining a colleague's project, not starting a new one.
    //
    // The local flow catches the equivalent case for free — a git clone brings the store and its
    // `recipients` along, so `init` sees other people's keys and reports "you're joining." A
    // central store isn't cloned, so there is nothing on disk to notice, and the naive path
    // cheerfully creates a SECOND empty store with the same name. Two stores, no sync, no
    // warning: the user thinks they joined and has actually diverged.
    //
    // The pointer is the one piece of evidence that someone else's store exists. Trust it and
    // stop, rather than manufacture a decoy.
    if let layout::StoreSelector::Named(name) = &sel {
        let pointer = cwd.join(layout::ENVSTOW_DIR);
        let points_here = pointer
            .is_file()
            .then(|| std::fs::read_to_string(&pointer).ok())
            .flatten()
            .and_then(|t| layout::parse_pointer_name(&t))
            .is_some_and(|n| &n == name);
        if points_here && !store_root.join(layout::RECIPIENTS_NAME).is_file() {
            return Err(AppError::msg(format!(
                "this project already points at the central store '{name}', but you don't have \
                 it yet.\n\
                 \x20  Creating it here would make a SECOND, empty store with the same name — \
                 not a copy\n\
                 \x20  of your colleague's — and nothing would warn you they'd diverged.\n\
                 \n\
                 \x20  To join, send them your public key:\n\
                 \x20    {public}\n\
                 \x20  They run:  envstow add-recipient {public} <your-name>\n\
                 \x20  …then send you their store directory (they can find it with \
                 `envstow store`).\n\
                 \x20  It goes here:\n\
                 \x20    {}\n\
                 \n\
                 \x20  (Starting an unrelated store that happens to share the name? Use a \
                 different\n\
                 \x20   name, or delete {} first.)",
                store_root.display(),
                pointer.display()
            )));
        }
    }
    if let Err(e) = std::fs::create_dir_all(&store_root) {
        return Err(AppError::msg(format!(
            "could not create {}: {e}",
            store_root.display()
        )));
    }
    let recipients_path = store_root.join(layout::RECIPIENTS_NAME);
    let mut recipients = if recipients_path.is_file() {
        layout::read_recipients(&recipients_path).unwrap_or_default()
    } else {
        Vec::new()
    };
    let joining_existing = !recipients.is_empty() && !recipients.iter().any(|r| r.key == public);
    if recipients.iter().any(|r| r.key == public) {
        eprintln!("already a recipient in {}", recipients_path.display());
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
        eprintln!("added you to {}", recipients_path.display());
    }

    // 3. Encrypted store: create an empty one if absent (the default profile → default.enc).
    let store_path = store_root.join(format!("{}.enc", layout::DEFAULT_PROFILE));
    if store_path.is_file() {
        eprintln!("store already exists at {}", store_path.display());
    } else {
        let seed = b"# envstow secrets -- KEY=value lines. Edit via `envstow unlock`.\n";
        match encrypt_payload(seed, &recipients) {
            Ok(ct) => {
                if let Err(e) = layout::write_store(&store_path, &ct) {
                    return Err(AppError::msg(format!("could not write store: {e}")));
                }
                eprintln!("created empty store at {}", store_path.display());
            }
            Err(e) => {
                return Err(AppError::msg(format!(
                    "could not encrypt initial store: {e}"
                )));
            }
        }
    }

    // 4. For a central store, leave a pointer in the CWD so this project resolves to it with no
    //    flag and no exported variable. Without it, every command here would need `--store`, and
    //    forgetting would fall through to the walk — which for a public repo means quietly
    //    finding some OTHER store, the exact outcome this setup exists to prevent.
    if let layout::StoreSelector::Named(name) = &sel {
        let pointer = cwd.join(layout::ENVSTOW_DIR);
        if pointer.is_dir() {
            eprintln!(
                "⚠️  {} is a local store directory, so no pointer was written here.\n\
                 \x20   Commands in this directory will use that local store, not '{name}'.",
                pointer.display()
            );
        } else if pointer.is_file() {
            eprintln!("pointer already exists at {}", pointer.display());
        } else if let Err(e) = std::fs::write(&pointer, layout::render_pointer(name)) {
            return Err(AppError::msg(format!("could not write pointer file: {e}")));
        } else {
            eprintln!(
                "wrote {} → central store '{name}' (safe to commit; contains no secrets)",
                pointer.display()
            );
        }
    }

    // 5. Offer to add the Claude Code agent skill to THIS repo (so it commits + travels to
    //    teammates). Prompts [Y/n]; --no-skill skips; non-interactive defaults to yes.
    if !skip_skill {
        maybe_install_skill(cwd.as_path());
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
        eprintln!("\nReady. Add secrets by editing the store, then `envstow unlock`.");
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
            eprintln!("{verb} agent skill at {}", dest.display());
            eprintln!("   commit `.claude/skills/envstow/` so teammates get it on clone.");
        }
        Err(e) => eprintln!("envstow: could not write agent skill: {e}"),
    }
}

// ---------------------------------------------------------------------------
// recipient management
// ---------------------------------------------------------------------------

fn cmd_add_recipient(args: &[String]) -> Cmd {
    let (sel, profile, args) = resolve_target(args)?;
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

    let paths = layout::locate_in(&sel, &profile)?;
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
    eprintln!("added recipient to {}", paths.recipients.display());
    reencrypt_store(&paths.store, &recipients)
}

fn cmd_remove_recipient(args: &[String]) -> Cmd {
    let (sel, profile, args) = resolve_target(args)?;
    let Some(target) = args.first() else {
        return Err(AppError::usage(
            "usage: envstow remove-recipient <age1...|label> [--profile P]",
        ));
    };

    let paths = layout::locate_in(&sel, &profile)?;
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
    eprintln!("removed recipient; {} remain.", kept.len());
    reencrypt_store(&paths.store, &kept)?;
    eprintln!(
        "\n⚠️  Removing a recipient only blocks FUTURE decryptions. Their key still decrypts\n\
         every historical commit in any clone they kept. Rotate every secret they saw at the\n\
         source to truly revoke access."
    );
    Ok(())
}

fn cmd_reencrypt(args: &[String]) -> Cmd {
    let (sel, profile, _args) = resolve_target(args)?;
    let paths = layout::locate_in(&sel, &profile)?;
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

// ---------------------------------------------------------------------------
// stores
// ---------------------------------------------------------------------------

/// `envstow store` — say which store is in effect and WHY, and list the central ones.
///
/// The "why" is the point. With four ways to select a store (flag, env var, committed pointer,
/// the walk), "am I about to write this secret where I think?" must be answerable without
/// guessing — especially for the setup this feature exists for, where the wrong answer means a
/// secret lands in a repo the user deliberately kept it out of.
fn cmd_store(args: &[String]) -> Cmd {
    let (sel, _rest) = cli::resolve_store(args)?;
    match layout::resolve_root(&sel) {
        Ok((root, source)) => {
            println!("current store: {} ({})", root.display(), source.describe());
            let profiles = layout::list_profiles(&root);
            if !profiles.is_empty() {
                eprintln!("profiles: {}", profiles.join(", "));
            }
        }
        // Not an error worth exiting on: `envstow store` is the command you run precisely
        // BECAUSE something isn't resolving. Print the reason and still list what exists.
        Err(e) => eprintln!("current store: none — {e}"),
    }
    let central = layout::list_central_stores();
    if central.is_empty() {
        eprintln!(
            "\ncentral stores: none yet ({})",
            layout::central_stores_dir().display()
        );
    } else {
        eprintln!("\ncentral stores: {}", central.join(", "));
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
    eprintln!("created profile '{name}' at {}", paths.store.display());
    eprintln!(
        "   use it with:  envstow --profile {name} set <NAME>   (or export ENVSTOW_PROFILE={name})"
    );
    Ok(())
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
         \x20 envstow list                     List secret NAMES (never values).\n\
         \x20 envstow pubkey                   Print your age PUBLIC key (share it to be added).\n\
         \x20 envstow unlock                   Interactive subshell with every secret set; `exit` locks.\n\
         \x20 envstow run [--only A,B] -- <c>  Run one command with all — or only the named — secrets.\n\
         \x20 envstow env [--off]              Load (or --off: unset) secrets in THIS shell: eval \"$(envstow env)\".\n\
         \x20 envstow refresh                  Unset secrets that left the store: eval \"$(envstow refresh)\".\n\
         \x20 envstow status                   Show whether you're unlocked, the profile, and secret NAMES.\n\
         \x20 envstow shell-init               Print the optional shell hook for your rc: eval \"$(envstow shell-init)\".\n\
         \x20 envstow init [--no-skill]        Create identity + recipients + store; add agent skill.\n\
         \x20 envstow store                    Show which store is in effect (and why); list stores.\n\
         \x20 envstow add-recipient <age1..>   Add a collaborator and re-encrypt.\n\
         \x20 envstow remove-recipient <k|nm>  Remove a collaborator and re-encrypt (then rotate).\n\
         \x20 envstow reencrypt                Re-encrypt the store to the current recipients.\n\
         \x20 envstow profile [create <name>]  Show the current profile, or create a new one.\n\
         \x20 envstow profiles                 List available profiles.\n\
         \x20 envstow upgrade [--check|--yes]  Upgrade envstow to the latest release.\n\
         \x20 envstow scan-leak                Hook: block tool output that leaks a value (see GUARDRAILS.md).\n\
         \x20 envstow --version                Print the envstow version.\n\
         \n\
         Profiles: add `--profile <name>` to any command to use a separate secret set\n\
         (e.g. dev/staging/prod), or set $ENVSTOW_PROFILE. Default is `default`.\n\
         \n\
         Stores: by default your secrets live in `.envstow/` beside your code, committed with\n\
         it. To keep them OUT of the repo (a public repo, or sharing via a synced folder rather\n\
         than git), use a central store instead:\n\
         \x20 envstow init --store <name>      Store lives in ~/.config/envstow/stores/<name>/;\n\
         \x20                                  a `.envstow` pointer file (no secrets) is written\n\
         \x20                                  here so commands in this repo need no flag.\n\
         \x20 envstow init --store-dir <path>  Store lives at any path (e.g. a shared folder).\n\
         Select one explicitly with `--store <name>` / `--store-dir <path>`, or $ENVSTOW_STORE /\n\
         $ENVSTOW_STORE_DIR. `envstow store` says which one is in effect.\n\
         \n\
         EXAMPLES:\n\
         \x20 envstow set MY_TOKEN --clipboard         # store a secret straight from the clipboard\n\
         \x20 envstow run --only DB_URL -- ./migrate   # one command, only the secrets it needs\n\
         \x20 envstow run -- npm run build             # one command, whole store\n\
         \x20 envstow unlock                           # interactive subshell (agents: prefer run --only)\n\
         \x20 do-thing \"$(envstow get DB_PASSWORD)\"    # one value by name; masked under an agent\n\
         \n\
         All crypto is the `age` crate — no external tools. Values are never printed unless\n\
         output is safe or you pass --show."
    );
    let _ = io::stdout().flush();
}
