# Changelog

All notable changes to envstow are documented here. Versions follow [SemVer](https://semver.org).

## 0.1.16

### Changed
- **The agent skill now teaches the output-guard's semantics as instructions.** The mechanical
  hook (`redact-guard.sh`) is opt-in and agent-only; the skill is what every `envstow init` ships.
  It gains a "Subtle ways a value leaks" section covering the non-obvious cases instructions can
  actually help with — a value riding out in verbose/debug output or a stack trace, encoding not
  laundering a secret, redirect-then-read, reconstructing from parts — plus a nudge to prefer
  scoped `unlock -- <cmd>` (secrets never enter the agent's own env) over a session-wide unlock.
  This strengthens the *instruction* layer; it does not replace the mechanical guard, which is the
  only layer that holds when an agent doesn't cooperate. Re-run `envstow init` to update the skill
  in an existing repo.

## 0.1.15

### Security
- **The output-guard hook now catches secrets it used to miss.** `scripts/redact-guard.sh`
  previously flagged only env vars whose **name** matched a convention (`*_KEY`, `*_TOKEN`, …), so
  a leaked `DATABASE_URL`, DSN, or connection string sailed through — the last line of defense was
  silently partial. It now keys off `ENVSTOW_LOADED` (the exact names `unlock` set), so detection
  is name-agnostic, and it matches multi-line values line by line (a leaked middle line of a PEM
  no longer evades it). Detection moved into the Python pass for exact, multi-line-safe substring
  matching. Short values (<8 chars) and non-raw/base64 encodings remain out of scope by design.
  *(If you've copied the guard into your own repo per GUARDRAILS.md, re-copy it to get this.)*
- **envstow warns when your identity key is readable by group/other** (Unix). It's created
  `0600`, but permissions drift — a copy, a backup restore, a loose umask — and a world-readable
  key decrypts every store you can. envstow now says so and prints the `chmod 600` fix, on any
  command that reads the key. It warns rather than refuses, so a permission slip can't lock you
  out of your own secrets.

## 0.1.14

### Changed
- **"No matching keys found" now explains itself.** age's message covered several unrelated
  situations, and explained the most common one worst: you installed envstow, cloned the repo, and
  nobody has added you yet. It read like a bug — especially right after `init` reported adding your
  key to `recipients` and printed "🔓 Ready". envstow can tell the cases apart before decrypting,
  by comparing your public key against the recipients file:
  ```
  envstow: your key isn't a recipient of this store, so you can't decrypt it yet.
     Your public key:
       age1xw73c7…
     Send it to someone who already has access and ask them to run:
       envstow add-recipient age1xw73c7… <your-name>
  ```
  If your key *is* listed but the store predates it, the fix is different and it says so — ask a
  recipient to `envstow reencrypt`. Genuinely unrelated failures keep their original message.
- **`envstow init` no longer claims "🔓 Ready" when you're joining someone else's store.** It ends
  with `⏳ Almost there`, your public key, and the exact `add-recipient` command to send — because
  adding your key to `recipients` grants nothing until a recipient re-encrypts.
- ONBOARDING.md: sharpened the same point (`recipients` is an **input to encryption, not an access
  list**) and dropped `gh release download` examples pinned to a version whose artifacts the
  prune policy has since removed.

## 0.1.13

### Changed
- **`envstow update` is now `envstow upgrade`.** `update` still works as an undocumented alias, so
  nothing breaks. The rename follows the convention the comparable tools settled on: **`upgrade`
  means the program itself** (`deno upgrade`, `rustup self update`), while **`update` means the
  things a program manages** (`npm update`, `brew upgrade`, `rustup update` → toolchains). envstow
  manages secrets, so `update` is better left free for that sense.

## 0.1.12

### Added
- **`envstow upgrade`** and **`envstow upgrade --check`** (shipped in 0.1.12 as `envstow update`;
  renamed in 0.1.13, with `update` kept as an alias). Upgrade envstow without remembering the
  installer URL — which was the only real reason to remember it.
  ```
  $ envstow upgrade --check
  ⬆️  envstow 0.1.13 is available (you have 0.1.12).
     https://github.com/jhnhnsn/envstow/releases/tag/v0.1.13
  ```
  It re-runs the published installer (same URL, same TLS pinning the README documents);
  `--check` only reports. **Zero new dependencies** — the version check follows the
  `/releases/latest` redirect with `curl` and reads the tag off the final URL (no JSON to parse,
  no API token, no rate limit), and the install shells out to the same `curl … | sh` you'd type.
  Linking a self-updater crate would have pulled ~60 more crates including a full async runtime
  into a secrets tool that deliberately has three dependencies.

  **It refuses to upgrade an install it doesn't own.** If there's no cargo-dist receipt — a
  Homebrew/AUR/`cargo install` copy — overwriting the binary would desync it from the package
  manager or leave two envstows on PATH, so it names the right updater instead. And it won't
  replace the binary non-interactively without `--yes`: it downloads and executes a remote
  script over the running executable, which no CI job should do by accident.

## 0.1.11

### Added
- **`eval "$(envstow refresh)"`** — clear secrets an unlocked shell still holds after they've left
  the store. An unlocked shell owns a *copy* of the environment from spawn time, and no process
  can modify a running process's environment, so a deleted secret otherwise stays live until you
  `exit`. `refresh` sidesteps that the way `ssh-agent` and `direnv` do: envstow prints shell code
  and **your shell** evaluates it.
  ```
  $ envstow delete OLD_TOKEN --force
  $ eval "$(envstow refresh)"
  🔄 envstow: unset 1 secret(s) no longer in the store: OLD_TOKEN
  ```
  **It only ever emits `unset`.** Updating a changed value would mean printing plaintext to
  stdout — the one thing envstow exists to prevent, and catastrophic under an agent that captures
  it. So deleted secrets are unset in place; changed or added ones are *reported* with a nudge to
  `exit` and re-unlock. Only names envstow itself set are touched (tracked in the new
  `ENVSTOW_LOADED` marker), so a same-named var from your shell rc is never unset, and names that
  aren't plain shell identifiers are refused rather than interpolated into eval'd code. POSIX
  shells only; on PowerShell, `exit` and unlock again.

### Changed
- `unlock` now also sets **`ENVSTOW_LOADED`** in the child: a comma-separated list of the secret
  **names** it set (never values). Nested unlocks union with the outer list.

## 0.1.10

### Added
- **`unlock` warns when it shadows a name that's already set.** Unlocking one store from inside
  another (e.g. a subproject with its own vars, under a parent with shared ones) gives the child
  the **union** of both — env vars are inherited, and the inner store wins on any shared name.
  That layering is usually the point, so this warns rather than blocks:
  ```
  🔓 envstow: loaded 2 secret(s) from default: SHARED_KEY, CURA_TOKEN
  ⚠️  envstow: 1 name was already set with a different value — this store's value wins inside:
     SHARED_KEY
  ```
  Only names whose value actually **differs** are listed — re-unlocking the same store is silent.
  Neither value is ever printed, and envstow can't tell what set the outer one (an outer unlock,
  your shell rc, CI), so the warning says only that the name was already set.

### Changed
- `unlock` now names the profile it loaded from (`loaded 2 secret(s) from prod: …`), which
  matters once more than one store is in play.

## 0.1.9

### Changed (breaking — everyone sharing a store must update to ≥ 0.1.9)
- **Stores now carry a format header** (`envstow-format: 2`) on the first line, before the age
  payload. **Anyone still on ≤ 0.1.8 who reads a store written by 0.1.9 gets
  `decryption failed: Header is invalid`** — their binary predates the header and can't recognize
  it. Update everyone on a shared store; no re-init or migration is needed beyond that. Your
  existing stores are read fine by 0.1.9 (a headerless store is format 1) and are upgraded to
  format 2 the first time anything writes them.

### Added
- **Store format versioning, with an upgrade prompt.** envstow now checks a store's format before
  attempting decryption and, when it's too new, says so and points at the repo:
  ```
  envstow: this store uses format 3, but your envstow only understands format 2.
           A teammate wrote it with a newer envstow. Update yours to read it:
             https://github.com/jhnhnsn/envstow
  ```
  Previously a format change surfaced as `decryption failed: No matching keys found` —
  indistinguishable from "you were removed as a recipient", sending people to chase the wrong
  problem. The check runs before any crypto, so it catches envelope changes too. A matching guard
  refuses to overwrite a store newer than the running binary, so an old envstow can't silently
  downgrade a store and break it for teammates who have updated.
  This is the last format change that breaks quietly; every one after it explains itself.

## 0.1.8

### Added
- **`envstow set <NAME> --clipboard`** (`-c`). Read the value straight from the OS clipboard
  instead of stdin, so you don't have to remember your platform's paste command. Uses the
  system's own tool — `pbpaste` (macOS), `wl-paste`/`xclip`/`xsel` (Linux, probed at runtime so
  one binary covers Wayland and X11), `Get-Clipboard` (Windows) — and errors with a hint to pipe
  instead if none is installed. The value never touches argv or shell history, one trailing
  newline is stripped (matching stdin), and an empty clipboard is refused rather than stored.
  Piping (`pbpaste | envstow set NAME`) still works and is unchanged.

## 0.1.7

### Added
- **`envstow delete <NAME>`.** Remove one secret from the store and re-encrypt, without opening
  `$EDITOR`. Confirms `[y/N]` on a terminal; `--force` skips the prompt, and a non-interactive
  stdin (CI) proceeds without asking. Respects `--profile`, so deleting a name from `prod`
  leaves the same name in `default` untouched. The value is never printed and is zeroized.
  Deleting only removes a secret going **forward** — the value stays readable in the store's git
  history to anyone who is (or was) a recipient, so the command prints the same rotate-at-the-
  source reminder `remove-recipient` does.

## 0.1.6

### Changed (breaking — re-run `envstow init`)
- **New on-disk layout: everything lives under `.envstow/`.** Recipients moved to
  `.envstow/recipients` and the store is now `.envstow/default.enc` (was `recipients` +
  `secrets/secrets.enc`). Clean break — a repo on the old layout must be re-initialized.
  Commit the whole `.envstow/` directory.

### Added
- **Profiles.** A repo can hold multiple secret sets (e.g. `dev`/`staging`/`prod`) as separate
  encrypted stores (`.envstow/<profile>.enc`), all keyed to the same `.envstow/recipients`. Add
  `--profile <name>` to any command (before or after the subcommand), or set `ENVSTOW_PROFILE`.
  `envstow profile create <name>` makes a new one; `envstow profile` shows the current;
  `envstow profiles` lists them. The unnamed `default` profile is `.envstow/default.enc`. Using
  a profile that doesn't exist errors with a hint to create it (typo-safe).

## 0.1.5

### Changed
- **Renamed the project from `envseal` to `envstow`.** The binary, config directory
  (`~/.config/envstow/`), environment variables (`ENVSTOW_IDENTITY`, `ENVSTOW_AGENT`,
  `ENVSTOW_UNLOCKED`, `ENVSTOW_INSTALL_DIR`), and repo are all renamed. This is a clean break:
  the new binary does **not** read the old `ENVSEAL_*` variables. Re-run `envstow init` to set
  up (a fresh identity/store under the new name).

## 0.1.4

### Added
- **`envstow init` offers to install the Claude Code agent skill** into the current repo's
  `.claude/skills/envstow/` (prompts `[Y/n]`, default yes; `--no-skill` to skip). Committing it
  means every teammate who clones the repo gets it — their agent learns to use secrets by name
  and never print a value. The skill is embedded in the binary, so no separate download is
  needed. Non-interactive runs (CI) install it without prompting.

## 0.1.3

### Changed
- **`get` now masks under any recognized AI agent, not just Claude Code.** Detection was
  broadened to Cursor (`CURSOR_TRACE_ID`/`CURSOR_AGENT`), Aider (`AIDER_*`), Windsurf, and
  generic `AI_AGENT`/`AGENT` markers, alongside the existing `ENVSTOW_AGENT=1` opt-in. Human
  `$(envstow get X)` scripting (no agent markers) still reveals as before.

### Documentation
- Added **[GUARDRAILS.md](GUARDRAILS.md)** — manual setup for the three agent-safety layers
  (instructions, command denylist, output-guard hook), with Claude Code as the worked example
  and the pattern generalized to Cursor, Aider, and Windsurf. A human or an agent can fetch it
  by URL and apply the guardrails for whatever editor is in use.

## 0.1.2

### Added
- **Masked confirmation for `envstow set`.** After storing a value, `set` now prints a masked
  preview — the first 5 characters followed by dots (e.g. `✔ set MY_SECRET (sk-pr••••••••)`) —
  so you can sanity-check a paste without the full value on screen. Values of 5 characters or
  fewer are fully masked, and under an AI agent the preview is fully masked so no characters
  reach the transcript.

### Changed
- **Smoother first install.** The installer now prints a clear next step — open a new terminal
  (or `source ~/.local/bin/env`), then run `envstow --version` — so a "command not found" in the
  same terminal you installed from is no longer mistaken for a failed install. `~/.local/bin` is
  added to PATH for new shells automatically.

### Documentation
- `ONBOARDING.md` leads with a single copy-paste install line; the inspect-the-script,
  verify-checksums, and custom-path (`ENVSTOW_INSTALL_DIR`) options moved into a collapsible
  "security-conscious" section.
- Documented that envstow operates **per project directory** (commands act on the store of the
  repo you're inside), and how to install from a clone to a directory you choose.
- The first `set` example now shows pasting from a password manager (`pbpaste | envstow set …`).
- Fixed a contradiction that said multi-line values were "rejected" — they are supported (pipe
  them in; stored base64-encoded internally).
- Examples use a neutral `MY_SUPER_SECRET_KEY` placeholder.

## 0.1.1

### Added
- **`envstow --version`** (also `-V` / `version`) — prints the installed version.

### Documentation
- Documented safer install options (inspect the installer script, verify SHA-256 by hand).

## 0.1.0

Initial release.

### Features
- Age-encrypted key-value secret store (`secrets/secrets.enc`) committed to your repo, decrypted
  per-user with each collaborator's own age key. All crypto is the `age` crate — no external
  `sops`/`age` CLIs required.
- Commands: `init`, `set` (value via stdin), `edit` (`$EDITOR` round-trip), `get` (masked under
  an AI agent unless `--show`), `list`, `unlock [-- <cmd>]`, `pubkey`, `add-recipient`,
  `remove-recipient`, `reencrypt`.
- **AI-safe by design:** secrets are referenced by name; `get` masks its output under an agent so
  plaintext never enters an agent's context.
- Multi-line secrets (PEM keys, certs, JSON) supported via stdin, base64-encoded internally.
- One-line prebuilt-binary installer (macOS arm64/x86_64, Linux arm64/x86_64, Windows) with
  SHA-256 verification.
- Bundled Claude Code agent skill so an agent knows how to use envstow on clone.
