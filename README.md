# envstow

An **age-encrypted key-value store committed to your repo**, decrypted with each collaborator's
**own age key** and surfaced **by name** — so neither a human nor an AI coding agent (Claude
Code, Cursor, …) has to paste a secret's plaintext onto a command line.

- **Self-contained:** one Rust binary. All crypto is the [`age`](https://crates.io/crates/age)
  crate (X25519 + ChaCha20-Poly1305) compiled in — **no `sops`, no `age` CLI, nothing else to
  install.**
- **Multi-user:** the store is encrypted to every collaborator's age public key. Each decrypts
  with their own private key. Add/remove people by editing a `recipients` file.
- **AI-safe by construction:** agents reference secrets by **name** (`$AI_API_KEY`). A value is
  never printed unless it's safe to (not captured by an agent) or a human explicitly asks.

---

## How it works

```
.envstow/recipients               # age PUBLIC keys, committed. Who can decrypt.
.envstow/default.enc              # age-encrypted KEY=value store (default profile), committed.
.envstow/<profile>.enc            # additional profiles (dev/staging/prod), committed.
                                  #   Each store starts with an `envstow-format: N` line, so a
                                  #   too-old envstow tells you to update instead of failing
                                  #   with a confusing decryption error.
~/.config/envstow/identity.txt    # YOUR age private key. Never committed. (0600)
                                  #   Windows: %APPDATA%\envstow\identity.txt
```

To *use* a secret you unlock it into a **child process**. The child gets the value in its
environment and does its job; the value never appears in your shell history, an agent's tool
call, or its transcript. You only ever type the variable **name**.

---

## Install

**macOS / Linux** — a prebuilt binary, no toolchain needed:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jhnhnsn/envstow/releases/latest/download/envstow-installer.sh | sh
```

**Windows** (PowerShell):

```powershell
powershell -c "irm https://github.com/jhnhnsn/envstow/releases/latest/download/envstow-installer.ps1 | iex"
```

Installs to `~/.local/bin` — **open a new terminal** (or `source ~/.local/bin/env`) before
running `envstow`, then `envstow --version` to confirm. The installer verifies the binary's
SHA-256 and enforces TLS. To inspect the script first, or verify checksums by hand, see the
install options in [ONBOARDING.md](./ONBOARDING.md#1-install-envstow-once-per-machine). Or build
from source (needs [Rust](https://rustup.rs)): `cargo install --path bin`.

**Joining a team that already uses envstow?** See **[ONBOARDING.md](./ONBOARDING.md)** — install,
share your key, get added. A ready-made **AI-agent skill** ([`agent/envstow-skill.md`](./agent/envstow-skill.md))
teaches Claude Code to use secrets by name — install it globally or per-repo (see
[GUARDRAILS.md](./GUARDRAILS.md)).

---

## Usage scenarios

Secrets are always referenced by **name**; the plaintext only ever lives inside the child
process envstow spawns.

### 1. First-time setup

```bash
envstow init
git add .envstow && git commit -m "Add envstow store"
```

`init` creates your private key (in `~/.config/envstow/`, never committed), the `recipients`
list, and an empty store. Idempotent.

### 2. Add and list secrets

Copy a secret from your password manager, then paste it into `set` — the value comes from
**stdin**, so it never lands on the command line or in your shell history:

```bash
envstow set MY_SUPER_SECRET_KEY --clipboard                 # read the OS clipboard directly
#   → ✔  set MY_SUPER_SECRET_KEY (sk-pr••••••••)   ← masked confirmation of what you stored
# Uses your platform's paste tool: pbpaste (macOS), wl-paste/xclip/xsel (Linux),
# Get-Clipboard (Windows). Piping still works if you prefer:
pbpaste | envstow set MY_SUPER_SECRET_KEY                   # macOS: paste from clipboard

envstow set MY_SUPER_SECRET_KEY                             # …or run bare, then paste + Enter
printf 'sk-proj-abc123' | envstow set MY_SUPER_SECRET_KEY   # …or pipe a literal
envstow edit                                           # …or edit them all in $EDITOR
envstow list                                           # names only, never values
envstow delete MY_SUPER_SECRET_KEY                     # remove one (then rotate it at the source)
```

`set` confirms with a **masked preview** — the first 5 characters then dots (or all dots for
short values) — so you can sanity-check the paste without the full value on screen. Under an AI
agent the preview is fully masked.

The bare interactive prompt reads a **single line** (API keys, tokens, passwords). Multi-line
values (PEM keys, certs, JSON) work too — just **pipe** them rather than typing at the prompt;
see [Multi-line secrets](#multi-line-secrets) below.

### 3. Run something that needs secrets

`envstow unlock -- <cmd>` runs one command with every secret set as an env var:

```bash
envstow unlock -- npm run build
envstow unlock -- flyctl deploy
envstow unlock -- sh -c 'psql "$DATABASE_URL" -f migrate.sql'
```

You typed `$DATABASE_URL` — the shell expands it *inside the child*, so the value reaches `psql`
but never your history or a log.

### 4. Working with an AI agent

Start the agent from an unlocked subshell; every command it runs inherits the secrets:

```bash
envstow unlock     # subshell with all secrets set; `exit` locks
claude             # launched inside it — references $MY_SUPER_SECRET_KEY by name
```

If the agent tries to read a value directly, it can't — `envstow get` masks under an agent:

```bash
envstow get FLY_API_TOKEN    # → ••••••••  (see "Why this is AI-safe")
```

### 5. Read a value yourself

Outside an agent, `envstow get` prints the value when its output is captured; `--show` forces it:

```bash
export GITHUB_TOKEN="$(envstow get GITHUB_TOKEN)"
envstow get DATABASE_URL --show
```

### 6. Onboard a teammate

```bash
# Alice: generate her key and share the public half (safe to paste anywhere).
envstow init && envstow pubkey        # → age1abc…

# You: add her, re-encrypt, commit.
envstow add-recipient age1abc… alice
git add .envstow && git commit -m "Add Alice"
```

Only the **public** key (`age1…`) is shared — it lets you encrypt *to* someone, never decrypt.
The private key (`~/.config/envstow/identity.txt`) is never shared or committed.

### 7. Offboard a teammate

```bash
envstow remove-recipient alice
```

This re-encrypts without Alice, but her key still decrypts old commits. **Rotation is the real
revocation:** regenerate each secret she saw and `envstow set` the new value.

### 8. CI / automation

Point `$ENVSTOW_IDENTITY` at a dedicated CI key (added as a recipient, stored as a CI secret):

```bash
ENVSTOW_IDENTITY=/path/to/ci-key envstow unlock -- npm run deploy
```

### On Windows

Most commands are identical — `envstow init`, `list`, `pubkey`, `add-recipient`, and
`envstow unlock -- <program>` all work as-is. Only a few things differ:

```powershell
# Your identity lives at %APPDATA%\envstow\identity.txt; `edit` opens Notepad.
'sk-proj-abc123' | envstow set MY_SUPER_SECRET_KEY     # PowerShell pipes a value to stdin
envstow unlock -- npm run build                   # runs the program directly — same as POSIX

# The only real difference: no `sh -c`. To reference a value by name in a shell,
# use PowerShell (%VAR% for cmd.exe):
envstow unlock -- powershell -c 'psql $env:DATABASE_URL -f migrate.sql'
envstow unlock -- cmd /c "psql %DATABASE_URL% -f migrate.sql"

# Start an unlocked subshell (cmd.exe by default via %COMSPEC%):
envstow unlock
```

### Multi-line secrets

`set` handles multi-line values (PEM keys, TLS certs, service-account JSON) — **pipe them in**,
since a multi-line value can't be typed at the single-line interactive prompt:

```bash
envstow set TLS_KEY   < privkey.pem
envstow set GCP_CREDS < service-account.json
```

Under the hood, multi-line values are base64-encoded inside the store (so the on-disk dotenv
stays one line per key); `unlock`/`get` decode them transparently, so the env var your program
sees is the exact original. Single-line secrets are stored as-is. Pasting a multi-line value
into the interactive prompt won't work — pipe it or use `envstow edit`.

### Profiles

A repo can hold multiple secret sets — e.g. `dev`, `staging`, `prod` — as separate encrypted
stores (`.envstow/<profile>.enc`), all keyed to the same `.envstow/recipients`. The unnamed
**`default`** profile is `.envstow/default.enc`.

```bash
envstow profile create prod                 # create a new profile (empty store)
envstow --profile prod set DB_URL           # write to prod's store
envstow --profile prod unlock -- npm start  # run with prod's secrets
export ENVSTOW_PROFILE=prod                  # …or make it sticky for the shell
envstow profile                              # show the current profile + list available
envstow profiles                             # list profiles
```

Selection precedence: `--profile <name>` flag (before or after the subcommand) > `ENVSTOW_PROFILE`
env var > `default`. Using a profile that doesn't exist errors and tells you to
`envstow profile create` it (so a typo can't silently make a junk store).

---

## Command reference

| Command | Purpose |
|---|---|
| `envstow init` | Generate identity, create `recipients` + empty store. Idempotent. |
| `envstow set <NAME> [--clipboard]` | Store a value read from **stdin**, or the OS clipboard with `--clipboard` (`-c`). Never in argv either way. |
| `envstow delete <NAME> [--force]` | Remove one secret; re-encrypt (then **rotate**). Confirms on a TTY. |
| `envstow edit` | Decrypt all secrets into `$EDITOR`, re-encrypt on save (temp file shredded). |
| `envstow get <NAME> [--show]` | Resolve one secret by name. **Masked under an agent** unless `--show`. |
| `envstow list` | List secret **names** (never values). |
| `envstow pubkey` | Print your age **public** key, to share so a member can add you. |
| `envstow unlock [-- <cmd>]` | Run a command (or subshell) with every secret set as an env var. |
| `eval "$(envstow refresh)"` | Unset secrets this shell still holds that have left the store. Only emits `unset` — see [Stale secrets](#stale-secrets-in-an-unlocked-shell). |
| `envstow add-recipient <age1…> [label]` | Add a collaborator; re-encrypt. |
| `envstow remove-recipient <key\|label>` | Remove a collaborator; re-encrypt (then **rotate**). |
| `envstow reencrypt` | Re-encrypt the store to the current `recipients` (after hand-editing it). |
| `envstow profile [create <name>]` | Show the current profile, or create a new one. |
| `envstow profiles` | List available profiles. |
| `--profile <name>` | (On any command) use a separate secret set; see [Profiles](#profiles). |

**Environment:** `ENVSTOW_IDENTITY` overrides the identity path (default
`~/.config/envstow/identity.txt`). `ENVSTOW_AGENT=1` forces agent-masking for `get` in tools
that aren't auto-detected. Inside an `envstow unlock` subshell, `ENVSTOW_UNLOCKED=1` is set —
use it to show an "unlocked" indicator in your prompt (below).

### Show unlock state in your prompt

`envstow unlock` sets `ENVSTOW_UNLOCKED=1` in the subshell it spawns, so you can tell at a glance
when secrets are live in your shell (and it disappears when you `exit`).

**Starship** (`~/.config/starship.toml`) — add the module to your `format` and define it:

```toml
format = "${env_var.ENVSTOW_UNLOCKED}$directory$character"   # …plus your other modules

[env_var.ENVSTOW_UNLOCKED]
variable = "ENVSTOW_UNLOCKED"
format = "[🔓 envstow]($style) "
style = "bold yellow"
```

**Plain bash/zsh** (`~/.bashrc` / `~/.zshrc`):

```bash
[[ -n "$ENVSTOW_UNLOCKED" ]] && PS1="🔓 $PS1"     # bash
[[ -n "$ENVSTOW_UNLOCKED" ]] && PROMPT="🔓 $PROMPT" # zsh
```

---

## Why this is AI-safe

The environment-variable channel and the AI's context channel are **separate**. You tell the
agent "the token is in `$FLY_API_TOKEN`", and it runs `envstow unlock -- sh -c 'deploy --token
"$FLY_API_TOKEN"'`. The shell expands `$FLY_API_TOKEN` *inside the child envstow spawns* — the
value never appears in the agent's tool call or its output.

`envstow get` reinforces this: **under an agent it masks its output by default** (prints
`••••••••`), because an agent captures stdout and we can't distinguish "used inside `$(…)`"
from "run bare into the transcript". A human who needs the value runs `envstow get NAME --show`.

Three optional defense layers back this up — set them up in **your** repo by following
**[GUARDRAILS.md](./GUARDRAILS.md)** (Claude Code, Cursor, and other agents covered):
- **Instructions** — a skill / `CLAUDE.md` / `.cursorrules` / `AGENTS.md` telling the agent to
  reference by name and never echo/print/log a value.
- **Denylist** — deny `env`, `printenv`, `echo $*`, `set`, … (Claude Code `settings.json`, or
  Cursor's `beforeShellExecution` hook).
- **Output guard** — a post-command hook (`scripts/redact-guard.sh`) that blocks any command
  output containing a live secret value (raw or base64), regardless of the agent's judgment.

> Defense-in-depth, **not** a vault. It makes accidental exposure very unlikely. A human or
> agent who deliberately runs `--show` will see the value — that's by design (you own the
> secret). What it prevents is *pasting* and *accidental* leakage.
>
> **Setting up a repo that USES envstow?** The guardrails don't install themselves — follow
> **[GUARDRAILS.md](./GUARDRAILS.md)**, or point your agent at its URL and ask it to apply them.

---

## Threat model

**Protects:** secrets readable in the repo/host (encrypted at rest); onboarding/offboarding
without a shared master password; **humans/agents pasting plaintext onto command lines**;
casual/accidental AI exposure of values.

**Does NOT protect:** a compromised dependency reading `process.env` at runtime; a determined
process exfiltrating a live var; plaintext already in git history; retroactive access removal;
a value someone deliberately reveals with `--show` or re-encodes to evade the redact-guard.
For those: rotate, and treat this as strong hygiene, not a vault.

---

## Stale secrets in an unlocked shell

Your unlocked shell got its environment **at spawn time, as a copy**. Delete or change a secret
afterwards and the shell keeps the old value — no process can reach into a running one and change
its environment. That's an OS boundary, not an envstow limitation.

For a **deleted** secret, `refresh` clears it in place:

```bash
eval "$(envstow refresh)"
#   → 🔄 envstow: unset 1 secret(s) no longer in the store: OLD_TOKEN
```

The `eval` is what makes it work: envstow prints shell code and **your shell** runs it, which is
the only way to alter the shell you're standing in. (Same trick as `ssh-agent` and `direnv`.)

It is deliberately **one-directional — it only ever emits `unset`:**

| Change | `refresh` | Why |
|---|---|---|
| Secret **deleted** | ✅ unset in place | Unsetting a name reveals nothing |
| Secret **changed** or **added** | ❌ reported, not applied | Would mean printing the value to stdout |

Updating a value would require `export NAME=<value>` on stdout — dumping plaintext, the one thing
envstow exists to prevent (and catastrophic under an agent, which captures stdout). So for changed
or added secrets, `refresh` tells you and you re-unlock:

```bash
exit && envstow unlock
```

`refresh` only unsets names **envstow itself set** (tracked in `ENVSTOW_LOADED`), so a same-named
variable from your shell rc is never touched. Note that neither `envstow unlock` again nor
`exec envstow unlock` fixes a stale delete — both **inherit** the current environment, and
inheriting can add or overwrite but never unset. `exit` is what actually drops it.

It emits POSIX `unset` syntax (bash/zsh/sh/fish), so on **PowerShell** use `exit` +
`envstow unlock` instead.

---

## Nested unlocks (a store inside a store)

envstow's unit is the **folder** — `.envstow/` anchors a store, and nothing stops a subfolder from
having its own. Unlocking one from inside another is supported and often what you want: a
subproject gets its own vars layered on top of the shared ones above it.

The child sees the **union** of both. Env vars are inherited, and envstow only ever *adds*, so:

- names only in the outer store stay set,
- names only in the inner store are added,
- **names in both take the inner store's value** — the one you unlocked last wins.

Because a silently-inherited credential is worse than a missing one, `unlock` names any collision:

```
🔓 envstow: loaded 2 secret(s) from default: SHARED_KEY, CURA_TOKEN
⚠️  envstow: 1 name was already set with a different value — this store's value wins inside:
   SHARED_KEY
```

Only names whose value actually differs are listed. Two caveats worth knowing: envstow can't tell
*what* set the outer value (an outer unlock, your `.zshrc`, CI — it only sees that the name was
taken), and it never prints either value, so the warning tells you a collision happened, not which
value is which. Exiting the inner shell drops the inner store's vars; the outer shell's
environment was never modified.

---

## Store format & version mismatches

Each store begins with a plaintext `envstow-format: N` line before the age payload. It versions
the **file layout**, not the tool — most releases don't touch it (adding `delete` and
`--clipboard` didn't). It's checked **before** decryption, so a store written by a newer envstow
tells you what to do:

```
envstow: this store uses format 3, but your envstow only understands format 2.
         A teammate wrote it with a newer envstow. Update yours to read it:
           https://github.com/jhnhnsn/envstow
```

Without it, that same situation surfaced as `decryption failed: No matching keys found` — which
looks exactly like "you were removed as a recipient", and sends you chasing the wrong problem.
An old envstow also refuses to *overwrite* a newer store, so it can't silently downgrade one and
break it for teammates who have updated.

**Upgrading from ≤ 0.1.8:** the header itself arrived in 0.1.9, so a `≤ 0.1.8` binary reading a
store that 0.1.9 has written reports `decryption failed: Header is invalid`. Everyone sharing a
store needs to be on ≥ 0.1.9 — no re-init or migration beyond that. Stores made by older
versions are read fine and are upgraded in place the first time anything writes them.

---

## Developing on envstow

```bash
cd bin && cargo test         # unit + integration: crypto round-trip, masking, full CLI lifecycle
scripts/test-redact-guard.sh # proves the hook blocks a leak and allows name references
```

CI (`.github/workflows/ci.yml`) builds + tests + `fmt` + `clippy` on macOS/Linux/Windows, and
runs `shellcheck` + the redact-guard test on Linux.

See `DESIGN.md` for the full design rationale.
