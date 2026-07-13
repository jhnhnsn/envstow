# envseal

A local, file-based **GitHub Secrets**: an **age-encrypted key-value store committed to your
repo**, decrypted with each collaborator's **own age key**, surfaced **by name** so neither a
human nor an AI coding agent (Claude Code, Cursor, …) has to paste a secret's plaintext onto a
command line.

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
recipients            # age PUBLIC keys, committed. Who can decrypt.
secrets/secrets.enc   # age-encrypted KEY=value store, committed.
~/.config/envseal/identity.txt   # YOUR age private key. Never committed.
```

You unlock secrets into a child process — an agent references them by name; the plaintext only
ever lives in that child's environment, never in the agent's transcript.

---

## Quickstart

```bash
# 1. Build (needs Rust: https://rustup.rs). No other tools required.
cargo install --path bin          # installs `envseal` onto your PATH (~/.cargo/bin)
#   or: cargo build --release --manifest-path bin/Cargo.toml

# 2. First-time setup: generate your key, create the recipients file + empty store.
envseal init

# 3. Add secrets (value comes from stdin, so it never sits on the command line).
printf 'sk-...' | envseal set AI_API_KEY
envseal edit                       # …or edit all secrets at once in $EDITOR

# 4a. Run a command with every secret set as an env var:
envseal unlock -- npm run build
envseal unlock -- sh -c 'deploy --token "$FLY_API_TOKEN"'

# 4b. …or start your AI in an unlocked subshell (it inherits the vars):
envseal unlock                     # spawns a subshell; `exit` locks

# 5. Commit `recipients` and `secrets/secrets.enc`. Never commit identity.txt.
```

---

## Commands

| Command | Purpose |
|---|---|
| `envseal init` | Generate identity, create `recipients` + empty store. |
| `envseal set <NAME>` | Store a value read from **stdin** (keeps it off the command line). |
| `envseal edit` | Decrypt all secrets into `$EDITOR`, re-encrypt on save (temp file shredded). |
| `envseal get <NAME> [--show]` | Resolve one secret by name. **Masked under an agent** unless `--show`. |
| `envseal list` | List secret **names** (never values). |
| `envseal unlock [-- <cmd>]` | Run a command (or subshell) with every secret set as an env var. |
| `envseal add-recipient <age1…> [label]` | Add a collaborator; re-encrypt. |
| `envseal remove-recipient <key\|label>` | Remove a collaborator; re-encrypt (then **rotate**). |
| `envseal reencrypt` | Re-encrypt the store to the current `recipients` (after hand-editing it). |

---

## Why this is AI-safe

The environment-variable channel and the AI's context channel are **separate**. You tell the
agent "the token is in `$FLY_API_TOKEN`", and it runs `envseal unlock -- sh -c 'deploy --token
"$FLY_API_TOKEN"'`. The shell expands `$FLY_API_TOKEN` *inside the child envseal spawns* — the
value never appears in the agent's tool call or its output.

`envseal get` reinforces this: **under an agent it masks its output by default** (prints
`••••••••`), because an agent captures stdout and we can't distinguish "used inside `$(…)`"
from "run bare into the transcript". A human who needs the value runs `envseal get NAME --show`.

Three defense layers back this up:
- **`CLAUDE.md`** — reference by name; never echo/print/log a value.
- **`.claude/settings.json`** — denies `env`, `printenv`, `echo $*`, `set`, …
- **`scripts/redact-guard.sh`** — `PostToolUse` hook; blocks any command output containing a
  live secret value (raw or base64) as accident insurance.

> Defense-in-depth, **not** a vault. It makes accidental exposure very unlikely. A human or
> agent who deliberately runs `--show` will see the value — that's by design (you own the
> secret). What it prevents is *pasting* and *accidental* leakage.

---

## Collaborating

- **Onboard yourself to an existing repo:** clone it, run `envseal init` (this generates your
  key and adds you to `recipients`), then send your public key — printed by `init` — to a
  current member. They run `envseal add-recipient <your-age1…>` and commit. Only then can you
  decrypt: `envseal init` alone adds your name but can't re-key a store you can't yet read.
- **Add a teammate:** `envseal add-recipient <their-age1…> alice`, commit.
- **Remove a teammate:** `envseal remove-recipient alice`, then **rotate every secret they
  saw** (see below), commit.

## Revoking access

`envseal remove-recipient` stops **future** decryptions, but the removed key still decrypts
every historical commit in any clone that person kept. **Rotation — not removal — is what
actually revokes access.** The command prints this reminder. To truly revoke: regenerate each
secret at its source (the API provider, the DB, …) and `envseal set` the new value.

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

## Developing on envseal

```bash
cd bin && cargo test         # crypto round-trip, dotenv parse, recipient parsing, masking
scripts/test-redact-guard.sh # proves the hook blocks a leak and allows name references
```

CI (`.github/workflows/ci.yml`) builds + tests + `fmt` + `clippy` on macOS/Linux/Windows, and
runs `shellcheck` + the redact-guard test on Linux.

See `DESIGN.md` for the full design rationale.
