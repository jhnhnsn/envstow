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
recipients                        # age PUBLIC keys, committed. Who can decrypt.
secrets/secrets.enc               # age-encrypted KEY=value store, committed.
~/.config/envseal/identity.txt    # YOUR age private key. Never committed. (0600)
```

To *use* a secret you unlock it into a **child process**. The child gets the value in its
environment and does its job; the value never appears in your shell history, an agent's tool
call, or its transcript. You only ever type the variable **name**.

---

## Install

```bash
# Needs Rust (https://rustup.rs). No other tools required.
cargo install --path bin          # → ~/.cargo/bin/envseal (on your PATH)
#   or, without installing:
cargo build --release --manifest-path bin/Cargo.toml   # → bin/target/release/envseal
```

---

## Usage scenarios

Everything below is copy-pasteable. Values are always referenced by **name**; the plaintext
only ever lives inside the child process envseal spawns.

### 1. First-time setup on a new repo

```bash
cd my-project
envseal init
#   ✔ generated identity at ~/.config/envseal/identity.txt
#   ✔ added you to my-project/recipients
#   ✔ created empty store at my-project/secrets/secrets.enc
#      your public key: age1fr7sffq...jt7m7l

git add recipients secrets/secrets.enc
git commit -m "Add envseal secrets store"
```

`init` is idempotent — safe to re-run. Your private key stays in `~/.config/envseal/`; only the
`recipients` list and the encrypted store belong in git.

### 2. Add and edit secrets

```bash
# One at a time — the value comes from stdin, so it never lands on the command line
# (or in your shell history):
printf 'sk-proj-abc123'            | envseal set OPENAI_API_KEY
pbpaste                            | envseal set STRIPE_SECRET_KEY   # paste from clipboard
op read op://vault/fly/token       | envseal set FLY_API_TOKEN       # pull from 1Password

# …or edit them all at once in your editor (decrypt → edit → re-encrypt; temp file shredded):
envseal edit

# See what's stored (names only, never values):
envseal list
#   OPENAI_API_KEY
#   STRIPE_SECRET_KEY
#   FLY_API_TOKEN

git add secrets/secrets.enc && git commit -m "Add API secrets"
```

### 3. Run a build/deploy that needs secrets

`envseal unlock -- <cmd>` runs one command with **every** secret set as an env var, then the
secrets die with the process:

```bash
envseal unlock -- npm run build
envseal unlock -- flyctl deploy
envseal unlock -- terraform apply

# When a tool wants the value as a flag, reference it by name inside a shell:
envseal unlock -- sh -c 'curl -H "Authorization: Bearer $OPENAI_API_KEY" https://api.openai.com/v1/models'
envseal unlock -- sh -c 'psql "$DATABASE_URL" -f migrate.sql'
```

You typed `$OPENAI_API_KEY` — six inert characters. The shell expands it *inside the child*, so
the value reaches `curl` but never your history or a log.

### 4. Working with an AI coding agent (the main event)

Start your agent from an unlocked subshell so every command it runs inherits the secrets:

```bash
envseal unlock          # spawns a subshell with all secrets set
claude                  # or `cursor`, etc. — launched INSIDE the unlocked shell
# … work with the agent; it references $OPENAI_API_KEY by name and it just works …
exit                    # leaving the subshell "locks" — the vars are gone
```

Now the agent can run `deploy --token "$FLY_API_TOKEN"` and the token resolves — but the agent
only ever *wrote* the string `$FLY_API_TOKEN`. It never sees, and can't print, the value:

```bash
# If the agent (or anyone) tries to read a value directly under an agent session:
envseal get FLY_API_TOKEN
#   ••••••••
#   envseal: value masked (running under an agent or a terminal)…
```

That mask is the guarantee working. (See [Why this is AI-safe](#why-this-is-ai-safe).)

### 5. Human scripting — when you actually want the value

Outside an agent, `envseal get` prints the value when its output is captured (a pipe or
`$(…)`), so you can script with it. `--show` forces it anywhere:

```bash
export GITHUB_TOKEN="$(envseal get GITHUB_TOKEN)"     # into a var for a one-off
envseal get DATABASE_URL --show | pbcopy              # copy to clipboard
docker run -e OPENAI_API_KEY="$(envseal get OPENAI_API_KEY)" myimage
```

### 6. Onboard a teammate

```bash
# Teammate (Alice): clone the repo, then generate her key and print it.
git clone …/my-project && cd my-project
envseal init            # adds her to `recipients`; prints her public key: age1abc…
envseal pubkey          # …or reprint it any time — safe to paste in Slack/email/a PR
#   ⚠️ adding your key here does NOT let you decrypt yet — a current member must re-key.

# You (existing member): add Alice's key and re-encrypt the store to include her.
envseal add-recipient age1abc… alice
git add recipients secrets/secrets.enc && git commit -m "Add Alice" && git push

# Alice pulls — now she can decrypt with her own key:
git pull && envseal list
```

> **What's actually shared:** only the **public** key (`age1…`), which is not a secret —
> knowing it lets you *encrypt to* someone, never decrypt. So the channel doesn't need to be
> confidential (Slack, email, a PR are all fine), but it should be *authentic*: make sure the
> `age1…` really is your teammate's. The safest path is to have them add their own key line in
> a **pull request** — the key is in the diff, tied to their identity, and recorded in git
> history. The **private** key (`AGE-SECRET-KEY-…` in `~/.config/envseal/identity.txt`) is
> never shared, pasted, or committed; if one ever leaks, rotate that person's key *and* every
> secret it could decrypt.

### 7. Offboard a teammate (and actually revoke)

```bash
envseal remove-recipient alice
#   ✔ removed recipient; N remain.
#   ✔ re-encrypted store to N recipient(s).
#   ⚠️ Removing a recipient only blocks FUTURE decryptions. Rotate every secret
#      they saw at the source to truly revoke.

# Rotation is the real revocation — regenerate each secret at its provider and re-set it:
op read op://vault/fly/new-token | envseal set FLY_API_TOKEN
# …repeat for every secret Alice could see…

git add recipients secrets/secrets.enc && git commit -m "Remove Alice, rotate secrets"
```

### 8. CI / automation

envseal reads the identity from `$ENVSEAL_IDENTITY` if set, so give CI a **dedicated** key:

```yaml
# Add the CI key as a recipient once:  envseal add-recipient <ci-age1…> ci-runner
# Store the PRIVATE ci key as a masked CI secret, then in the job:
- run: |
    printf '%s' "$ENVSEAL_CI_KEY" > /tmp/ci-identity && chmod 600 /tmp/ci-identity
    ENVSEAL_IDENTITY=/tmp/ci-identity envseal unlock -- npm run deploy
```

---

## Command reference

| Command | Purpose |
|---|---|
| `envseal init` | Generate identity, create `recipients` + empty store. Idempotent. |
| `envseal set <NAME>` | Store a value read from **stdin** (keeps it off the command line). |
| `envseal edit` | Decrypt all secrets into `$EDITOR`, re-encrypt on save (temp file shredded). |
| `envseal get <NAME> [--show]` | Resolve one secret by name. **Masked under an agent** unless `--show`. |
| `envseal list` | List secret **names** (never values). |
| `envseal pubkey` | Print your age **public** key, to share so a member can add you. |
| `envseal unlock [-- <cmd>]` | Run a command (or subshell) with every secret set as an env var. |
| `envseal add-recipient <age1…> [label]` | Add a collaborator; re-encrypt. |
| `envseal remove-recipient <key\|label>` | Remove a collaborator; re-encrypt (then **rotate**). |
| `envseal reencrypt` | Re-encrypt the store to the current `recipients` (after hand-editing it). |

**Environment:** `ENVSEAL_IDENTITY` overrides the identity path (default
`~/.config/envseal/identity.txt`). `ENVSEAL_AGENT=1` forces agent-masking for `get` in tools
that aren't auto-detected.

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
- **`CLAUDE.md`** — instructs the agent to reference by name; never echo/print/log a value.
- **`.claude/settings.json`** — denies `env`, `printenv`, `echo $*`, `set`, …
- **`scripts/redact-guard.sh`** — `PostToolUse` hook; blocks any command output containing a
  live secret value (raw or base64) as accident insurance.

> Defense-in-depth, **not** a vault. It makes accidental exposure very unlikely. A human or
> agent who deliberately runs `--show` will see the value — that's by design (you own the
> secret). What it prevents is *pasting* and *accidental* leakage.

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
cd bin && cargo test         # unit + integration: crypto round-trip, masking, full CLI lifecycle
scripts/test-redact-guard.sh # proves the hook blocks a leak and allows name references
```

CI (`.github/workflows/ci.yml`) builds + tests + `fmt` + `clippy` on macOS/Linux/Windows, and
runs `shellcheck` + the redact-guard test on Linux.

See `DESIGN.md` for the full design rationale.
