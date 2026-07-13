# envseal — design

## What it is

A local, file-based version of GitHub Secrets. An **encrypted key–value file lives in the
git repo**; each collaborator decrypts it with their **own age private key** (the file is
encrypted to everyone's public keys). Secrets are surfaced **by name** so that neither a
human nor an agent has to paste a literal value onto a command line.

## The job (one sentence)

> Decrypt a git-committed key–value store and surface its values **by name** on demand, so
> commands (run by a human or an agent) use secrets like `$SUPABASE_DB_PASSWORD` without the
> literal value being pasted — hidden by default, visible only on deliberate request.

## Threat model (deliberately pragmatic)

- **Primary goal:** stop humans/agents from *pasting literal secret values* into command
  lines, prompts, and transcripts. Reference by name instead.
- **Explicitly NOT a goal:** cryptographic secrecy of values *from the human or agent*. A
  human who deliberately asks to see a value may see it — they own the secret.
- **"Hidden by default":** a value is never printed unless explicitly requested; naked/
  accidental invocations do not spray plaintext into a terminal or an agent's context.

## Why not persist env vars in the agent session

Verified in Claude Code: **each Bash tool call is a fresh process; `export`ed vars do not
persist to the next call.** So "unlock once, use later" is impossible for the agent. The
value must be resolved *per command*, in the same process tree as its use.

## Crypto & format

- **age** (X25519 + ChaCha20-Poly1305) via the mature `age` Rust crate — compiled into the
  binary. **Multi-recipient**: encrypted to each collaborator's age public key.
- **No external CLIs at runtime** (no `sops`, no `age` binary, no `rops`). Self-contained.
- **File:** `secrets/secrets.enc` — an age-encrypted blob whose plaintext is dotenv
  (`KEY=value` lines). Committed to git.
- Recipients live in a small committed config (age public keys). Adding/removing a recipient
  re-encrypts the file to the new set.

## Commands

### `envseal get <NAME>`  — the core interface
Resolves one secret by name. **Guarded output:**
- **Under an agent** (detected via `CLAUDECODE` / `CLAUDE_CODE_ENTRYPOINT` env): masked by
  default (`••••`), because the agent captures stdout via a pipe and we cannot reliably tell
  "inside `$(...)`" from "ran bare into the transcript." The agent must opt in with `--show`
  (or use the env-injection wrapper below).
- **Not under an agent:** stdout is a **pipe / command substitution** → prints the raw value
  (for `do-something "$(envseal get SUPABASE_DB_PASSWORD)"`); stdout is a **terminal** →
  masks, since a bare terminal print is usually not what's wanted.
- `--show` always prints the raw value (explicit human/agent request).

Rationale: the primary thing to prevent is *accidental* plaintext landing in an agent
transcript. Masking-under-agent-unless-`--show` makes the safe path the default and the
reveal path deliberate, which matches the threat model.

### `envseal unlock` — session convenience (optional path)
Spawns a subshell (or `-- <cmd>`) with all vars in its env, for a human who wants a whole
unlocked session. Prints **names only**. Exit = lock.

### recipient management
- `envseal init` — generate an age key, add self as a recipient, create the first file.
- `envseal add-recipient <age1...>` / `envseal remove-recipient <age1...|name>` —
  re-encrypt to the new recipient set. Removal prints the rotation reminder (removing a key
  only blocks future commits; rotate to truly revoke).

## Guardrails (secondary, accident-only)

- `CLAUDE.md` — reference by name; use `envseal get` rather than pasting.
- redact-guard `PostToolUse` hook — still catches **accidental** dumps (a stray `env`, a
  tool echoing its config). It exempts the sanctioned `envseal get` path. Kept as accident
  insurance, not as a hard secrecy boundary (see threat model).

## Explicitly dropped / deferred

- **`sync` (fly/wrangler push):** dropped. Those tools are *consumers*; use
  `envseal get`/`unlock -- <cmd>` with them directly.
- **cargo-dist packaging:** deferred to a later pass.
- **rops / SOPS-format reimplementation:** dropped in favor of the `age` crate + dotenv.
