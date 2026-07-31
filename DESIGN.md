# envstow — design

## What it is

An **encrypted key–value file** — by default committed to the git repo, optionally kept
outside it (see [Where the store lives](#where-the-store-lives)); each collaborator decrypts it
with their **own age private key** (the file is encrypted to everyone's public keys). Secrets
are surfaced **by name** so that neither a human nor an agent has to paste a literal value onto
a command line.

## The job (one sentence)

> Decrypt a key–value store and surface its values **by name** on demand, so
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
- **File:** `<store root>/default.enc` (default profile) — an age-encrypted blob whose plaintext
  is dotenv (`KEY=value` lines). Committed to git for a local store; see
  [Where the store lives](#where-the-store-lives) for the alternatives.
- Recipients live in a small config beside it (age public keys), one per store. Adding/removing
  a recipient re-encrypts the file to the new set.

## Where the store lives

The store started as one thing: `.envstow/` committed beside your code. That is still the
default, and it is the right default — git already solves distribution, history, and "who has
the current version," and a store that travels with the repo needs no separate mechanism.

It is not, however, always possible or wise:

- **A public repo.** The blob is encrypted, so publishing it is not a plaintext leak. But it
  *is* a permanent, world-downloadable ciphertext record — decryptable later if a recipient key
  is ever compromised — and `recipients` publicly enumerates your collaborators. Defense in
  depth argues for keeping it out.
- **No git at all.** Collaborators sharing a folder over Drive/Dropbox/Syncthing. Nothing about
  age or the store format needs git; only distribution assumed it.

So a store root is resolved from one of two kinds:

| Kind | Root | Addressed by | Selected by |
|---|---|---|---|
| **In the repo** | `.envstow/` beside your code | position (walk up from the CWD) | the default |
| **Outside it** | `~/.config/envstow/stores/<name>/`, or any path | name, or path | `--store` / `--store-dir`, or their env vars — **never** anything committed |

### Nothing committed may point outside the repo

An earlier cut of this let a repo commit a `.envstow` **file** containing `store: <name>` — a
redirect saying *this project's secrets live elsewhere*, so commands in that project needed no
flag. It borrowed the trick git uses for worktrees, where `.git` is a file holding `gitdir:`.

It was removed, because of what it makes possible rather than what it does.

A committed redirect makes *where a project's secrets come from* a thing one person can change
and everyone else inherits on the next `git pull`. The external → committed direction is the
dangerous one, and it is **silent**: someone hits friction with the external store, creates a
local `.envstow/`, commits it; everyone else pulls and the walk finds that perfectly plausible
local store. Same command, same directory, different secret, no error. Anyone who is a recipient
of both stores — which happens the moment they have ever run `init` in that repo — simply gets
the wrong value. (The reverse, committed → external, fails loudly, because a missing store is
unmissable.)

Detecting the switch after the fact was the obvious fix and the wrong one: it needs per-project
state envstow doesn't otherwise keep, and it fires on legitimate migrations too, so it decays
into a warning people dismiss. Making the redirect **unrepresentable** removes the failure class
instead.

The cost is real and worth stating: reaching an external store now takes a flag or an exported
variable every time, and forgetting one falls back to the walk. But that mistake is one person's,
in their own shell, and recoverable — where the other silently changed everybody's secrets.

The corollary is a deliberate non-feature: **if a team shares an external store, they must agree
how.** Who has it, how a new person gets a copy, what happens when someone adds a secret. envstow
will not arrange it and no file in the repo will either. A team that finds that tedious is being
told something true — commit the store and let git do the work.

Leftover pointer files are **refused, not skipped**. Skipping would let the walk sail past and
return some outer store, which is precisely the silent substitution being designed out.

### Stores vs profiles

Two orthogonal axes, deliberately:

- **store** — *whose* secrets: which root, and therefore which `recipients`.
- **profile** — *which set* within that store: `<profile>.enc`.

Profiles share one `recipients` file (correct: dev/staging/prod are the same team). Stores do
not (correct: unrelated projects are not the same team). That per-store recipients file is the
main thing `--store` provides that a profile never could.

`--store` rather than `--project` for the name: "store" is already the word used throughout the
code and docs, and `--pro<tab>` colliding with `--profile` would be a bad ambiguity in a tool
where confusing "whose secrets" with "which environment" has real consequences.

### Which store am I using?

With four ways to select one, *"am I about to write this secret where I think?"* must be
answerable without guessing. `envstow store` reports the resolved root and **why** it was
chosen; `unlock`/`run`/`env` name the store in their banner whenever it isn't a plain local
`.envstow/` (for which the working directory already says it, and saying more would be noise).

### Joining an external store

A committed store travels with the repo. An external one does not — and since nothing in the
repo may name it either, joining is entirely a human arrangement: get added as a recipient, then
obtain the store directory by whatever means the team agreed on.

`envstow init` distinguishes "creating a store" from "joining one" by reading `recipients`: if it
already lists other people's keys, you're joining, and it says so rather than pretending you can
decrypt. A git clone supplies that file for free, which is why the in-repo flow gets this right
without trying. An external store has no clone step, so `init --store <name>` on a machine that
lacks it genuinely cannot tell "I am starting this store" from "I am joining it" — and creates an
empty one. Nothing in the tool can distinguish those, which is the honest reason sharing is
documented as a coordination problem rather than automated.

### What git was quietly providing

Two things a non-git store loses, worth stating rather than discovering:

- **Concurrent-write protection.** Two people running `envstow set` against the same shared
  folder produces a last-writer-wins clobber or a sync-conflict copy. Git would have refused
  the push. envstow does **not** currently guard this — coordinate writes, or use git.
- **History.** A bad `reencrypt` or an accidental `delete` is recoverable from git, and from a
  shared folder only via that service's own version history.

Error messages that used to assume git (`git pull && envstow reencrypt && git add …`) now check
whether the store is actually in a work tree, so a central-store user isn't told to commit a
file they deliberately kept out of the repo.

## Commands

### `envstow get <NAME>`  — the core interface
Resolves one secret by name. **Guarded output:**
- **Under an agent** (detected via `CLAUDECODE` / `CLAUDE_CODE_ENTRYPOINT` env): masked by
  default (`••••`), because the agent captures stdout via a pipe and we cannot reliably tell
  "inside `$(...)`" from "ran bare into the transcript." The agent must opt in with `--show`
  (or use the env-injection wrapper below).
- **Not under an agent:** stdout is a **pipe / command substitution** → prints the raw value
  (for `do-something "$(envstow get SUPABASE_DB_PASSWORD)"`); stdout is a **terminal** →
  masks, since a bare terminal print is usually not what's wanted.
- `--show` always prints the raw value (explicit human/agent request).

Rationale: the primary thing to prevent is *accidental* plaintext landing in an agent
transcript. Masking-under-agent-unless-`--show` makes the safe path the default and the
reveal path deliberate, which matches the threat model.

### `envstow unlock` — session convenience (optional path)
Spawns a subshell (or `-- <cmd>`) with all vars in its env, for a human who wants a whole
unlocked session. Prints **names only**. Exit = lock.

### recipient management
- `envstow init [--store <name> | --store-dir <path>]` — generate an age key, add self as a
  recipient, create the first file. With `--store`/`--store-dir` the store is created outside the
  repo and **nothing** is written into it; reach it with the same flag or its env var.
- `envstow add-recipient <age1...>` / `envstow remove-recipient <age1...|name>` —
  re-encrypt to the new recipient set. Removal prints the rotation reminder (removing a key
  only blocks future commits; rotate to truly revoke).

## Guardrails (secondary, accident-only)

- `CLAUDE.md` — reference by name; use `envstow get` rather than pasting.
- `envstow scan-leak` `PostToolUse` hook (built into the binary; the old `redact-guard.sh`
  is a deprecated equivalent) — still catches **accidental** dumps (a stray `env`, a tool
  echoing its config). It exempts the sanctioned `envstow get` path. Kept as accident
  insurance, not as a hard secrecy boundary (see threat model).

## Explicitly dropped / deferred

- **`sync` (fly/wrangler push):** dropped. Those tools are *consumers*; use
  `envstow get`/`run -- <cmd>` with them directly.
- **cargo-dist packaging:** deferred to a later pass.
- **rops / SOPS-format reimplementation:** dropped in favor of the `age` crate + dotenv.
