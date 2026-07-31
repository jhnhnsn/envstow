# envstow

An **age-encrypted key-value store that lives in a folder**, surfaced **by name** — so neither a
human nor an AI coding agent (Claude Code, Cursor, …) has to paste a secret's plaintext onto a
command line.

- **Works solo, offline, no git.** A folder with `.envstow/` in it is all you need.
- **Share it by committing it**, if you want to. The store is encrypted to each collaborator's
  age public key, so it's safe in a repo. Everyone decrypts with their own private key.
- **Or keep it out of the repo** — in your config dir, or a synced folder — reached by
  `--store <name>` / `--store-dir <path>`. Nothing committed can change which store a project
  uses, so a `git pull` can never swap your secrets underneath you. See [Stores](#stores).
- **Self-contained:** one Rust binary. All crypto is the [`age`](https://crates.io/crates/age)
  crate (X25519 + ChaCha20-Poly1305) compiled in — **no `sops`, no `age` CLI, nothing else to
  install.**
- **AI-safe by construction:** agents reference secrets by **name** (`$AI_API_KEY`). A value is
  never printed unless it's safe to (not captured by an agent) or a human explicitly asks.

---

## Quickstart (you + a collaborator)

The minimum to go from nothing to two people sharing a secret.

**Both of you — install envstow** (macOS/Linux; Windows, and inspect-first / verify-by-hand
options, are under [Install](#install)):

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jhnhnsn/envstow/releases/latest/download/envstow-installer.sh | sh
```

**You — create the store, add a secret, commit it:**

```bash
cd my-project
envstow init                                # your key + an empty store in .envstow/
printf 'sk-proj-abc123' | envstow set OPENAI_API_KEY
git add .envstow && git commit -m "Add secrets store" && git push
```

**Your collaborator — make a key and send you the public half.** They do this **outside the
project** so they don't touch its `recipients` file:

```bash
cd ~                                        # anywhere but the project
envstow init
envstow pubkey                              # → age1abc…   they send you this (Slack/email is fine)
```

**You — add their key (this re-encrypts the store) and push:**

```bash
cd my-project
envstow add-recipient age1abc… alice
git add .envstow && git commit -m "Add alice" && git push
```

**Your collaborator — pull, and they're in:**

```bash
git pull
envstow list                                # sees the names
envstow run -- your-app                  # runs it with the secrets set, values by name
```

That's the whole loop. The public key is safe to share; the value never leaves an encrypted store
or a child process. Full walkthrough and the reasoning behind each step:
**[ONBOARDING.md](./ONBOARDING.md)**.

Don't want the store committed? `envstow init --store <name>` keeps it outside the repo entirely
— at the cost of naming it on every command, and of sharing it yourself, since git no longer
carries it. See **[Stores](#stores)**.

---

## The problem

You have secrets a project needs — API keys, a database URL, deploy tokens — and every way of
handling them has a catch:

- A **`.env` file** is plaintext. You can't commit it, so onboarding a teammate means
  out-of-band copying, and one stray `git add` leaks everything.
- A **cloud secrets manager or SaaS** (Vault, Doppler, AWS/GCP/Azure) means an account, a server,
  a network round-trip, and a bill — heavy for a small repo or a solo project, and useless
  offline.
- **Existing file-encryption tools** (SOPS, git-crypt) let you commit encrypted secrets, but need
  external binaries and key backends set up, and none of them address the newest leak path: an
  **AI coding agent** that reads a value into its context and echoes it into a transcript, a
  commit, or a log.

envstow is the small-footprint answer: **one binary, no server, no account.** Encrypt a key-value
store to your collaborators' public keys and commit it to the repo (or keep it purely local).
Everyone decrypts with their own key. Secrets are used strictly **by name** — the plaintext is
injected into a child process's environment, never onto a command line, into your shell history,
or into an agent's context. It's the "just commit the secrets, safely" option for repos and
agents that don't need — or don't want — a secrets service.

---

## How it works

envstow's unit is a **folder**. Every command looks for `.envstow` in the current directory and
walks up to find it. Git is optional — it's just how the folder travels to other people.

```
.envstow/recipients               # age PUBLIC keys. Who the store is encrypted TO.
.envstow/default.enc              # age-encrypted KEY=value store (default profile).
.envstow/<profile>.enc            # additional profiles (dev/staging/prod).
~/.config/envstow/identity.txt    # YOUR age private key. Never shared, never committed. (0600)
                                  #   Windows: %APPDATA%\envstow\identity.txt
```

The store doesn't have to live in the repo. You can keep it in your config directory or any
path you like — but nothing in the repo will point at it, so you name it per command. See
[Stores](#stores).

To *use* a secret you unlock it into a **child process**. The child gets the value in its
environment and does its job; the value never appears in your shell history, an agent's tool
call, or its transcript. You only ever type the variable **name**.

If you commit `.envstow/`, everything in it is safe to share: the store is ciphertext and
`recipients` holds only public keys. Your private key lives outside the folder and is never
committed.

---

## How it compares

envstow occupies a specific niche: **committed, encrypted secrets with no server and an
AI-agent-safety layer.** It is not a secrets *service* and doesn't try to be — if you need central
audit logs, automatic rotation, dynamic/short-lived credentials, or per-secret access control,
one of the tools below is the right call, and this grid is meant to send you there honestly.

| | **envstow** | SOPS (+age) | git-crypt | 1Password (`op`) | Doppler / Infisical | Vault / cloud KMS |
|---|---|---|---|---|---|---|
| **Where secrets live** | encrypted file in the repo/folder | encrypted file in the repo | encrypted file in the repo | hosted vault | hosted service | hosted server / cloud |
| **Server or account?** | none | none | none | account (paid) | account (free tier + paid) | server / cloud account |
| **Works offline** | ✅ | ✅ | ✅ | cached | cached | ❌ |
| **Install footprint** | one binary, no deps | `sops` + a key backend | `git-crypt` + GPG | `op` CLI + app | CLI + account | CLI + infra |
| **Commit secrets to git** | ✅ (ciphertext) | ✅ (ciphertext) | ✅ (ciphertext) | ❌ (refs only) | ❌ (refs only) | ❌ |
| **Who can decrypt** | per-recipient age key | age/PGP/KMS keys | GPG or shared key | account / groups | teams / roles | IAM / policies |
| **Run a cmd with secrets** | `run -- cmd` | `sops exec-env` | (files on disk) | `op run -- cmd` | `run -- cmd` | via SDK/CLI |
| **Reference by name, value off the CLI** | ✅ core design | partial | ❌ (plaintext on disk) | ✅ (`op://…` refs) | ✅ | ✅ |
| **AI-agent masking / leak guard** | ✅ built in | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Central audit log** | ❌ (git history only) | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Automatic rotation** | ❌ (manual + rotate at source) | ❌ | ❌ | partial | ✅ | ✅ |
| **Access granularity** | whole store per recipient | whole file | whole file | per-item | per-secret | per-secret |
| **Dynamic / short-lived secrets** | ❌ | ❌ | ❌ | ❌ | some | ✅ |
| **Cost** | free (OSS) | free (OSS) | free (OSS) | paid | free tier + paid | infra + usage |

**Reach for envstow when** you want to commit a repo's secrets safely, work offline or solo, add
no infrastructure, and keep values out of an AI agent's context — and you're fine rotating
secrets by hand and granting access at the whole-store level.

**Reach for something else when:** you need a tamper-evident audit trail or automatic rotation
(**Vault**, **Doppler**, cloud KMS); dynamic/leased credentials (**Vault**); per-secret access
control across a large org (**Doppler**, **Infisical**, cloud KMS); or you already live in
**1Password** and want its `op run` / `op://` references (very close in spirit to envstow's
by-name model — just server-backed instead of committed). **SOPS** is the closest OSS cousin:
same "encrypted file in git" idea, more backends and CI integrations, but external tooling to set
up and no agent-safety layer. **git-crypt** is simplest but decrypts to plaintext in your working
tree and has no by-name access.

*(Feature details for hosted tools change over time; check their docs for specifics. This grid is
about shape, not a point-in-time spec.)*

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

Already have envstow? **`envstow upgrade`** installs the latest release (or `envstow upgrade --check`
to just look). It re-runs the installer above for you — and refuses if a package manager owns the
install, telling you to use that instead.

Installs to `~/.local/bin` — **open a new terminal** (or `source ~/.local/bin/env`) before
running `envstow`, then `envstow --version` to confirm. The installer verifies the binary's
SHA-256 and enforces TLS. To inspect the script first, or verify checksums by hand, see the
install options in [ONBOARDING.md](./ONBOARDING.md#1-install-envstow-once-per-machine). Or build
from source (needs [Rust](https://rustup.rs)): `cargo install --path crates/envstow`.

**Prefer no installer?** Grab the binary directly from the
[latest release](https://github.com/jhnhnsn/envstow/releases/latest) — download the archive for
your platform (e.g. `envstow-aarch64-apple-darwin.tar.xz`, or the `x86_64-…` / `…-linux-gnu` /
`…-windows-msvc.zip` variant), extract it, and move `envstow` onto your `PATH`:

```bash
tar xf envstow-aarch64-apple-darwin.tar.xz            # → envstow-aarch64-apple-darwin/
mv envstow-aarch64-apple-darwin/envstow ~/.local/bin/ # any dir on your PATH
```

Each archive ships with a `.sha256` you can check first (`shasum -a 256 -c envstow-*.tar.xz.sha256`).
It's the same binary the installer places — this just skips the script. `envstow upgrade` won't
manage a hand-placed binary (no install receipt); re-download to update, or use the installer.

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
cd ~/my-project        # any folder — a git repo, or not
envstow init
```

`init` creates your private key (in `~/.config/envstow/`, once per machine), a `recipients` list
holding your public key, and an empty store. Idempotent.

That's it if you're working **solo** — no git, no sharing, nothing else to do. The folder is the
scope; `.envstow/` stays local until you decide otherwise.

To keep the store out of the folder entirely, `envstow init --store <name>` puts it in
`~/.config/envstow/stores/<name>/` and writes nothing here — you reach it with `--store <name>`.
See [Stores](#stores).

**Optional: one line in your shell rc.** Everything below works with the bare binary — envstow
prints the exact `eval` line to run whenever your shell needs it. If you'd rather skip even
that, add the shell hook to `~/.zshrc` / `~/.bashrc`:

```bash
eval "$(envstow shell-init)"
```

It installs a small wrapper function so that `envstow set NAME` run *inside* an unlocked shell
makes the new value live in that shell immediately — no reminder, no re-unlock. (`delete`
still prints the one-line reminder; see
[Stale secrets](#stale-secrets-in-an-unlocked-shell).) Like direnv's hook, this is a
convenience, not a dependency: nothing else in envstow needs it.

**Want teammates to have it?** Commit the folder — it's encrypted:

```bash
git add .envstow && git commit -m "Add envstow store"
```

### 2. Add and list secrets

Copy a secret from your password manager, then paste it into `set` — the value comes from
**stdin**, so it never lands on the command line or in your shell history:

```bash
envstow set MY_SUPER_SECRET_KEY --clipboard                 # read the OS clipboard directly
#   → set MY_SUPER_SECRET_KEY (sk-pr••••••••)   ← masked confirmation of what you stored
# Uses your platform's paste tool: pbpaste (macOS), wl-paste/xclip/xsel (Linux),
# Get-Clipboard (Windows). Piping still works if you prefer:
pbpaste | envstow set MY_SUPER_SECRET_KEY                   # macOS: paste from clipboard

envstow set MY_SUPER_SECRET_KEY                             # …or run bare, then paste + Enter
printf 'sk-proj-abc123' | envstow set MY_SUPER_SECRET_KEY   # …or pipe a literal
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

`envstow run -- <cmd>` runs one command with every secret set as an env var:

```bash
envstow run -- npm run build
envstow run -- flyctl deploy
envstow run -- sh -c 'psql "$DATABASE_URL" -f migrate.sql'
```

You typed `$DATABASE_URL` — the shell expands it *inside the child*, so the value reaches `psql`
but never your history or a log.

**Give a command only what it needs** with `--only` (comma list, repeatable, or both):

```bash
envstow run --only FLY_API_TOKEN -- flyctl deploy
envstow run --only DB_URL,SENTRY_DSN -- ./migrate.sh
```

That `npm run build` above? Its dependencies' postinstall scripts inherit the child's env — all
of it. `--only` is least privilege for exactly that case: the command gets the named secrets and
nothing else. A typo'd name is a **hard error before anything spawns** (`unknown secret
'SENTRY_DNS' (did you mean SENTRY_DSN?)`) — never a child launched with a silently missing
variable. (One-shot commands are `run`'s job alone — `envstow unlock` opens an interactive
subshell and no longer takes a command.)

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

### 6. Add a teammate

**Alice** — generate a key and send you the public half. Do this **outside the project** so she
doesn't touch its `recipients` file:

```bash
cd ~                                  # anywhere but the project
envstow init                          # once per machine
envstow pubkey                        # → age1abc…  send this to you (Slack/email is fine)
```

**You** — add her and push:

```bash
cd ~/my-project
envstow add-recipient age1abc… alice  # adds her key AND re-encrypts the store
git add .envstow && git commit -m "Add Alice" && git push
```

**Alice** — `git pull`, and she's in. `envstow list` works.

> **`recipients` is an input to encryption, not an access list.** Putting a key in that file
> grants nothing on its own — the store has to be **re-encrypted** to include it. That's why
> `add-recipient` does both in one step.
>
> If Alice runs `envstow init` *inside* the project, it appends her key to `recipients` but she
> still can't decrypt. envstow tells her so, and the fix is for you to run `envstow reencrypt`
> (not `add-recipient` — her key is already listed). Avoid the detour: have her `init` elsewhere.

Only the **public** key (`age1…`) is ever shared. It lets you encrypt *to* someone, never decrypt.

### 7. Remove a teammate

```bash
envstow remove-recipient alice
git add .envstow && git commit -m "Remove Alice" && git push
```

This re-encrypts without Alice — but **her key still decrypts every older commit** in any clone
she kept. **Rotation is the real revocation:** regenerate each secret she saw at its source and
`envstow set` the new value.

### 8. CI / automation

Point `$ENVSTOW_IDENTITY` at a dedicated CI key (added as a recipient, stored as a CI secret):

```bash
ENVSTOW_IDENTITY=/path/to/ci-key envstow run -- npm run deploy
```

That's the whole setup when the store is committed — the checkout brings it along. If the store
lives **outside** the repo, the runner has no copy, so put it where the job can reach it and name
it explicitly:

```bash
ENVSTOW_IDENTITY=/path/to/ci-key \
ENVSTOW_STORE_DIR=/path/to/store \
  envstow run -- npm run deploy
```

### 9. Keeping the store out of the repo

Sometimes committing the store is the wrong call:

- **A public repo.** The store is ciphertext, so publishing it isn't a plaintext leak — but it is
  a permanent, world-downloadable copy, and `recipients` publicly lists your collaborators.
- **Secrets you use across projects.** One personal store, many repos, no duplication.
- **No git, or a team that shares a folder** over Drive/Dropbox/Syncthing instead.

```bash
envstow init --store personal          # → ~/.config/envstow/stores/personal/
envstow --store personal set OPENAI_API_KEY
envstow --store personal run -- ./script.sh
export ENVSTOW_STORE=personal          # …or set it once per shell
```

Nothing is written into the working directory, so **nothing in a checkout can select this
store** — that's deliberate (see [Stores](#stores)). The trade is that you name it every time,
or export it; forget, and envstow falls back to looking for `.envstow/` as usual.

For a folder your team already syncs, use a path instead — everyone points at their own synced
copy and the sync service handles delivery:

```bash
envstow init --store-dir ~/"Drive/team-secrets"
export ENVSTOW_STORE_DIR=~/"Drive/team-secrets"
```

Sharing a store that *isn't* synced is manual: `add-recipient` their key, then send them the
directory. envstow won't arrange that for you — see [Sharing one](#sharing-one).

### On Windows

Most commands are identical — `envstow init`, `list`, `pubkey`, `add-recipient`, and
`envstow run -- <program>` all work as-is. Only a few things differ:

```powershell
# Your identity lives at %APPDATA%\envstow\identity.txt.
'sk-proj-abc123' | envstow set MY_SUPER_SECRET_KEY     # PowerShell pipes a value to stdin
envstow run -- npm run build                   # runs the program directly — same as POSIX

# The only real difference: no `sh -c`. To reference a value by name in a shell,
# use PowerShell (%VAR% for cmd.exe):
envstow run -- powershell -c 'psql $env:DATABASE_URL -f migrate.sql'
envstow run -- cmd /c "psql %DATABASE_URL% -f migrate.sql"

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
into the interactive prompt won't work — pipe it (`cat key.pem | envstow set TLS_KEY`).

### Profiles

A store can hold multiple secret sets — e.g. `dev`, `staging`, `prod` — as separate encrypted
files (`<profile>.enc`), all keyed to the same `recipients`. The unnamed **`default`** profile
is `default.enc`. In a local store those sit in `.envstow/`; in a
[central store](#stores), in that store's directory.

Profiles and stores are the two independent axes: a **store** selects *whose* secrets (which
directory, and therefore which `recipients`), a **profile** selects *which set* within it.
Profiles share one recipients list — dev/staging/prod are the same team — while separate stores
don't.

```bash
envstow profile create prod                 # create a new profile (empty store)
envstow --profile prod set DB_URL           # write to prod's store
envstow --profile prod run -- npm start  # run with prod's secrets
export ENVSTOW_PROFILE=prod                  # …or make it sticky for the shell
envstow profile                              # show the current profile + list available
envstow profiles                             # list profiles
```

Selection precedence: `--profile <name>` flag (before or after the subcommand) > `ENVSTOW_PROFILE`
env var > `default`. Using a profile that doesn't exist errors and tells you to
`envstow profile create` it (so a typo can't silently make a junk store).

---

## Stores

*New in 0.2.0.* By default the store lives in `.envstow/` beside your code and is committed with
it. Git handles distribution, history, and "who has the current version," which is most of the
problem — so that's the default, and for a team on a private repo it's usually the right answer.
**If it suits you, skip this section.**

You can also keep the store outside the repo — a folder synced by Drive/Dropbox/Syncthing, a
path in your config directory, an encrypted volume:

```bash
envstow init --store acme                       # → ~/.config/envstow/stores/acme/
envstow init --store-dir ~/"Drive/team-secrets"  # → any path you like
```

### Reaching one

An external store is **never** referenced from inside the repo. You name it per command, or
export it for the shell:

```bash
envstow --store acme list                  # by name (config dir)
envstow --store-dir ~/"Drive/team-secrets" list   # by path
export ENVSTOW_STORE=acme                  # …or make it sticky for this shell
export ENVSTOW_STORE_DIR=~/"Drive/team-secrets"
envstow store                              # which store is in effect, and why
```

Layout for a named store:

```
~/.config/envstow/
  identity.txt          # your private key — deliberately NOT inside stores/
  stores/
    acme/
      recipients        # THIS store's collaborators (its own, not shared with other stores)
      default.enc
      prod.enc          # profiles live inside a store: --store acme --profile prod
```

The identity sits *beside* `stores/` on purpose: together, one directory would be enough to
decrypt everything in it — which an over-broad backup or a synced config folder would carry
whole.

### Nothing in the repo can point at one

This is deliberate, and it's the one design decision here worth knowing.

An earlier version let a repo commit a `.envstow` *file* containing `store: acme`, so commands
in that project needed no flag. Convenient — and it made "where do this project's secrets come
from" something **one person could change for everyone**, silently, on the next `git pull`.

The dangerous direction is external → committed. Someone hits friction with the external store,
creates a local `.envstow/`, and commits it. Everyone else pulls, and the walk finds that
perfectly plausible local store. Same command, same directory, *different secret*, no error —
and if you're a recipient of both stores (which you are the moment you've ever run `init`
there), you just deploy the wrong credential.

Making the redirect impossible removes the failure rather than detecting it afterward. The cost
is real: reaching an external store means a flag or an exported variable every time, and
forgetting falls back to the walk. But that mistake is *yours*, in *your* shell, and it's
recoverable — the other one silently changed everybody's secrets.

The corollary: **if a team shares an external store, they have to agree how.** Who has it, how
a new person gets a copy, what happens when someone adds a secret. envstow won't arrange it, and
no file in the repo will either. If that sounds like work, that's the honest signal to commit
the store instead and let git do it.

### Sharing one

Nothing transports an external store — you send it yourself.

```bash
# Them:
envstow pubkey                              # → age1kk8x4…  send it over
# You:
envstow --store acme add-recipient age1kk8x4… bob   # adds + re-encrypts
envstow --store acme store                  # shows the directory; send them that
# Them: drop it at ~/.config/envstow/stores/acme/, then
envstow --store acme list
```

A **synced folder** with `--store-dir` avoids most of this: everyone points at their own synced
copy and the sync service does the transport.

### Selection precedence

```
--store-dir <path>        explicit path
--store <name>            a store in your config dir, by name
$ENVSTOW_STORE_DIR
$ENVSTOW_STORE
.envstow/ found by walking up from the CWD    (the default)
otherwise                 error, listing the stores you have
```

Flags work before or after the subcommand and compose with `--profile`. Passing both `--store`
and `--store-dir` is refused rather than resolved. Naming a store that doesn't exist is always
an error listing the ones that do — it never quietly falls back to the walk.

### Upgrading from a repo with a `.envstow` file

If a project still carries a committed pointer file from the earlier scheme, envstow refuses it
and explains the options rather than following it — skipping it would be the same silent
substitution described above:

```
$ envstow list
envstow: /my-project/.envstow is a FILE saying this project's secrets live in the external store 'acme'.
  envstow no longer follows these — a committed file that redirects where secrets
  come from silently changes them for everyone on the next pull.

   If you HAVE that store, name it per command (nothing to commit):
     envstow --store <name> <command>     …or export ENVSTOW_STORE=<name>
     envstow store                        …lists the stores you have
   If you DON'T have it, ask whoever set this up to share it — and agree with
   them how you'll keep it in sync, since git won't do it for you.
   If this project's secrets should live IN THE REPO (simplest for a team):
     rm /my-project/.envstow && envstow init
```

To move an external store into the repo (no `migrate` command needed — they're just files):

```bash
rm .envstow                                     # drop the old pointer
cp -R ~/.config/envstow/stores/acme .envstow    # bring the store in
git add .envstow && git commit -m "Keep secrets in the repo"
```

For a **public** repo, moving files is only half of it: any ciphertext already pushed stays in
git history. Treat those secrets as exposed and **rotate at the source** — the same reasoning
`remove-recipient` prints.

### What git was quietly providing

Two things an external store loses:

- **No history.** A bad `reencrypt` or an accidental `delete` is recoverable from git; from a
  shared folder, only via your sync service's own version history.
- **No merge.** Two people can't edit the same store concurrently and have both changes survive.
  envstow refuses the losing write rather than dropping a secret (below), but the loser has to
  re-run — there's no equivalent of `git pull --rebase`.

### Concurrent writes

Every envstow write is read-modify-write: decrypt the whole store, change one key, re-encrypt
the whole thing. If two people do that at once, the second write is built on contents that
predate the first — so "last one wins" quietly loses a secret.

envstow checks the store hasn't changed since the command read it, and refuses rather than
overwrite:

```
envstow: could not write store: someone else changed this store while your command was running, so writing
  now would silently discard their change:
    /shared/team-secrets/default.enc

  Nothing was written — your change is the one that didn't happen. Re-run the
  same command and it will apply on top of theirs.
```

Re-running applies your change on top of theirs. The check compares the file's actual bytes, not
its timestamp — sync clients rewrite files with timestamps that don't reflect edit order.

This makes the failure loud rather than impossible: you still can't have two people editing one
store at the same moment. A committed store gets the stronger guarantee, because git refuses the
push and makes you pull first.

Error messages adapt: advice like `git pull && envstow reencrypt && git add .envstow` only
appears when the store actually is in a git work tree.

---

## Command reference

| Command | Purpose |
|---|---|
| `envstow init [--store <name>\|--store-dir <path>]` | Generate identity, create `recipients` + empty store. Default: in this folder. With `--store`/`--store-dir`, outside it — nothing is written here. Idempotent. |
| `envstow store` | Show which store is in effect **and why**; list central stores. |
| `envstow set <NAME> [--clipboard]` | Store a value read from **stdin**, or the OS clipboard with `--clipboard` (`-c`). Never in argv either way. |
| `envstow delete <NAME> [--force]` | Remove one secret; re-encrypt (then **rotate**). Confirms on a TTY. |
| `envstow get <NAME> [--show]` | Resolve one secret by name. **Masked under an agent** unless `--show`. |
| `envstow list` | List secret **names** (never values). |
| `envstow pubkey` | Print your age **public** key, to share so a member can add you. |
| `envstow unlock` | Interactive subshell with every secret set as an env var; `exit` locks. |
| `envstow run [--only A,B] -- <cmd>` | Run one command with all — or `--only` the named — secrets. Unknown names error before spawning. |
| `envstow status` | Show whether you're in an unlocked shell, which profile, and the loaded secret **names** (never values; reads only env markers). |
| `eval "$(envstow env)"` | Load — or reset, after a store change — every secret in **this** shell, no subshell. Refuses under an agent and when stdout is a terminal; see [Stale secrets](#stale-secrets-in-an-unlocked-shell). |
| `eval "$(envstow env --off)"` | Unset everything envstow set in this shell (names only — needs no key). |
| `eval "$(envstow refresh)"` | Unset *deleted* names an unlocked shell still holds (emits only `unset`, never a value — safe anywhere `env` isn't). |
| `eval "$(envstow shell-init)"` | (In your shell rc, optional) install the wrapper so `set` inside an unlocked shell goes live instantly — see [First-time setup](#1-first-time-setup). |
| `envstow add-recipient <age1…> [label]` | Add a collaborator **and** re-encrypt — both steps. |
| `envstow remove-recipient <key\|label>` | Remove a collaborator; re-encrypt (then **rotate**). |
| `envstow reencrypt` | Re-encrypt to the current `recipients` — after someone's key was added by hand or by their `init`. |
| `envstow profile [create <name>]` | Show the current profile, or create a new one. |
| `envstow upgrade [--check\|--yes]` | Upgrade envstow to the latest release (`--check` just reports). |
| `envstow profiles` | List available profiles. |
| `--profile <name>` | (On any command) use a separate secret set; see [Profiles](#profiles). |
| `--store <name>` / `--store-dir <path>` | (On any command) use a different store; see [Stores](#stores). |

**Environment:** `ENVSTOW_IDENTITY` overrides the identity path (default
`~/.config/envstow/identity.txt`). `ENVSTOW_STORE` / `ENVSTOW_STORE_DIR` select a store by name
or path (see [Stores](#stores)). `ENVSTOW_AGENT=1` forces agent-masking for `get` in tools
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
agent "the token is in `$FLY_API_TOKEN`", and it runs `envstow run -- sh -c 'deploy --token
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
- **Output guard** — a post-command hook (`envstow scan-leak`, built into the binary) that blocks
  any command output containing a live secret value (raw or base64), regardless of the agent's
  judgment. It keys off `ENVSTOW_LOADED` (the exact names `unlock` set), so it catches **any**
  secret — `DATABASE_URL`, a DSN, a connection string — not just conventionally-named ones, and
  matches multi-line values line by line. One line in your agent's config wires it up; `envstow
  upgrade` keeps it current. (The old hand-copied `scripts/redact-guard.sh` still works but is
  deprecated.)

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
a value someone deliberately reveals with `--show`, or re-encodes (hex, gzip, url) to evade the
output guard (`scan-leak`). The guard also can't safely match a **short, low-entropy** value (a 4-digit PIN, a
dictionary word) — matching those would block innocent output — so it skips them; short but
*random* tokens (5+ chars, mixed character classes) are still caught.
For those gaps: rotate, and treat this as strong hygiene, not a vault.

envstow warns (on Unix) if your identity key (`~/.config/envstow/identity.txt`) is readable by
group or other — a loose key decrypts every store you can. Fix with `chmod 600`.

---

## Stale secrets in an unlocked shell

An `envstow unlock` shell got its environment **at spawn time, as a copy**. If you change the
store afterwards — a `set` or a `delete` — the running shell keeps the *old* values. No
process can reach into a running one and change its environment; that's an OS boundary, not an
envstow limitation.

So after any change to the store while unlocked, reset your shell's values in place:

```bash
eval "$(envstow env)"   # re-export everything from the store, unset what left it
```

(envstow reminds you of this line after any `set`/`delete` made inside an unlocked
shell.) One consistent answer for every kind of change — added, changed, or deleted. If you'd
rather not patch in place, `exit` + `envstow unlock` always works too, and remains the way
agents pick up changes. And with the optional [shell hook](#1-first-time-setup) sourced, `set`
skips even the reminder — the new value goes live in your shell the moment it's stored.

> How can this be safe, when the only way to alter a running shell's environment is to print
> shell code for it to evaluate — values included? Because `envstow env` only ever emits into an
> eval: it **refuses when stdout is a terminal** (so a bare `envstow env` can't splash values on
> screen) and **refuses under an AI agent** (whose captured stdout is a transcript — agents are
> pointed back to `unlock`). Values are single-quoted so hostile content is inert, names must be
> plain identifiers, and the plaintext transits only the pipe between the binary and your shell —
> never disk, never argv. The same guarded channel powers `eval "$(envstow env --off)"`, which
> unsets everything envstow set here (that direction prints only names, so it's safe anywhere).

---

## Nested unlocks (a store inside a store)

Nothing stops a subfolder from having its own `.envstow/`. Unlocking one from inside another is
supported and often what you want: a subproject gets its own vars layered on top of the shared
ones above it.

The child sees the **union** of both. Env vars are inherited, and envstow only ever *adds*, so:

- names only in the outer store stay set,
- names only in the inner store are added,
- **names in both take the inner store's value** — the one you unlocked last wins.

Because a silently-inherited credential is worse than a missing one, `unlock` names any collision:

```
envstow: loaded 2 secret(s) from default: SHARED_KEY, CURA_TOKEN
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

**External stores need ≥ 0.2.0** on any machine that uses one — `--store` / `--store-dir` and
their env vars don't exist in `0.1.x`. Nothing about this affects the store *format*, and a
local `.envstow/` directory reads and writes identically on both.

A `.envstow` **file** (the committed redirect that 0.2.0 briefly supported) is refused from
0.2.2 on; see [Upgrading from a repo with a `.envstow` file](#upgrading-from-a-repo-with-a-envstow-file).

---

## Developing on envstow

```bash
cd crates/envstow && cargo test         # unit + integration: crypto round-trip, masking, full CLI lifecycle
scripts/test-redact-guard.sh # proves the hook blocks a leak and allows name references
```

**Before pushing, check the Windows target too.** CI runs `clippy -D warnings` on all three OSes,
and `#[cfg]`-gated code that's fine on your machine can be dead code (or a lint) on Windows — a
host-only clippy run won't catch it:

```bash
rustup target add x86_64-pc-windows-msvc              # once
cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings
```

No MSVC toolchain is needed — `clippy`/`check` don't link, so this works from macOS or Linux.

If you touch `scripts/*.sh`, also run **`shellcheck scripts/*.sh`** — CI fails on any warning, and
it catches shell issues a local run won't (`brew install shellcheck` / `apt install shellcheck`).

CI (`.github/workflows/ci.yml`) builds + tests + `fmt` + `clippy` on macOS/Linux/Windows, and
runs `shellcheck` + the redact-guard test on Linux.

See `DESIGN.md` for the full design rationale.
