---
name: envstow
description: Use envstow to access encrypted secrets in a repo that uses it — reference secrets by name, run commands that need them, and onboard to the shared store. Load this whenever a task needs an API key, token, password, database URL, or any secret (e.g. deploy, call an authed API, run migrations, set an env var), when `envstow` commands fail, or when a teammate needs to be added to the secret store. Only applies if the repo has a `.envstow/recipients` file and `.envstow/default.enc`.
---

# Using envstow

envstow manages secrets as an **age-encrypted key-value store** (`.envstow/default.enc`)
committed to a repo. `envstow` is a single self-contained binary — no `sops`/`age` CLIs needed.
Secrets are used **by name**; their plaintext must never enter your output, a tool-call
argument, or a file.

**Does this repo use envstow?** It does if there's a `.envstow/recipients` file and `.envstow/default.enc`
at the repo root (`envstow list` succeeds). If not, this skill doesn't apply — the repo may use
a plain `.env` or another secrets tool.

## The one rule

**Never print, echo, log, or paste a secret's value.** Reference it by variable name (e.g.
`$FLY_API_TOKEN`). If you need a secret in a command, use `envstow unlock -- <cmd>` (below) so
the value only ever lives in the child process — never in your transcript.

## Subtle ways a value leaks (guard against these yourself)

The obvious leak is `echo $SECRET`. The dangerous leaks are the ones you don't intend — a value
riding out in output you didn't think to check. Treat these as your own responsibility, because
no tool will catch them for you:

- **A command's output can contain a secret you never named.** Verbose/debug flags (`-v`,
  `--debug`, `DEBUG=*`), stack traces, and error messages routinely echo the environment or a
  config object. Before you quote *any* command's output back into your reply, scan it for a live
  value. If a command might print one, don't run it with secrets in scope, or discard its output.
- **Prefer per-command unlock over a session-wide one.** `envstow unlock -- <cmd>` puts the
  secrets only in that one child — they are never in *your* environment, so nothing you run can
  accidentally echo them. A bare `envstow unlock` (whole session unlocked) is riskier: every
  command then inherits the secrets and any stray output can leak one. Use the scoped form by
  default.
- **Encoding is not laundering.** Base64/hex/JSON-embedding a value, or piping it through another
  tool, still exposes it. `echo "$TOKEN" | base64` is a leak.
- **Redirect-then-read still surfaces it.** Writing a value to a file and reading the file back,
  or teeing output to a log you then display, puts the plaintext in your context just the same.
- **Don't reconstruct a value from parts.** Concatenating a prefix you saw with the rest, or
  quoting a "masked" value you managed to partially reveal, defeats the point.

Rule of thumb: if plaintext could end up in your reply, a file, a commit, or a tool-call argument
by *any* path — don't take that path. Reference the name; let `unlock` expand it in a child.

## Using a secret in a command (the main pattern)

`envstow unlock -- <cmd>` runs one command with **every** secret set as an env var. Reference
the secret by name; the value is expanded inside the child, not by you:

```bash
envstow unlock -- npm run build
envstow unlock -- flyctl deploy
# When a tool needs the value as an argument, reference it by name inside a shell:
envstow unlock -- sh -c 'psql "$DATABASE_URL" -f migrate.sql'
envstow unlock -- sh -c 'curl -H "Authorization: Bearer $MY_SUPER_SECRET_KEY" https://api.example.com'
```

You write the literal string `$DATABASE_URL` — inert characters. Never substitute the actual
value yourself.

## Discovering what's available

```bash
envstow list          # prints the NAMES of stored secrets (never values) — safe
```

Use this to learn which names exist before referencing them. If you're unsure a secret exists,
`list` first.

## Reading a value

Prefer **not** to. If you genuinely must resolve a value (rare), `envstow get <NAME>` — but
under an agent it prints a **mask** (`••••••••`) by default. **That masking is intentional; do
not try to defeat it.** If a human needs to see the value, tell them to run
`envstow get <NAME> --show` themselves. Do not run `--show` on the human's behalf unless they
explicitly ask.

## Adding / changing a secret

Do NOT put the value as a command-line argument (it lands in shell history). Have the human
provide it via stdin — a paste from their password manager, an interactive prompt, or a file:

```bash
envstow set SOME_TOKEN --clipboard                # human copies it, you run this — no value in argv
envstow set SOME_TOKEN                            # interactive: prompts, human types + Enter
pbpaste | envstow set SOME_TOKEN                  # human pastes from clipboard (macOS)
envstow set TLS_KEY < key.pem                     # multi-line value (PEM, cert, JSON) from a file
```

`--clipboard` is the smoothest one for you to run on a human's behalf: ask them to copy the
secret, then run it. The value goes clipboard → store without passing through you.

After changing secrets, remind the human to `git add .envstow && git commit`.

## Stale secrets after a change

An unlocked shell holds a **copy** of the environment from when it started. If a secret is deleted
or changed after that, the shell (and anything you run in it) still has the old value — no process
can modify a running process's environment.

If a secret was **deleted** and is still set, clear it in place:

```bash
eval "$(envstow refresh)"     # emits only `unset` lines — no values, safe for you to run
```

If a secret was **changed**, `refresh` can't help (updating it would mean printing the value).
Tell the human to `exit` the unlocked shell and re-run `envstow unlock`.

## Removing a secret

```bash
envstow delete SOME_TOKEN          # prompts [y/N] on a terminal; --force skips the prompt
```

This is safe to run — it never prints the value. Deleting only removes the secret going
**forward**: the value stays readable in the store's git history to anyone who is (or was) a
recipient. If it's being deleted because it leaked or should stop working, tell the human to
rotate it at its source too. Deletion is per-profile — a name in `dev` and `prod` needs a
`delete` for each (`--profile <name>`).

## Common failures and what they mean

- **`no 'recipients' file found ... (run envstow init first)`** — you are not inside an
  envstow repo. `cd` into the project root (the dir containing `.envstow/`) and retry. Do NOT
  run `envstow init` in a repo that already has a store elsewhere.
- **`decryption failed: No matching keys found`** — the current identity isn't a recipient of
  this store. The human needs to be added (see Onboarding) and the store re-encrypted.
- **`this store uses format N, but your envstow only understands format M`** — a teammate wrote
  the store with a newer envstow. Tell the human to update; the message links the repo. Don't try
  to work around it — the store is fine, the binary is old.
- **`decryption failed: Header is invalid`** — usually the same cause, but from the other side:
  an envstow ≤ 0.1.8 (which predates the format header) reading a store written by ≥ 0.1.9. Have
  the human update.
- **`envstow set` seems to hang** — it's waiting on stdin. Have the human pipe or type the value.
- **`command not found: envstow`** — not installed. Point the human at the installer:
  `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/jhnhnsn/envstow/releases/latest/download/envstow-installer.sh | sh`

## Onboarding a teammate to the shared store

Adding a person is a two-sided key exchange. Walk the human through it:

1. **New teammate** (on their machine): `envstow init`, then `envstow pubkey` — this prints
   their age **public** key (`age1...`). It is safe to share (Slack, email, a PR); it only lets
   others encrypt *to* them, never decrypt. Their **private** key never leaves their machine.
2. **An existing member** adds them and re-encrypts:
   ```bash
   envstow add-recipient age1theirkey... alice
   git add .envstow && git commit -m "Add alice" && git push
   ```
3. The new teammate pulls; they can now decrypt with their own key.

Prefer having the teammate add their own key line via a **pull request** — the key is in the
diff, tied to their identity, and recorded in history.

## Removing a teammate

```bash
envstow remove-recipient alice
```

This re-encrypts without them, but their key still decrypts old commits. **Rotation is the real
revocation:** for every secret they could see, regenerate it at its source and re-set it. Remind
the human — the command prints the warning too.

## Hardening a repo for agents

To steer/block an agent from exposing a value (skill + denylist + output-guard hook), see
https://github.com/jhnhnsn/envstow/blob/main/GUARDRAILS.md — a human or an agent can follow it.

## What you must never do

- Never run `env`, `printenv`, `echo $SECRET`, `set`, `export -p`, or anything that dumps a value.
- Never write a secret's value into a file, a commit, a log, or your reply — in any encoding.
- Never quote command output into your reply without checking it holds no live value first.
- Never run a verbose/debug command with secrets in scope just to read its output.
- Never run `envstow get ... --show` on the human's behalf unless they explicitly ask to see it.
- Never try to defeat `get`'s mask, or reconstruct a value from pieces.
- If you think you truly need a plaintext value, **stop and ask the human.**
