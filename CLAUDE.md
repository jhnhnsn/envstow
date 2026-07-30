# envstow — project instructions

This repo stores an **age-encrypted key-value store** (`.envstow/default.enc`) checked into git.
Each collaborator decrypts it with **their own age private key**. Secrets are surfaced **by
name** so their plaintext never has to be pasted onto a command line. All crypto is the `age`
crate compiled into the `envstow` binary — there are no external tools (`sops`/`age` CLIs) to
install or invoke.

(A store can also live outside the repo — `~/.config/envstow/stores/<name>/` via a committed
`.envstow` pointer file, or any path via `--store-dir`. This repo uses the committed
`.envstow/` directory; `envstow store` reports which is in effect. Everything below applies
identically either way.)

## Secret handling — MANDATORY

- Refer to secrets by their variable **name** only (e.g. `$FLY_API_TOKEN`). Never paste,
  echo, print, `cat`, or log a secret **value**.
- To use a secret in a command, reference it by name inside an unlocked context:
  - **Prefer** `envstow run --only <NAMES> -- <cmd>`: it runs `<cmd>` with exactly the named
    secrets set as env vars, so
    `envstow run --only FLY_API_TOKEN -- sh -c 'deploy --token "$FLY_API_TOKEN"'` works and the
    value is only ever in the child's environment — never in your tool call or its output — and
    the child gets nothing it doesn't need.
  - `envstow run -- <cmd>` does the same with the whole store; use it only when the command
    genuinely needs many secrets.
  - `$(envstow get NAME)` resolves one secret by name. **Under an agent, `envstow get`
    masks its output by default** (prints `••••••••`) precisely so a value can't land in your
    context. That masking is working as intended — do not try to defeat it. If a human needs
    the value, they run `envstow get NAME --show` themselves.
- **Never run:** `env`, `printenv`, `echo $SOME_SECRET`, `set`, `export -p`, or any command
  whose purpose is to reveal a secret value. These are denied in `.claude/settings.json`.
- A `PostToolUse` hook blocks any command output that contains a live secret value, as accident
  insurance (this repo currently wires the legacy `scripts/redact-guard.sh`; the built-in
  `envstow scan-leak` is the equivalent going forward). A "BLOCKED by envstow" message is working
  as intended — do not retry in a way that surfaces the value.
- If you believe you genuinely need a secret's plaintext, **STOP and ask the human.**

## Using envstow

- `envstow get <NAME>` — resolve one secret by name (masked under an agent; `--show` to reveal).
- `envstow unlock` — open an interactive subshell with all secrets set as env vars (`exit`
  locks). One-shot commands are `run`'s job; `unlock` no longer takes a command.
- `envstow run [--only NAME[,NAME...]] -- <cmd>` — run one command with all, or only the named,
  secrets. **Prefer `run --only` with just the names the command needs** — least privilege for
  the child and everything it spawns.
- `envstow set <NAME> [--clipboard]` — store a value read from **stdin**, or the OS clipboard
  with `--clipboard`. Both keep the value off the command line.
- `envstow delete <NAME>` — remove one secret and re-encrypt (`--force` to skip the prompt).
- `envstow list` — list secret **names** (never values).
- `envstow store` — show which store is in effect and why; list central stores. Safe (paths and
  names only).
- After any store change (`set`/`delete`) made **inside** an unlocked shell, the running
  shell still holds the old values — `exit` and `envstow unlock` again to pick up the change.
  (`eval "$(envstow refresh)"` can unset deleted names in place, but `exit` + `unlock` is the
  uniform rule.)
- `envstow env` is **human-only**: it prints plaintext `export` lines for the human's shell to
  eval, and refuses under an agent. Do not run it or try to work around the refusal — that
  refusal is working as intended. You pick up store changes via `unlock`, never `env`.
- `envstow add-recipient <age1...>` / `remove-recipient <key|label>` — manage collaborators.
- `envstow upgrade [--check]` — upgrade envstow itself. Safe to run `--check`; the human should run
  the actual upgrade (it needs `--yes` non-interactively and replaces the binary).

The human generates their key and creates the store with `envstow init`. You do not need to
run `init`. Just use secrets by name via `unlock`/`get` as above.

## Revoking access

`envstow remove-recipient` stops **future** decryptions, but the removed key still decrypts
every historical commit in any clone. To truly revoke, **rotate every secret that person saw**
at its source. The command prints this reminder; heed it.
