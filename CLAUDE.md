# envseal — project instructions

This repo stores an **age-encrypted key-value store** (`secrets/secrets.enc`) checked into git.
Each collaborator decrypts it with **their own age private key**. Secrets are surfaced **by
name** so their plaintext never has to be pasted onto a command line. Think of it as a local,
file-based GitHub Secrets. All crypto is the `age` crate compiled into the `envseal` binary —
there are no external tools (`sops`/`age` CLIs) to install or invoke.

## Secret handling — MANDATORY

- Refer to secrets by their variable **name** only (e.g. `$FLY_API_TOKEN`). Never paste,
  echo, print, `cat`, or log a secret **value**.
- To use a secret in a command, reference it by name inside an unlocked context:
  - `envseal unlock -- <cmd>` runs `<cmd>` with every secret set as an env var, so
    `envseal unlock -- sh -c 'deploy --token "$FLY_API_TOKEN"'` works and the value is only
    ever in the child's environment — never in your tool call or its output.
  - `$(envseal get NAME)` resolves one secret by name. **Under an agent, `envseal get`
    masks its output by default** (prints `••••••••`) precisely so a value can't land in your
    context. That masking is working as intended — do not try to defeat it. If a human needs
    the value, they run `envseal get NAME --show` themselves.
- **Never run:** `env`, `printenv`, `echo $SOME_SECRET`, `set`, `export -p`, or any command
  whose purpose is to reveal a secret value. These are denied in `.claude/settings.json`.
- A `PostToolUse` hook (`scripts/redact-guard.sh`) blocks any command output that contains a
  live secret value, as accident insurance. A "BLOCKED by envseal" message is working as
  intended — do not retry in a way that surfaces the value.
- If you believe you genuinely need a secret's plaintext, **STOP and ask the human.**

## Using envseal

- `envseal get <NAME>` — resolve one secret by name (masked under an agent; `--show` to reveal).
- `envseal unlock [-- <cmd>]` — run a command (or a subshell) with all secrets set as env vars.
- `envseal set <NAME>` — store a value read from **stdin** (keeps it off the command line).
- `envseal edit` — open all secrets in `$EDITOR` (decrypt → edit → re-encrypt).
- `envseal list` — list secret **names** (never values).
- `envseal add-recipient <age1...>` / `remove-recipient <key|label>` — manage collaborators.

The human generates their key and creates the store with `envseal init`. You do not need to
run `init`. Just use secrets by name via `unlock`/`get` as above.

## Revoking access

`envseal remove-recipient` stops **future** decryptions, but the removed key still decrypts
every historical commit in any clone. To truly revoke, **rotate every secret that person saw**
at its source. The command prints this reminder; heed it.
