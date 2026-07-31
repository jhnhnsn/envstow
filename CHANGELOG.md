# Changelog

All notable changes to envstow are documented here. Versions follow [SemVer](https://semver.org).

## 0.2.2

### Removed
- **A committed `.envstow` file can no longer redirect a project to an external store.** 0.2.0
  introduced these pointer files so a repo using an external store needed no flag. They're gone,
  and existing ones are refused with migration advice rather than followed.

  The reason is what they made possible: *where a project's secrets come from* became something
  one person could change and everyone else inherited on the next `git pull` — **silently**, in
  the dangerous direction. Someone hits friction with the external store, creates a local
  `.envstow/`, commits it; everyone else pulls and the walk finds that perfectly plausible local
  store. Same command, same directory, **different secret**, no error. Anyone who is a recipient
  of both stores (which you are the moment you've ever run `init` there) simply gets the wrong
  value — and deploys it. Detecting the switch afterward needs per-project state and fires on
  legitimate migrations too; making the redirect unrepresentable removes the failure class.

  External stores still work, via `--store <name>` / `--store-dir <path>` and their env vars —
  a per-machine choice, never inherited from a checkout. The cost is a flag or an exported
  variable every time, and forgetting falls back to the walk; that mistake is one person's, in
  their own shell, and recoverable. The corollary is deliberate: **a team sharing an external
  store has to agree how**, because no file in the repo will arrange it for them. If that's
  tedious, commit the store and let git do the work.

  `envstow init --store <name>` now writes nothing into the working directory and tells you how
  to reach the store it made. Everything the pointer scheme needed — the fork guard, the
  file-or-directory rule, the intent-routing for pointer collisions — is gone with it.

### Changed
- **`init --store` / `--store-dir` now say how to reach the store they made.** With nothing
  written into the working directory, the walk will never find it — so the closing line names the
  flag (or env var) instead of leaving the next command to fail with "no store found".

## 0.2.1

### Fixed
- **`init --store <name>` no longer forks a store this repo already points at.** Joining a
  colleague's central-store project by running `envstow init --store acme` created a *second*,
  empty store with the same name rather than an error — two stores, no sync, and nothing to say
  they'd diverged. The local flow never had this problem because a git clone brings `recipients`
  along, so `init` can see other people's keys and report "you're joining"; a central store isn't
  cloned, so there was nothing on disk to notice. The pointer file is that evidence, and `init`
  now trusts it: if the repo points at the named store and you don't have it, it stops and prints
  your public key with the steps to actually join. Creating a differently-named store, or
  re-running `init` when you *do* have the store, are unaffected.

### Documentation
- **Stores is now a top-level README section**, covering what 0.2.0 shipped: the three kinds of
  store side by side, the pointer file, the `stores/`-beside-`identity.txt` layout and why,
  selection precedence, `envstow store`, the file-or-directory rule, a migration recipe, and the
  compatibility boundary. Every quoted command and error output is verified against the binary.
- **The 0.2.0 compatibility boundary is written down** — an `≤ 0.1.x` binary in a repo with a
  pointer file reports `no `.envstow/recipients` file found`, as though envstow weren't in use.
  The store-format guard can't catch it, since this changed what `.envstow` *is* rather than the
  store bytes. Local `.envstow/` directories are unaffected in both directions.

## 0.2.0

A minor bump rather than a patch: `.envstow` changes what it *is* — a name that was always a
directory can now also be a file. Existing repos are unaffected in the forward direction (a
`.envstow/` directory resolves exactly as before), but the reverse isn't safe: an 0.1.x binary in
a repo using a pointer file walks straight past it and reports "no recipients file found in this
directory or any parent." The version signals that.

### Added
- **Stores: the secret store no longer has to live in the repo.** Two new places it can live,
  for the cases where a committed `.envstow/` is wrong or impossible — a **public repo** whose
  owner doesn't want a permanent world-downloadable ciphertext record (or a public list of
  collaborators in `recipients`), and **collaborators with no git remote**, sharing a folder
  over Drive/Dropbox/Syncthing.
  - `envstow init --store <name>` creates the store at `~/.config/envstow/stores/<name>/` and
    writes a small `.envstow` **pointer file** into the repo. Nothing encrypted, and no key
    material, enters the working tree.
  - `envstow init --store-dir <path>` creates it at any path — a synced folder, say. No pointer
    is written, since a path wouldn't resolve on anyone else's machine.
  - Select one on any command with `--store <name>` / `--store-dir <path>`, or `$ENVSTOW_STORE`
    / `$ENVSTOW_STORE_DIR`.
- **`.envstow` is now a file *or* a directory** — a directory holds a local store (unchanged), a
  file contains `store: <name>` pointing at a central one. Same trick git uses for worktrees,
  where `.git` is a file holding `gitdir:`. One name to learn, and a repo can't ambiguously be
  both. The pointer holds a **name, not a path**, which is what makes it safe to commit: it
  resolves under each collaborator's own home directory and leaks nothing.
- **Each store has its own `recipients`.** Profiles share one recipient list (right: dev/staging/
  prod are one team); stores don't (right: unrelated projects aren't). This is the thing
  `--store` provides that a profile never could.
- **`envstow store`** — says which store is in effect **and why**, and lists central stores.
  With four ways to select one, "am I about to write this secret where I think?" needs an
  answer that isn't a guess. `unlock`/`run`/`env` now name the store in their banner too,
  whenever it isn't a plain local `.envstow/`.

### Changed
- **Errors that assumed git no longer do.** The "ask a recipient to re-encrypt" and corrupt-store
  messages checked nothing before telling you to `git pull` / `git add .envstow` — advice that
  can't work for a store deliberately kept out of the repo. They now detect whether the store is
  actually in a work tree. "No store found" additionally lists your central stores, since being
  outside a repo that points at one is the likeliest reason you're seeing it.
- **A missing store is always an error, never a fallback.** Naming a store that isn't there —
  by flag, env var, or a pointer whose store you don't have — fails and lists the stores that do
  exist. It never falls through to walking up the tree, which could otherwise hand you a
  different store than you asked for. For the public-repo case that store would be precisely the
  local one the user moved their secrets out of.

Existing repos are unaffected: a `.envstow/` directory resolves exactly as before, and plain
`envstow init` still creates one. See [DESIGN.md](DESIGN.md#where-the-store-lives) for the
reasoning behind the layout, and the README's [Stores](README.md#stores) section for usage.

## 0.1.25

### Changed
- **The last emoji is gone:** `upgrade`'s "new version available" notice dropped its ⬆️, missed
  by 0.1.23's sweep. A Unicode-range audit confirms the binary now emits only ⚠️ (the seven
  security warnings) and the `••••••••` mask.

## 0.1.24

### Changed
- **`unlock` and `run` fully separated — each verb now means exactly one thing.** `envstow
  unlock` opens an interactive subshell (`exit` locks) and **no longer takes a command**;
  `unlock -- <cmd>` prints a redirect to `envstow run [--only NAME,...] -- <cmd>` instead of
  silently duplicating it. The shell verbs are now a clean triad: `unlock` = subshell, `run` =
  one command (scope with `--only`), `env` = this shell (guarded eval). Every doc, example, and
  in-binary hint that suggested `unlock -- <cmd>` now says `run` — including `get`'s masking
  hint and `env`'s agent refusal, which now point at `run --only <NAMES>`.
- **Help text refreshed:** `--version` rejoined the USAGE block, examples lead with
  `run --only`, and the `get` example's comment now correctly says values are masked under an
  agent (always — not just when run "bare").

## 0.1.23

### Changed
- **Quieter output: emoji removed except warnings.** The 🔓/🔒/🔄/ℹ️/✔ decorations are gone from
  every message; ⚠️ stays, and now stands out as the only marker — reserved for the lines worth
  stopping for (shadowed values, rotation reminders, a world-readable key). The stale-shell
  reminder also lost its leading blank line.

## 0.1.22

### Added
- **`envstow run [--only NAME[,NAME...]]... [--] <cmd>...`** — the one-shot verb, with least
  privilege built in. Bare `run -- <cmd>` matches `unlock -- <cmd>` (which still works); `--only`
  scopes the child's env to exactly the named secrets — so an `npm install`'s postinstall scripts
  get the one token they need, not the whole store. `--only` accepts a comma list, repeated
  flags, or both. An unknown name is a **hard error before anything spawns**, with a
  did-you-mean suggestion (`unknown secret 'SENTRY_DNS' (did you mean SENTRY_DSN?)`) — never a
  child launched with a silently missing variable. `ENVSTOW_LOADED` reflects the scoped set, so
  `status` and `scan-leak` see exactly what's live. The agent skill now teaches `run --only` as
  the preferred pattern.

## 0.1.21

### Added
- **`envstow env [--off]`** — load (or reset) every secret **in your current shell**, no subshell:
  ```bash
  eval "$(envstow env)"        # export the store into this shell; unset what left it
  eval "$(envstow env --off)"  # unset everything envstow set here (names only — needs no key)
  ```
  This is the one command that prints plaintext values, so it is guarded twice: it **refuses under
  an AI agent** (agents keep using `unlock -- <cmd>`) and **refuses when stdout is a terminal** —
  output only ever flows into an eval pipe, never onto a screen or into a transcript. Values are
  single-quoted so hostile content is inert when eval'd; names must be plain shell identifiers.
  Unlike `refresh` (which could only `unset` deleted names), one eval also picks up **changed**
  values — so it's the uniform answer to a stale unlocked shell.
- **Stale-shell reminders now print the fix.** A `set` or `delete` inside an unlocked shell prints
  the exact line to run — `eval "$(envstow env)"` — alongside the old exit-and-re-unlock advice.
- **`envstow shell-init` (optional)** — print a small wrapper function to source from your rc:
  `eval "$(envstow shell-init)"`. With it sourced, `envstow set NAME` inside an unlocked shell
  makes the new value live in that shell immediately (via an internal `set --export`), skipping
  even the reminder. Like direnv's hook, it's a convenience — nothing else in envstow needs it.

### Removed
- **`envstow edit`.** It was the one command that parked the whole store's plaintext on disk for
  an editor session: a crash or `kill -9` skips the shred; editors copy plaintext into swap, undo,
  and backup files no shred can reach; zero-overwrite is ineffective on copy-on-write filesystems;
  and it had no agent guard (`EDITOR=cat envstow edit` printed every value). With it gone,
  "plaintext is never written to disk" holds **unconditionally**. `set` (pipe for multi-line
  values) and `delete` cover all changes; typing `edit` now prints a tombstone pointing at them.
  A bulk `import` from stdin may come later if there's real demand.

## 0.1.20

### Added
- **`envstow status`** — a one-glance check of your unlock state. It reports whether you're inside
  an `envstow unlock` shell, which **profile** it holds, and the secret **names** loaded in it:
  ```
  🔓 unlocked — profile: prod
     secrets loaded (2): DB_URL, API_KEY
  ```
  (or `🔒 locked` outside one). It reads only the env markers `unlock` set — no store is decrypted,
  no identity touched, and only names are printed, never values — so it's safe anywhere, including
  under an agent. It reports what envstow put in *this* shell; it can't see shell nesting depth
  (that's a shell fact, not envstow's).

## 0.1.19

### Added
- **`envstow scan-leak` — the output guard, now built into the binary.** The mechanical
  leak-blocking hook used to be a hand-copied bash+python script (`scripts/redact-guard.sh`) that
  went stale the moment its detection was improved and couldn't be updated centrally. Its logic now
  lives in the binary as `envstow scan-leak`: wire it as a Claude Code (or Cursor/…) `PostToolUse`
  hook with **one line** — `"command": "envstow scan-leak"` — and `envstow upgrade` keeps the
  detection current. No script to copy, no `python3`, no config envstow writes for you.

  Behavior is identical to the hardened script: it reads the tool-result payload on stdin, exits
  `2` (block) if the output contains a live secret value or `0` (allow) otherwise, keys off
  `ENVSTOW_LOADED` so it catches non-conventionally-named secrets (`DATABASE_URL`, DSNs), matches
  multi-line values line by line and base64 copies, and applies the length+entropy distinctiveness
  gate. It never prints a value — only the offending variable name. Run by hand at a terminal it
  prints a one-line explainer instead of hanging on stdin. The JSON payload is parsed by a small
  built-in extractor (no `serde` dependency), failing open on anything unparseable.

### Deprecated
- **`scripts/redact-guard.sh`** — superseded by `envstow scan-leak`. It still works and behaves
  identically, but it doesn't auto-update and needs `python3`. Point your hook at `envstow
  scan-leak` and delete the script. See GUARDRAILS.md.

## 0.1.18

### Added
- **`set`, `delete`, and `edit` now nudge you when you run them inside an unlocked shell.** That
  shell holds a copy of the *old* values (a running process's environment can't be changed from
  outside), so after changing the store you'd otherwise be working with stale secrets silently.
  It prints a one-line reminder to `exit` and `envstow unlock` again:
  ```
  ℹ️  envstow: you're in an unlocked shell — it still holds the previous values.
     Run `exit` then `envstow unlock` to pick up this change.
  ```
  Fires only when `ENVSTOW_UNLOCKED` is set (no noise outside an unlock), on stderr only (never
  touches stdout or the exit code), and leaves the choice to restart with you rather than doing it
  for you.

## 0.1.17

### Changed
- **Simplified the stale-shell guidance to one consistent rule.** After any change to the store
  made *inside* an unlocked shell (`set`, `delete`, or `edit`), the fix is now uniformly
  **`exit` then `envstow unlock`** — for added, changed, and deleted secrets alike. Docs
  previously split it (`refresh` for deletions, `exit` + unlock for changes), which was more to
  remember for little gain. `envstow refresh` still exists and still unsets deleted names in place
  for anyone who wants it, but it's no longer the recommended path. Updated the README, the
  embedded agent skill (re-run `envstow init` to refresh it), and CLAUDE.md. No behavior change —
  the `refresh` command is unchanged.

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
