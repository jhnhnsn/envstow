//! Command-line argument parsing: profile resolution and the shared `[flags] <NAME>` parser
//! used by get/set/delete. Kept dependency-free (no `clap`) to hold envstow to three crates.

use std::env;

use crate::error::AppError;
use crate::layout;

/// Resolve which profile to use and return `(profile, remaining_args)` with any `--profile
/// <name>` (or `--profile=<name>`) removed from the args. Precedence: `--profile` flag >
/// `ENVSTOW_PROFILE` env var > `default`. Returns an error string on a bad/missing name.
pub fn resolve_profile(args: &[String]) -> Result<(String, Vec<String>), AppError> {
    let mut profile: Option<String> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--profile" {
            let Some(name) = args.get(i + 1) else {
                return Err(AppError::usage("--profile requires a name"));
            };
            profile = Some(name.clone());
            i += 2;
        } else if let Some(name) = a.strip_prefix("--profile=") {
            profile = Some(name.to_string());
            i += 1;
        } else {
            rest.push(a.clone());
            i += 1;
        }
    }
    let profile = profile
        .or_else(|| env::var("ENVSTOW_PROFILE").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| layout::DEFAULT_PROFILE.to_string());
    if !layout::valid_profile_name(&profile) {
        return Err(AppError::usage(format!(
            "invalid profile name '{profile}' (use letters, digits, - or _)"
        )));
    }
    Ok((profile, rest))
}

/// Resolve which STORE to use and return `(selector, remaining_args)` with any `--store <name>`
/// / `--store-dir <path>` (and their `=` forms) removed.
///
/// Precedence: `--store-dir` > `--store` > `$ENVSTOW_STORE_DIR` > `$ENVSTOW_STORE` > discover
/// (walk up from the CWD). Path beats name at each level because a path is the more specific
/// statement — it names one directory, where a name is resolved through config.
///
/// `--store` and `--store-dir` together is a usage error rather than a precedence rule: passing
/// both is a mistake about which store you're touching, and in a secrets tool that deserves a
/// stop rather than a silent winner.
pub fn resolve_store(args: &[String]) -> Result<(layout::StoreSelector, Vec<String>), AppError> {
    let mut name: Option<String> = None;
    let mut dir: Option<String> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--store" {
            let Some(v) = args.get(i + 1) else {
                return Err(AppError::usage("--store requires a name"));
            };
            name = Some(v.clone());
            i += 2;
        } else if let Some(v) = a.strip_prefix("--store=") {
            name = Some(v.to_string());
            i += 1;
        } else if a == "--store-dir" {
            let Some(v) = args.get(i + 1) else {
                return Err(AppError::usage("--store-dir requires a path"));
            };
            dir = Some(v.clone());
            i += 2;
        } else if let Some(v) = a.strip_prefix("--store-dir=") {
            dir = Some(v.to_string());
            i += 1;
        } else {
            rest.push(a.clone());
            i += 1;
        }
    }
    // Reject the conflict across BOTH spellings, not just the flags. The global pre-subcommand
    // lift in main() turns `--store`/`--store-dir` into these env vars, so checking only the
    // parsed flags would let `envstow --store a --store-dir b ...` through — silently picking
    // one. Comparing the effective values catches it wherever it was written.
    let eff_name = name
        .clone()
        .or_else(|| env::var("ENVSTOW_STORE").ok().filter(|s| !s.is_empty()));
    let eff_dir = dir
        .clone()
        .or_else(|| env::var("ENVSTOW_STORE_DIR").ok().filter(|s| !s.is_empty()));
    if eff_name.is_some() && eff_dir.is_some() {
        return Err(AppError::usage(
            "pass either --store <name> or --store-dir <path>, not both",
        ));
    }
    let sel = if let Some(d) = dir {
        layout::StoreSelector::Dir(d.into())
    } else if let Some(n) = name {
        layout::StoreSelector::Named(n)
    } else if let Some(d) = env::var_os("ENVSTOW_STORE_DIR").filter(|s| !s.is_empty()) {
        layout::StoreSelector::Dir(d.into())
    } else if let Some(n) = env::var("ENVSTOW_STORE").ok().filter(|s| !s.is_empty()) {
        layout::StoreSelector::Named(n)
    } else {
        layout::StoreSelector::Discover
    };
    if let layout::StoreSelector::Named(n) = &sel {
        if !layout::valid_store_name(n) {
            return Err(AppError::usage(format!(
                "invalid store name '{n}' (use letters, digits, - or _)"
            )));
        }
    }
    Ok((sel, rest))
}

/// Resolve both axes at once: which store, and which profile within it. Most commands want
/// this — the two are orthogonal (a store selects WHOSE secrets, a profile WHICH set of them).
pub fn resolve_target(
    args: &[String],
) -> Result<(layout::StoreSelector, String, Vec<String>), AppError> {
    let (sel, rest) = resolve_store(args)?;
    let (profile, rest) = resolve_profile(&rest)?;
    Ok((sel, profile, rest))
}

/// A parsed `[flags] [<NAME>]` command line, shared by `get`/`set`/`delete` — the three commands
/// with the same shape.
pub struct ParsedArgs<'a> {
    /// Canonical names of the boolean flags that were present.
    pub flags: Vec<&'static str>,
    /// The single positional argument (a secret NAME), if given.
    pub positional: Option<&'a str>,
}

impl ParsedArgs<'_> {
    pub fn has(&self, flag: &'static str) -> bool {
        self.flags.contains(&flag)
    }
}

/// Parse `[flags] [<NAME>]`. `known` maps each accepted flag spelling to a canonical name (so
/// aliases like `-c`/`--clipboard` collapse to one). An unknown `-flag`, or more than one
/// positional, is a usage error naming the offender.
pub fn parse_simple<'a>(
    args: &'a [String],
    known: &[(&str, &'static str)],
) -> Result<ParsedArgs<'a>, AppError> {
    let mut flags = Vec::new();
    let mut positional = None;
    for a in args {
        let s = a.as_str();
        if let Some((_, canon)) = known.iter().find(|(spelling, _)| *spelling == s) {
            if !flags.contains(canon) {
                flags.push(*canon);
            }
        } else if s.starts_with('-') {
            return Err(AppError::usage(format!("unknown flag '{s}'")));
        } else if positional.is_some() {
            return Err(AppError::usage("expected a single NAME"));
        } else {
            positional = Some(s);
        }
    }
    Ok(ParsedArgs { flags, positional })
}
