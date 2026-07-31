//! The store layer: decrypt/encrypt the age file and marshal it to/from the dotenv text and the
//! in-memory [`Secrets`]. This is the glue between the commands and the `crypto`/`layout` modules;
//! commands never touch `crypto` directly.

use std::path::Path;

use zeroize::Zeroize;

use crate::crypto;
use crate::error::AppError;
use crate::layout::{self, Recipient};
use crate::secrets::Secrets;

/// Decrypt the selected store for `profile` with the user's identity into a [`Secrets`] (whose
/// values are zeroized on drop).
pub fn load_secrets_in(sel: &layout::StoreSelector, profile: &str) -> Result<Secrets, AppError> {
    load_secrets_versioned(sel, profile).map(|(secrets, _)| secrets)
}

/// [`load_secrets_in`], also returning the store's on-disk state at the moment it was read.
///
/// Commands that write the store back must use this and hand the [`layout::StoreVersion`] to
/// [`write_secrets`], so a concurrent writer can't be silently overwritten. Read-only commands
/// (`get`, `list`, `run`) have nothing to protect and use the plain version.
pub fn load_secrets_versioned(
    sel: &layout::StoreSelector,
    profile: &str,
) -> Result<(Secrets, layout::StoreVersion), AppError> {
    let paths = layout::locate_in(sel, profile)?;
    let secret = layout::read_identity_secret()?;
    let identity = crypto::parse_identity(&secret)?;
    // A missing store for a NAMED profile means the profile doesn't exist — point the user at
    // `profile create` rather than the generic "no store" error (guards against typos too).
    if !paths.store.is_file() && profile != layout::DEFAULT_PROFILE {
        return Err(AppError::msg(format!(
            "no such profile '{profile}'. Create it with `envstow profile create {profile}`"
        )));
    }
    // One read serves both purposes: the bytes we decrypt ARE the version we'll check against.
    // Reading twice would open a window where the file changes in between, leaving the version
    // describing contents we never decrypted — a spurious conflict rather than a caught one.
    let version = layout::StoreVersion::read(&paths.store)?;
    let ciphertext = version.split_ciphertext(&paths.store)?;

    let mut text = crypto::decrypt_to_text(&ciphertext, &identity).map_err(|e| {
        AppError::msg(explain_decrypt_failure(
            e.to_string(),
            &secret,
            &paths.recipients,
        ))
    })?;
    let parsed = crypto::parse_dotenv(&text);
    text.zeroize();
    // Decode any base64-marked (multi-line) values back to their originals.
    let mut vars = Vec::with_capacity(parsed.len());
    for (k, v) in parsed {
        let decoded = crypto::decode_value(&v)?;
        vars.push((k, decoded));
    }
    Ok((Secrets::from_pairs(vars), version))
}

/// Turn age's `No matching keys found` into an error that says what to actually do.
///
/// That one message covers several very different situations, and the most common — "you've
/// installed envstow and cloned the repo, but nobody has added you yet" — is the one it explains
/// worst. It reads as though something is broken, especially right after `init` has cheerfully
/// reported adding your key to `recipients`. (It did; but `recipients` is an INPUT to encryption,
/// not an access list. Your key only grants decryption once an existing recipient re-encrypts.)
///
/// We can tell the cases apart without any crypto: compare our public key against the recipients
/// file. If we're absent, we were never added. If we're present but decryption still failed, the
/// store is stale — encrypted before our key was listed, and someone needs to `reencrypt`.
fn explain_decrypt_failure(original: String, secret: &str, recipients_path: &Path) -> String {
    // Only reinterpret the "your key doesn't open this" case; other failures (corrupt file, bad
    // format) should keep their own message.
    if !original.contains("No matching keys") {
        return original;
    }
    let Ok(public) = crypto::public_from_secret(secret) else {
        return original;
    };
    let listed = layout::read_recipients(recipients_path)
        .map(|rs| rs.iter().any(|r| r.key == public))
        .unwrap_or(false);

    // How the re-keyed store gets BACK to you depends on how this store is shared. A committed
    // store travels by git; a central or synced-folder store does not, and telling someone to
    // `git pull` a store that was deliberately kept out of the repo is worse than saying
    // nothing — it's advice that can't work, for a setup they chose on purpose.
    let committed = is_committed_store(recipients_path);
    if listed {
        let rekey = if committed {
            "git pull && envstow reencrypt && git add .envstow && git commit && git push"
        } else {
            "envstow reencrypt   (then re-share the updated store)"
        };
        format!(
            "your key is listed in `{}`, but the store wasn't encrypted to it yet.\n\
             \x20  The store is re-keyed only when someone runs a re-encrypt. Ask an existing \
             recipient to:\n\
             \x20    {rekey}\n\
             \x20  (Adding a key to `recipients` alone does not grant access — that file is an \
             input to\n\
             \x20   encryption, not an access list.)",
            recipients_path.display()
        )
    } else {
        let after = if committed {
            "…then `git pull` once they've pushed."
        } else {
            "…then get the updated store from them."
        };
        format!(
            "your key isn't a recipient of this store, so you can't decrypt it yet.\n\
             \x20  Your public key:\n\
             \x20    {public}\n\
             \x20  Send it to someone who already has access and ask them to run:\n\
             \x20    envstow add-recipient {public} <your-name>\n\
             \x20  {after}"
        )
    }
}

/// Whether this store looks like a committed, git-distributed one — i.e. it sits in a
/// `.envstow/` directory inside a git work tree. Used only to pick which "how do I get the
/// re-keyed store" advice to print; a wrong guess costs a slightly-off hint, never correctness.
fn is_committed_store(recipients_path: &Path) -> bool {
    let Some(root) = recipients_path.parent() else {
        return false;
    };
    if root.file_name().and_then(|n| n.to_str()) != Some(layout::ENVSTOW_DIR) {
        return false;
    }
    let mut dir = root.parent();
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return true;
        }
        dir = d.parent();
    }
    false
}

/// Serialize `secrets` to dotenv, encrypt to the current recipients, and write the store.
/// Zeroizes the plaintext payload buffer; the caller's `Secrets` scrubs its own values on drop.
///
/// `expected` is the store's state when this cycle read it (from [`load_secrets_versioned`]).
/// If the file changed since, the write is refused rather than silently discarding whoever else
/// wrote it. Pass `None` only when not modifying prior contents.
pub fn write_secrets(
    recipients_path: &Path,
    store: &Path,
    secrets: &Secrets,
    expected: Option<&layout::StoreVersion>,
) -> crate::Cmd {
    let recipients = layout::read_recipients(recipients_path).unwrap_or_default();
    if recipients.is_empty() {
        return Err(AppError::msg("no recipients — cannot encrypt."));
    }
    let recips = parse_all_recipients(&recipients)?;

    // Multi-line values are stored base64-encoded (see crypto::encode_value), so the dotenv
    // store stays one line per key. render_dotenv applies the encoding.
    let mut payload = render_dotenv(secrets.pairs());
    let result = crypto::encrypt(payload.as_bytes(), &recips);
    payload.zeroize();
    let ct = result?; // CryptoError -> "encryption failed: {e}"

    layout::write_store(store, &ct, expected)
        .map_err(|e| AppError::msg(format!("could not write store: {e}")))
}

/// Decrypt the store with our identity and re-encrypt it to `recipients`. Used after any change
/// to the recipient set. Plaintext is zeroized.
pub fn reencrypt_store(store: &Path, recipients: &[Recipient]) -> crate::Cmd {
    let secret = layout::read_identity_secret()?;
    let identity = crypto::parse_identity(&secret)?;
    // Its own read-modify-write cycle, so it needs the same concurrency guard as `set`/`delete`:
    // re-encrypting stale contents would drop whatever landed in between.
    let version = layout::StoreVersion::read(store)?;
    let ciphertext = version.split_ciphertext(store)?;
    let mut plaintext = crypto::decrypt(&ciphertext, &identity)?;

    let recips = match parse_all_recipients(recipients) {
        Ok(r) => r,
        Err(e) => {
            plaintext.zeroize();
            return Err(AppError::msg(e));
        }
    };
    let result = crypto::encrypt(&plaintext, &recips);
    plaintext.zeroize();
    let ct = result.map_err(|e| AppError::msg(format!("re-encryption failed: {e}")))?;

    layout::write_store(store, &ct, Some(&version))
        .map_err(|e| AppError::msg(format!("could not write store: {e}")))?;
    eprintln!("re-encrypted store to {} recipient(s).", recips.len());
    Ok(())
}

/// Encrypt a plaintext payload to a recipient set (helper for init's empty store).
pub fn encrypt_payload(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, String> {
    let recips = parse_all_recipients(recipients)?;
    crypto::encrypt(plaintext, &recips).map_err(|e| e.to_string())
}

/// True if `v` both starts and ends with the same quote char — the one case where writing it
/// verbatim would let `parse_dotenv` strip a quote pair that is actually part of the value.
fn starts_and_ends_with_matching_quote(v: &str) -> bool {
    let b = v.as_bytes();
    v.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
}

/// Render (name, value) pairs to dotenv text that `crypto::parse_dotenv` reads back exactly.
/// Values are written verbatim after `=`; a value that itself begins and ends with a matching
/// quote is wrapped in the *other* quote style so parse's quote-stripping cancels out.
/// Caller must ensure no value contains a newline.
pub fn render_dotenv(vars: &[(String, String)]) -> String {
    let mut payload = String::new();
    for (k, v) in vars {
        // Encode multi-line values (base64 behind a marker); single-line values pass through.
        let encoded = crypto::encode_value(v);
        payload.push_str(k);
        payload.push('=');
        if starts_and_ends_with_matching_quote(&encoded) {
            let q = if encoded.starts_with('"') { '\'' } else { '"' };
            payload.push(q);
            payload.push_str(&encoded);
            payload.push(q);
        } else {
            payload.push_str(&encoded);
        }
        payload.push('\n');
    }
    payload
}

/// Parse every recipient string into an age recipient, failing on the first bad one.
fn parse_all_recipients(recipients: &[Recipient]) -> Result<Vec<age::x25519::Recipient>, String> {
    recipients
        .iter()
        .map(|r| crypto::parse_recipient(&r.key).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn render_dotenv_roundtrips_through_parse() {
        let cases = vec![
            ("A".to_string(), "1".to_string()),
            ("SPACES".to_string(), "has spaces and # hash".to_string()),
            ("EQ".to_string(), "a=b=c".to_string()),
            ("B64".to_string(), "abc123==".to_string()),
            ("QUOTED".to_string(), "\"already quoted\"".to_string()),
            ("SQUOTED".to_string(), "'single quoted'".to_string()),
            ("URL".to_string(), "postgres://u:p@h/db?x=1".to_string()),
        ];
        let text = render_dotenv(&cases);
        let parsed = crypto::parse_dotenv(&text);
        assert_eq!(
            parsed, cases,
            "every value must survive render -> parse unchanged"
        );
    }
}
