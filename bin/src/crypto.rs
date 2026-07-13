//! envseal crypto core — age (X25519 + ChaCha20-Poly1305) encrypt/decrypt and dotenv parsing.
//!
//! This module owns all cryptography, delegated to the `age` crate (the reference Rust
//! implementation). envseal does NOT reimplement the age format or shell out to any external
//! CLI. Everything here operates on in-memory buffers; callers are responsible for zeroizing
//! plaintext once it is no longer needed.
//!
//! The plaintext payload is dotenv (`KEY=value` lines), matching how secrets are consumed as
//! environment variables. Keys stay parseable so we can list variable *names* without ever
//! surfacing values.

use std::io::{Read, Write};
use std::iter;
use std::str::FromStr;

/// Errors surfaced by the crypto layer. Messages NEVER include secret values or key material.
#[derive(Debug)]
pub enum CryptoError {
    /// The recipient set was empty — age refuses to encrypt to nobody.
    NoRecipients,
    /// A recipient string ("age1...") could not be parsed.
    BadRecipient(String),
    /// An identity string ("AGE-SECRET-KEY-...") could not be parsed.
    BadIdentity,
    /// Encryption failed inside the age layer.
    Encrypt(String),
    /// Decryption failed — wrong key, corrupt file, or MAC mismatch.
    Decrypt(String),
    /// The decrypted bytes were not valid UTF-8 (a dotenv payload must be text).
    NotUtf8,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::NoRecipients => write!(f, "no recipients to encrypt to"),
            CryptoError::BadRecipient(s) => write!(f, "invalid age recipient: {s}"),
            CryptoError::BadIdentity => write!(f, "invalid age identity (secret key)"),
            CryptoError::Encrypt(e) => write!(f, "encryption failed: {e}"),
            CryptoError::Decrypt(e) => write!(f, "decryption failed: {e}"),
            CryptoError::NotUtf8 => write!(f, "decrypted payload was not valid UTF-8"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Generate a fresh X25519 age keypair.
///
/// Returns `(public, secret)` as their canonical strings:
///   * public: `age1...`            (share this — it goes in the recipients list)
///   * secret: `AGE-SECRET-KEY-...` (keep this private — never commit or print)
pub fn generate_keypair() -> (String, String) {
    let id = age::x25519::Identity::generate();
    let public = id.to_public().to_string();
    let secret = age::secrecy::ExposeSecret::expose_secret(&id.to_string()).to_string();
    (public, secret)
}

/// Derive the `age1...` public recipient string from an `AGE-SECRET-KEY-...` secret string.
pub fn public_from_secret(secret: &str) -> Result<String, CryptoError> {
    let id =
        age::x25519::Identity::from_str(secret.trim()).map_err(|_| CryptoError::BadIdentity)?;
    Ok(id.to_public().to_string())
}

/// Parse and validate an `age1...` recipient string.
pub fn parse_recipient(s: &str) -> Result<age::x25519::Recipient, CryptoError> {
    age::x25519::Recipient::from_str(s.trim()).map_err(|_| CryptoError::BadRecipient(s.to_string()))
}

/// Encrypt `plaintext` to every recipient in `recipients`. Any recipient's identity can later
/// decrypt the result. Returns the age ciphertext (binary format).
pub fn encrypt(
    plaintext: &[u8],
    recipients: &[age::x25519::Recipient],
) -> Result<Vec<u8>, CryptoError> {
    if recipients.is_empty() {
        return Err(CryptoError::NoRecipients);
    }
    // age wants an iterator of &dyn Recipient; box + collect so the borrows outlive the call.
    let boxed: Vec<Box<dyn age::Recipient + Send>> = recipients
        .iter()
        .map(|r| Box::new(r.clone()) as Box<dyn age::Recipient + Send>)
        .collect();
    let encryptor =
        age::Encryptor::with_recipients(boxed.iter().map(|b| b.as_ref() as &dyn age::Recipient))
            .map_err(|e| CryptoError::Encrypt(e.to_string()))?;

    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| CryptoError::Encrypt(e.to_string()))?;
    Ok(out)
}

/// Decrypt age `ciphertext` with a single X25519 `identity`. Returns the plaintext bytes.
pub fn decrypt(
    ciphertext: &[u8],
    identity: &age::x25519::Identity,
) -> Result<Vec<u8>, CryptoError> {
    let decryptor =
        age::Decryptor::new(ciphertext).map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(iter::once(identity as &dyn age::Identity))
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    let mut out = Vec::new();
    reader
        .read_to_end(&mut out)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;
    Ok(out)
}

/// Parse an `AGE-SECRET-KEY-...` string into an identity for decryption.
pub fn parse_identity(secret: &str) -> Result<age::x25519::Identity, CryptoError> {
    age::x25519::Identity::from_str(secret.trim()).map_err(|_| CryptoError::BadIdentity)
}

/// Decrypt and interpret the store as UTF-8 dotenv text in one step.
pub fn decrypt_to_text(
    ciphertext: &[u8],
    identity: &age::x25519::Identity,
) -> Result<String, CryptoError> {
    let bytes = decrypt(ciphertext, identity)?;
    String::from_utf8(bytes).map_err(|_| CryptoError::NotUtf8)
}

/// Parse dotenv `KEY=value` text into ordered pairs.
///
/// Rules (kept deliberately simple and predictable):
///   * blank lines and lines whose first non-space char is `#` are skipped;
///   * the first `=` splits key from value (values may contain further `=`, e.g. base64/JWT);
///   * a single matching pair of surrounding quotes is stripped from the value;
///   * trailing `\r` (CRLF files) is trimmed;
///   * lines with an empty key or no `=` are dropped.
pub fn parse_dotenv(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in s.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim();
        if key.is_empty() {
            continue;
        }
        let mut val = line[eq + 1..].to_string();
        if val.len() >= 2 {
            let b = val.as_bytes();
            if (b[0] == b'"' && b[val.len() - 1] == b'"')
                || (b[0] == b'\'' && b[val.len() - 1] == b'\'')
            {
                val = val[1..val.len() - 1].to_string();
            }
        }
        out.push((key.to_string(), val));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- age round-trip ---

    #[test]
    fn keypair_roundtrip_single_recipient() {
        let (public, secret) = generate_keypair();
        assert!(public.starts_with("age1"));
        assert!(secret.starts_with("AGE-SECRET-KEY-"));

        let recip = parse_recipient(&public).unwrap();
        let id = parse_identity(&secret).unwrap();

        let pt = b"AI_API_KEY=sk-abc\nDB_PASSWORD=hunter2\n";
        let ct = encrypt(pt, &[recip]).unwrap();
        assert_ne!(ct, pt, "ciphertext must differ from plaintext");
        let out = decrypt(&ct, &id).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn public_derivable_from_secret() {
        let (public, secret) = generate_keypair();
        assert_eq!(public_from_secret(&secret).unwrap(), public);
    }

    #[test]
    fn multi_recipient_each_can_decrypt() {
        let (pub_a, sec_a) = generate_keypair();
        let (pub_b, sec_b) = generate_keypair();
        let recips = [
            parse_recipient(&pub_a).unwrap(),
            parse_recipient(&pub_b).unwrap(),
        ];

        let pt = b"TOKEN=xyz\n";
        let ct = encrypt(pt, &recips).unwrap();

        // Both identities independently decrypt the same ciphertext.
        assert_eq!(decrypt(&ct, &parse_identity(&sec_a).unwrap()).unwrap(), pt);
        assert_eq!(decrypt(&ct, &parse_identity(&sec_b).unwrap()).unwrap(), pt);
    }

    #[test]
    fn wrong_identity_cannot_decrypt() {
        let (pub_a, _sec_a) = generate_keypair();
        let (_pub_b, sec_b) = generate_keypair(); // B is NOT a recipient

        let ct = encrypt(b"SECRET=1\n", &[parse_recipient(&pub_a).unwrap()]).unwrap();
        let err = decrypt(&ct, &parse_identity(&sec_b).unwrap());
        assert!(matches!(err, Err(CryptoError::Decrypt(_))));
    }

    #[test]
    fn empty_recipients_is_rejected() {
        assert!(matches!(
            encrypt(b"X=1\n", &[]),
            Err(CryptoError::NoRecipients)
        ));
    }

    #[test]
    fn corrupt_ciphertext_fails_cleanly() {
        let (public, secret) = generate_keypair();
        let mut ct = encrypt(b"X=1\n", &[parse_recipient(&public).unwrap()]).unwrap();
        // Flip bytes in the body to trigger a MAC/format failure, not a panic.
        let n = ct.len();
        for b in ct[n / 2..].iter_mut() {
            *b ^= 0xff;
        }
        assert!(decrypt(&ct, &parse_identity(&secret).unwrap()).is_err());
    }

    #[test]
    fn bad_recipient_and_identity_strings() {
        assert!(matches!(
            parse_recipient("not-an-age-key"),
            Err(CryptoError::BadRecipient(_))
        ));
        assert!(matches!(
            parse_identity("not-a-secret"),
            Err(CryptoError::BadIdentity)
        ));
    }

    // --- dotenv parsing (ported, unchanged semantics) ---

    #[test]
    fn dotenv_simple_pairs() {
        assert_eq!(
            parse_dotenv("A=1\nB=two\n"),
            vec![("A".into(), "1".into()), ("B".into(), "two".into())]
        );
    }

    #[test]
    fn dotenv_strips_one_quote_pair() {
        assert_eq!(parse_dotenv("A=\"hi\"\n"), vec![("A".into(), "hi".into())]);
        assert_eq!(parse_dotenv("A='hi'\n"), vec![("A".into(), "hi".into())]);
    }

    #[test]
    fn dotenv_preserves_equals_in_value() {
        assert_eq!(
            parse_dotenv("T=abc==\n"),
            vec![("T".into(), "abc==".into())]
        );
        assert_eq!(
            parse_dotenv("URL=postgres://u:p@h/db?x=1\n"),
            vec![("URL".into(), "postgres://u:p@h/db?x=1".into())]
        );
    }

    #[test]
    fn dotenv_skips_comments_and_blanks_and_crlf() {
        assert_eq!(
            parse_dotenv("# c\r\n\r\nA=1\r\n  # c2\r\nB=2\r\n"),
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
    }

    #[test]
    fn dotenv_drops_empty_key_or_no_equals_keeps_empty_value() {
        assert_eq!(
            parse_dotenv("=nokey\nnoequals\nA=\n"),
            vec![("A".into(), String::new())]
        );
    }
}
