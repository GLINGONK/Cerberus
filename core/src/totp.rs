//! TOTP (RFC 6238) so entries can carry their own second factor.
//!
//! Base32 decoding is implemented here rather than pulled in as a dependency:
//! it is thirty lines, and it must reject malformed secrets loudly instead of
//! silently producing a code that never works.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Concrete per-hash HMAC. A generic version needs a wall of `digest` trait
/// bounds for no benefit at three call sites.
macro_rules! hmac_bytes {
    ($hash:ty, $key:expr, $msg:expr) => {{
        let mut mac =
            <Hmac<$hash> as Mac>::new_from_slice($key).expect("HMAC accepts any key length");
        mac.update($msg);
        mac.finalize().into_bytes().to_vec()
    }};
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(TotpAlgorithm::Sha1),
            "SHA256" => Ok(TotpAlgorithm::Sha256),
            "SHA512" => Ok(TotpAlgorithm::Sha512),
            _ => Err(CoreError::InvalidFactor(format!(
                "unsupported TOTP algorithm: {s}"
            ))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

/// A configured TOTP generator.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Totp {
    /// Raw shared secret, already base32-decoded.
    secret: Vec<u8>,
    pub digits: u32,
    pub period: u64,
    pub algorithm: TotpAlgorithm,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Totp {
    /// Build from a base32 secret with the RFC defaults: SHA-1, 6 digits, 30 s.
    ///
    /// Those defaults are weak-looking but correct — they are what every
    /// authenticator app and every server actually implement.
    pub fn from_base32(secret: &str) -> Result<Self> {
        Ok(Totp {
            secret: base32_decode(secret)?,
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
            issuer: None,
            account: None,
        })
    }

    /// Parse an `otpauth://totp/...` URI, the format QR codes encode.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("otpauth://totp/")
            .ok_or_else(|| CoreError::InvalidFactor("not an otpauth://totp URI".into()))?;

        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label);
        let (issuer_from_label, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_string()), Some(a.trim().to_string())),
            None if label.is_empty() => (None, None),
            None => (None, Some(label.clone())),
        };

        let mut secret = None;
        let mut digits = 6;
        let mut period = 30;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut issuer = issuer_from_label;

        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair
                .split_once('=')
                .ok_or_else(|| CoreError::InvalidFactor("malformed TOTP parameter".into()))?;
            let v = percent_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(base32_decode(&v)?),
                "digits" => {
                    digits = v.parse().map_err(|_| {
                        CoreError::InvalidFactor("the digits parameter is not a number".into())
                    })?
                }
                "period" => {
                    period = v.parse().map_err(|_| {
                        CoreError::InvalidFactor("the period parameter is not a number".into())
                    })?
                }
                "algorithm" => algorithm = TotpAlgorithm::parse(&v)?,
                "issuer" => issuer = Some(v),
                _ => {}
            }
        }

        let totp = Totp {
            secret: secret
                .ok_or_else(|| CoreError::InvalidFactor("the URI carries no secret".into()))?,
            digits,
            period,
            algorithm,
            issuer,
            account,
        };
        totp.validate()?;
        Ok(totp)
    }

    fn validate(&self) -> Result<()> {
        if self.secret.is_empty() {
            return Err(CoreError::InvalidFactor("empty TOTP secret".into()));
        }
        if !(6..=10).contains(&self.digits) {
            return Err(CoreError::InvalidFactor(
                "TOTP codes must be 6 to 10 digits".into(),
            ));
        }
        if self.period == 0 || self.period > 600 {
            return Err(CoreError::InvalidFactor(
                "the TOTP period must be between 1 and 600 seconds".into(),
            ));
        }
        Ok(())
    }

    /// Code for an explicit Unix timestamp. The testable entry point.
    pub fn code_at(&self, unix_time: u64) -> Result<Zeroizing<String>> {
        self.validate()?;
        let counter = unix_time / self.period;
        let msg = counter.to_be_bytes();

        let digest: Vec<u8> = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac_bytes!(Sha1, &self.secret, &msg),
            TotpAlgorithm::Sha256 => hmac_bytes!(Sha256, &self.secret, &msg),
            TotpAlgorithm::Sha512 => hmac_bytes!(Sha512, &self.secret, &msg),
        };

        // Dynamic truncation, RFC 4226 §5.4.
        let offset = (digest[digest.len() - 1] & 0x0F) as usize;
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7F,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);

        let modulus = 10u32.pow(self.digits);
        Ok(Zeroizing::new(format!(
            "{:0width$}",
            binary % modulus,
            width = self.digits as usize
        )))
    }

    /// Code for right now.
    pub fn code(&self) -> Result<Zeroizing<String>> {
        self.code_at(now_unix())
    }

    /// Seconds until the current code expires, for the UI countdown ring.
    pub fn seconds_remaining(&self) -> u64 {
        let now = now_unix();
        self.period - (now % self.period)
    }

    /// Re-emit the `otpauth://` URI, so the entry can be shown as a QR code.
    pub fn to_uri(&self) -> String {
        let label = match (&self.issuer, &self.account) {
            (Some(i), Some(a)) => format!("{i}:{a}"),
            (None, Some(a)) => a.clone(),
            (Some(i), None) => i.clone(),
            (None, None) => "Cerberus".to_string(),
        };
        let mut uri = format!(
            "otpauth://totp/{}?secret={}&digits={}&period={}&algorithm={}",
            percent_encode(&label),
            base32_encode(&self.secret),
            self.digits,
            self.period,
            self.algorithm.name()
        );
        if let Some(i) = &self.issuer {
            uri.push_str(&format!("&issuer={}", percent_encode(i)));
        }
        uri
    }
}

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decode RFC 4648 base32, tolerating lowercase, spaces and missing padding —
/// all three appear in secrets users copy from real websites.
pub fn base32_decode(input: &str) -> Result<Vec<u8>> {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(input.len() * 5 / 8);

    for c in input.chars() {
        if c == '=' || c == ' ' || c == '-' {
            continue;
        }
        let upper = c.to_ascii_uppercase() as u8;
        let value = BASE32_ALPHABET
            .iter()
            .position(|&a| a == upper)
            .ok_or_else(|| CoreError::InvalidFactor(format!("invalid base32 character: {c:?}")))?
            as u32;

        bits = (bits << 5) | value;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }

    if out.is_empty() {
        return Err(CoreError::InvalidFactor("empty base32 secret".into()));
    }
    Ok(out)
}

pub fn base32_encode(data: &[u8]) -> String {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = String::new();
    for &b in data {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(BASE32_ALPHABET[((bits >> nbits) & 0x1F) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(BASE32_ALPHABET[((bits << (5 - nbits)) & 0x1F) as usize] as char);
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference secret: the ASCII string "12345678901234567890".
    const RFC_SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn rfc_totp(algorithm: TotpAlgorithm, secret: &str) -> Totp {
        Totp {
            secret: base32_decode(secret).unwrap(),
            digits: 8,
            period: 30,
            algorithm,
            issuer: None,
            account: None,
        }
    }

    #[test]
    fn matches_the_rfc_6238_sha1_vectors() {
        let t = rfc_totp(TotpAlgorithm::Sha1, RFC_SECRET_B32);
        for (time, expected) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(&*t.code_at(time).unwrap(), expected, "at t={time}");
        }
    }

    #[test]
    fn matches_the_rfc_6238_sha256_vectors() {
        // The SHA-256 vectors use a 32-byte secret: "12345678901234567890123456789012".
        let secret = base32_encode(b"12345678901234567890123456789012");
        let t = rfc_totp(TotpAlgorithm::Sha256, &secret);
        for (time, expected) in [
            (59u64, "46119246"),
            (1111111109, "68084774"),
            (1234567890, "91819424"),
            (2000000000, "90698825"),
        ] {
            assert_eq!(&*t.code_at(time).unwrap(), expected, "at t={time}");
        }
    }

    #[test]
    fn matches_the_rfc_6238_sha512_vectors() {
        // 64-byte secret: "1234567890" repeated to length 64.
        let secret =
            base32_encode(b"1234567890123456789012345678901234567890123456789012345678901234");
        let t = rfc_totp(TotpAlgorithm::Sha512, &secret);
        for (time, expected) in [
            (59u64, "90693936"),
            (1111111109, "25091201"),
            (1234567890, "93441116"),
            (2000000000, "38618901"),
        ] {
            assert_eq!(&*t.code_at(time).unwrap(), expected, "at t={time}");
        }
    }

    #[test]
    fn the_code_is_stable_within_its_period_and_changes_across_it() {
        let t = Totp::from_base32(RFC_SECRET_B32).unwrap();
        assert_eq!(t.code_at(0).unwrap(), t.code_at(29).unwrap());
        assert_ne!(t.code_at(29).unwrap(), t.code_at(30).unwrap());
    }

    #[test]
    fn base32_survives_a_round_trip() {
        for len in 1..40 {
            let data = crate::random::vec(len).unwrap();
            assert_eq!(base32_decode(&base32_encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn base32_tolerates_the_formats_users_actually_paste() {
        let canonical = base32_decode(RFC_SECRET_B32).unwrap();
        assert_eq!(
            base32_decode(&RFC_SECRET_B32.to_lowercase()).unwrap(),
            canonical
        );
        assert_eq!(
            base32_decode("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ").unwrap(),
            canonical
        );
        assert_eq!(
            base32_decode("GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ").unwrap(),
            canonical
        );
    }

    #[test]
    fn malformed_base32_is_refused() {
        assert!(base32_decode("").is_err());
        assert!(
            base32_decode("ABC!DEF").is_err(),
            "punctuation must not be silently dropped"
        );
        assert!(
            base32_decode("ABC1DEF").is_err(),
            "1 is not in the base32 alphabet"
        );
    }

    #[test]
    fn an_otpauth_uri_round_trips() {
        let uri = "otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub&digits=6&period=30&algorithm=SHA1";
        let t = Totp::from_uri(uri).unwrap();
        assert_eq!(t.issuer.as_deref(), Some("GitHub"));
        assert_eq!(t.account.as_deref(), Some("octocat"));
        assert_eq!(t.digits, 6);

        let back = Totp::from_uri(&t.to_uri()).unwrap();
        assert_eq!(back.secret, t.secret);
        assert_eq!(back.digits, t.digits);
        assert_eq!(back.algorithm, t.algorithm);
        assert_eq!(
            back.code_at(1234567890).unwrap(),
            t.code_at(1234567890).unwrap()
        );
    }

    #[test]
    fn percent_encoded_labels_are_decoded() {
        let t =
            Totp::from_uri("otpauth://totp/ACME%20Co:john%40example.com?secret=GEZDGNBVGY3TQOJQ")
                .unwrap();
        assert_eq!(t.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(t.account.as_deref(), Some("john@example.com"));
    }

    #[test]
    fn malformed_uris_are_refused() {
        assert!(Totp::from_uri("https://example.com").is_err());
        assert!(
            Totp::from_uri("otpauth://totp/x?digits=6").is_err(),
            "no secret"
        );
        assert!(Totp::from_uri("otpauth://totp/x?secret=GEZDGNBV&digits=99").is_err());
        assert!(Totp::from_uri("otpauth://totp/x?secret=GEZDGNBV&period=0").is_err());
        assert!(Totp::from_uri("otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5").is_err());
    }

    #[test]
    fn the_countdown_stays_within_the_period() {
        let t = Totp::from_base32(RFC_SECRET_B32).unwrap();
        let remaining = t.seconds_remaining();
        assert!(remaining > 0 && remaining <= 30);
    }
}
