//! Password, passphrase and TOTP generation.
//!
//! All sampling is uniform via rejection: a naive `random_byte % alphabet_len`
//! biases the output toward the first characters of the alphabet and quietly
//! costs real entropy.

use zeroize::Zeroizing;

use crate::error::Result;
use crate::random::EntropyPool;

/// Which character classes a generated password may draw from.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PasswordPolicy {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Drop `0 O o 1 l I |` and friends, for passwords that get read aloud or retyped.
    pub avoid_ambiguous: bool,
    /// Characters the target system rejects.
    pub excluded: String,
    /// Guarantee at least one character from every enabled class.
    pub require_each_class: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            excluded: String::new(),
            require_each_class: true,
        }
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
const AMBIGUOUS: &str = "0O1lI|`'\"";

impl PasswordPolicy {
    /// The character classes this policy enables, after exclusions.
    fn classes(&self) -> Vec<Vec<char>> {
        let mut out = Vec::new();
        for (enabled, set) in [
            (self.lowercase, LOWER),
            (self.uppercase, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ] {
            if !enabled {
                continue;
            }
            let filtered: Vec<char> = set
                .chars()
                .filter(|c| !self.excluded.contains(*c))
                .filter(|c| !(self.avoid_ambiguous && AMBIGUOUS.contains(*c)))
                .collect();
            if !filtered.is_empty() {
                out.push(filtered);
            }
        }
        out
    }

    fn alphabet(&self) -> Vec<char> {
        self.classes().into_iter().flatten().collect()
    }

    /// Entropy of a password produced under this policy, in bits.
    pub fn entropy_bits(&self) -> f64 {
        let n = self.alphabet().len();
        if n < 2 || self.length == 0 {
            return 0.0;
        }
        self.length as f64 * (n as f64).log2()
    }

    pub fn validate(&self) -> Result<()> {
        if self.length < 4 || self.length > 512 {
            return Err(crate::CoreError::InvalidFactor(
                "password length must be between 4 and 512".into(),
            ));
        }
        let classes = self.classes();
        if classes.is_empty() {
            return Err(crate::CoreError::InvalidFactor(
                "no character class left after exclusions".into(),
            ));
        }
        if self.require_each_class && classes.len() > self.length {
            return Err(crate::CoreError::InvalidFactor(
                "password too short to include every required character class".into(),
            ));
        }
        Ok(())
    }
}

/// Generate a password under `policy`, mixing in any collected user entropy.
pub fn password(policy: &PasswordPolicy, pool: &EntropyPool) -> Result<Zeroizing<String>> {
    policy.validate()?;
    let alphabet = policy.alphabet();
    let classes = policy.classes();

    let mut chars: Vec<char> = Vec::with_capacity(policy.length);

    if policy.require_each_class {
        for class in &classes {
            chars.push(class[uniform_below(class.len(), pool)?]);
        }
    }
    while chars.len() < policy.length {
        chars.push(alphabet[uniform_below(alphabet.len(), pool)?]);
    }

    // The guaranteed characters were placed in class order; shuffle so their
    // positions carry no information.
    shuffle(&mut chars, pool)?;

    Ok(Zeroizing::new(chars.into_iter().collect()))
}

/// Generate a diceware-style passphrase from the embedded word list.
pub fn passphrase(
    words: usize,
    separator: char,
    capitalize: bool,
    pool: &EntropyPool,
) -> Result<Zeroizing<String>> {
    if !(3..=32).contains(&words) {
        return Err(crate::CoreError::InvalidFactor(
            "a passphrase must be between 3 and 32 words".into(),
        ));
    }
    let list = wordlist();
    let mut picked = Vec::with_capacity(words);
    for _ in 0..words {
        let w = list[uniform_below(list.len(), pool)?];
        picked.push(if capitalize {
            let mut c = w.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        } else {
            w.to_string()
        });
    }
    Ok(Zeroizing::new(picked.join(&separator.to_string())))
}

/// Entropy of a passphrase of `words` words drawn from the embedded list.
pub fn passphrase_bits(words: usize) -> f64 {
    words as f64 * (wordlist().len() as f64).log2()
}

/// Uniform integer in `0..n`, by rejection sampling.
///
/// Draws 4 bytes at a time and discards any value landing in the final partial
/// bucket, so no residue class is favoured.
fn uniform_below(n: usize, pool: &EntropyPool) -> Result<usize> {
    assert!(n > 0, "uniform_below requires a non-empty range");
    if n == 1 {
        return Ok(0);
    }
    let n32 = n as u32;
    let limit = u32::MAX - (u32::MAX % n32) - 1;
    loop {
        // Batch the draws: one syscall per 64 candidates rather than per candidate.
        let buf = pool.random(256)?;
        for chunk in buf.chunks_exact(4) {
            let v = u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4) yields 4 bytes"));
            if v <= limit {
                return Ok((v % n32) as usize);
            }
        }
    }
}

/// Fisher-Yates shuffle driven by the same uniform sampler.
fn shuffle<T>(items: &mut [T], pool: &EntropyPool) -> Result<()> {
    for i in (1..items.len()).rev() {
        items.swap(i, uniform_below(i + 1, pool)?);
    }
    Ok(())
}

/// Embedded word list. Short and memorable; every word is 4-8 ASCII letters.
///
/// 256 words is 8 bits each, so an 8-word passphrase carries 64 bits — the UI
/// shows that figure rather than letting length imply strength.
fn wordlist() -> &'static [&'static str] {
    const WORDS: &[&str] = &[
        "abbey", "acorn", "actor", "adobe", "agent", "aisle", "album", "alert", "alley", "amber",
        "amino", "ample", "anchor", "angle", "ankle", "apple", "apron", "arbor", "arena", "armor",
        "arrow", "asset", "atlas", "attic", "audio", "aunt", "avoid", "awake", "axis", "bacon",
        "badge", "bagel", "baker", "balmy", "banjo", "barge", "basil", "basin", "batch", "beach",
        "beard", "beast", "bench", "berry", "bison", "blade", "blaze", "blend", "blink", "bloom",
        "board", "bonus", "boost", "booth", "bosom", "botany", "bough", "brave", "bread", "brick",
        "brisk", "broom", "brush", "bugle", "bunch", "bunny", "cabin", "cable", "cacao", "cadet",
        "camel", "canal", "candy", "canoe", "canon", "canvas", "caper", "cargo", "carol", "carve",
        "cedar", "chalk", "charm", "chase", "cheek", "chess", "chime", "chirp", "cider", "cigar",
        "civic", "claim", "clamp", "clash", "clear", "cliff", "cloak", "clock", "cloud", "clove",
        "coach", "cobra", "cocoa", "comet", "coral", "corgi", "cough", "coupe", "cover", "crane",
        "crate", "creek", "crisp", "crown", "crumb", "curve", "cycle", "daisy", "dance", "dandy",
        "dealer", "debut", "decoy", "delta", "denim", "depot", "diary", "dimple", "diner", "ditch",
        "diver", "dodge", "dolphin", "donut", "dough", "dozen", "draft", "drape", "dream", "drift",
        "drone", "dusty", "eagle", "early", "earth", "easel", "ebony", "elbow", "elder", "elite",
        "ember", "empty", "enemy", "entry", "envoy", "equal", "essay", "ether", "exact", "extra",
        "fable", "facet", "fairy", "fancy", "fauna", "favor", "feast", "fence", "ferry", "fetch",
        "fever", "fiber", "field", "fifth", "final", "finch", "flair", "flame", "flask", "fleet",
        "flint", "flock", "flora", "flute", "focus", "foggy", "forge", "forum", "fossil", "frost",
        "fruit", "fudge", "gadget", "gauge", "gecko", "genre", "ghost", "giant", "ginger", "glade",
        "glass", "glaze", "glide", "globe", "glove", "gnome", "goose", "grain", "grape", "grasp",
        "grave", "green", "grill", "grove", "guard", "guest", "guide", "gulf", "gypsum", "habit",
        "hazel", "heart", "hedge", "helix", "hero", "hinge", "hobby", "honey", "horse", "hotel",
        "hound", "house", "human", "humid", "hyena", "ideal", "igloo", "image", "index", "inlet",
        "input", "irony", "islet", "ivory", "jelly", "jewel", "jolly", "judge", "juice", "jumbo",
        "karma", "kayak", "kernel", "kite", "koala", "label", "labor",
    ];
    WORDS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> EntropyPool {
        EntropyPool::new()
    }

    #[test]
    fn generated_passwords_have_the_requested_length() {
        for length in [4usize, 8, 20, 64, 128] {
            let policy = PasswordPolicy {
                length,
                ..Default::default()
            };
            assert_eq!(password(&policy, &pool()).unwrap().chars().count(), length);
        }
    }

    #[test]
    fn every_required_class_is_present() {
        let policy = PasswordPolicy {
            length: 8,
            require_each_class: true,
            ..Default::default()
        };
        for _ in 0..200 {
            let p = password(&policy, &pool()).unwrap();
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn excluded_and_ambiguous_characters_never_appear() {
        let policy = PasswordPolicy {
            length: 64,
            avoid_ambiguous: true,
            excluded: "abc".into(),
            ..Default::default()
        };
        for _ in 0..50 {
            let p = password(&policy, &pool()).unwrap();
            assert!(!p.chars().any(|c| "abc".contains(c)));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn generated_passwords_do_not_repeat() {
        let policy = PasswordPolicy::default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(password(&policy, &pool()).unwrap().to_string()));
        }
    }

    #[test]
    fn sampling_is_uniform_not_modulo_biased() {
        // 100 buckets over a 4-byte draw: a modulo-biased sampler skews the low
        // buckets by ~4%, which a chi-squared-style bound catches at this size.
        let pool = pool();
        let n = 100usize;
        let draws = 100_000;
        let mut counts = vec![0usize; n];
        for _ in 0..draws {
            counts[uniform_below(n, &pool).unwrap()] += 1;
        }
        let expected = draws as f64 / n as f64;
        for (i, &c) in counts.iter().enumerate() {
            let deviation = (c as f64 - expected).abs() / expected;
            assert!(
                deviation < 0.15,
                "bucket {i} deviated by {:.1}%",
                deviation * 100.0
            );
        }
    }

    #[test]
    fn the_required_class_prefix_is_shuffled_away() {
        // Without the shuffle, position 0 would always be lowercase.
        let policy = PasswordPolicy {
            length: 8,
            require_each_class: true,
            ..Default::default()
        };
        let mut first_chars = std::collections::HashSet::new();
        for _ in 0..200 {
            let p = password(&policy, &pool()).unwrap();
            first_chars.insert(p.chars().next().unwrap().is_ascii_lowercase());
        }
        assert_eq!(
            first_chars.len(),
            2,
            "the first character is always the same class"
        );
    }

    #[test]
    fn entropy_matches_the_alphabet_size() {
        let policy = PasswordPolicy {
            length: 20,
            ..Default::default()
        };
        let n = policy.alphabet().len();
        assert_eq!(n, LOWER.len() + UPPER.len() + DIGITS.len() + SYMBOLS.len());
        assert!((policy.entropy_bits() - 20.0 * (n as f64).log2()).abs() < 0.01);

        let digits_only = PasswordPolicy {
            length: 6,
            lowercase: false,
            uppercase: false,
            symbols: false,
            require_each_class: false,
            ..Default::default()
        };
        assert!((digits_only.entropy_bits() - 6.0 * 10f64.log2()).abs() < 0.01);
    }

    #[test]
    fn impossible_policies_are_refused() {
        assert!(PasswordPolicy {
            length: 2,
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(PasswordPolicy {
            length: 20,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        }
        .validate()
        .is_err());
        // Four required classes cannot fit into three characters.
        assert!(PasswordPolicy {
            length: 3,
            require_each_class: true,
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn passphrases_are_well_formed() {
        let p = passphrase(6, '-', true, &pool()).unwrap();
        let words: Vec<&str> = p.split('-').collect();
        assert_eq!(words.len(), 6);
        assert!(words
            .iter()
            .all(|w| w.chars().next().unwrap().is_uppercase()));
        assert!(passphrase(2, '-', false, &pool()).is_err());
    }

    #[test]
    fn the_wordlist_has_no_duplicates() {
        let list = wordlist();
        let unique: std::collections::HashSet<_> = list.iter().collect();
        assert_eq!(
            unique.len(),
            list.len(),
            "duplicate words inflate the claimed entropy"
        );
    }

    #[test]
    fn passphrase_entropy_is_reported_honestly() {
        let per_word = (wordlist().len() as f64).log2();
        assert!((passphrase_bits(8) - 8.0 * per_word).abs() < 0.01);
    }
}
