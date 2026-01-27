use rand::{
    Rng, rng,
    seq::{IteratorRandom, SliceRandom},
};
use tauri::command;

const UPPERCASE_LETTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_LETTERS: &str = "abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &str = "1234567890";
const PUNCTUATION: &str = ".,:;";
const QUOTES: &str = "\'\"";
const DASHES_SLASHES: &str = "\\/|_-";
const MATH_SYMBOLS: &str = "<>*+!?=";
const BRACES: &str = "{[()]}";
const LOGOGRAMS: &str = "#$%&@^`~";
const SPECIAL_CHARACTERS: &str = concat!(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
    ".,:;",
    "\\/|_-",
    "<>*+!?=",
    "#$%&@^`~"
);

pub enum CharacterSet {
    Uppercase,
    Lowercase,
    Numbers,
    Punctuation,
    Quotes,
    DashesSlashes,
    MathSymbols,
    Braces,
    Logograms,
    SpecialCharacters,
}

impl CharacterSet {
    pub fn as_chars(&self) -> &'static str {
        match self {
            CharacterSet::Uppercase => UPPERCASE_LETTERS,
            CharacterSet::Lowercase => LOWERCASE_LETTERS,
            CharacterSet::Numbers => NUMBERS,
            CharacterSet::Punctuation => PUNCTUATION,
            CharacterSet::Quotes => QUOTES,
            CharacterSet::DashesSlashes => DASHES_SLASHES,
            CharacterSet::MathSymbols => MATH_SYMBOLS,
            CharacterSet::Braces => BRACES,
            CharacterSet::Logograms => LOGOGRAMS,
            CharacterSet::SpecialCharacters => SPECIAL_CHARACTERS,
        }
    }
}

impl std::str::FromStr for CharacterSet {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "upper" => Ok(Self::Uppercase),
            "lower" => Ok(Self::Lowercase),
            "numbers" => Ok(Self::Numbers),
            "punctuation" => Ok(Self::Punctuation),
            "quotes" => Ok(Self::Quotes),
            "dashes" | "slashes" => Ok(Self::DashesSlashes),
            "math" => Ok(Self::MathSymbols),
            "braces" => Ok(Self::Braces),
            "logograms" => Ok(Self::Logograms),
            "special" => Ok(Self::SpecialCharacters),
            other => Err(format!("Unknown character set: {other}")),
        }
    }
}

// Here for tests
fn _generate_password<R: Rng>(
    rng: &mut R,
    names: Vec<&str>,
    length: usize,
) -> Result<String, String> {
    let mut charset = String::new();
    for name in names {
        let set: CharacterSet = name.parse()?;
        charset.push_str(set.as_chars());
    }
    let mut out = charset.chars().choose_multiple(rng, length);
    out.shuffle(rng);
    Ok(out.into_iter().collect())
}

#[command]
#[cfg_attr(debug_assertions, specta::specta)]
pub fn generate_password(names: Vec<&str>, length: usize) -> Result<String, String> {
    _generate_password(&mut rng(), names, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::SmallRng};

    fn get_rng() -> impl Rng {
        SmallRng::seed_from_u64(1u64)
    }

    #[test]
    fn test_generate_password() {
        let mut rng = get_rng();
        assert_eq!(
            Ok(String::from("S]s`AXY}Chlvwt:BRabnx=GgdOLnpJJe")),
            _generate_password(&mut rng, vec!["special", "braces", "upper", "lower"], 32)
        );
    }
}
