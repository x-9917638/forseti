use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

use iced::{Color, theme::Palette};

#[derive(serde::Deserialize, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq, Debug))]
struct Config {
    theme: Theme,
    recent_path: Rc<str>,
    // TODO!
    // ...
}

#[derive(serde::Deserialize, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq, Debug))]
struct Theme {
    // TODO!
    // ...
}

impl Config {
    /// Attempts to load a config file from a given path.
    ///
    /// On Err, returns the default Config wrapped in Err.
    fn load(path: &str) -> Result<Self, Self> {
        let mut toml_str = fs::read_to_string(path).map_err(|_| Self::default())?;
        toml::from_str(&toml_str).map_err(|_| Self::default())
    }
    /// Attempts to write a config file to disk.
    fn write(&self, path: &str) -> Result<(), String> {
        let toml_str = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        let mut file = File::create(path).map_err(|e| e.to_string())?;
        writeln!(&mut file, "{}", toml_str);
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: Theme {},
            recent_path: Rc::from("/tmp/test.toml"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write() -> Result<(), String> {
        let config = Config::default();
        config.write("/tmp/test.toml")
    }

    #[test]
    fn test_load() {
        let config = Config::default();
        config.write("/tmp/test.toml").expect("");
        let loaded = Config::load("/tmp/test.toml").expect("");
        assert!(config == loaded);
    }
}
