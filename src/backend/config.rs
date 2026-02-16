use std::{
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

use iced::theme::Palette;

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
    background: Color,
    foreground: Color,
    primary: Color,
    // TODO?
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            background: Color::default(),
            foreground: Color::default(),
            primary: Color::default(),
        }
    }
}

#[cfg_attr(test, derive(PartialEq, Debug))]
struct Color {
    r: f32,
    g: f32,
    b: f32,
    a: f32,
}

impl<'de> serde::Deserialize<'de> for Color {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ColorVisitor;

        impl<'de> serde::de::Visitor<'de> for ColorVisitor {
            type Value = Color;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("rgba(r, g, b, a)")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = v.trim();
                if !value.starts_with("rgba(") || !value.ends_with(')') {
                    return Err(E::custom("expected format rgba(r, g, b, a)"));
                }

                let inner = &value[5..value.len() - 1];
                let parts: Vec<_> = inner.split(',').map(|p| p.trim()).collect();
                if parts.len() != 4 {
                    return Err(E::custom("expected four components in rgba"));
                }

                let r = parts[0].parse::<f32>().map_err(E::custom)?;
                let g = parts[1].parse::<f32>().map_err(E::custom)?;
                let b = parts[2].parse::<f32>().map_err(E::custom)?;
                let a = parts[3].parse::<f32>().map_err(E::custom)?;

                Ok(Color { r, g, b, a })
            }
        }

        deserializer.deserialize_str(ColorVisitor)
    }
}

impl serde::Serialize for Color {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let as_string = format!("rgba({}, {}, {}, {})", self.r, self.g, self.b, self.a);
        serializer.serialize_str(&as_string)
    }
}

impl From<Color> for iced::Color {
    fn from(value: Color) -> Self {
        Self {
            r: value.r,
            g: value.g,
            b: value.b,
            a: value.a,
        }
    }
}

impl Default for Color {
    fn default() -> Self {
        Self {
            r: 0.0,
            g: 0.0,
            b: 0.0,
            a: 1.0,
        }
    }
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
            theme: Theme::default(),
            recent_path: Rc::from(""),
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
