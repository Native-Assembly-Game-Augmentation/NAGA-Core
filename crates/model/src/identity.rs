use std::fmt::{Display, Formatter, Result as FmtResult};
use semver::Version;
use serde::{Deserialize, Serialize};
use crate::ModelError;

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl TryFrom<String> for $name {
            type Error = ModelError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                if value.is_empty() || value.len() > 128 || !value.as_bytes()[0].is_ascii_lowercase()
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-_".contains(&byte)
                    }) || value.contains("..") || value.ends_with('.') {
                    return Err(ModelError::Identifier(value))
                }

                Ok(Self(value))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

identifier!(PackageId);
identifier!(ModuleId);

#[derive(Debug, Clone, PartialOrd, PartialEq, Ord, Eq, Hash, Serialize, Deserialize)]
pub struct ModuleKey {
    pub package_id: PackageId,
    pub package_version: Version,
    pub module_id: ModuleId
}

impl Display for ModuleKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}@{}/{}", self.package_id, self.package_version, self.module_id)
    }
}

#[derive(Debug, Clone, PartialOrd, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LibraryPath(String);

impl TryFrom<String> for LibraryPath {
    type Error = ModelError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_archive_path(&value)?;
        if !value.starts_with("bin/") {
            return Err(ModelError::Path(value))
        }
        Ok(Self(value))
    }
}

impl From<LibraryPath> for String {
    fn from(value: LibraryPath) -> Self {
        value.0
    }
}

impl AsRef<str> for LibraryPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

pub fn validate_archive_path(path: &str) -> Result<(), ModelError> {
    let invalid = || ModelError::Path(path.into());
    if path.is_empty() || path.len() > 512 || path.contains(['\\', ':', '\0'])
        || path.starts_with('/') || path.bytes().any(|byte| byte < 32 || byte == 127) {
        return Err(invalid())
    }

    for component in path.split('/') {
        if component.is_empty() || matches!(component, "." | "..") || component.ends_with(['.', ' ']) {
            return Err(invalid())
        }

        let stem = component.split('.').next().unwrap_or_default().to_ascii_uppercase();
        let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") || ((
            stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));

        if reserved || component.contains(['<', '>', '"', '|', '?', '*']) {
            return Err(invalid())
        }
    }

    Ok(())
}
