use std::collections::{BTreeMap, BTreeSet};
use std::env::consts::{ARCH, OS};
use std::iter::once;
use std::str::from_utf8;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_slice};
use toml::from_str as from_toml;
use crate::{LibraryPath, ModelError, ModuleId, PackageId};

pub const MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq, Ord, Eq, Serialize, Deserialize)]
pub enum Platform {
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[serde(rename = "linux-aarch64")]
    LinuxAarch64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub package: PackageMetadata,
    pub modules: Vec<ModuleManifest>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageMetadata {
    pub id: PackageId,
    pub version: Version,
    pub publisher: String,
    #[serde(default)]
    pub description: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    pub id: ModuleId,
    pub version: Version,
    pub abi_min: Version,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub provides: Vec<ServiceContract>,
    #[serde(default)]
    pub requires_services: Vec<ServiceRequirement>,
    pub libraries: BTreeMap<Platform, LibrarySpec>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceContract {
    pub name: String,
    pub version: Version
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequirement {
    pub name: String,
    pub version: VersionReq
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub package_id: PackageId,
    pub module_id: ModuleId,
    pub version: VersionReq,
    #[serde(default)]
    pub package_version: Option<VersionReq>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibrarySpec {
    pub library_path: LibraryPath,
    #[serde(default)]
    pub load_libraries: Vec<LibraryPath>
}

impl Platform {
    pub fn directory(self) -> &'static str {
        match self {
            Self::LinuxAarch64 => "linux-aarch64",
            Self::LinuxX86_64 => "linux-x86_64",
            Self::WindowsX86_64 => "windows-x86_64"
        }
    }

    pub fn current() -> Result<Self, ModelError> {
        match (OS, ARCH) {
            ("windows", "x86_64") => Ok(Self::WindowsX86_64),
            ("linux", "x86_64") => Ok(Self::LinuxX86_64),
            ("linux", "aarch64") => Ok(Self::LinuxAarch64),
            target => Err(ModelError::Manifest(format!("unsupported host: {target:?}")))
        }
    }
}

impl Manifest {
    pub fn parse(name: &str, bytes: &[u8]) -> Result<Self, ModelError> {
        let manifest: Self = match name {
            "manifest.toml" => from_toml(
                from_utf8(bytes).map_err(|err| ModelError::Manifest(err.to_string()))?
            ).map_err(|err| ModelError::Manifest(err.to_string()))?,
            "manifest.json" => from_slice(bytes).map_err(|err| ModelError::Manifest(err.to_string()))?,
            _ => return Err(ModelError::Manifest("expected manifest.toml or manifest.json".into()))
        };

        manifest.validate()?;

        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let invalid = |message: &str| ModelError::Manifest(message.into());
        if self.schema_version != MANIFEST_SCHEMA { return Err(invalid("unsupported schema version")) }
        if self.package.publisher.is_empty() || self.package.publisher.len() > 128
            || self.package.publisher.chars().any(char::is_control) {
            return Err(invalid("publisher is empty or invalid"))
        }
        if self.modules.is_empty() || self.modules.len() > 256 {
            return Err(invalid("a package must contain 1 to 256 modules"))
        }

        let mut ids = BTreeSet::new();
        for module in &self.modules {
            if !ids.insert(&module.id) { return Err(invalid("duplicate module ID within package")) }
            if module.abi_min.major == 0 || !module.abi_min.pre.is_empty() || !module.abi_min.build.is_empty() {
                return Err(invalid("ABI minimum must be a stable major version"))
            }
            if module.libraries.is_empty() { return Err(invalid("module has no native libraries")) }

            let mut services = BTreeSet::new();
            for service in &module.provides {
                ModuleId::try_from(service.name.clone())?;
                if !services.insert((&service.name, &service.version)) {
                    return Err(invalid("duplicate provided service"))
                }
            }

            let mut requirements = BTreeSet::new();
            for service in &module.requires_services {
                ModuleId::try_from(service.name.clone())?;
                if !requirements.insert(&service.name) { return Err(invalid("duplicate service requirement")) }
            }

            let mut dependencies = BTreeSet::new();
            for dependency in &module.dependencies {
                if !dependencies.insert((&dependency.package_id, &dependency.module_id)) {
                    return Err(invalid("duplicate module dependency"))
                }
            }

            for (platform, library) in &module.libraries {
                let prefix = format!("bin/{}/", platform.directory());
                let mut paths = BTreeSet::new();
                let mut filenames = BTreeSet::new();
                for path in once(&library.library_path).chain(&library.load_libraries) {
                    let filename = path.as_ref().rsplit('/').next().unwrap_or_default();
                    let extension_valid = if *platform == Platform::WindowsX86_64 {
                        filename.ends_with(".dll")
                    } else {
                        filename.ends_with(".so") || filename.rsplit_once(".so.").is_some_and(|(_, version)| {
                            !version.is_empty() && version.split('.').all(|part| {
                                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                            })
                        })
                    };
                    if !path.as_ref().starts_with(&prefix) || !extension_valid || !paths.insert(path.as_ref())
                        || !filenames.insert(filename.to_ascii_lowercase()) {
                        return Err(invalid("invalid, duplicated or mismatched platform library path"))
                    }
                }
            }
        }

        Ok(())
    }
}
