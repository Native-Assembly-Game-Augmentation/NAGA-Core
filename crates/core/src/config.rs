use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use naga_model::{ModuleId, ModuleKey, PackageId};
use naga_package::{PackageLimits, TrustPolicy};
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_str};
use toml::from_str as from_toml;

use crate::CoreError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Configuration {
    pub packages: Vec<PathBuf>,
    pub root_modules: Vec<ModuleKey>,
    pub start_all_modules: bool,
    pub disabled_modules: Vec<ModuleSelector>,
    pub max_modules: usize,
    pub host_binary: Option<PathBuf>,
    pub data_directory: PathBuf,
    pub trust: TrustPolicy,
    pub package_limits: PackageLimits,
    pub startup_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub shutdown_timeout_ms: u64,
    pub event_queue_capacity: usize,
    pub event_queue_bytes: usize,
    pub diagnostic_capacity: usize,
    pub module_configuration: BTreeMap<String, Value>
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            packages: Vec::new(),
            root_modules: Vec::new(),
            start_all_modules: true,
            disabled_modules: Vec::new(),
            max_modules: 256,
            host_binary: None,
            data_directory: PathBuf::from("run"),
            trust: TrustPolicy::default(),
            package_limits: PackageLimits::default(),
            startup_timeout_ms: 15000,
            request_timeout_ms: 5000,
            shutdown_timeout_ms: 5000,
            event_queue_capacity: 128,
            event_queue_bytes: 67108864,
            diagnostic_capacity: 1000,
            module_configuration: BTreeMap::new()
        }
    }
}

impl Configuration {
    pub fn load(path: &Path) -> Result<Self, CoreError> {
        let path = fs::canonicalize(path)?;
        let text = fs::read_to_string(&path)?;
        let mut configuration: Self = if path.extension().is_some_and(|extension| extension == "json") {
            from_str(&text).map_err(|error| CoreError::Configuration(error.to_string()))?
        } else {
            from_toml(&text).map_err(|error| CoreError::Configuration(error.to_string()))?
        };
        let root = path.parent().ok_or_else(|| CoreError::Configuration("missing configuration parent".into()))?;
        for package in &mut configuration.packages {
            if package.is_relative() {
                *package = root.join(&*package);
            }
        }
        if configuration.data_directory.is_relative() {
            configuration.data_directory = root.join(&configuration.data_directory);
        }
        if let Some(host) = &mut configuration.host_binary && host.is_relative() {
            *host = root.join(&*host);
        }
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<(), CoreError> {
        self.package_limits.validate()?;
        if self.packages.len() > 256 { return Err(CoreError::Configuration("package count exceeds 256".into())) }
        if self.max_modules == 0 || self.max_modules > 4096 {
            return Err(CoreError::Configuration("max_modules must be between 1 and 4096".into()))
        }
        for timeout in [
            self.startup_timeout_ms,
            self.request_timeout_ms,
            self.shutdown_timeout_ms,
        ] {
            if !(10..=300000).contains(&timeout) {
                return Err(CoreError::Configuration("timeouts must be between 10 and 300000 ms".into()))
            }
        }
        if self.event_queue_capacity == 0 || self.event_queue_capacity > 100000 || self.event_queue_bytes == 0
            || self.diagnostic_capacity == 0 {
            return Err(CoreError::Configuration("invalid event or diagnostic limits".into()))
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSelector {
    pub package_id: PackageId,
    pub module_id: ModuleId
}

impl ModuleSelector {
    pub fn matches(&self, key: &ModuleKey) -> bool {
        self.package_id == key.package_id && self.module_id == key.module_id
    }
}
