use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use getrandom::fill as fill_random;
use hex::encode as encode_hex;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, to_vec_pretty};

use crate::{Configuration, CoreError, Diagnostic};

const MAX_DOCUMENT_BYTES: u64 = 16777216;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredConfiguration {
    pub revision: u64,
    pub configuration: Configuration
}

pub trait ConfigurationStore: Send + Sync {
    fn load(&self) -> Result<Option<StoredConfiguration>, CoreError>;
    fn commit(&self, expected: Option<u64>, configuration: &Configuration) -> Result<StoredConfiguration, CoreError>;
}

pub trait DiagnosticStore: Send + Sync {
    fn save(&self, session: &Path, diagnostics: &[Diagnostic]) -> Result<(), CoreError>;
}

#[derive(Default)]
pub struct FileDiagnosticStore;

impl DiagnosticStore for FileDiagnosticStore {
    fn save(&self, session: &Path, diagnostics: &[Diagnostic]) -> Result<(), CoreError> {
        atomic_write(&session.join("diagnostics.json"), &to_vec_pretty(diagnostics).map_err(configuration_error)?)
    }
}

pub struct FileConfigurationStore {
    path: PathBuf,
    lock: Mutex<File>
}

impl FileConfigurationStore {
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        let parent = path.parent().ok_or_else(|| configuration_error("configuration path has no parent"))?;
        fs::create_dir_all(parent)?;
        let parent = parent.canonicalize()?;
        let filename = path.file_name().ok_or_else(|| configuration_error("configuration path has no filename"))?;
        let path = parent.join(filename);
        let lock = OpenOptions::new().create(true).truncate(false).read(true).write(true).open(path.with_extension("lock"))?;
        lock.try_lock().map_err(configuration_error)?;
        Ok(Self {
            path,
            lock: Mutex::new(lock)
        })
    }

    fn read(&self) -> Result<Option<StoredConfiguration>, CoreError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into())
        };
        let mut bytes = Vec::new();
        file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES { return Err(configuration_error("configuration document exceeds limit")) }
        let stored: StoredConfiguration = from_slice(&bytes).map_err(configuration_error)?;
        stored.configuration.validate()?;
        if stored.revision == 0 { return Err(configuration_error("invalid configuration revision")) }
        Ok(Some(stored))
    }
}

impl ConfigurationStore for FileConfigurationStore {
    fn load(&self) -> Result<Option<StoredConfiguration>, CoreError> {
        let _guard = self.lock.lock().map_err(configuration_error)?;
        self.read()
    }

    fn commit(&self, expected: Option<u64>, configuration: &Configuration) -> Result<StoredConfiguration, CoreError> {
        let _guard = self.lock.lock().map_err(configuration_error)?;
        let current = self.read()?;
        if current.as_ref().map(|stored| stored.revision) != expected { return Err(configuration_error("configuration revision changed")) }
        configuration.validate()?;
        let revision = expected.unwrap_or(0).checked_add(1).ok_or_else(|| configuration_error("configuration revision exhausted"))?;
        let stored = StoredConfiguration {
            revision,
            configuration: configuration.clone()
        };
        atomic_write(&self.path, &to_vec_pretty(&stored).map_err(configuration_error)?)?;
        Ok(stored)
    }
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CoreError> {
    if bytes.len() as u64 > MAX_DOCUMENT_BYTES { return Err(configuration_error("document exceeds limit")) }
    let mut nonce = [0; 16];
    fill_random(&mut nonce).map_err(configuration_error)?;
    let temporary = path.with_extension(format!("{}.tmp", encode_hex(nonce)));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn configuration_error(error: impl ToString) -> CoreError {
    CoreError::Configuration(error.to_string())
}
