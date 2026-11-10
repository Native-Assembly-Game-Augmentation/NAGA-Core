#![forbid(unsafe_code)]

mod archive;
mod pack;
mod signature;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use naga_model::ModelError;
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::result::ZipError;

pub use archive::{VerifiedPackage, inspect};
pub use pack::{PackSigner, pack};
pub use signature::{Checksums, SignatureEnvelope, SignatureStatus, TrustPolicy};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PackageLimits {
    pub archive_bytes: u64,
    pub entries: usize,
    pub single_file_bytes: u64,
    pub total_bytes: u64,
    pub metadata_bytes: u64
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            archive_bytes: 2147483648,
            entries: 10000,
            single_file_bytes: 536870912,
            total_bytes: 2147483648,
            metadata_bytes: 8388608
        }
    }
}

impl PackageLimits {
    pub fn validate(&self) -> Result<(), PackageError> {
        if self.archive_bytes == 0 || self.entries == 0 || self.single_file_bytes == 0
            || self.total_bytes == 0 || self.metadata_bytes == 0 || self.metadata_bytes > 67108864 {
            return Err(PackageError::Invalid("invalid package limits; metadata limit must be at most 64 MiB".into()))
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum PackageError {
    #[error("package I/O: {0}")]
    Io(#[from] io::Error),
    #[error("ZIP: {0}")]
    Zip(#[from] ZipError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("package validation: {0}")]
    Invalid(String),
    #[error("signature validation: {0}")]
    Signature(String),
    #[error("metadata JSON: {0}")]
    Json(#[from] JsonError)
}

pub fn hash_file(path: &Path) -> Result<String, PackageError> {
    hash_reader(&mut File::open(path)?, u64::MAX)
}

fn hash_reader(reader: &mut impl Read, limit: u64) -> Result<String, PackageError> {
    hash_reader_counted(reader, limit).map(|(digest, _)| digest)
}

fn hash_reader_counted(reader: &mut impl Read, limit: u64) -> Result<(String, u64), PackageError> {
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 { break }
        total = total.checked_add(count as u64).ok_or_else(|| PackageError::Invalid("file length overflow".into()))?;
        if total > limit { return Err(PackageError::Invalid("file exceeds package size limit".into())) }
        digest.update(&buffer[..count]);
    }
    Ok((hex::encode(digest.finalize()), total))
}
