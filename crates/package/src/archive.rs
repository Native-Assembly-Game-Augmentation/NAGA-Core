use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::iter::once;
use std::path::{Path, PathBuf};
use std::str::from_utf8;
use naga_model::{Manifest, validate_archive_path};
use sha2::{Digest, Sha256};
use zip::ZipArchive;
use crate::{Checksums, PackageError, PackageLimits, SignatureStatus, TrustPolicy,
            hash_reader, hash_reader_counted, signature};

#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    pub source: PathBuf,
    pub manifest: Manifest,
    pub checksum_files: BTreeMap<String, String>,
    pub digest: String,
    pub signature: SignatureStatus,
    limits: PackageLimits
}

pub fn inspect(path: &Path, trust: &TrustPolicy, limits: &PackageLimits) -> Result<VerifiedPackage, PackageError> {
    limits.validate()?;
    if path.extension().is_none_or(|extension| extension != "nmod") {
        return Err(PackageError::Invalid("expected a .nmod ZIP package".into()))
    }
    let source = fs::canonicalize(path)?;
    if fs::metadata(&source)?.len() > limits.archive_bytes {
        return Err(PackageError::Invalid("compressed archive size limit exceeded".into()))
    }
    let digest = hash_reader(&mut File::open(&source)?, limits.archive_bytes)?;
    let mut archive = ZipArchive::new(File::open(&source)?)?;
    if archive.len() > limits.entries { return Err(PackageError::Invalid("too many ZIP entries".into())) }
    let mut names = BTreeSet::new();
    let mut folded = BTreeSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        let name = from_utf8(entry.name_raw()).map_err(|_| PackageError::Invalid("ZIP filename is not UTF-8".into()))?;
        let canonical = if entry.is_dir() { name.strip_suffix('/').unwrap_or(name) } else { name };
        validate_archive_path(canonical)?;
        if !canonical.is_ascii() {
            return Err(PackageError::Invalid("portable package paths must use ASCII".into()))
        }
        if !folded.insert(canonical.to_ascii_lowercase()) {
            return Err(PackageError::Invalid("duplicate or case-ambiguous ZIP path".into()))
        }
        let kind = entry.unix_mode().unwrap_or(0) & 61440;
        if kind != 0 && kind != 32768 && !(entry.is_dir() && kind == 16384) {
            return Err(PackageError::Invalid("links and special files are not allowed".into()))
        }
        if entry.is_dir() { continue }
        if entry.size() > limits.single_file_bytes { return Err(PackageError::Invalid("ZIP entry is too large".into())) }
        total = total.checked_add(entry.size()).ok_or_else(|| PackageError::Invalid("ZIP size overflow".into()))?;
        if total > limits.total_bytes {
            return Err(PackageError::Invalid("package uncompressed size limit exceeded".into()))
        }
        names.insert(name.to_owned());
    }
    for name in &names {
        let mut parent = String::new();
        let parts: Vec<_> = name.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            if !parent.is_empty() { parent.push('/'); }
            parent.push_str(part);
            if names.contains(&parent) {
                return Err(PackageError::Invalid("a file is also used as a directory".into()))
            }
        }
    }
    let manifests: Vec<_> = ["manifest.toml", "manifest.json"].into_iter()
        .filter(|name| names.contains(*name)).collect();
    if manifests.len() != 1 {
        return Err(PackageError::Invalid("exactly one TOML or JSON manifest is required".into()))
    }
    let metadata_limit = limits.metadata_bytes.min(limits.single_file_bytes).min(limits.total_bytes);
    let manifest = Manifest::parse(manifests[0], &read_metadata(&mut archive, manifests[0], metadata_limit)?)?;
    let checksum_bytes = read_metadata(&mut archive, "checksums.json", metadata_limit)?;
    let checksums: Checksums = serde_json::from_slice(&checksum_bytes)?;
    if checksums.schema_version != 1 { return Err(PackageError::Invalid("unsupported checksum schema".into())) }
    let expected: BTreeSet<_> = names.iter()
        .filter(|name| !matches!(name.as_str(), "checksums.json" | "signature.sig")).cloned().collect();
    if expected != checksums.files.keys().cloned().collect() {
        return Err(PackageError::Invalid("checksums must cover every payload file exactly".into()))
    }
    let mut actual_total = checksum_bytes.len() as u64;
    for (name, expected) in &checksums.files {
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(PackageError::Invalid("invalid SHA-256 encoding".into()))
        }
        let (actual, bytes) = hash_reader_counted(&mut archive.by_name(name)?,
            limits.single_file_bytes.min(limits.total_bytes.saturating_sub(actual_total)))?;
        actual_total += bytes;
        if actual != *expected { return Err(PackageError::Invalid(format!("checksum mismatch: {name}"))) }
    }
    for module in &manifest.modules {
        for library in module.libraries.values() {
            for path in once(&library.library_path).chain(&library.load_libraries) {
                if !checksums.files.contains_key(path.as_ref()) {
                    return Err(PackageError::Invalid(format!("missing library: {}", path.as_ref())))
                }
            }
        }
    }
    let signed = if names.contains("signature.sig") {
        Some(read_metadata(&mut archive, "signature.sig",
            metadata_limit.min(limits.total_bytes.saturating_sub(actual_total)))?)
    } else { None };
    let signature = signature::verify(&manifest.package.publisher, &checksum_bytes, signed.as_deref(), trust)?;
    Ok(VerifiedPackage { source, manifest, checksum_files: checksums.files, digest, signature, limits: limits.clone() })
}

impl VerifiedPackage {
    pub fn extract(&self, target: &Path) -> Result<(), PackageError> {
        fs::create_dir(target)?;
        let mut archive = ZipArchive::new(File::open(&self.source)?)?;
        for (name, expected) in &self.checksum_files {
            let path = target.join(name);
            fs::create_dir_all(path.parent().ok_or_else(|| PackageError::Invalid("missing extraction parent".into()))?)?;
            let mut output = OpenOptions::new().write(true).create_new(true).open(&path)?;
            let mut input = archive.by_name(name)?;
            let mut digest = Sha256::new();
            let mut buffer = [0; 65536];
            let mut total = 0u64;
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 { break }
                total = total.checked_add(count as u64).ok_or_else(|| PackageError::Invalid("extracted size overflow".into()))?;
                if total > self.limits.single_file_bytes {
                    return Err(PackageError::Invalid("extracted file is too large".into()))
                }
                output.write_all(&buffer[..count])?;
                digest.update(&buffer[..count]);
            }
            if hex::encode(digest.finalize()) != *expected {
                return Err(PackageError::Invalid(format!("package changed during extraction: {name}")))
            }
        }
        Ok(())
    }
}

fn read_metadata(archive: &mut ZipArchive<File>, name: &str, limit: u64) -> Result<Vec<u8>, PackageError> {
    let mut bytes = Vec::new();
    archive.by_name(name)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit { return Err(PackageError::Invalid(format!("metadata limit exceeded: {name}"))) }
    Ok(bytes)
}
