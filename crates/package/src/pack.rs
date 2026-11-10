use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::iter::once;
use std::path::{Path, PathBuf};
use ed25519_dalek::{Signer, SigningKey};
use naga_model::{Manifest, validate_archive_path};
use sha2::{Digest, Sha256};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};
use crate::{Checksums, PackageError, SignatureEnvelope, signature::signature_message};

pub struct PackSigner {
    pub key_id: String,
    pub secret: [u8; 32]
}

pub fn pack(directory: &Path, output: &Path, signer: Option<&PackSigner>) -> Result<(), PackageError> {
    if output.extension().is_none_or(|extension| extension != "nmod") {
        return Err(PackageError::Invalid("output must use .nmod extension".into()))
    }
    let root = fs::canonicalize(directory)?;
    let mut paths = BTreeMap::new();
    collect(&root, &root, &mut paths)?;
    let mut folded = BTreeSet::new();
    if paths.keys().any(|name| !name.is_ascii() || !folded.insert(name.to_ascii_lowercase())) {
        return Err(PackageError::Invalid("pack paths must be portable and case-unambiguous".into()))
    }
    if signer.is_some_and(|signer| signer.key_id.is_empty()) {
        return Err(PackageError::Signature("signing key ID cannot be empty".into()))
    }
    if paths.contains_key("checksums.json") || paths.contains_key("signature.sig") {
        return Err(PackageError::Invalid("pack input must not contain generated checksums or signature".into()))
    }
    let manifests: Vec<_> = ["manifest.toml", "manifest.json"].into_iter()
        .filter(|name| paths.contains_key(*name)).collect();
    if manifests.len() != 1 { return Err(PackageError::Invalid("exactly one manifest is required".into())) }
    let manifest_path = &paths[manifests[0]];
    let manifest_bytes = fs::read(manifest_path)?;
    let manifest = Manifest::parse(manifests[0], &manifest_bytes)?;
    for module in &manifest.modules {
        for library in module.libraries.values() {
            for path in once(&library.library_path).chain(&library.load_libraries) {
                if !paths.contains_key(path.as_ref()) {
                    return Err(PackageError::Invalid(format!("missing native library: {}", path.as_ref())))
                }
            }
        }
    }
    let file = OpenOptions::new().write(true).create_new(true).open(output)?;
    let mut archive = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated).unix_permissions(420);
    let mut files = BTreeMap::new();
    for (name, path) in &paths {
        archive.start_file(name, options)?;
        let mut digest = Sha256::new();
        if *name == manifests[0] {
            archive.write_all(&manifest_bytes)?;
            digest.update(&manifest_bytes);
        } else {
            let mut input = File::open(path)?;
            let mut buffer = [0; 65536];
            loop {
                let count = input.read(&mut buffer)?;
                if count == 0 { break }
                archive.write_all(&buffer[..count])?;
                digest.update(&buffer[..count]);
            }
        }
        files.insert(name.clone(), hex::encode(digest.finalize()));
    }
    let checksums = serde_json::to_vec_pretty(&Checksums { schema_version: 1, files })?;
    archive.start_file("checksums.json", options)?;
    archive.write_all(&checksums)?;
    if let Some(signer) = signer {
        let key = SigningKey::from_bytes(&signer.secret);
        let signature = key.sign(&signature_message(&checksums));
        let envelope = SignatureEnvelope {
            algorithm: "ed25519".into(), key_id: signer.key_id.clone(), signature: hex::encode(signature.to_bytes())
        };
        archive.start_file("signature.sig", options)?;
        archive.write_all(&serde_json::to_vec_pretty(&envelope)?)?;
    }
    archive.finish()?;
    Ok(())
}

fn collect(root: &Path, directory: &Path, paths: &mut BTreeMap<String, PathBuf>) -> Result<(), PackageError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() { return Err(PackageError::Invalid("input contains a symbolic link".into())) }
        let path = entry.path();
        if kind.is_dir() {
            collect(root, &path, paths)?;
        } else if kind.is_file() {
            let name = path.strip_prefix(root)
                .map_err(|_| PackageError::Invalid("pack input escaped its root".into()))?
                .to_str().ok_or_else(|| PackageError::Invalid("input filename is not UTF-8".into()))?
                .replace('\\', "/");
            validate_archive_path(&name)?;
            paths.insert(name, path);
        } else {
            return Err(PackageError::Invalid("input contains a special file".into()))
        }
    }
    Ok(())
}
