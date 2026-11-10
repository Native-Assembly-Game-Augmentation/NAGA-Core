use std::collections::BTreeMap;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use crate::PackageError;

pub const SIGNATURE_DOMAIN: &[u8] = b"naga-package-signature-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checksums {
    pub schema_version: u32,
    pub files: BTreeMap<String, String>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustPolicy {
    pub allow_unsigned: bool,
    pub publishers: BTreeMap<String, BTreeMap<String, String>>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureStatus {
    Unsigned,
    Trusted { publisher: String, key_id: String }
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self { allow_unsigned: true, publishers: BTreeMap::new() }
    }
}

pub fn signature_message(checksums: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + checksums.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(checksums);
    message
}

pub fn verify(publisher: &str, checksums: &[u8], signature: Option<&[u8]>,
              trust: &TrustPolicy) -> Result<SignatureStatus, PackageError> {
    let keys = trust.publishers.get(publisher);
    let Some(bytes) = signature else {
        if keys.is_some() {
            return Err(PackageError::Signature("trusted publisher requires a signature".into()))
        }
        if !trust.allow_unsigned {
            return Err(PackageError::Signature("unsigned packages are disabled".into()))
        }
        return Ok(SignatureStatus::Unsigned)
    };
    let envelope: SignatureEnvelope = serde_json::from_slice(bytes)?;
    if envelope.algorithm != "ed25519" {
        return Err(PackageError::Signature("unsupported signature algorithm".into()))
    }
    let public = keys.and_then(|keys| keys.get(&envelope.key_id))
        .ok_or_else(|| PackageError::Signature("publisher or signing key is not trusted".into()))?;
    let key: [u8; 32] = hex::decode(public)
        .map_err(|err| PackageError::Signature(err.to_string()))?.try_into()
        .map_err(|_| PackageError::Signature("expected a 32-byte public key".into()))?;
    let key = VerifyingKey::from_bytes(&key).map_err(|err| PackageError::Signature(err.to_string()))?;
    let bytes = hex::decode(envelope.signature).map_err(|err| PackageError::Signature(err.to_string()))?;
    let signature = Signature::try_from(bytes.as_slice()).map_err(|err| PackageError::Signature(err.to_string()))?;
    key.verify_strict(&signature_message(checksums), &signature)
        .map_err(|err| PackageError::Signature(err.to_string()))?;
    Ok(SignatureStatus::Trusted { publisher: publisher.into(), key_id: envelope.key_id })
}
