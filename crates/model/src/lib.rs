#![forbid(unsafe_code)]

mod identity;
mod manifest;
pub mod resolver;

pub use identity::{LibraryPath, ModuleId, ModuleKey, PackageId, validate_archive_path};
pub use manifest::{
    Dependency, LibrarySpec, Manifest, ModuleManifest, PackageMetadata, Platform, ServiceContract,
    ServiceRequirement
};
pub use resolver::{ResolvedGraph, ResolvedModule, resolve, resolve_with_roots, resolve_with_services};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("invalid identifier: {0}")]
    Identifier(String),
    #[error("invalid package path: {0}")]
    Path(String),
    #[error("invalid manifest: {0}")]
    Manifest(String),
    #[error("dependency resolution: {0}")]
    Resolution(String)
}
