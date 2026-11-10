#![forbid(unsafe_code)]

mod config;
mod manager;
mod persistence;
mod process;
mod process_tree;
mod registry;
mod router;
mod runtime;
mod transactions;
mod types;

pub use config::{Configuration, ModuleSelector};
pub use manager::ModuleManager;
pub use persistence::{
    ConfigurationStore, DiagnosticStore, FileConfigurationStore, FileDiagnosticStore,
    StoredConfiguration
};
pub use registry::{LocalService, ServiceCall, ServiceRegistry};
pub use runtime::RuntimeContext;
pub use transactions::{
    ModuleChanges, ModuleTransactionManager, NativeRuntime, RuntimeDriver, TransactionPlan
};
pub use types::{Diagnostic, DiagnosticOrigin, LifecycleState, ModuleSnapshot};

use std::io::Error as IoError;
use std::path::PathBuf;

use naga_abi::ABIVersion;
use naga_ipc::RpcError;
use naga_model::{ModelError, ModuleKey};
use naga_package::PackageError;
use semver::Version;
use thiserror::Error;

pub fn abi_version() -> Version {
    let abi = ABIVersion::CURRENT;
    Version::new(abi.major as u64, abi.minor as u64, abi.patch as u64)
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("startup: {0}")]
    Startup(#[source] Box<StartupFailure>),
    #[error(transparent)]
    Package(#[from] PackageError),
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error(transparent)]
    Io(#[from] IoError),
    #[error("configuration: {0}")]
    Configuration(String),
    #[error("lifecycle: {0}")]
    Lifecycle(String)
}

#[derive(Debug, Error)]
#[error("{module}: {message}")]
pub struct StartupFailure {
    pub module: ModuleKey,
    pub message: String,
    pub diagnostics: Vec<Diagnostic>,
    pub modules: Vec<ModuleSnapshot>,
    pub session_directory: PathBuf,
    #[source]
    pub cause: Box<CoreError>
}
