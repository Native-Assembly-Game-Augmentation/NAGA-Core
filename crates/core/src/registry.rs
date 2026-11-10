use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use naga_abi::MAX_ABI_BYTES;
use naga_ipc::RpcError;
use naga_model::{ModuleId, ModuleKey, ServiceContract};
use semver::{Version, VersionReq};

pub struct ServiceCall<'a> {
    pub caller: Option<&'a ModuleKey>,
    pub operation: &'a str,
    pub payload: &'a [u8]
}

pub trait LocalService: Send + Sync {
    fn call(&self, request: ServiceCall<'_>) -> Result<Vec<u8>, RpcError>;

    fn release(&self, _owner: &ModuleKey) {}
}

#[derive(Clone, Default)]
pub struct ServiceRegistry {
    entries: BTreeMap<(String, Version), Arc<dyn LocalService>>
}

impl ServiceRegistry {
    pub fn register(&mut self, contract: ServiceContract, implementation: Arc<dyn LocalService>) -> Result<(), RpcError> {
        ModuleId::try_from(contract.name.clone()).map_err(|error| RpcError::new("invalid_argument", error.to_string()))?;
        let key = (contract.name, contract.version);
        if self.entries.contains_key(&key) { return Err(RpcError::new("conflict", "service version already registered")) }
        self.entries.insert(key, implementation);
        Ok(())
    }

    pub fn contracts(&self) -> Vec<ServiceContract> {
        self.entries.keys().map(|(name, version)| ServiceContract {
            name: name.clone(),
            version: version.clone()
        }).collect()
    }

    pub(crate) fn select(&self, name: &str, requirement: &VersionReq) -> Option<Version> {
        self.entries.keys().filter(|(candidate, version)| candidate == name && requirement.matches(version))
            .map(|(_, version)| version.clone()).max()
    }

    pub(crate) fn invoke(&self, name: &str, version: &Version, request: ServiceCall<'_>) -> Result<Vec<u8>, RpcError> {
        let service = self.entries.get(&(name.into(), version.clone()))
            .ok_or_else(|| RpcError::new("unavailable", "local service is unavailable"))?;
        let result = catch_unwind(AssertUnwindSafe(|| service.call(request)))
            .map_err(|_| RpcError::new("service_panic", "local service panicked"))??;
        if result.len() > MAX_ABI_BYTES { return Err(RpcError::new("limit", "local service response exceeds ABI limit")) }
        Ok(result)
    }

    pub(crate) fn release(&self, owner: &ModuleKey) {
        for service in self.entries.values() {
            let _ = catch_unwind(AssertUnwindSafe(|| service.release(owner)));
        }
    }
}
