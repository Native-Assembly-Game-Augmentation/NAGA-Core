use std::sync::atomic::Ordering;

use naga_abi::MAX_ABI_BYTES;
use naga_ipc::{DiagnosticLevel, Request, RpcError, RpcResult};
use naga_model::ModuleKey;
use semver::VersionReq;
use serde_json::json;

use super::Router;
use crate::{LifecycleState, ServiceCall};

impl Router {
    pub fn call_service(&self, caller: Option<&ModuleKey>, name: &str, requirement: &str, operation: &str, payload: Vec<u8>) -> RpcResult {
        self.call_targeted(caller, None, name, requirement, operation, payload)
    }

    pub fn call_targeted(
        &self, caller: Option<&ModuleKey>, target: Option<&ModuleKey>, name: &str, requirement: &str, operation: &str,
        payload: Vec<u8>
    ) -> RpcResult {
        if self.closed.load(Ordering::Acquire) { return Err(RpcError::new("disconnected", "Core runtime stopped")) }
        let requirement = VersionReq::parse(requirement).map_err(|error| RpcError::new("invalid_argument", error.to_string()))?;
        if operation.is_empty() || operation.len() > 256 || payload.len() > MAX_ABI_BYTES {
            return Err(RpcError::new("invalid_argument", "invalid service operation or payload"))
        }
        if target.is_none() && let Some(version) = self.local_services.select(name, &requirement) {
            if let Some(caller) = caller {
                let slots = self.slots.lock().unwrap();
                let allowed = slots.get(caller).is_some_and(|slot| {
                    !matches!(slot.state, LifecycleState::Stopped | LifecycleState::Failed)
                        && slot.descriptor.manifest.requires_services.iter().any(|declared| {
                            declared.name == name && declared.version.matches(&version)
                        })
                });
                if !allowed { return Err(RpcError::new("dependency_denied", "local service was not declared")) }
            }
            let result = self.local_services.invoke(name, &version, ServiceCall { caller, operation, payload: &payload })?;
            return Ok(json!(result))
        }
        let (key, peer) = {
            let slots = self.slots.lock().unwrap();
            let allowed = caller.map(|key| &slots[key].descriptor.dependencies);
            slots.iter().filter(|(key, slot)| {
                slot.state == LifecycleState::Running && target.is_none_or(|target| *key == target)
                    && allowed.is_none_or(|dependencies| dependencies.contains(key))
            }).flat_map(|(key, slot)| {
                slot.services.iter().map(move |service| (key, slot, service))
            }).filter(|(_, _, (service, version))| {
                service == name && requirement.matches(version)
            }).max_by(|(left, _, (_, left_version)), (right, _, (_, right_version))| {
                left_version.cmp(right_version).then_with(|| left.cmp(right))
            }).and_then(|(key, slot, _)| slot.peer.clone().map(|peer| (key.clone(), peer)))
                .ok_or_else(|| {
                    RpcError::new("unavailable", format!("no allowed running provider for {name} {requirement}"))
                })?
        };
        let result = peer.call(
            Request::InvokeService {
                name: name.into(),
                operation: operation.into(),
                payload
            },
            self.timeout()
        );
        if let Err(error) = &result {
            self.record(&key, DiagnosticLevel::Warn, format!("service call failed: {error}"));
            if matches!(error.code.as_str(), "timeout" | "disconnected" | "native_panic") {
                self.set_state(&key, LifecycleState::Failed);
                peer.close();
            }
        }
        result
    }
}
