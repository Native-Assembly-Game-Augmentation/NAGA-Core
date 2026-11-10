use naga_ipc::{DiagnosticLevel, ServiceDescriptor};
use naga_model::ModuleKey;
use serde::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Verified,
    Starting,
    Ready,
    Running,
    Stopping,
    Stopped,
    Failed
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub timestamp_ms: u128,
    pub module: ModuleKey,
    pub level: DiagnosticLevel,
    pub message: String,
    pub origin: DiagnosticOrigin
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticOrigin {
    Core,
    Host,
    Module
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleSnapshot {
    pub key: ModuleKey,
    pub state: LifecycleState,
    pub services: Vec<ServiceDescriptor>,
    pub pid: Option<u32>
}
