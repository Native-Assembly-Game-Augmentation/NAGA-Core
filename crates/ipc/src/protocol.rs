use std::collections::BTreeMap;
use std::path::PathBuf;
use naga_model::{ModuleKey, ModuleManifest};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::RpcResult;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootTicket {
    pub protocol: u32,
    pub address: String,
    pub token: String,
    pub key: ModuleKey,
    pub manifest: ModuleManifest,
    pub root: PathBuf,
    pub files: BTreeMap<String, String>,
    pub configuration: Value,
    pub request_timeout_ms: u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDescriptor {
    pub name: String,
    pub version: Version
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum DiagnosticLevel {
    Trace,
    Info,
    Warn,
    Error
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEvent {
    pub source: ModuleKey,
    pub topic: String,
    pub payload: Vec<u8>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "arguments")]
pub enum Request {
    HostReady,
    Start,
    Stop,
    RegisterService(ServiceDescriptor),
    UnregisterService(ServiceDescriptor),
    CallService {
        name: String,
        requirement: String,
        operation: String,
        payload: Vec<u8>
    },
    InvokeService {
        name: String,
        operation: String,
        payload: Vec<u8>
    },
    Subscribe { topic: String },
    Unsubscribe { topic: String },
    Publish { topic: String, payload: Vec<u8> },
    DeliverEvent(HostEvent),
    Diagnostic { level: DiagnosticLevel, message: String }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body")]
pub enum Frame {
    Hello { protocol: u32, token: String, key: ModuleKey },
    Accepted { protocol: u32 },
    Request { id: u64, request: Request },
    Reply { id: u64, result: RpcResult }
}
