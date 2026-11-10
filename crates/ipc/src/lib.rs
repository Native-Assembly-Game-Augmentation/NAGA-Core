#![forbid(unsafe_code)]

mod channel;
mod frame;
mod peer;
mod protocol;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub use channel::{ChannelEndpoint, ChannelListener, ChannelOptions, DirectChannel, OverflowPolicy};
pub use frame::{MAX_FRAME_BYTES, read_frame, write_frame};
pub use peer::{Handler, Peer};
pub use protocol::{BootTicket, DiagnosticLevel, Frame, HostEvent, PROTOCOL_VERSION, Request, ServiceDescriptor};

pub type RpcResult = Result<Value, RpcError>;

#[derive(Debug, Clone, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
pub struct RpcError {
    pub code: String,
    pub message: String
}

impl RpcError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}
