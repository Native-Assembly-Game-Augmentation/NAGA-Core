use std::io::{Read, Write};
use serde::{Serialize, de::DeserializeOwned};
use crate::RpcError;

pub const MAX_FRAME_BYTES: usize = 67108864;

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), RpcError> {
    let data = serde_json::to_vec(value).map_err(|err| RpcError::new("serialization", err.to_string()))?;
    if data.is_empty() || data.len() > MAX_FRAME_BYTES {
        return Err(RpcError::new("frame_size", "frame exceeds the protocol limit"))
    }

    writer.write_all(&(data.len() as u32).to_be_bytes())
        .and_then(|()| writer.write_all(&data))
        .and_then(|()| writer.flush())
        .map_err(|err| RpcError::new("io", err.to_string()))
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, RpcError> {
    let mut header = [0; 4];
    reader.read_exact(&mut header).map_err(|err| RpcError::new("io", err.to_string()))?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(RpcError::new("frame_size", "invalid frame length"))
    }

    let mut data = vec![0; size];
    reader.read_exact(&mut data).map_err(|err| RpcError::new("io", err.to_string()))?;
    serde_json::from_slice(&data).map_err(|err| RpcError::new("serialization", err.to_string()))
}
