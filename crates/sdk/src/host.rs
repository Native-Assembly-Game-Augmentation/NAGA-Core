use std::ffi::c_void;
use std::path::PathBuf;
use std::str::from_utf8;

use naga_abi::{self as abi, Bytes, HostAPI, Output};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{from_slice, to_vec};

use crate::{Error, Result};

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum Level {
    Trace,
    Info,
    Warn,
    Error
}

#[derive(Copy, Clone)]
pub struct Host(HostAPI);

unsafe impl Send for Host {}
unsafe impl Sync for Host {}

impl Host {
    pub unsafe fn from_raw(pointer: *const HostAPI) -> Result<Self> {
        if pointer.is_null() || unsafe { pointer.cast::<u32>().read() } < HostAPI::expected_size() {
            return Err(Error::new(abi::UNSUPPORTED, "host ABI table is too small"))
        }
        let api = unsafe { pointer.read() };
        if api.abi.major != abi::ABIVersion::CURRENT.major || api.register_service.is_none() || api.unregister_service.is_none()
            || api.call_service.is_none() || api.publish.is_none() || api.subscribe.is_none() || api.unsubscribe.is_none()
            || api.diagnostic.is_none() || api.configuration.is_none() || api.package_root.is_none() {
            return Err(Error::new(abi::UNSUPPORTED, "host ABI is incompatible or incomplete"))
        }
        Ok(Self(api))
    }

    pub fn register_service(self, name: &str, version: &str) -> Result<()> {
        status(unsafe {
            self.0.register_service.unwrap()(self.0.context, Bytes::new(name.as_bytes()), Bytes::new(version.as_bytes()))
        })
    }

    pub fn unregister_service(self, name: &str, version: &str) -> Result<()> {
        status(unsafe {
            self.0.unregister_service.unwrap()(self.0.context, Bytes::new(name.as_bytes()), Bytes::new(version.as_bytes()))
        })
    }

    pub fn call(self, name: &str, version: &str, operation: &str, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > abi::MAX_ABI_BYTES { return Err(Error::new(abi::INVALID_ARG, "payload exceeds ABI limit")) }
        let mut bytes = Vec::new();
        status(unsafe {
            self.0.call_service.unwrap()(
                self.0.context, Bytes::new(name.as_bytes()), Bytes::new(version.as_bytes()), Bytes::new(operation.as_bytes()),
                Bytes::new(payload), output(&mut bytes)
            )
        })?;
        Ok(bytes)
    }

    pub fn call_json<I: Serialize, O: DeserializeOwned>(self, name: &str, version: &str, operation: &str, payload: &I) -> Result<O> {
        let input = to_vec(payload).map_err(|error| Error::new(abi::INVALID_ARG, error.to_string()))?;
        from_slice(&self.call(name, version, operation, &input)?).map_err(|error| Error::new(abi::INVALID_ARG, error.to_string()))
    }

    pub fn publish(self, topic: &str, payload: &[u8]) -> Result<()> {
        status(unsafe {
            self.0.publish.unwrap()(self.0.context, Bytes::new(topic.as_bytes()), Bytes::new(payload))
        })
    }

    pub fn subscribe(self, topic: &str) -> Result<()> {
        status(unsafe { self.0.subscribe.unwrap()(self.0.context, Bytes::new(topic.as_bytes())) })
    }

    pub fn unsubscribe(self, topic: &str) -> Result<()> {
        status(unsafe { self.0.unsubscribe.unwrap()(self.0.context, Bytes::new(topic.as_bytes())) })
    }

    pub fn log(self, level: Level, message: &str) -> Result<()> {
        status(unsafe {
            self.0.diagnostic.unwrap()(self.0.context, level as u32, Bytes::new(message.as_bytes()))
        })
    }

    pub fn configuration<T: DeserializeOwned>(self) -> Result<T> {
        let mut bytes = Vec::new();
        status(unsafe { self.0.configuration.unwrap()(self.0.context, output(&mut bytes)) })?;
        from_slice(&bytes).map_err(|error| Error::new(abi::INVALID_ARG, error.to_string()))
    }

    pub fn package_root(self) -> Result<PathBuf> {
        let mut bytes = Vec::new();
        status(unsafe { self.0.package_root.unwrap()(self.0.context, output(&mut bytes)) })?;
        Ok(PathBuf::from(from_utf8(&bytes).map_err(|error| {
            Error::new(abi::INVALID_ARG, error.to_string())
        })?))
    }
}

fn status(code: i32) -> Result<()> {
    if code == abi::OK {
        Ok(())
    } else {
        Err(Error::new(code, "host operation failed; see Core diagnostics"))
    }
}

fn output(bytes: &mut Vec<u8>) -> Output {
    Output {
        context: (bytes as *mut Vec<u8>).cast(),
        write: Some(collect)
    }
}

unsafe extern "C" fn collect(context: *mut c_void, input: Bytes) -> i32 {
    if context.is_null() { return abi::INVALID_ARG }
    let Ok(input) = (unsafe { input.read() }) else {
        return abi::INVALID_ARG
    };
    let output = unsafe { &mut *context.cast::<Vec<u8>>() };
    if input.len() > abi::MAX_ABI_BYTES.saturating_sub(output.len()) { return abi::INVALID_ARG }
    output.extend_from_slice(input);
    abi::OK
}
