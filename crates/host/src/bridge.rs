use std::ffi::c_void;
use std::str::from_utf8;
use std::time::Duration;
use naga_abi::{self as abi, ABIVersion, Bytes, HostAPI, Output};
use naga_ipc::{BootTicket, DiagnosticLevel, Peer, Request, RpcError, ServiceDescriptor};
use semver::Version;
use serde_json::Value;

pub struct Bridge {
    peer: Peer,
    configuration: Vec<u8>,
    root: Vec<u8>,
    timeout: Duration
}

impl Bridge {
    pub fn new(peer: Peer, ticket: &BootTicket, timeout: Duration) -> Result<Self, RpcError> {
        let root = ticket.root.to_str()
            .ok_or_else(|| RpcError::new("invalid_argument", "package root is not Unicode"))?.as_bytes().to_vec();
        let configuration = serde_json::to_vec(&ticket.configuration)
            .map_err(|err| RpcError::new("invalid_argument", err.to_string()))?;
        if configuration.len() > abi::MAX_ABI_BYTES {
            return Err(RpcError::new("invalid_argument", "module configuration exceeds ABI limit"))
        }
        Ok(Self { peer, root, configuration, timeout })
    }

    pub fn api(&self) -> HostAPI {
        HostAPI {
            struct_size: HostAPI::expected_size(),
            abi: ABIVersion::CURRENT,
            context: (self as *const Self).cast_mut().cast(),
            register_service: Some(register),
            unregister_service: Some(unregister),
            call_service: Some(call),
            publish: Some(publish),
            subscribe: Some(subscribe),
            unsubscribe: Some(unsubscribe),
            diagnostic: Some(diagnostic),
            configuration: Some(configuration),
            package_root: Some(package_root)
        }
    }

    fn request(&self, request: Request) -> Result<Value, RpcError> {
        self.peer.call(request, self.timeout)
    }
}

fn checked(context: *mut c_void, action: impl FnOnce(&Bridge) -> Result<(), RpcError>) -> i32 {
    if context.is_null() { return abi::INVALID_ARG }
    let bridge = unsafe { &*context.cast::<Bridge>() };
    match action(bridge) {
        Ok(()) => abi::OK,
        Err(err) => {
            eprintln!("naga-host API: {err}");
            match err.code.as_str() {
                "invalid_argument" => abi::INVALID_ARG,
                "unsupported" => abi::UNSUPPORTED,
                "unavailable" | "disconnected" => abi::UNAVAILABLE,
                "timeout" => abi::TIMEOUT,
                "dependency_denied" => abi::DEPENDENCY_DENIED,
                "busy" => abi::BUSY,
                _ => abi::INTERNAL
            }
        }
    }
}

fn text(input: Bytes) -> Result<String, RpcError> {
    let bytes = unsafe { input.read() }.map_err(|_| RpcError::new("invalid_argument", "invalid ABI bytes"))?;
    from_utf8(bytes).map(str::to_owned).map_err(|err| RpcError::new("invalid_argument", err.to_string()))
}

fn data(input: Bytes) -> Result<Vec<u8>, RpcError> {
    Ok(unsafe { input.read() }.map_err(|_| RpcError::new("invalid_argument", "invalid ABI payload"))?.to_vec())
}

fn write(output: Output, bytes: &[u8]) -> Result<(), RpcError> {
    let callback = output.write.ok_or_else(|| RpcError::new("invalid_argument", "missing output callback"))?;
    if bytes.len() > abi::MAX_ABI_BYTES || unsafe { callback(output.context, Bytes::new(bytes)) } != abi::OK {
        return Err(RpcError::new("invalid_argument", "output callback rejected response"))
    }
    Ok(())
}

fn descriptor(name: Bytes, version: Bytes) -> Result<ServiceDescriptor, RpcError> {
    Ok(ServiceDescriptor {
        name: text(name)?,
        version: Version::parse(&text(version)?).map_err(|err| RpcError::new("invalid_argument", err.to_string()))?
    })
}

unsafe extern "C" fn register(context: *mut c_void, name: Bytes, version: Bytes) -> i32 {
    checked(context, |bridge| {
        bridge.request(Request::RegisterService(descriptor(name, version)?))?;
        Ok(())
    })
}

unsafe extern "C" fn unregister(context: *mut c_void, name: Bytes, version: Bytes) -> i32 {
    checked(context, |bridge| {
        bridge.request(Request::UnregisterService(descriptor(name, version)?))?;
        Ok(())
    })
}

unsafe extern "C" fn call(context: *mut c_void, name: Bytes, version: Bytes,
                          operation: Bytes, payload: Bytes, output: Output) -> i32 {
    checked(context, |bridge| {
        let value = bridge.request(Request::CallService {
            name: text(name)?, requirement: text(version)?, operation: text(operation)?, payload: data(payload)?
        })?;
        let bytes: Vec<u8> = serde_json::from_value(value).map_err(|err| RpcError::new("invalid_argument", err.to_string()))?;
        write(output, &bytes)
    })
}

unsafe extern "C" fn publish(context: *mut c_void, topic: Bytes, payload: Bytes) -> i32 {
    checked(context, |bridge| {
        bridge.request(Request::Publish { topic: text(topic)?, payload: data(payload)? })?;
        Ok(())
    })
}

unsafe extern "C" fn subscribe(context: *mut c_void, topic: Bytes) -> i32 {
    checked(context, |bridge| {
        bridge.request(Request::Subscribe { topic: text(topic)? })?;
        Ok(())
    })
}

unsafe extern "C" fn unsubscribe(context: *mut c_void, topic: Bytes) -> i32 {
    checked(context, |bridge| {
        bridge.request(Request::Unsubscribe { topic: text(topic)? })?;
        Ok(())
    })
}

unsafe extern "C" fn diagnostic(context: *mut c_void, level: u32, message: Bytes) -> i32 {
    checked(context, |bridge| {
        let level = match level {
            0 => DiagnosticLevel::Trace,
            1 => DiagnosticLevel::Info,
            2 => DiagnosticLevel::Warn,
            3 => DiagnosticLevel::Error,
            _ => return Err(RpcError::new("invalid_argument", "invalid diagnostic level"))
        };
        bridge.request(Request::Diagnostic { level, message: text(message)? })?;
        Ok(())
    })
}

unsafe extern "C" fn configuration(context: *mut c_void, output: Output) -> i32 {
    checked(context, |bridge| write(output, &bridge.configuration))
}

unsafe extern "C" fn package_root(context: *mut c_void, output: Output) -> i32 {
    checked(context, |bridge| write(output, &bridge.root))
}
