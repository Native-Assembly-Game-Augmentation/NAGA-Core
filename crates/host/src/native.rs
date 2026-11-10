use std::collections::BTreeSet;
use std::error::Error;
use std::iter::once;
use naga_abi::{self as abi, HostAPI};
use naga_ipc::{BootTicket, Request, RpcError, RpcResult};
use naga_model::Platform;
use naga_native::{Library, ModuleBinding, NativeError, initialize};
use naga_package::hash_file;
use serde_json::Value;

pub struct NativeModule {
    binding: ModuleBinding<'static>,
    _libraries: Vec<Library>
}

impl NativeModule {
    pub fn load(ticket: &BootTicket, host: &'static HostAPI) -> Result<Self, Box<dyn Error>> {
        initialize();
        let root = ticket.root.canonicalize()?;
        let library = ticket.manifest.libraries.get(&Platform::current()?).ok_or("missing native platform library")?;
        let mut paths = Vec::new();
        let mut directories = BTreeSet::new();
        for path in library.load_libraries.iter().chain(once(&library.library_path)) {
            let name = path.as_ref();
            eprintln!("naga-host: trace: verifying {name}");
            let target = root.join(name).canonicalize()?;
            if !target.starts_with(&root) || !target.is_file() {
                return Err("native library path escaped package root".into())
            }
            if ticket.files.get(name) != Some(&hash_file(&target)?) {
                return Err(format!("native library checksum mismatch: {name}").into())
            }
            directories.insert(target.parent().ok_or("missing native library directory")?.to_owned());
            paths.push(target);
        }
        for directory in directories { Library::add_directory(&directory)?; }
        let mut libraries = Vec::new();
        for path in &paths {
            eprintln!("naga-host: trace: loading {}", path.file_name().unwrap().to_string_lossy());
            libraries.push(unsafe { Library::load(path)? });
        }
        let library = libraries.last().ok_or("missing entry library")?;
        eprintln!("naga-host: trace: entering module");
        let binding = unsafe { library.bind(host, ticket.key.module_id.as_ref(), &ticket.manifest.version.to_string())? };
        Ok(Self { binding, _libraries: libraries })
    }

    pub fn handle(&mut self, request: Request) -> RpcResult {
        match request {
            Request::Start => {
                self.binding.start().map_err(callback)?;
                Ok(Value::Null)
            }
            Request::Stop => {
                self.binding.stop().map_err(callback)?;
                Ok(Value::Null)
            }
            Request::InvokeService { name, operation, payload } => {
                let output = self.binding.service(&name, &operation, &payload).map_err(callback)?;
                serde_json::to_value(output).map_err(|err| RpcError::new("serialization", err.to_string()))
            }
            Request::DeliverEvent(event) => {
                self.binding.event(&event.source.to_string(), &event.topic, &event.payload).map_err(callback)?;
                Ok(Value::Null)
            }
            _ => Err(RpcError::new("dependency_denied", "request direction is not allowed"))
        }
    }
}

fn callback(err: NativeError) -> RpcError {
    let code = match err.code {
        abi::INVALID_ARG => "invalid_argument",
        abi::UNSUPPORTED => "unsupported",
        abi::UNAVAILABLE => "unavailable",
        abi::TIMEOUT => "timeout",
        abi::DEPENDENCY_DENIED => "dependency_denied",
        abi::BUSY => "busy",
        abi::PANIC => "native_panic",
        _ => "native_callback"
    };
    RpcError::new(code, err.message)
}
