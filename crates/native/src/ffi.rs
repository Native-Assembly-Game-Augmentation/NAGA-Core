#![allow(unsafe_code)]

use std::error::Error;
use std::ffi::{c_char, c_void};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io;
use std::marker::PhantomData;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
use std::path::Path;
use std::process::Child;
use std::ptr::{null_mut, NonNull};
use std::slice::from_raw_parts;

use naga_abi::{Bytes, HostAPI, Output, OK, INVALID_ARG, MAX_ABI_BYTES};

#[cfg(windows)]
type NativeChar = u16;
#[cfg(unix)]
type NativeChar = u8;

#[repr(C)]
struct CError {
    code: u32,
    message: [c_char; 512]
}

#[derive(Debug)]
pub struct NativeError {
    pub code: i32,
    pub message: String
}

pub struct Library {
    handle: NonNull<c_void>
}

pub struct ModuleBinding<'a> {
    handle: NonNull<c_void>,
    host: PhantomData<&'a HostAPI>
}

pub struct ProcessTree {
    handle: Option<u64>
}

impl Default for CError {
    fn default() -> Self {
        Self {
            code: 0,
            message: [0; 512]
        }
    }
}

impl Display for NativeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl Error for NativeError {}

unsafe extern "C" {
    fn naga_native_initialize();
    fn naga_native_directory(path: *const NativeChar, length: usize, error: *mut CError) -> i32;
    fn naga_native_library(path: *const NativeChar, length: usize, output: *mut *mut c_void, error: *mut CError) -> i32;
    fn naga_native_bind(library: *mut c_void, host: *const HostAPI, id: Bytes, version: Bytes, output: *mut *mut c_void, error: *mut CError) -> i32;
    fn naga_native_start(module: *mut c_void) -> i32;
    fn naga_native_stop(module: *mut c_void) -> i32;
    fn naga_native_service(module: *const c_void, name: Bytes, operation: Bytes, payload: Bytes, output: Output) -> i32;
    fn naga_native_event(module: *mut c_void, source: Bytes, topic: Bytes, payload: Bytes) -> i32;
    fn naga_native_release(module: *mut c_void);
    fn naga_native_process_attach(process: u64, pid: u32, output: *mut u64) -> u32;
    fn naga_native_process_terminate(tree: u64) -> u32;
}

impl Library {
    pub fn add_directory(path: &Path) -> Result<(), NativeError> {
        let path = encode_path(path);
        let mut error = CError::default();
        let status = unsafe { naga_native_directory(path.as_ptr(), path.len(), &mut error) };

        checked(status, error)
    }

    pub unsafe fn load(path: &Path) -> Result<Self, NativeError> {
        let path = encode_path(path);
        let mut error = CError::default();
        let mut pointer = null_mut();
        let status = unsafe { naga_native_library(path.as_ptr(), path.len(), &mut pointer, &mut error) };
        checked(status, error)?;

        Ok(Self {
            handle: NonNull::new(pointer).ok_or_else(||
                failure(INVALID_ARG, "native loader returned no handle")
            )?
        })
    }

    pub unsafe fn bind<'a>(&self, host: &'a HostAPI, id: &str, version: &str) -> Result<ModuleBinding<'a>, NativeError> {
        let mut error = CError::default();
        let mut pointer = null_mut();
        let status = unsafe {
            naga_native_bind(self.handle.as_ptr(), host, Bytes::new(id.as_bytes()), Bytes::new(version.as_bytes()), &mut pointer, &mut error)
        };

        checked(status, error)?;
        Ok(ModuleBinding {
            handle: NonNull::new(pointer).ok_or_else(|| failure(INVALID_ARG, "native binder returned no module"))?,
            host: PhantomData
        })
    }
}

impl ModuleBinding<'_> {
    pub fn start(&mut self) -> Result<(), NativeError> {
        callback(unsafe { naga_native_start(self.handle.as_ptr()) })
    }

    pub fn stop(&mut self) -> Result<(), NativeError> {
        callback(unsafe { naga_native_stop(self.handle.as_ptr()) })
    }

    pub fn service(&mut self, name: &str, operation: &str, payload: &[u8]) -> Result<Vec<u8>, NativeError> {
        if payload.len() > MAX_ABI_BYTES { return Err(failure(INVALID_ARG, "payload exceeds native ABI size")) }

        let mut output = Vec::<u8>::new();
        let writer = Output {
            context: (&mut output as *mut Vec<u8>).cast(),
            write: Some(collect)
        };

        callback(unsafe { naga_native_service(
            self.handle.as_ptr(), Bytes::new(name.as_bytes()), Bytes::new(operation.as_bytes()),
            Bytes::new(payload), writer
        ) })?;

        Ok(output)
    }

    pub fn event(&mut self, source: &str, topic: &str, payload: &[u8]) -> Result<(), NativeError> {
        if payload.len() > MAX_ABI_BYTES {
            return Err(failure(INVALID_ARG, "payload exceeds native ABI budget"))
        }

        callback(unsafe {
            naga_native_event(self.handle.as_ptr(), Bytes::new(source.as_bytes()), Bytes::new(topic.as_bytes()), Bytes::new(payload))
        })
    }
}

impl Drop for ModuleBinding<'_> {
    fn drop(&mut self) {
        unsafe { naga_native_release(self.handle.as_ptr()) }
    }
}

unsafe extern "C" fn collect(context: *mut c_void, bytes: Bytes) -> i32 {
    if context.is_null() || bytes.len > MAX_ABI_BYTES || bytes.len > 0 && bytes.data.is_null() {
        return INVALID_ARG
    }

    let output = unsafe { &mut *context.cast::<Vec<u8>>() };

    if bytes.len > MAX_ABI_BYTES.saturating_sub(output.len()) { return INVALID_ARG }
    if bytes.len > 0 { output.extend_from_slice(unsafe { from_raw_parts(bytes.data, bytes.len) }) }

    OK
}

impl ProcessTree {
    pub fn attach(child: &Child) -> io::Result<Self> {
        #[cfg(windows)]
        let process = child.as_raw_handle() as usize as u64;
        #[cfg(unix)]
        let process = 0;
        let mut handle = 0;
        let status = unsafe { naga_native_process_attach(process, child.id(), &mut handle) };
        if status != 0 { return Err(io::Error::from_raw_os_error(status as i32)) }

        Ok(Self {
            handle: Some(handle)
        })
    }

    pub fn terminate(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = unsafe { naga_native_process_terminate(handle) };
        }
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        self.terminate()
    }
}

pub fn initialize() {
    unsafe {
        naga_native_initialize()
    }
}
fn encode_path(path: &Path) -> Vec<NativeChar> {
    #[cfg(windows)]
    {
        path.as_os_str().encode_wide().collect()
    }
    #[cfg(unix)]
    {
        path.as_os_str().as_bytes().to_vec()
    }
}

fn checked(status: i32, error: CError) -> Result<(), NativeError> {
    if status == OK {
        return Ok(())
    }
    let bytes: Vec<_> = error.message
        .iter()
        .take_while(|b| **b != 0)
        .map(|b| *b as u8)
        .collect();

    let detail = String::from_utf8_lossy(&bytes);

    Err(failure(status, format!("{detail} (OS code {})", error.code)))
}

fn failure(code: i32, message: impl Into<String>) -> NativeError {
    NativeError {
        code,
        message: message.into()
    }
}

fn callback(status: i32) -> Result<(), NativeError> {
    if status == OK { Ok(()) } else {
        Err(failure(status, format!("module callback returned {status}")))
    }
}

#[cfg(test)]
mod tests {
    use std::mem::{offset_of, size_of};
    use std::path::Path;
    use naga_abi::UNAVAILABLE;
    use super::{CError, Library};

    #[test]
    fn native_error_layout_matches_the_c11_boundary() {
        assert_eq!(size_of::<CError>(), 516);
        assert_eq!(offset_of!(CError, message), 4);
    }

    #[test]
    fn native_path_rejection_preserves_the_full_error_message() {
        for path in ["", "invalid\0directory"] {
            let err = Library::add_directory(Path::new(path)).unwrap_err();
            assert_eq!(err.code, UNAVAILABLE);
            assert_eq!(err.message, "invalid native library directory (OS code 0)");
        }
    }
}
