use std::{ptr, slice};
use std::ffi::c_void;
use std::mem::size_of;

pub const ENTRY_SYMBOL: &[u8] = b"naga_entry_v1\0";
pub const MAX_ABI_BYTES: usize = 8388608;
pub const OK: i32 = 0;
pub const INVALID_ARG: i32 = 1;
pub const UNSUPPORTED: i32 = 2;
pub const INTERNAL: i32 = 3;
pub const UNAVAILABLE: i32 = 4;
pub const TIMEOUT: i32 = 5;
pub const DEPENDENCY_DENIED: i32 = 6;
pub const BUSY: i32 = 7;
pub const PANIC: i32 = 8;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ABIVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32
}

impl ABIVersion {
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0
    };
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Bytes {
    pub data: *const u8,
    pub len: usize
}

impl Bytes {
    pub const EMPTY: Self = Self {
        data: ptr::null(),
        len: 0
    };

    pub fn new(value: &[u8]) -> Self {
        Self {
            data: value.as_ptr(),
            len: value.len()
        }
    }

    pub unsafe fn read<'a>(self) -> Result<&'a [u8], i32> {
        if self.len > MAX_ABI_BYTES || (self.data.is_null() && self.len != 0) {
            return Err(INVALID_ARG)
        }

        if self.len == 0 {
            return Ok(&[])
        }

        Ok(unsafe { slice::from_raw_parts(self.data, self.len) })
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Output {
    pub context: *mut c_void,
    pub write: Option<unsafe extern "C" fn (*mut c_void, Bytes) -> i32>
}

pub type RegisterService = unsafe extern "C" fn (*mut c_void, Bytes, Bytes) -> i32;
pub type CallService = unsafe extern "C" fn (*mut c_void, Bytes, Bytes, Bytes, Bytes, Output) -> i32;
pub type Publish = unsafe extern "C" fn (*mut c_void, Bytes, Bytes) -> i32;
pub type Subscribe = unsafe extern "C" fn (*mut c_void, Bytes) -> i32;
pub type Diagnostic = unsafe extern "C" fn (*mut c_void, u32, Bytes) -> i32;
pub type Configuration = unsafe extern "C" fn (*mut c_void, Output) -> i32;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostAPI {
    pub struct_size: u32,
    pub abi: ABIVersion,
    pub context: *mut c_void,
    pub register_service: Option<RegisterService>,
    pub unregister_service: Option<RegisterService>,
    pub call_service: Option<CallService>,
    pub publish: Option<Publish>,
    pub subscribe: Option<Subscribe>,
    pub unsubscribe: Option<Subscribe>,
    pub diagnostic: Option<Diagnostic>,
    pub configuration: Option<Configuration>,
    pub package_root: Option<Configuration>
}

impl HostAPI {
    pub fn expected_size() -> u32 {
        size_of::<Self>() as u32
    }
}

pub type Lifecycle = unsafe extern "C" fn (*mut c_void) -> i32;
pub type Service = unsafe extern "C" fn (*mut c_void, Bytes, Bytes, Bytes, Output) -> i32;
pub type Event = unsafe extern "C" fn (*mut c_void, Bytes, Bytes, Bytes) -> i32;
pub type Destroy = unsafe extern "C" fn (*mut c_void);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ModuleAPI {
    pub struct_size: u32,
    pub abi: ABIVersion,
    pub module_id: Bytes,
    pub module_version: Bytes,
    pub context: *mut c_void,
    pub start: Option<Lifecycle>,
    pub stop: Option<Lifecycle>,
    pub service: Option<Service>,
    pub event: Option<Event>,
    pub destroy: Option<Destroy>
}

impl ModuleAPI {
    pub fn expected_size() -> u32 {
        size_of::<Self>() as u32
    }
}

pub type Entry = unsafe extern "C" fn (*const HostAPI, *mut *const ModuleAPI) -> i32;
