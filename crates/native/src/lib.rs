#![deny(unsafe_code)]

mod ffi;

pub use ffi::{Library, ModuleBinding, NativeError, ProcessTree, initialize};
