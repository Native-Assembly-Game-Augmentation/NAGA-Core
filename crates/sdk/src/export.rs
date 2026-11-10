use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::str::from_utf8;
use std::sync::Mutex;

use naga_abi::{self as abi, Bytes, HostAPI, ModuleAPI, Output};

use crate::{Error, Host, Level, Module, Result};

struct Context<M: Module> {
    host: Host,
    module: Mutex<M>
}

pub unsafe fn entry<M: Module>(host: *const HostAPI, output: *mut *const ModuleAPI) -> i32 {
    if output.is_null() { return abi::INVALID_ARG }
    unsafe {
        output.write(ptr::null());
    }
    let Ok(host) = (unsafe { Host::from_raw(host) }) else {
        return abi::UNSUPPORTED
    };
    let created = catch_unwind(AssertUnwindSafe(|| M::create(host)));
    let module = match created {
        Ok(Ok(module)) => module,
        Ok(Err(error)) => {
            let _ = host.log(Level::Error, &error.to_string());
            return error.code
        }
        Err(_) => return abi::PANIC
    };
    let context = Box::into_raw(Box::new(Context {
        host,
        module: Mutex::new(module)
    })).cast();
    let api = Box::new(ModuleAPI {
        struct_size: ModuleAPI::expected_size(),
        abi: abi::ABIVersion::CURRENT,
        module_id: Bytes::new(M::ID.as_bytes()),
        module_version: Bytes::new(M::VERSION.as_bytes()),
        context,
        start: Some(start::<M>),
        stop: Some(stop::<M>),
        service: Some(service::<M>),
        event: Some(event::<M>),
        destroy: Some(destroy::<M>)
    });
    unsafe {
        output.write(Box::into_raw(api));
    }
    abi::OK
}

fn invoke<M: Module>(pointer: *mut c_void, action: impl FnOnce(&mut M) -> Result<()>) -> i32 {
    if pointer.is_null() { return abi::INVALID_ARG }
    let context = unsafe { &*pointer.cast::<Context<M>>() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut module = context.module.lock().map_err(|_| Error::new(abi::PANIC, "module mutex is poisoned"))?;
        action(&mut *module)
    }));
    match result {
        Ok(Ok(())) => abi::OK,
        Ok(Err(error)) => {
            let _ = context.host.log(Level::Error, &error.to_string());
            error.code
        }
        Err(_) => {
            let _ = context.host.log(Level::Error, "panic contained at module ABI boundary");
            abi::PANIC
        }
    }
}

unsafe extern "C" fn start<M: Module>(context: *mut c_void) -> i32 {
    invoke::<M>(context, M::start)
}
unsafe extern "C" fn stop<M: Module>(context: *mut c_void) -> i32 {
    invoke::<M>(context, M::stop)
}

unsafe extern "C" fn service<M: Module>(context: *mut c_void, name: Bytes, operation: Bytes, payload: Bytes, output: Output) -> i32 {
    invoke::<M>(context, |module| {
        let name = text(name)?;
        let operation = text(operation)?;
        let payload = unsafe { payload.read() }.map_err(|code| Error::new(code, "invalid input payload"))?;
        let result = module.service(name, operation, payload)?;
        if result.len() > abi::MAX_ABI_BYTES { return Err(Error::new(abi::INVALID_ARG, "module response exceeds ABI limit")) }
        let writer = output.write.ok_or_else(|| Error::new(abi::INVALID_ARG, "missing output writer"))?;
        let code = unsafe { writer(output.context, Bytes::new(&result)) };
        if code != abi::OK { return Err(Error::new(code, "output writer rejected response")) }
        Ok(())
    })
}

unsafe extern "C" fn event<M: Module>(context: *mut c_void, source: Bytes, topic: Bytes, payload: Bytes) -> i32 {
    invoke::<M>(context, |module| {
        module.event(
            text(source)?,
            text(topic)?,
            unsafe { payload.read() }.map_err(|code| Error::new(code, "invalid event payload"))?,
        )
    })
}

unsafe extern "C" fn destroy<M: Module>(context: *mut c_void) {
    if !context.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(context.cast::<Context<M>>()));
        }));
    }
}

fn text<'a>(input: Bytes) -> Result<&'a str> {
    from_utf8(unsafe { input.read() }.map_err(|code| Error::new(code, "invalid ABI string"))?)
        .map_err(|error| Error::new(abi::INVALID_ARG, error.to_string()))
}
