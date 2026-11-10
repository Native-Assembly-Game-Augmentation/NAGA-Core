mod export;
mod host;

pub use export::entry;
pub use host::{Host, Level};
pub use naga_abi as abi;
use std::error::Error as StdError;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug)]
pub struct Error {
    pub code: i32,
    pub message: String
}

impl Error {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl StdError for Error {}

pub trait Module: Send + Sized + 'static {
    const ID: &'static str;
    const VERSION: &'static str;
    fn create(host: Host) -> Result<Self>;
    fn start(&mut self) -> Result<()>;
    fn stop(&mut self) -> Result<()> {
        Ok(())
    }
    fn service(&mut self, _name: &str, _operation: &str, _payload: &[u8]) -> Result<Vec<u8>> {
        Err(Error::new(abi::UNSUPPORTED, "service operation is unsupported"))
    }
    fn event(&mut self, _source: &str, _topic: &str, _payload: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[macro_export]
macro_rules! export_module {
    ($module:ty) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn naga_entry_v1(
            host: *const $crate::abi::HostAPI,
            output: *mut *const $crate::abi::ModuleAPI
        ) -> i32 {
            unsafe { $crate::entry::<$module>(host, output) }
        }
    };
}
