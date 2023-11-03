#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(temporary_cstring_as_ptr)]
#![feature(let_chains)]

pub mod libpcap;
pub mod wrapper;
pub mod errors;
pub mod sniff;
pub mod traits;
pub(crate) mod time;

use errors::LibPcapError;
pub use wrapper::LibPcap;
pub use sniff::Sniff;

pub type PResult<I> = Result<I, LibPcapError>;
