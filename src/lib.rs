#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod libpcap;
pub mod wrapper;
pub mod errors;
pub mod sniff;
pub mod traits;
pub(crate) mod time;
mod utils;
mod ffi;
pub mod path;
pub mod net;

pub use wrapper::{LibPcap, get_first_iface, get_iface_list, send_packet};
pub use sniff::Sniff;
pub use errors::LibPcapError;
pub use net::*;

pub type PResult<I> = Result<I, LibPcapError>;
