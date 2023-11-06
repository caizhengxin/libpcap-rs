use std::ptr::null_mut;
use std::str::FromStr;
use std::ffi::{CString, CStr};
use std::path::{Path, PathBuf};
use jkcenum::JkcEnum;
use crate::PResult;
use crate::errors::LibPcapError;
use crate::time::now_timestamp;
use crate::make_cstr;
use crate::libpcap::{
    pcap_t, pcap_pkthdr, pcap_dumper_t, bpf_program,
    pcap_open_offline, pcap_dump_open, pcap_open_dead, pcap_dump_open_append,
    pcap_next, pcap_close, pcap_dump, pcap_dump_close, pcap_dump_flush, pcap_compile, pcap_setfilter, pcap_freecode,
    pcap_lookupdev,
    PCAP_ERRBUF_SIZE, pcap_findalldevs, pcap_freealldevs, pcap_open_live, pcap_sendpacket,
};


pub struct LibPcap<'a> {
    in_pcap_iter: LibPcapIterator<'a>,
    out_pcap: *mut pcap_dumper_t,
}


#[derive(Debug, Default, JkcEnum, PartialEq, Eq)]
pub enum LibPcapMode {
    #[default]
    #[jenum(rename="r")]
    Read,
    #[jenum(rename="w")]
    Write,
    #[jenum(rename="a")]
    Append,
}


#[derive(Debug)]
pub struct LibPcapIterator<'a> {
    in_pcap: *mut pcap_t,
    _mark: &'a [u8]
}


#[derive(Debug)]
pub struct LibPcapPacketInfo<'a> {
    pub timestamp: i64,
    pub caplen: u32,
    pub buf: &'a [u8],
}


pub fn join_home<'a>(path: &'a str) -> PathBuf {
    if let Some(path) = path.strip_prefix('~') && let Ok(home_dir) = std::env::var("HOME") {
        return Path::new(&home_dir).join(Path::new(path));
    }

    Path::new(path).to_path_buf()
}


pub fn libpcap_set_filter<'a>(handle: *mut pcap_t, bpf_filter: &'a str) -> Result<(), LibPcapError> {
    let fp: std::mem::MaybeUninit<bpf_program> = std::mem::MaybeUninit::uninit();
    let mut fp = unsafe { fp.assume_init() };

    let bpf_filter = CString::new(bpf_filter).unwrap_or_default();

    let ret = unsafe { pcap_compile(handle, &mut fp, bpf_filter.as_ptr() as *const i8, 1, 0) };

    if ret == -1 {
        return Err(LibPcapError::InvalidBpfFilter);
    }

    let ret = unsafe { pcap_setfilter(handle, &mut fp) };

    if ret == -1 {
        unsafe { pcap_freecode(&mut fp) };
        return Err(LibPcapError::InvalidBpfFilter);
    }

    unsafe { pcap_freecode(&mut fp) };

    Ok(())
}


impl<'a> Drop for LibPcap<'a> {
    fn drop(&mut self) {
        if !self.out_pcap.is_null() {
            unsafe {
                pcap_dump_flush(self.out_pcap);
                pcap_dump_close(self.out_pcap);
            }
        }
    }
}


impl<'a> LibPcap<'a> {
    pub fn open(path: &'a str, mode: &'a str) -> Result<Self, LibPcapError> {
        let mut errbuf = [0; PCAP_ERRBUF_SIZE as usize];
        let pathobj = join_home(path);
        let mut mode_tmp = LibPcapMode::Read;

        if let Ok(v) = LibPcapMode::from_str(mode) {
            mode_tmp = v;
        }

        if mode_tmp == LibPcapMode::Read && !pathobj.exists() {
            return Err(LibPcapError::FileNotExtists { path: path.to_string() });
        }

        if mode_tmp == LibPcapMode::Read && !pathobj.is_file() {
            return Err(LibPcapError::InvalidFile { path: path.to_string() });
        }

        let path_cstring = CString::new(pathobj.to_str().unwrap_or_default()).unwrap_or_default();

        let in_pcap = if mode_tmp == LibPcapMode::Read { 
            let value = unsafe { pcap_open_offline(path_cstring.as_ptr(), errbuf.as_mut_ptr()) };

            if value.is_null() {
                return Err(LibPcapError::InvalidFile { path: path.to_string() })
            }    

            value
        } else { null_mut() };

        let out_pcap = match mode_tmp {
            LibPcapMode::Write => {
                let value = unsafe { pcap_dump_open(pcap_open_dead (1, 65535), path_cstring.as_ptr()) };

                if value.is_null() {
                    return Err(LibPcapError::InvalidFile { path: path.to_string() })
                }    

                value
            },
            LibPcapMode::Append => {
                let value = unsafe { pcap_dump_open_append(pcap_open_dead (1, 65535), path_cstring.as_ptr()) };

                if value.is_null() {
                    return Err(LibPcapError::InvalidFile { path: path.to_string() })
                }    

                value
            },
            _ => null_mut(),
        };

        Ok(Self {
            in_pcap_iter: LibPcapIterator { in_pcap, _mark: &[] },
            out_pcap,
        })
    }

    pub fn with_filter(&self, value: &'a str) -> Result<&Self, LibPcapError> {
        libpcap_set_filter(self.in_pcap_iter.in_pcap, value)?;

        Ok(&self)
    }

    pub fn read(&self) -> &LibPcapIterator<'a> {
        &self.in_pcap_iter
    }

    pub fn write(&self, buf: &[u8]) {
        if !self.out_pcap.is_null() {
            let pkt_header: std::mem::MaybeUninit<pcap_pkthdr> = std::mem::MaybeUninit::uninit();
            let mut pkt_header = unsafe { pkt_header.assume_init() };
    
            pkt_header.caplen = buf.len() as u32;
            pkt_header.len = pkt_header.caplen;
            let timestamp = now_timestamp() as i64;
            pkt_header.ts.tv_sec = timestamp as i64;
            
            unsafe { pcap_dump(self.out_pcap as *mut u8, &pkt_header, buf.as_ptr()); };    
        }
    }
}


impl<'a> Iterator for &LibPcapIterator<'a> {
    type Item = LibPcapPacketInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.in_pcap.is_null() {
            return None;
        }

        let mut pkt_header = std::mem::MaybeUninit::uninit();

        let pkt = unsafe {
            let pkt = pcap_next(self.in_pcap, pkt_header.as_mut_ptr());
            std::slice::from_raw_parts(pkt, pkt_header.assume_init().caplen as usize)
        };

        let pkt_header = unsafe { pkt_header.assume_init() };

        if pkt.is_empty() {
            None
        }
        else {
            Some(Self::Item {
                timestamp: pkt_header.ts.tv_sec,
                caplen: pkt_header.caplen,
                buf: &pkt,
            })
        }
    }
}


impl<'a> Drop for LibPcapIterator<'a> {
    fn drop(&mut self) {
        if !self.in_pcap.is_null() {
            unsafe { pcap_close(self.in_pcap); }
        }
    }
} 


/// Obtain the first active network port
/// 
/// # Returns:
/// 
/// - `PResult<String>`
/// 
/// # Examples:
/// 
/// ```rust
/// use libpcap_rs::get_first_iface;
/// 
/// println!("{:?}", get_first_iface())
/// ```
/// 
pub fn get_first_iface() -> PResult<String> {
    let mut errbuf = [0; PCAP_ERRBUF_SIZE as usize];

    unsafe {
        let value = pcap_lookupdev(errbuf.as_mut_ptr());

        if value.is_null() {
            Err(LibPcapError::LookUpDevError {
                msg: CStr::from_ptr(errbuf.as_ptr()).to_string_lossy().to_string(),
            })
        }
        else {
            Ok(CStr::from_ptr(value).to_string_lossy().to_string())
        }
    }
}


/// Obtain active network port list
/// 
/// # Returns:
/// 
/// - `PResult<Vec<String>>`
/// 
/// # Examples:
/// 
/// ```rust
/// use libpcap_rs::get_iface_list;
/// 
/// println!("{:?}", get_iface_list())
/// ```
/// 
pub fn get_iface_list() -> PResult<Vec<String>> {
    let mut errbuf = [0; PCAP_ERRBUF_SIZE as usize];
    let mut interfaces = std::mem::MaybeUninit::uninit();
    let mut interface_list = vec![];

    let ret = unsafe { pcap_findalldevs(interfaces.as_mut_ptr(), errbuf.as_mut_ptr()) };

    if ret == -1 {
        return Err(LibPcapError::FindAllDevsError {
            msg: make_cstr!(errbuf.as_ptr()),
        })
    }

    let interfaces = unsafe { interfaces.assume_init() };

    let mut interface_temp = interfaces;

    while !interface_temp.is_null() {
        interface_list.push(make_cstr!((*interface_temp).name));
        interface_temp = unsafe {(*interface_temp).next};
    }

    unsafe { pcap_freealldevs(interfaces) };

    Ok(interface_list)
}


/// Using network port send raw packet
/// 
/// # Args:
/// 
/// - `iface: T`: network port name
/// - `buf: T`: send raw data
/// 
/// # Returns
/// 
/// - `PResult<()>`
/// 
/// # Examples:
/// 
/// ```rust
/// use libpcap_rs::send_packet;
/// 
/// let input = b"\x00\x0c\x29\xaf\x7f\xfe\x10\x9a\xdd\x4e\x06\x0d\x08\x00\x45\x00\
///               \x00\x40\xb5\xf2\x00\x00\x40\x06\xa9\x7c\x0a\x01\x01\xea\x0a\x0a\
///               \x05\x55\xc8\xd3\x01\xf6\xe0\x76\x90\x16\xc4\x44\x9b\x5a\x80\x18\
///               \xff\xff\x6c\x1c\x00\x00\x01\x01\x08\x0a\x37\xc4\x50\xe2\x00\xba\
///               \x7c\x1c\x4d\x6e\x00\x00\x00\x06\xff\x03\x01\xf4\x00\x64";
/// send_packet("lo", input);
/// ```
/// 
pub fn send_packet<T: Into<Vec<u8>> + std::marker::Copy>(iface: T, buf: &[u8]) -> PResult<()> {
    let mut errbuf = [0; PCAP_ERRBUF_SIZE as usize];
    let iface = CString::new(iface).unwrap_or_default();

    let handle = unsafe { pcap_open_live(iface.as_ptr(), 65535, 0, 0, errbuf.as_mut_ptr()) };

    if handle.is_null() {
        return Err(LibPcapError::InvalidInterface {
            iface: make_cstr!(iface.as_ptr()),
            msg: make_cstr!(errbuf.as_ptr()),
        });
    }

    let ret = unsafe { pcap_sendpacket(handle, buf.as_ptr(), buf.len() as i32) };

    if ret == -1 {
        return Err(LibPcapError::SendRawPacketError);
    }

    unsafe { pcap_close(handle) };

    Ok(())
}
