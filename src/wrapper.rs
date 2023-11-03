use std::ptr::null_mut;
use std::str::FromStr;
use std::time::SystemTime;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use jkcenum::JkcEnum;
use crate::errors::LibPcapError;
use crate::libpcap::{pcap_t, pcap_pkthdr, pcap_dumper_t,
    pcap_open_offline, pcap_dump_open, pcap_open_dead, pcap_dump_open_append,
    pcap_next, pcap_close, pcap_dump, pcap_dump_close
};


#[derive(Debug)]
pub struct LibPcap<'a> {
    // pub path: &'a str,
    // pub filter: Option<&'a str>,
    mode: LibPcapMode,
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


impl<'a> Drop for LibPcap<'a> {
    fn drop(&mut self) {
        if !self.out_pcap.is_null() {
            unsafe { pcap_dump_close(self.out_pcap); }
        }
    }
}


impl<'a> LibPcap<'a> {
    pub fn open(path: &'a str, mode: &'a str) -> Result<Self, LibPcapError> {
        let mut errbuf = [0; 65535];
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
            // path,
            // filter: None,
            mode: mode_tmp,
            in_pcap_iter: LibPcapIterator { in_pcap, _mark: &[] },
            out_pcap,
        })
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
            let timestamp = SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
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