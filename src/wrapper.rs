use std::str::FromStr;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use jkcenum::JkcEnum;
use crate::errors::LibPcapError;
use crate::libpcap::{pcap_t, pcap_open_offline, pcap_next};


#[derive(Debug)]
pub struct LibPcap<'a> {
    pub path: &'a str,
    pub filter: Option<&'a str>,
    pub mode: LibPcapMode,
    pub snaplen: usize,
    iter: LibPcapIterator<'a>,
    // in_pcap: *mut pcap_t,
    // out_pcap: pcap_t,
}


#[derive(Debug, Default, JkcEnum)]
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


impl<'a> LibPcap<'a> {
    pub fn open(path: &'a str, mode: &'a str) -> Result<Self, LibPcapError<'a>> {
        let mut errbuf = [0; 65535];

        let pathobj = join_home(path);

        println!("{:?}", pathobj.to_str());

        if !pathobj.is_file() {
            return Err(LibPcapError::InvalidFile { path });
        }

        let in_pcap = unsafe {
            pcap_open_offline(CString::new(pathobj.to_str().unwrap_or_default()).unwrap_or_default().as_ptr(), errbuf.as_mut_ptr())
        };

        Ok(Self {
            path,
            filter: None,
            mode: LibPcapMode::from_str(mode).unwrap(),
            snaplen: 65535,
            iter: LibPcapIterator { in_pcap, _mark: &[] },
        })
    }

    pub fn read(&self) -> &LibPcapIterator<'a> {
        &self.iter
    }
}


impl<'a> Iterator for &LibPcapIterator<'a> {
    type Item = LibPcapPacketInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
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
