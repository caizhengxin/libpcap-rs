use std::ffi::{CString, CStr};
use crate::libpcap::{
    pcap_t, pcap_create, pcap_activate, pcap_geterr,
    pcap_set_snaplen, pcap_set_promisc, pcap_set_timeout,
    pcap_set_immediate_mode, pcap_set_buffer_size, pcap_set_datalink,
    pcap_set_rfmon, pcap_set_tstamp_precision, pcap_set_tstamp_type, pcap_close,
    pcap_next
};
use crate::time::now_timestamp;
use crate::errors::LibPcapError;
use crate::wrapper::libpcap_set_filter;
use crate::wrapper::LibPcapPacketInfo;


#[derive(Debug)]
pub struct Sniff<'a> {
    pub iface: &'a str,
    handle: *mut pcap_t,
}


fn get_pcap_error(handle: *mut pcap_t) -> String {
    let slice = unsafe { CStr::from_ptr(pcap_geterr(handle)) };
    
    String::from_utf8_lossy(slice.to_bytes()).to_string()
}


impl<'a> Sniff<'a> {
    pub fn open(iface: &'a str) -> Result<Self, LibPcapError> {
        let mut errbuf = String::new();
        let iface_cstring = CString::new(iface).unwrap_or_default();

        let handle = unsafe { pcap_create(iface_cstring.as_ptr(), errbuf.as_mut_ptr() as *mut i8) };

        if handle.is_null() {
            return Err(LibPcapError::InvalidInterface {
                iface: iface.to_string(),
                msg: errbuf,
            });
        }

        unsafe {
            pcap_set_snaplen(handle, 65535);
            pcap_set_promisc(handle, 0);
            pcap_set_timeout(handle, 0);
            pcap_set_immediate_mode(handle, 1);
        }

        let activate = unsafe { pcap_activate(handle) };

        if activate != 0 {
            return Err(LibPcapError::InvalidInterface {
                iface: iface.to_string(),
                msg: get_pcap_error(handle),
            });
        }

        Ok(Self {
            iface,
            handle,
        })
    }

    pub fn with_snaplen(&self, snaplen: i32) -> &Self {
        unsafe { pcap_set_snaplen(self.handle, snaplen) };

        &self
    }

    pub fn with_filter(&self, value: &'a str) -> Result<&Self, LibPcapError> {
        libpcap_set_filter(self.handle, value)?;

        Ok(&self)
    }

    pub fn with_promisc(&self, value: i32) -> &Self {
        unsafe { pcap_set_promisc(self.handle, value) };

        &self
    }

    pub fn with_timeout(&self, value: i32) -> &Self {
        unsafe { pcap_set_timeout(self.handle, value) };

        &self
    }

    pub fn with_immediate_mode(&self, value: i32) -> &Self {
        unsafe { pcap_set_immediate_mode(self.handle, value) };

        &self
    }

    pub fn with_buffer_size(&self, value: i32) -> &Self {
        unsafe { pcap_set_buffer_size(self.handle, value) };

        &self
    }

    pub fn with_datalink(&self, value: i32) -> &Self {
        unsafe { pcap_set_datalink(self.handle, value) };

        &self
    }

    pub fn with_rfmon(&self, value: i32) -> &Self {
        unsafe { pcap_set_rfmon(self.handle, value) };

        &self
    }

    pub fn with_tstamp_precision(&self, value: i32) -> &Self {
        unsafe { pcap_set_tstamp_precision(self.handle, value) };

        &self
    }

    pub fn with_tstamp_type(&self, value: i32) -> &Self {
        unsafe { pcap_set_tstamp_type(self.handle, value) };

        &self
    }

    pub fn capture(&self, count: isize) -> SniffIterator {
        SniffIterator::new(self.handle, count)
    }
}


impl<'a> Drop for Sniff<'a> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { pcap_close(self.handle) };
        }
    }
}


pub struct SniffIterator<'a> {
    handle: *mut pcap_t,
    count: isize,
    index: isize,
    _mark: Option<&'a [u8]>,
}


impl<'a> SniffIterator<'a> {
    pub fn new(handle: *mut pcap_t, count: isize) -> Self {
        Self {
            handle,
            count,
            index: 0,
            _mark: None,
        }
    }
}


impl<'a> Iterator for SniffIterator<'a> {
    type Item = LibPcapPacketInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.handle.is_null() {
            return None;
        }

        if self.count != -1 {
            if self.index >= self.count {
                return None;
            }
        }

        let pkt_header = std::mem::MaybeUninit::uninit();
        let mut pkt_header = unsafe { pkt_header.assume_init() };

        let pkt = unsafe {
            let pkt = pcap_next(self.handle, &mut pkt_header);
            std::slice::from_raw_parts(pkt, pkt_header.caplen as usize)
        };

        if pkt.is_empty() {
            Some(Self::Item {
                timestamp: now_timestamp() as i64,
                caplen: 0,
                buf: &[],
            })
        }
        else {
            self.index += 1;

            Some(Self::Item {
                timestamp: pkt_header.ts.tv_sec,
                caplen: pkt_header.caplen,
                buf: &pkt,
            })
        }
    }
}
