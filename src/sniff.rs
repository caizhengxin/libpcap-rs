use std::ffi::{CString, CStr};
use std::marker::PhantomData;
use crate::PResult;
use crate::libpcap::{
    pcap_t, pcap_stat,
    pcap_create, pcap_activate, pcap_geterr,
    pcap_set_snaplen, pcap_set_promisc, pcap_set_timeout,
    pcap_set_immediate_mode, pcap_set_buffer_size, pcap_set_datalink,
    pcap_set_rfmon, pcap_set_tstamp_precision, pcap_set_tstamp_type, pcap_close,
    pcap_next, pcap_stats,
};
use crate::time::now_timestamp;
use crate::errors::LibPcapError;
use crate::wrapper::{libpcap_set_filter, get_first_iface};
use crate::wrapper::LibPcapPacketInfo;


type PcapStat = pcap_stat;


#[derive(Debug)]
pub struct Sniff {
    pub iface: String,
    handle: *mut pcap_t,
}


fn get_pcap_error(handle: *mut pcap_t) -> String {
    let slice = unsafe { CStr::from_ptr(pcap_geterr(handle)) };
    
    String::from_utf8_lossy(slice.to_bytes()).to_string()
}


unsafe impl std::marker::Sync for Sniff { }
unsafe impl std::marker::Send for Sniff { }


impl Sniff {
    /// Open capture device
    /// 
    /// # Args:
    /// 
    /// - `iface`: Network port name.
    pub fn open<T>(iface: T) -> Result<Self, LibPcapError>
    where
        T: AsRef<[u8]>,
    {
        let mut errbuf = String::new();
        let iface_cstring = CString::new(iface.as_ref()).unwrap_or_default();

        let handle = unsafe { pcap_create(iface_cstring.as_ptr(), errbuf.as_mut_ptr() as *mut i8) };

        if handle.is_null() {
            return Err(LibPcapError::InvalidInterface {
                iface: iface_cstring.to_string_lossy().to_string(),
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
                iface: iface_cstring.to_string_lossy().to_string(),
                msg: get_pcap_error(handle),
            });
        }

        Ok(Self {
            iface: iface_cstring.to_string_lossy().to_string(),
            handle,
        })
    }

    /// Find the active network port and open the device
    pub fn lookup(&self) -> PResult<Self> {
        let iface = get_first_iface()?;

        Self::open(iface)
    }

    /// Set snaplen
    pub fn with_snaplen(&self, snaplen: i32) -> &Self {
        unsafe { pcap_set_snaplen(self.handle, snaplen) };

        &self
    }

    /// Set bpf filter
    pub fn with_filter<T>(&self, value: T) -> Result<&Self, LibPcapError>
    where
        T: Into<Vec<u8>>,
    {
        libpcap_set_filter(self.handle, value)?;

        Ok(&self)
    }

    /// Set promiscuous
    pub fn with_promisc(&self, value: i32) -> &Self {
        unsafe { pcap_set_promisc(self.handle, value) };

        &self
    }

    /// Set timeout
    pub fn with_timeout(&self, value: i32) -> &Self {
        unsafe { pcap_set_timeout(self.handle, value) };

        &self
    }

    /// Set immediate mode
    pub fn with_immediate_mode(&self, value: i32) -> &Self {
        unsafe { pcap_set_immediate_mode(self.handle, value) };

        &self
    }

    /// Set buffer size
    pub fn with_buffer_size(&self, value: i32) -> &Self {
        unsafe { pcap_set_buffer_size(self.handle, value) };

        &self
    }

    /// Set data link
    pub fn with_datalink(&self, value: i32) -> &Self {
        unsafe { pcap_set_datalink(self.handle, value) };

        &self
    }

    /// Set rfmon
    pub fn with_rfmon(&self, value: i32) -> &Self {
        unsafe { pcap_set_rfmon(self.handle, value) };

        &self
    }

    /// Set timestamp precision
    pub fn with_tstamp_precision(&self, value: i32) -> &Self {
        unsafe { pcap_set_tstamp_precision(self.handle, value) };

        &self
    }

    /// Set timestamp type
    pub fn with_tstamp_type(&self, value: i32) -> &Self {
        unsafe { pcap_set_tstamp_type(self.handle, value) };

        &self
    }

    /// Capture data packet
    /// 
    /// # Args:
    /// 
    /// - `count`: Number of captured packets.
    /// 
    /// # Returns:
    /// 
    /// - `SniffIterator`
    /// 
    pub fn capture(&self, count: isize) -> SniffIterator {
        SniffIterator::new(self.handle, count)
    }

    /// pcap stats
    pub fn stats(&self) -> Option<PcapStat> {
        let mut pcap_stat_value = std::mem::MaybeUninit::uninit();
        if unsafe { pcap_stats(self.handle, pcap_stat_value.as_mut_ptr()) } != 0 {
            return None;
        }

        let pcap_stat_value = unsafe { pcap_stat_value.assume_init() };

        Some(pcap_stat_value)
    }
}


impl Drop for Sniff {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { pcap_close(self.handle) };
        }
    }
}


/// Capture the packet iterator
pub struct SniffIterator<'a> {
    handle: *mut pcap_t,
    count: isize,
    index: isize,
    _mark: PhantomData<&'a u8>,
}


impl<'a> SniffIterator<'a> {
    /// Initializes the iterator
    /// 
    /// # Args:
    /// 
    /// - `handle`: `pcap_create` handle.
    /// - `count`: Capture the packet count.
    /// 
    /// # Returns:
    /// 
    /// - `SniffIterator`
    /// 
    pub fn new(handle: *mut pcap_t, count: isize) -> Self {
        Self {
            handle,
            count,
            index: 0,
            _mark: PhantomData,
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
