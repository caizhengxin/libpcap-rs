use libpcap_rs::libpcap::pcap_lookupdev;

fn main() {
    let mut errbuf = [0; 65535];

    unsafe {
        let value = pcap_lookupdev(errbuf.as_mut_ptr());
        println!("{:?}", std::ffi::CStr::from_ptr(value));
    }
}
