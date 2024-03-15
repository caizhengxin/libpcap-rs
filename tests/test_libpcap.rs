// use std::path::Path;
#[allow(unused_imports)]
use libpcap_rs::{LibPcap, get_first_iface, get_iface_list};


#[test]
fn test_read_pcap() {
    // let path = std::env::current_dir().unwrap_or_default().join(Path::new("tests/pcap/http_1.pcap")).to_string_lossy().to_string();
    let f = LibPcap::open("tests/pcap/http_1.pcap", "r");
    assert_eq!(f.is_ok(), true);
}


#[test]
fn test_write_pcap() {
    let input = b"\x00\x0c\x29\xaf\x7f\xfe\x10\x9a\xdd\x4e\x06\x0d\x08\x00\x45\x00\
    \x00\x40\xb5\xf2\x00\x00\x40\x06\xa9\x7c\x0a\x01\x01\xea\x0a\x0a\
    \x05\x55\xc8\xd3\x01\xf6\xe0\x76\x90\x16\xc4\x44\x9b\x5a\x80\x18\
    \xff\xff\x6c\x1c\x00\x00\x01\x01\x08\x0a\x37\xc4\x50\xe2\x00\xba\
    \x7c\x1c\x4d\x6e\x00\x00\x00\x06\xff\x03\x01\xf4\x00\x64";

    let f = LibPcap::open("test.pcap", "w");

    assert_eq!(f.is_ok(), true);

    match f {
        Ok(f) => f.write(input),
        Err(e) => println!("[ERROR]: {e:?}"),
    }
}


#[test]
fn test_get_first_iface() {
    // assert_eq!(get_first_iface().is_ok(), true);
}


#[test]
fn test_get_iface_list() {
    assert_eq!(get_iface_list().is_ok(), true);
}
