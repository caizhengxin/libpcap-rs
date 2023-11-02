use std::path::Path;
use libpcap_rs::LibPcap;


#[test]
fn test_read_pcap() {
    let path = std::env::current_dir().unwrap_or_default().join(Path::new("tests/pcap/http_1.pcap")).to_string_lossy().to_string();

    match LibPcap::open(&path, "r") {
        Ok(f) => {
            for pkt in f.read() {
                println!("{:?}", pkt);
            }        
        }
        Err(e) => {
            println!("[ERROR]: {e:?}");
        }
    }
}