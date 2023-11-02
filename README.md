# libpcap-rs

- python-libpcap: https://github.com/caizhengxin/python-libpcap

## Features

- [x] Read pcap file
- [ ] Write pcap file
- [ ] Merge pcap file
- [ ] Get first iface
- [ ] Get iface list
- [ ] Send raw packet
- [ ] Capture data

## Usage

### Read pcap file

```rust
use libpcap_rs::LibPcap;


#[test]
fn test_read_pcap() {
    match LibPcap::open("~/tests/pcap/http_1.pcap", "r") {
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
```
