# libpcap-rs

developing ...

- python-libpcap: https://github.com/caizhengxin/python-libpcap

## Features

- [x] Read pcap file
- [x] Write pcap file
- [ ] Merge pcap file
- [ ] Get first iface
- [ ] Get iface list
- [ ] Send raw packet
- [x] Capture packet

## Usage

> Cargo.toml

```toml
[dependencies]
libpcap_rs = { git = "https://github.com/caizhengxin/libpcap-rs.git" }
```

### Read pcap file

```rust
use libpcap_rs::LibPcap;


fn main() {
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

### Write pcap file

```rust
use libpcap_rs::LibPcap;


fn main() {
    let input = b"\x00\x0c\x29\xaf\x7f\xfe\x10\x9a\xdd\x4e\x06\x0d\x08\x00\x45\x00\
    \x00\x40\xb5\xf2\x00\x00\x40\x06\xa9\x7c\x0a\x01\x01\xea\x0a\x0a\
    \x05\x55\xc8\xd3\x01\xf6\xe0\x76\x90\x16\xc4\x44\x9b\x5a\x80\x18\
    \xff\xff\x6c\x1c\x00\x00\x01\x01\x08\x0a\x37\xc4\x50\xe2\x00\xba\
    \x7c\x1c\x4d\x6e\x00\x00\x00\x06\xff\x03\x01\xf4\x00\x64";

    let libpcap = LibPcap::open("test.pcap", "w");

    match libpcap {
        Ok(f) => f.write(input),
        Err(e) => println!("[ERROR]: {e:?}"),
    }
}
```

### Capture packet

```rust
use libpcap_rs::{Sniff, PResult};


fn main() -> PResult<()> {
    let sniff = Sniff::open("lo")?;

    for pkt in sniff.capture(-1) {
        println!("{pkt:?}");
    }

    Ok(())
}
```

```rust
use libpcap_rs::{Sniff, PResult};


fn main() -> PResult<()> {
    let sniff = Sniff::open("lo")?
        .with_filter("port 80")?
        .with_snaplen(65535)
        .with_immediate_mode(1)
        .with_timeout(0);

    for pkt in sniff.capture(-1) {
        println!("{pkt:?}");
    }

    Ok(())
}
```
