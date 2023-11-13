# libpcap-rs

developing ...

- python-libpcap: https://github.com/caizhengxin/python-libpcap

## Features

- [x] Read pcap file
- [x] Write pcap file
- [x] Merge pcap file
- [x] Get first iface (active)
- [x] Get iface list (active)
- [x] Send raw packet
- [x] Capture packet

## Usage

> Install

```bash
$ sudo apt install libpcap-dev -yq
```

> Command

```bash
$ cargo build --release

$ ./target/release/libpcap-merge -i ~/pcap/ -o new.pcap port 80
```

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

### Obtain the first active network port

```rust
use libpcap_rs::get_first_iface;


fn main() {
    println!("{:?}", get_first_iface);
}
```

### Obtain active network port list

```rust
use libpcap_rs::get_iface_list;


fn main() {
    println!("{:?}", get_iface_list());
}
```

### Using network port send raw packet

```rust
use libpcap_rs::send_packet;


fn main() {
    let input = b"\x00\x0c\x29\xaf\x7f\xfe\x10\x9a\xdd\x4e\x06\x0d\x08\x00\x45\x00\
                \x00\x40\xb5\xf2\x00\x00\x40\x06\xa9\x7c\x0a\x01\x01\xea\x0a\x0a\
                \x05\x55\xc8\xd3\x01\xf6\xe0\x76\x90\x16\xc4\x44\x9b\x5a\x80\x18\
                \xff\xff\x6c\x1c\x00\x00\x01\x01\x08\x0a\x37\xc4\x50\xe2\x00\xba\
                \x7c\x1c\x4d\x6e\x00\x00\x00\x06\xff\x03\x01\xf4\x00\x64";
    send_packet("lo", input);
}
```
