use libpcap_rs::{get_first_iface, get_iface_list};


fn main() {
    println!("{:?}", get_first_iface());
    println!("{:?}", get_iface_list());
}